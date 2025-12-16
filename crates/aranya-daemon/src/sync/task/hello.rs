//! Hello notification functionality for Aranya QUIC sync.
//!
//! This module handles subscription management and broadcasting of hello notifications
//! when graph heads change, allowing peers to stay synchronized.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_daemon_api::TeamId;
use aranya_runtime::{Address, GraphId, Storage, StorageProvider, SyncHelloType, SyncType};
use aranya_util::Addr;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};

use crate::sync::{
    task::{
        quic::{Error, Server, State},
        Client, SyncPeer, SyncPeers, Syncer,
    },
    Result as SyncResult,
};

/// Storage for sync hello subscriptions
#[derive(Debug, Clone)]
pub struct HelloSubscription {
    /// Delay between notifications when graph changes (rate limiting)
    graph_change_delay: Duration,
    /// Last notification time for delay management
    last_notified: Option<Instant>,
    /// Expiration time of the subscription
    expires_at: Instant,
    /// Token to cancel the scheduled sending task
    cancel_token: CancellationToken,
}

/// Type alias for hello subscription storage
/// Maps from (team_id, subscriber_address) to subscription details
pub(crate) type HelloSubscriptions = HashMap<SyncPeer, HelloSubscription>;

impl Syncer<State> {
    /// Broadcast hello notifications to all subscribers of a graph.
    #[instrument(skip_all)]
    pub async fn broadcast_hello_notifications(
        &mut self,
        graph_id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        let now = Instant::now();

        // Get all valid (non-expired) subscribers for this graph
        let subscribers = {
            let mut subscriptions = self.client.hello_subscriptions().lock().await;

            // Remove expired subscriptions and collect valid ones
            let mut valid_subscribers = Vec::new();
            subscriptions.retain(|peer, subscription| {
                if peer.graph_id == graph_id {
                    if now >= subscription.expires_at {
                        // Subscription has expired, remove it
                        debug!(?peer, "Removed expired subscription");
                        false
                    } else {
                        // Subscription is valid, collect it
                        valid_subscribers.push((*peer, subscription.clone()));
                        true
                    }
                } else {
                    // Keep subscriptions for other graphs
                    true
                }
            });

            valid_subscribers
        };
        let subscriber_count = subscribers.len();

        // Send hello notification to each valid subscriber
        for (peer, subscription) in subscribers {
            // Check if enough time has passed since last notification
            if let Some(last_notified) = subscription.last_notified {
                if now - last_notified < subscription.graph_change_delay {
                    continue;
                }
            }

            // Send the notification
            match self.send_hello_notification_to_subscriber(peer, head).await {
                Ok(()) => {
                    // Update the last notified time
                    let mut subscriptions = self.client.hello_subscriptions().lock().await;
                    if let Some(sub) = subscriptions.get_mut(&peer) {
                        sub.last_notified = Some(now);
                    } else {
                        warn!(?peer, "Failed to find subscription to update last_notified");
                    }
                }
                Err(error) => {
                    warn!(
                        ?peer,
                        ?head,
                        %error,
                        "Failed to send hello notification"
                    );
                }
            }
        }

        trace!(
            ?graph_id,
            ?head,
            subscriber_count,
            "Completed broadcast_hello_notifications"
        );
        Ok(())
    }

    /// Sends a hello message to a peer and waits for a response.
    ///
    /// This is a helper method that handles the common logic for sending hello messages,
    /// including serialization, connection management, and response handling.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the message to
    /// * `id` - The graph ID for the team/graph
    /// * `sync_type` - The hello message to send
    ///
    /// # Returns
    /// * `Ok(())` if the message was sent successfully
    /// * `Err(SyncError)` if there was an error
    #[instrument(skip_all)]
    async fn send_hello_request(
        &mut self,
        peer: SyncPeer,
        sync_type: SyncType<Addr>,
    ) -> SyncResult<()> {
        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Determine operation name from sync_type
        let operation_name = match &sync_type {
            SyncType::Hello(hello_type) => match hello_type {
                SyncHelloType::Subscribe { .. } => "subscribe",
                SyncHelloType::Unsubscribe { .. } => "unsubscribe",
                SyncHelloType::Hello { .. } => "hello",
            },
            _ => "unknown",
        };
        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .with_context(|| format!("failed to read hello {} response", operation_name))?;
        assert!(!response_buf.is_empty());
        Ok(())
    }

    /// Sends a subscribe request to a peer for hello notifications.
    ///
    /// This method sends a [`SyncHelloType::Subscribe`] message to the specified peer,
    /// requesting to be notified when the peer's graph head changes. The peer will
    /// send hello notifications with the specified delay between them.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the subscribe request to
    /// * `id` - The graph ID for the team/graph to subscribe to
    /// * `graph_change_delay` - Delay between notifications when graph changes (rate limiting)
    /// * `duration` - How long the subscription should last
    /// * `schedule_delay` - Schedule-based hello sending delay
    /// * `subscriber_server_addr` - The address where this subscriber's QUIC sync server is listening
    ///
    /// # Returns
    /// * `Ok(())` if the subscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_sync_hello_subscribe_request(
        &mut self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        // Create the subscribe message
        let hello_msg = SyncHelloType::Subscribe {
            graph_change_delay,
            duration,
            schedule_delay,
            address: subscriber_server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        self.send_hello_request(peer, sync_type).await
    }

    /// Sends an unsubscribe request to a peer to stop hello notifications.
    ///
    /// This method sends a `SyncHelloType::Unsubscribe` message to the specified peer,
    /// requesting to stop receiving hello notifications when the peer's graph head changes.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the unsubscribe request to
    /// * `id` - The graph ID for the team/graph to unsubscribe from
    /// * `subscriber_server_addr` - The subscriber's server address to identify which subscription to remove
    ///
    /// # Returns
    /// * `Ok(())` if the unsubscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_hello_unsubscribe_request(
        &mut self,
        peer: SyncPeer,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        debug!("client sending unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let sync_type: SyncType<Addr> = SyncType::Hello(SyncHelloType::Unsubscribe {
            address: subscriber_server_addr,
        });

        self.send_hello_request(peer, sync_type).await
    }

    /// Sends a hello notification to a specific subscriber.
    ///
    /// This method sends a `SyncHelloType::Hello` message to the specified subscriber,
    /// notifying them that the graph head has changed. Uses the existing connection
    /// infrastructure to efficiently reuse connections.
    ///
    /// # Arguments
    /// * `peer` - The network address of the subscriber to send the notification to
    /// * `id` - The graph ID for the team/graph
    /// * `head` - The new head address to include in the notification
    ///
    /// # Returns
    /// * `Ok(())` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub async fn send_hello_notification_to_subscriber(
        &mut self,
        peer: SyncPeer,
        head: Address,
    ) -> SyncResult<()> {
        // Set the team for this graph
        let team_id = TeamId::transmute(peer.graph_id);
        self.state.store().set_team(team_id);

        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        let stream = self.connect(peer).await.map_err(|error| {
            warn!(
                ?peer,
                %error,
                "Failed to connect to peer"
            );
            error
        })?;

        // Spawn async task to send the notification
        self.hello_tasks.spawn(async move {
            let (mut recv, mut send) = stream.split();

            if let Err(error) = send.send(bytes::Bytes::from(data)).await {
                warn!(
                    ?peer,
                    %error,
                    "Failed to send hello message"
                );
                return;
            }

            if let Err(error) = send.close().await {
                warn!(
                    ?peer,
                    %error,
                    "Failed to close send stream"
                );
                return;
            }

            // Read the response to avoid race condition with server
            let mut response_buf = Vec::new();
            if let Err(e) = recv.read_to_end(&mut response_buf).await {
                warn!(
                    error = %e,
                    ?peer,
                    "Failed to read hello notification response"
                );
                return;
            }
            debug!(
                response_len = response_buf.len(),
                "received hello notification response"
            );
        });

        Ok(())
    }
}

/// Spawns a background task to send scheduled hello messages.
///
/// The task will periodically send hello notifications to the subscriber at the specified interval,
/// regardless of whether the graph has changed. The task will exit when the subscription expires
/// or the cancellation token is triggered.
fn spawn_scheduled_hello_sender(
    peer: SyncPeer,
    schedule_delay: Duration,
    expires_at: Instant,
    cancel_token: CancellationToken,
    sync_peers: SyncPeers,
    client: Client,
) {
    #[allow(clippy::disallowed_macros)] // tokio::select! uses unreachable! internally
    tokio::spawn(async move {
        loop {
            // Wait for either the schedule delay, expiration, or cancellation
            tokio::select! {
                _ = tokio::time::sleep(schedule_delay) => {
                    // Get the current head address
                    let head = {
                        let mut aranya = client.client().aranya.lock().await;
                        match aranya.provider().get_storage(peer.graph_id) {
                            Ok(storage) => match storage.get_head_address() {
                                Ok(addr) => addr,
                                Err(error) => {
                                    warn!(
                                        ?peer,
                                        %error,
                                        "Failed to get head address for scheduled hello"
                                    );
                                    continue;
                                }
                            },
                            Err(error) => {
                                warn!(
                                    ?peer,
                                    %error,
                                    "Failed to get storage for scheduled hello"
                                );
                                continue;
                            }
                        }
                    };

                    // Send scheduled hello notification
                    match sync_peers.broadcast_hello(peer.graph_id, head).await {
                        Ok(_) => trace!(?peer, ?head, "Sent scheduled hello notification"),
                        Err(error) => warn!(?peer, %error, "Failed to broadcast scheduled hello"),
                    }
                }
                _ = tokio::time::sleep_until(expires_at.into()) => {
                    debug!(?peer, "Scheduled hello sender exiting: subscription expired");
                    break;
                }
                _ = cancel_token.cancelled() => {
                    debug!(?peer, "Scheduled hello sender exiting: cancelled");
                    break;
                }
            }
        }
    });
}

impl Server {
    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    pub(crate) async fn process_hello_message(
        hello_msg: SyncHelloType<Addr>,
        client: Client,
        active_team: &TeamId,
        sync_peers: SyncPeers,
    ) {
        let graph_id = GraphId::transmute(*active_team);

        match hello_msg {
            SyncHelloType::Subscribe {
                graph_change_delay,
                duration,
                schedule_delay,
                address,
            } => {
                let peer = SyncPeer::new(address, graph_id);
                let expires_at = Instant::now() + duration;

                // Check if there's an existing subscription and cancel its scheduled task
                if let Some(subscription) = client.hello_subscriptions().lock().await.get(&peer) {
                    subscription.cancel_token.cancel();
                    debug!(?peer, "cancelled previous hello subscription");
                }

                // Create a new cancellation token for the new subscription
                let cancel_token = CancellationToken::new();

                let subscription = HelloSubscription {
                    graph_change_delay,
                    last_notified: None,
                    expires_at,
                    cancel_token: cancel_token.clone(),
                };

                // Store subscription (replaces any existing subscription for this peer+team)
                client
                    .hello_subscriptions()
                    .lock()
                    .await
                    .insert(peer, subscription);

                // Spawn the scheduled hello sender task
                spawn_scheduled_hello_sender(
                    peer,
                    schedule_delay,
                    expires_at,
                    cancel_token,
                    sync_peers.clone(),
                    client.clone(),
                );

                debug!(
                    ?peer,
                    ?graph_change_delay,
                    ?schedule_delay,
                    ?expires_at,
                    "Created hello subscription and spawned scheduled sender"
                );
            }
            SyncHelloType::Unsubscribe { address } => {
                let peer = SyncPeer::new(address, graph_id);
                debug!(?peer, "received message to unsubscribe from hello messages");

                // Remove subscription for this peer and team
                match client.hello_subscriptions().lock().await.remove(&peer) {
                    Some(subscription) => {
                        // Cancel the scheduled sending task
                        subscription.cancel_token.cancel();
                        debug!(?peer, "unsubscribed peer from hello messages");
                    }
                    None => {
                        debug!(?peer, "unable to remove hello peer from schedule");
                    }
                }
            }
            SyncHelloType::Hello { head, address } => {
                let peer = SyncPeer::new(address, graph_id);
                debug!(?peer, ?head, "received hello notification message");

                if !client
                    .client()
                    .aranya
                    .lock()
                    .await
                    .command_exists(graph_id, head)
                {
                    match sync_peers.sync_on_hello(peer).await {
                        Ok(()) => debug!(?peer, ?head, "sent sync_on_hello request"),
                        Err(error) => warn!(
                            ?peer,
                            ?head,
                            %error,
                            "unable to send sync_on_hello request"
                        ),
                    }
                }

                // Update the peer cache with the received head_id.
                let (mut aranya, mut caches) = client.lock_aranya_and_caches().await;
                let cache = caches.entry(peer).or_default();

                // Update the cache with the received head_id
                match aranya.update_heads(graph_id, [head], cache) {
                    Ok(_) => debug!(?peer, ?head, "updated peer cache with new graph head"),
                    Err(error) => warn!(
                        ?peer,
                        ?head,
                        %error,
                        "unable to update peer cache with new graph head"
                    ),
                }
            }
        }
    }
}
