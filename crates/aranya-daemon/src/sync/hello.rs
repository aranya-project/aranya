//! Hello notification functionality for the Aranya syncer.
//!
//! This module handles managing subscriptions and broadcasting hello messages periodically and when
//! graph heads change.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context as _};
use aranya_daemon_api::TeamId;
use aranya_runtime::{
    Address, PolicyStore, Storage as _, StorageProvider, SyncHelloType, SyncType,
};
use futures_util::AsyncReadExt as _;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};

use crate::{
    aranya::Client,
    sync::{
        transport::quic::{self, QuicState},
        Addr, Error, GraphId, Result, SyncHandle, SyncManager, SyncPeer,
    },
};

/// Storage for a subscription to hello messages.
#[derive(Debug, Clone)]
pub(crate) struct HelloSubscription {
    /// Rate limiting on how often to notify when a graph changes.
    graph_change_debounce: Duration,
    /// The last time we notified a peer about our current graph.
    last_notified: Option<Instant>,
    /// How long until the subscription is no longer valid.
    expires_at: Instant,
    /// Token to cancel the spawned sync task.
    cancel_token: CancellationToken,
}

/// Type alias to map a unique [`SyncPeer`] to their associated subscription.
pub(crate) type HelloSubscriptions = HashMap<SyncPeer, HelloSubscription>;

impl<PS, SP, EF> SyncManager<QuicState, PS, SP, EF>
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Broadcast hello notifications to all subscribers of a graph.
    #[instrument(skip_all)]
    pub(super) async fn broadcast_hello_notifications(
        &mut self,
        graph_id: GraphId,
        head: Address,
    ) -> Result<()> {
        let now = Instant::now();

        // Get all valid (non-expired) subscribers for this graph
        let subscribers = {
            let mut subscriptions = self.client.lock_hello_subscriptions().await;

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
                if now
                    .checked_duration_since(last_notified)
                    .unwrap_or_default()
                    < subscription.graph_change_debounce
                {
                    continue;
                }
            }

            // Send the notification
            match self.send_hello_notification_to_subscriber(peer, head).await {
                Ok(()) => {
                    // Update the last notified time
                    let mut subscriptions = self.client.lock_hello_subscriptions().await;
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

    /// Send a hello message to a peer and wait for a response.
    ///
    /// This is a helper method that handles the common logic for sending hello messages,
    /// including serialization, connection management, and response handling.
    ///
    /// # Arguments
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `sync_type` - The hello message to send
    ///
    /// # Returns
    /// * `Ok(())` if the message was sent successfully
    /// * `Err(SyncError)` if there was an error
    #[instrument(skip_all)]
    async fn send_hello_request(&mut self, peer: SyncPeer, sync_type: SyncType) -> Result<()> {
        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(quic::Error::from)?;
        send.close().await.map_err(quic::Error::from)?;

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
        if response_buf.is_empty() {
            return Err(Error::EmptyResponse);
        }
        Ok(())
    }

    /// Sends a subscribe request to a peer for hello notifications.
    ///
    /// This method sends a [`SyncHelloType::Subscribe`] message to the specified peer,
    /// requesting to be notified when the peer's graph head changes. The peer will
    /// send hello notifications with the specified delay between them.
    ///
    /// # Arguments
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `graph_change_debounce` - Rate limiting on how often to notify when a graph changes
    /// * `duration` - How long the subscription should last
    /// * `schedule_delay` - Interval to send hello notifications, regardless of graph changes
    /// * `subscriber_server_addr` - The address where this subscriber's sync server is listening
    ///
    /// # Returns
    /// * `Ok(())` if the subscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub(super) async fn send_sync_hello_subscribe_request(
        &mut self,
        peer: SyncPeer,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        // Create the subscribe message
        let hello_msg = SyncHelloType::Subscribe {
            graph_change_delay: graph_change_debounce,
            duration,
            schedule_delay,
            graph_id: peer.graph_id,
        };
        let sync_type = SyncType::Hello(hello_msg);

        self.send_hello_request(peer, sync_type).await
    }

    /// Sends an unsubscribe request to a peer to stop hello notifications.
    ///
    /// This method sends a `SyncHelloType::Unsubscribe` message to the specified peer,
    /// requesting to stop receiving hello notifications when the peer's graph head changes.
    ///
    /// # Arguments
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `subscriber_server_addr` - The subscriber's server address to identify which subscription to remove
    ///
    /// # Returns
    /// * `Ok(())` if the unsubscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub(super) async fn send_hello_unsubscribe_request(&mut self, peer: SyncPeer) -> Result<()> {
        debug!("client sending unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let sync_type: SyncType = SyncType::Hello(SyncHelloType::Unsubscribe {
            graph_id: peer.graph_id,
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
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `head` - The new head address to include in the notification
    ///
    /// # Returns
    /// * `Ok(())` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    async fn send_hello_notification_to_subscriber(
        &mut self,
        peer: SyncPeer,
        head: Address,
    ) -> Result<()> {
        // Set the team for this graph
        let team_id = TeamId::transmute(peer.graph_id);
        self.state.store().set_team(team_id);

        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            graph_id: peer.graph_id,
        };
        let sync_type: SyncType = SyncType::Hello(hello_msg);

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
fn spawn_scheduled_hello_sender<PS, SP>(
    peer: SyncPeer,
    schedule_delay: Duration,
    expires_at: Instant,
    cancel_token: CancellationToken,
    handle: SyncHandle,
    client: Client<PS, SP>,
) where
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
{
    #[allow(clippy::disallowed_macros)] // tokio::select! uses unreachable! internally
    tokio::spawn(async move {
        loop {
            // Wait for either the schedule delay, expiration, or cancellation
            tokio::select! {
                _ = tokio::time::sleep(schedule_delay) => {
                    // Get the current head address
                    let head = {
                        let mut aranya = client.lock_aranya().await;
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
                    match handle.broadcast_hello(peer.graph_id, head).await {
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

impl<PS, SP> quic::Server<PS, SP>
where
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
{
    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    pub(super) async fn process_hello_message(
        hello_msg: SyncHelloType,
        client: Client<PS, SP>,
        active_team: &TeamId,
        handle: SyncHandle,
        address: Addr,
    ) -> anyhow::Result<()> {
        let active_graph_id = GraphId::transmute(*active_team);

        match hello_msg {
            SyncHelloType::Subscribe {
                graph_change_delay: graph_change_debounce,
                duration,
                schedule_delay,
                graph_id,
            } => {
                ensure!(graph_id == active_graph_id);

                let peer = SyncPeer::new(address, graph_id);
                let expires_at = Instant::now()
                    .checked_add(duration)
                    .context("subscription expiry overflow")?;

                // Check if there's an existing subscription and cancel its scheduled task
                if let Some(subscription) = client.lock_hello_subscriptions().await.get(&peer) {
                    subscription.cancel_token.cancel();
                    debug!(?peer, "cancelled previous hello subscription");
                }

                // Create a new cancellation token for the new subscription
                let cancel_token = CancellationToken::new();

                let subscription = HelloSubscription {
                    graph_change_debounce,
                    last_notified: None,
                    expires_at,
                    cancel_token: cancel_token.clone(),
                };

                // Store subscription (replaces any existing subscription for this peer+team)
                client
                    .lock_hello_subscriptions()
                    .await
                    .insert(peer, subscription);

                // Spawn the scheduled hello sender task
                spawn_scheduled_hello_sender(
                    peer,
                    schedule_delay,
                    expires_at,
                    cancel_token,
                    handle,
                    client.clone(),
                );

                debug!(
                    ?peer,
                    ?graph_change_debounce,
                    ?schedule_delay,
                    ?expires_at,
                    "Created hello subscription and spawned scheduled sender"
                );
            }
            SyncHelloType::Unsubscribe { graph_id } => {
                ensure!(graph_id == active_graph_id);

                let peer = SyncPeer::new(address, graph_id);
                debug!(?peer, "received message to unsubscribe from hello messages");

                // Remove subscription for this peer and team
                match client.lock_hello_subscriptions().await.remove(&peer) {
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
            SyncHelloType::Hello { head, graph_id } => {
                ensure!(graph_id == active_graph_id);

                let peer = SyncPeer::new(address, graph_id);
                debug!(?peer, ?head, "received hello notification message");

                if !client.lock_aranya().await.command_exists(graph_id, head) {
                    match handle.sync_on_hello(peer).await {
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

        Ok(())
    }
}
