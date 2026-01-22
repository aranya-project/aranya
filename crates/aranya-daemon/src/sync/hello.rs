//! Hello notification functionality for the Aranya syncer.
//!
//! This module handles managing subscriptions and broadcasting hello messages periodically and when
//! graph heads change.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use aranya_runtime::{Address, Engine, Storage as _, StorageProvider, SyncHelloType, SyncType};
use quinn::{ConnectionError, WriteError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};

use crate::{
    aranya::Client,
    sync::{
        transport::quic::{self, Error, QuicState},
        Addr, GraphId, Result, SyncHandle, SyncManager, SyncPeer,
    },
};

/// Storage for a subscription to hello messages.
#[derive(Debug, Clone)]
pub(crate) struct HelloSubscription {
    /// Rate limiting on how often to notify when a graph changes.
    graph_change_delay: Duration,
    /// The last time we notified a peer about our current graph.
    last_notified: Option<Instant>,
    /// How long until the subscription is no longer valid.
    expires_at: Instant,
    /// Token to cancel the spawned sync task.
    cancel_token: CancellationToken,
}

/// Type alias to map a unique [`SyncPeer`] to their associated subscription.
pub(crate) type HelloSubscriptions = HashMap<SyncPeer, HelloSubscription>;

/// Maximum size for hello response buffer.
///
/// Hello responses are either:
/// - Success: `SyncResponse::Ok([])` (~3 bytes with postcard)
/// - Error: `SyncResponse::Err(String)` (3 bytes + error message)
///
/// Actual responses are small, but we use 64KB as a defensive upper bound
/// to accommodate potentially long error chains while preventing unbounded
/// allocations from malicious peers.
const MAX_HELLO_RESPONSE_SIZE: usize = 64 * 1024;

impl<EN, SP, EF> SyncManager<QuicState, EN, SP, EF>
where
    EN: Engine,
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
                if now - last_notified < subscription.graph_change_delay {
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
    async fn send_hello_request(
        &mut self,
        peer: SyncPeer,
        sync_type: SyncType<Addr>,
    ) -> Result<()> {
        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let (mut send, mut recv) = self.connect(peer).await?;

        // Send the message
        send.write_all(&data).await.map_err(Error::QuicWriteError)?;
        send.finish().map_err(|_| {
            Error::QuicWriteError(WriteError::ConnectionLost(ConnectionError::LocallyClosed))
        })?;

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
        let response_buf = recv
            .read_to_end(MAX_HELLO_RESPONSE_SIZE)
            .await
            .with_context(|| format!("failed to read hello {} response", operation_name))?;
        if response_buf.is_empty() {
            return Err(crate::sync::Error::EmptyResponse);
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
    /// * `graph_change_delay` - Rate limiting on how often to notify when a graph changes
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
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        subscriber_server_addr: Addr,
    ) -> Result<()> {
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
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `subscriber_server_addr` - The subscriber's server address to identify which subscription to remove
    ///
    /// # Returns
    /// * `Ok(())` if the unsubscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub(super) async fn send_hello_unsubscribe_request(
        &mut self,
        peer: SyncPeer,
        subscriber_server_addr: Addr,
    ) -> Result<()> {
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
        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        let (mut send, mut recv) = self.connect(peer).await.map_err(|error| {
            warn!(
                ?peer,
                %error,
                "Failed to connect to peer"
            );
            error
        })?;

        // Spawn async task to send the notification
        self.hello_tasks.spawn(async move {
            if let Err(error) = send.write_all(&data).await {
                warn!(
                    ?peer,
                    %error,
                    "Failed to send hello message"
                );
                return;
            }

            if let Err(error) = send.finish() {
                warn!(
                    ?peer,
                    %error,
                    "Failed to finish send stream"
                );
                return;
            }

            // Read the response to avoid race condition with server
            match recv.read_to_end(MAX_HELLO_RESPONSE_SIZE).await {
                Ok(response_buf) => {
                    debug!(
                        response_len = response_buf.len(),
                        "received hello notification response"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        ?peer,
                        "Failed to read hello notification response"
                    );
                }
            }
        });

        Ok(())
    }
}

/// Spawns a background task to send scheduled hello messages.
///
/// The task will periodically send hello notifications to the subscriber at the specified interval,
/// regardless of whether the graph has changed. The task will exit when the subscription expires
/// or the cancellation token is triggered.
fn spawn_scheduled_hello_sender<EN, SP>(
    peer: SyncPeer,
    schedule_delay: Duration,
    expires_at: Instant,
    cancel_token: CancellationToken,
    handle: SyncHandle,
    client: Client<EN, SP>,
) where
    EN: Engine + Send + 'static,
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

impl<EN, SP> quic::Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + 'static,
{
    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    /// Note: With mTLS, the graph_id is determined from the peer caches.
    /// TODO(hello-protocol): Add graph_id to the hello message protocol for proper multi-team support.
    #[instrument(skip_all)]
    pub(super) async fn process_hello_message(
        hello_msg: SyncHelloType<Addr>,
        client: Client<EN, SP>,
        peer_addr: Addr,
        sync_peers: SyncHandle,
    ) {
        // Extract the server address from the message.
        // For Subscribe/Unsubscribe/Hello messages, this is the peer's server address
        // which is what we use to key the peer cache (not the ephemeral client connection address).
        let server_addr = match &hello_msg {
            SyncHelloType::Subscribe { address, .. } => *address,
            SyncHelloType::Unsubscribe { address } => *address,
            SyncHelloType::Hello { address, .. } => *address,
        };

        // With mTLS, we need to determine the graph_id from context.
        // Look up the graph_id from the peer caches based on the peer's server address.
        // This assumes the peer has synced with us before for at least one graph.
        // TODO(hello-protocol): Add graph_id to the hello message protocol for proper multi-team support.
        let graph_id = {
            let (_, caches) = client.lock_aranya_and_caches().await;
            // Find any cache entry for this peer's server address
            let entry = caches.keys().find(|key| key.addr == server_addr);
            match entry {
                Some(key) => key.graph_id,
                None => {
                    warn!(
                        ?peer_addr,
                        ?server_addr,
                        "No graph found for peer in hello message processing"
                    );
                    return;
                }
            }
        };

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
                if let Some(subscription) = client.lock_hello_subscriptions().await.get(&peer) {
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
                    .lock_hello_subscriptions()
                    .await
                    .insert(peer, subscription);

                // Spawn the scheduled hello sender task
                spawn_scheduled_hello_sender(
                    peer,
                    schedule_delay,
                    expires_at,
                    cancel_token,
                    sync_peers,
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
            SyncHelloType::Hello { head, address } => {
                let peer = SyncPeer::new(address, graph_id);
                debug!(?peer, ?head, "received hello notification message");

                if !client.lock_aranya().await.command_exists(graph_id, head) {
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
