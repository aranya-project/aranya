//! Hello notification functionality for Aranya QUIC sync.
//!
//! This module handles subscription management and broadcasting of hello notifications
//! when graph heads change, allowing peers to stay synchronized.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_runtime::{Address, Engine, GraphId, Storage, StorageProvider, SyncHelloType, SyncType};
use aranya_util::Addr;
use quinn::{ConnectionError, WriteError};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};

use crate::{
    aranya::ClientWithState,
    sync::{
        error::SyncError,
        task::{
            quic::{Error, Server, State},
            PeerCacheKey, SyncPeers, Syncer,
        },
        Result as SyncResult,
    },
};

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
pub type HelloSubscriptions = HashMap<(GraphId, Addr), HelloSubscription>;

/// Hello-related information combining subscriptions and sync peers.
#[derive(Debug, Clone)]
pub struct HelloInfo {
    /// Storage for sync hello subscriptions
    pub subscriptions: Arc<Mutex<HelloSubscriptions>>,
    /// Interface to trigger sync operations
    pub sync_peers: SyncPeers,
}

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
            subscriptions.retain(|(sub_graph_id, addr), subscription| {
                if *sub_graph_id == graph_id {
                    if now >= subscription.expires_at {
                        // Subscription has expired, remove it
                        debug!(?addr, ?graph_id, "Removed expired subscription");
                        false
                    } else {
                        // Subscription is valid, collect it
                        valid_subscribers.push((*addr, subscription.clone()));
                        true
                    }
                } else {
                    // Keep subscriptions for other graphs
                    true
                }
            });

            valid_subscribers
        };

        // Send hello notification to each valid subscriber
        for (subscriber_addr, subscription) in subscribers.iter() {
            // Check if enough time has passed since last notification
            if let Some(last_notified) = subscription.last_notified {
                if now - last_notified < subscription.graph_change_delay {
                    continue;
                }
            }

            // Send the notification
            match self
                .send_hello_notification_to_subscriber(subscriber_addr, graph_id, head)
                .await
            {
                Ok(()) => {
                    // Update the last notified time
                    let mut subscriptions = self.client.hello_subscriptions().lock().await;
                    if let Some(sub) = subscriptions.get_mut(&(graph_id, *subscriber_addr)) {
                        sub.last_notified = Some(now);
                    } else {
                        warn!(
                            ?subscriber_addr,
                            ?graph_id,
                            "Failed to find subscription to update last_notified"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        ?subscriber_addr,
                        ?head,
                        "Failed to send hello notification"
                    );
                }
            }
        }

        trace!(
            ?graph_id,
            ?head,
            subscriber_count = subscribers.len(),
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
        peer: &Addr,
        _id: GraphId, // GraphId is kept in API for future use but not needed for mTLS connection
        sync_type: SyncType<Addr>,
    ) -> SyncResult<()> {
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
            return Err(SyncError::EmptyResponse);
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
        peer: &Addr,
        id: GraphId,
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

        self.send_hello_request(peer, id, sync_type).await
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
        peer: &Addr,
        id: GraphId,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        debug!("client sending unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let sync_type: SyncType<Addr> = SyncType::Hello(SyncHelloType::Unsubscribe {
            address: subscriber_server_addr,
        });

        self.send_hello_request(peer, id, sync_type).await
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
        peer: &Addr,
        id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        let (mut send, mut recv) = self.connect(peer).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                ?id,
                "Failed to connect to peer"
            );
            e
        })?;

        // Spawn async task to send the notification
        let peer = *peer;
        self.hello_tasks.spawn(async move {
            if let Err(e) = send.write_all(&data).await {
                warn!(
                    error = %e,
                    ?peer,
                    "Failed to send hello message"
                );
                return;
            }

            if let Err(e) = send.finish() {
                warn!(
                    error = %e,
                    ?peer,
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
    graph_id: GraphId,
    subscriber_addr: Addr,
    schedule_delay: Duration,
    expires_at: Instant,
    cancel_token: CancellationToken,
    sync_peers: SyncPeers,
    client: ClientWithState<EN, SP>,
) where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    #[allow(clippy::disallowed_macros)] // tokio::select! uses unreachable! internally
    tokio::spawn(async move {
        loop {
            // Wait for either the schedule delay, expiration, or cancellation
            tokio::select! {
                _ = tokio::time::sleep(schedule_delay) => {
                    // Get the current head address
                    let head = {
                        let mut aranya = client.client().aranya.lock().await;
                        match aranya.provider().get_storage(graph_id) {
                            Ok(storage) => match storage.get_head_address() {
                                Ok(addr) => addr,
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        ?graph_id,
                                        "Failed to get head address for scheduled hello"
                                    );
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    ?graph_id,
                                    "Failed to get storage for scheduled hello"
                                );
                                continue;
                            }
                        }
                    };

                    // Send scheduled hello notification
                    if let Err(e) = sync_peers.broadcast_hello(graph_id, head).await {
                        warn!(
                            error = %e,
                            ?graph_id,
                            ?subscriber_addr,
                            "Failed to broadcast scheduled hello"
                        );
                    } else {
                        trace!(
                            ?graph_id,
                            ?subscriber_addr,
                            ?head,
                            "Sent scheduled hello notification"
                        );
                    }
                }
                _ = tokio::time::sleep_until(expires_at.into()) => {
                    debug!(
                        ?graph_id,
                        ?subscriber_addr,
                        "Scheduled hello sender exiting: subscription expired"
                    );
                    break;
                }
                _ = cancel_token.cancelled() => {
                    debug!(
                        ?graph_id,
                        ?subscriber_addr,
                        "Scheduled hello sender exiting: cancelled"
                    );
                    break;
                }
            }
        }
    });
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    /// Note: With mTLS, the graph_id is determined from the peer caches.
    /// TODO(aranya-core#538): Add graph_id to the hello message protocol for proper multi-team support.
    #[instrument(skip_all)]
    pub(crate) async fn process_hello_message(
        hello_msg: SyncHelloType<Addr>,
        client: ClientWithState<EN, SP>,
        peer_addr: Addr,
        sync_peers: SyncPeers,
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
        // TODO(aranya-core#538): Add graph_id to the hello message protocol for proper multi-team support.
        let graph_id = {
            let (_, caches) = client.lock_aranya_and_caches().await;
            // Find any cache entry for this peer's server address
            let entry = caches.keys().find(|key| key.addr == server_addr);
            match entry {
                Some(key) => key.id,
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
                // Calculate expiration time
                let expires_at = Instant::now() + duration;

                let key = (graph_id, address);

                // Check if there's an existing subscription and cancel its scheduled task
                {
                    let subscriptions = client.hello_subscriptions().lock().await;
                    if let Some(old_subscription) = subscriptions.get(&key) {
                        old_subscription.cancel_token.cancel();
                        debug!(
                            ?address,
                            ?graph_id,
                            "Cancelled previous scheduled hello sender"
                        );
                    }
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
                {
                    let mut subscriptions = client.hello_subscriptions().lock().await;
                    subscriptions.insert(key, subscription);
                }

                // Spawn the scheduled hello sender task
                spawn_scheduled_hello_sender(
                    graph_id,
                    address,
                    schedule_delay,
                    expires_at,
                    cancel_token,
                    sync_peers.clone(),
                    client.clone(),
                );

                debug!(
                    ?address,
                    ?graph_id,
                    ?graph_change_delay,
                    ?schedule_delay,
                    ?expires_at,
                    "Created hello subscription and spawned scheduled sender"
                );
            }
            SyncHelloType::Unsubscribe { address } => {
                debug!(
                    ?address,
                    ?peer_addr,
                    ?graph_id,
                    "Received Unsubscribe hello message"
                );

                // Remove subscription for this peer and team
                let key = (graph_id, address);
                let mut subscriptions = client.hello_subscriptions().lock().await;
                if let Some(subscription) = subscriptions.remove(&key) {
                    // Cancel the scheduled sending task
                    subscription.cancel_token.cancel();
                    debug!(
                        ?graph_id,
                        ?address,
                        "Removed hello subscription and cancelled scheduled sender"
                    );
                } else {
                    debug!(?graph_id, ?address, "No subscription found to remove");
                }
            }
            SyncHelloType::Hello { head, address } => {
                debug!(
                    ?head,
                    ?peer_addr,
                    ?address,
                    ?graph_id,
                    "Received Hello notification message"
                );

                if !client
                    .client()
                    .aranya
                    .lock()
                    .await
                    .command_exists(graph_id, head)
                {
                    match sync_peers.sync_on_hello(address, graph_id).await {
                        Ok(()) => {
                            debug!(
                                ?address,
                                ?peer_addr,
                                ?graph_id,
                                ?head,
                                "Successfully sent sync_on_hello request to Syncer"
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                ?head,
                                ?address,
                                ?peer_addr,
                                ?graph_id,
                                "Failed to send sync_on_hello message"
                            );
                        }
                    }
                }

                // Update the peer cache with the received head_id
                let key = PeerCacheKey::new(peer_addr, graph_id);

                // Lock both aranya and caches in the correct order.
                let (mut aranya, mut caches) = client.lock_aranya_and_caches().await;
                let cache = caches.entry(key).or_default();

                // Update the cache with the received head_id
                if let Err(e) = aranya.update_heads(graph_id, [head], cache) {
                    warn!(
                        error = %e,
                        ?head,
                        ?peer_addr,
                        ?graph_id,
                        "Failed to update peer cache with hello head_id"
                    );
                } else {
                    debug!(
                        ?head,
                        ?peer_addr,
                        ?graph_id,
                        "Successfully updated peer cache with hello head"
                    );
                }
            }
        }
    }
}
