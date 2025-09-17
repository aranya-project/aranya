//! Hello notification functionality for Aranya QUIC sync.
//!
//! This module handles subscription management and broadcasting of hello notifications
//! when graph heads change, allowing peers to stay synchronized.

use core::net::SocketAddr;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_daemon_api::TeamId;
use aranya_runtime::{Address, Engine, GraphId, StorageProvider, SyncHelloType};
use aranya_util::Addr;
use tokio::{io::AsyncReadExt, sync::Mutex};
use tracing::{debug, instrument, trace, warn};

use crate::{
    aranya::Client as AranyaClient,
    sync::{
        task::{
            quic::{Error, Server, State},
            PeerCacheKey, PeerCacheMap, SyncPeers, Syncer,
        },
        Result as SyncResult,
    },
};

/// Storage for sync hello subscriptions
#[derive(Debug, Clone)]
pub struct HelloSubscription {
    /// Delay in milliseconds between notifications to this subscriber
    delay_milliseconds: u64,
    /// Last notification time for delay management
    last_notified: Option<Instant>,
    /// Expiration time of the subscription
    expires_at: Instant,
}

/// Type alias for hello subscription storage
/// Maps from (team_id, subscriber_address) to subscription details
pub type HelloSubscriptions = HashMap<(GraphId, SocketAddr), HelloSubscription>;

/// Hello-related information combining subscriptions and sync peers.
#[derive(Debug, Clone)]
pub struct HelloInfo {
    /// Storage for sync hello subscriptions
    pub subscriptions: Arc<Mutex<HelloSubscriptions>>,
    /// Interface to trigger sync operations
    pub sync_peers: SyncPeers,
}

/// Broadcast hello notifications to all subscribers of a graph.
#[instrument(skip_all)]
pub async fn broadcast_hello_notifications(
    syncer: &mut Syncer<State>,
    graph_id: GraphId,
    head: Address,
) -> SyncResult<()> {
    // Get all subscribers for this graph
    let subscribers = {
        let subscriptions = syncer.state.hello_subscriptions().lock().await;

        let filtered: Vec<_> = subscriptions
            .iter()
            .filter(|((sub_graph_id, _), _)| *sub_graph_id == graph_id)
            .map(|((_, addr), subscription)| (*addr, subscription.clone()))
            .collect();

        filtered
    };

    // Send hello notification to each subscriber
    for (subscriber_addr, subscription) in subscribers.iter() {
        // Check if subscription has expired
        if Instant::now() >= subscription.expires_at {
            // Remove expired subscription
            let mut subscriptions = syncer.state.hello_subscriptions().lock().await;
            subscriptions.remove(&(graph_id, *subscriber_addr));
            debug!(?subscriber_addr, ?graph_id, "Removed expired subscription");
            continue;
        }

        // Check if enough time has passed since last notification
        if let Some(last_notified) = subscription.last_notified {
            let delay = Duration::from_millis(subscription.delay_milliseconds);
            let elapsed = last_notified.elapsed();
            if elapsed < delay {
                continue;
            }
        }

        // Send the notification
        // Convert SocketAddr to Addr for the syncer method
        let peer_addr = Addr::from(*subscriber_addr);
        match syncer
            .send_hello_notification_to_subscriber(&peer_addr, graph_id, head)
            .await
        {
            Ok(()) => {
                // Update the last notified time
                let mut subscriptions = syncer.state.hello_subscriptions().lock().await;
                if let Some(sub) = subscriptions.get_mut(&(graph_id, *subscriber_addr)) {
                    sub.last_notified = Some(Instant::now());
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

impl Syncer<State> {
    /// Sends a subscribe request to a peer for hello notifications.
    ///
    /// This method sends a `SyncHelloType::Subscribe` message to the specified peer,
    /// requesting to be notified when the peer's graph head changes. The peer will
    /// send hello notifications with the specified delay between them.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the subscribe request to
    /// * `id` - The graph ID for the team/graph to subscribe to
    /// * `delay_milliseconds` - Delay in milliseconds between notifications (0 = immediate)
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
        delay: Duration,
        duration: Duration,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        let delay_milliseconds = delay.as_millis() as u64;

        // Create the subscribe message
        let duration_milliseconds = duration.as_millis() as u64;
        let hello_msg = SyncHelloType::Subscribe {
            delay_milliseconds,
            duration_milliseconds,
            address: subscriber_server_addr,
        };
        let sync_type: aranya_runtime::SyncType<Addr> = aranya_runtime::SyncType::Hello(hello_msg);

        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello subscribe response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello subscribe response"
        );

        debug!("sent subscribe request");
        Ok(())
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
        let sync_type: aranya_runtime::SyncType<Addr> =
            aranya_runtime::SyncType::Hello(SyncHelloType::Unsubscribe {
                address: subscriber_server_addr,
            });

        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(bytes::Bytes::from(data))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello unsubscribe response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello unsubscribe response"
        );

        debug!("sent unsubscribe request");
        Ok(())
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
        // Set the team for this graph
        let team_id = id.into_id().into();
        self.state.store().set_team(team_id);

        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: aranya_runtime::SyncType<Addr> = aranya_runtime::SyncType::Hello(hello_msg);

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        let stream = self.connect(peer, id).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                ?id,
                "Failed to connect to peer"
            );
            e
        })?;
        let (mut recv, mut send) = stream.split();

        send.send(bytes::Bytes::from(data)).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                "Failed to send hello message"
            );
            Error::from(e)
        })?;

        send.close().await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                "Failed to close send stream"
            );
            Error::from(e)
        })?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello notification response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello notification response"
        );

        Ok(())
    }
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    pub async fn process_hello_message(
        hello_msg: SyncHelloType<Addr>,
        client: AranyaClient<EN, SP>,
        caches: PeerCacheMap,
        peer_addr: Addr,
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        sync_peers: SyncPeers,
    ) {
        use aranya_runtime::SyncHelloType;

        let graph_id = active_team.into_id().into();

        match hello_msg {
            SyncHelloType::Subscribe {
                delay_milliseconds,
                duration_milliseconds,
                address,
            } => {
                // Use the subscriber server address directly from the message
                // Convert Addr to SocketAddr for the subscription storage
                let subscriber_address = match address.host().parse() {
                    Ok(ip) => SocketAddr::new(ip, address.port()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            ?address,
                            "Failed to parse subscriber address, ignoring subscription"
                        );
                        return;
                    }
                };

                // Calculate expiration time
                let expires_at = Instant::now() + Duration::from_millis(duration_milliseconds);

                let subscription = HelloSubscription {
                    delay_milliseconds,
                    last_notified: None,
                    expires_at,
                };

                // Store subscription (replaces any existing subscription for this peer+team)
                let key = (graph_id, subscriber_address);

                let mut subscriptions = hello_subscriptions.lock().await;
                subscriptions.insert(key, subscription);
            }
            SyncHelloType::Unsubscribe { address } => {
                debug!(
                    ?address,
                    ?peer_addr,
                    ?graph_id,
                    "Received Unsubscribe hello message"
                );

                // Use the address from the message
                // Convert Addr to SocketAddr for the subscription lookup
                let subscriber_address = match address.host().parse() {
                    Ok(ip) => SocketAddr::new(ip, address.port()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            ?address,
                            "Failed to parse subscriber address, ignoring unsubscribe"
                        );
                        return;
                    }
                };

                // Remove subscription for this peer and team
                let key = (graph_id, subscriber_address);
                let mut subscriptions = hello_subscriptions.lock().await;
                if subscriptions.remove(&key).is_some() {
                    debug!(
                        team_id = ?active_team,
                        ?subscriber_address,
                        "Removed hello subscription successfully"
                    );
                } else {
                    debug!(
                        team_id = ?active_team,
                        ?subscriber_address,
                        "No subscription found to remove"
                    );
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

                // Check if we have this command in our graph
                let command_exists = {
                    let mut aranya = match client.aranya.try_lock() {
                        Ok(lock) => lock,
                        Err(_) => client.aranya.lock().await,
                    };
                    aranya.command_exists(graph_id, head)
                };

                if !command_exists {
                    // Use the address from the Hello message for sync_on_hello
                    let server_addr_for_sync = address;

                    match sync_peers
                        .sync_on_hello(server_addr_for_sync, graph_id)
                        .await
                    {
                        Ok(()) => {
                            debug!(
                                ?server_addr_for_sync,
                                ?peer_addr,
                                ?graph_id,
                                ?head,
                                "Successfully sent sync_on_hello message"
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                ?head,
                                ?server_addr_for_sync,
                                ?peer_addr,
                                ?graph_id,
                                "Failed to send sync_on_hello message"
                            );
                        }
                    }
                }

                // Update the peer cache with the received head_id
                let key = PeerCacheKey::new(peer_addr, graph_id);

                // Must lock aranya then caches to prevent deadlock.
                let mut aranya = client.aranya.lock().await;
                let mut caches = caches.lock().await;
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
