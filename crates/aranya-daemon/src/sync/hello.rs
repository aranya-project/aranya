//! Hello notification functionality for the Aranya syncer.
//!
//! This module handles managing subscriptions and broadcasting hello messages periodically and when
//! graph heads change.

use std::{collections::HashMap, time::Duration};

use anyhow::ensure;
use aranya_daemon_api::TeamId;
use aranya_runtime::{PolicyStore, Storage as _, StorageProvider, SyncHelloType};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};

use crate::{
    aranya::Client,
    sync::{
        transport::quic::{self},
        Addr, GraphId, SyncHandle, SyncPeer,
    },
};

/// Storage for a subscription to hello messages.
#[derive(Debug, Clone)]
pub(crate) struct HelloSubscription {
    /// Rate limiting on how often to notify when a graph changes.
    pub(super) graph_change_delay: Duration,
    /// The last time we notified a peer about our current graph.
    pub(super) last_notified: Option<Instant>,
    /// How long until the subscription is no longer valid.
    pub(super) expires_at: Instant,
    /// Token to cancel the spawned sync task.
    pub(super) cancel_token: CancellationToken,
}

/// Type alias to map a unique [`SyncPeer`] to their associated subscription.
pub(crate) type HelloSubscriptions = HashMap<SyncPeer, HelloSubscription>;

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
                _ = tokio::time::sleep_until(expires_at) => {
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
                graph_change_delay,
                duration,
                schedule_delay,
                graph_id,
            } => {
                ensure!(graph_id == active_graph_id);

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
                    handle,
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
