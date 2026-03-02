//! This module handles the [`SyncManager`] used to manage sync tasks.
//!
//! # Architecture
//!
//! - A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! - [`SyncHandle`] handles adding/removing peers for the [`SyncManager`].
//! - [`SyncManager`] syncs with the next available peer from the [`DelayQueue`].
//! - [`SyncHandle`] and [`SyncManager`] communicate via mpsc channels so they can run independently.
//!
//! This prevents the need for an `Arc<Mutex>` which would lock until the next peer is retrieved from the [`DelayQueue`].
//!
//! # Hello Sync
//!
//! The sync task supports "hello" notifications that allow peers to proactively notify each other
//! when their graph head changes, enabling more responsive synchronization:
//!
//! - **Subscriptions**: Peers can subscribe to hello notifications from other peers using
//!   SyncHandle::sync_hello_subscribe, specifying a delay between notifications and a duration
//!   for the subscription.
//! - **Broadcasting**: When a graph head changes, hello notifications are broadcast to all
//!   subscribers via SyncHandle::broadcast_hello.
//! - **Sync on Hello**: Peers can be configured to automatically sync when they receive a hello
//!   notification by setting `sync_on_hello` in their [`SyncPeerConfig`].
//! - **Unsubscribe**: Peers can unsubscribe from hello notifications using
//!   SyncHandle::sync_hello_unsubscribe.
//!
//! See the [`hello`](super::hello) module for implementation details.
//!
//! [`SyncHandle`]: super::SyncHandle

use std::collections::HashMap;
#[cfg(feature = "preview")]
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Context as _;
use aranya_daemon_api::{SyncPeerConfig, SyncPeerInfo};
use aranya_runtime::{PolicyStore, StorageProvider};
use aranya_util::{error::ReportExt as _, ready};
use buggy::BugExt as _;
use bytes::Bytes;
use derive_where::derive_where;
use futures_util::StreamExt as _;
#[cfg(feature = "preview")]
use tokio::task::JoinSet;
use tokio::{sync::mpsc, time::Instant};
use tokio_util::time::{delay_queue, DelayQueue};
#[cfg(feature = "preview")]
use tracing::trace;
use tracing::{error, info, instrument, warn};

use super::{
    handle::{Callback, ManagerMessage},
    GraphId, Result, SyncPeer, SyncState,
};
use crate::{aranya::Client, vm_policy::VecSink};

/// State for a tracked sync peer.
#[derive(Debug)]
pub(super) struct PeerState {
    pub(super) config: SyncPeerConfig,
    pub(super) queue_key: Option<delay_queue::Key>,
    pub(super) last_synced_at: Option<SystemTime>,
}

/// Syncs with each peer after the specified interval.
///
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncHandle`] via mpsc channels.
///
/// [`SyncHandle`]: super::SyncHandle
#[derive_where(Debug; ST)]
pub(crate) struct SyncManager<ST, PS, SP, EF> {
    /// Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    pub(super) client: Client<PS, SP>,
    /// Keeps track of peer info.
    pub(super) peers: HashMap<SyncPeer, PeerState>,
    /// Receives added/removed peers.
    pub(super) recv: mpsc::Receiver<Callback>,
    /// Delay queue for getting the next peer to sync with.
    pub(super) queue: DelayQueue<SyncPeer>,
    /// Used to send effects to the API to be processed.
    pub(super) send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
    /// Additional state used by the syncer.
    pub(super) state: ST,
    /// Sync server port. Peers will make incoming connections to us on this port.
    pub(super) return_port: Bytes,
    /// Tracks spawned hello notification tasks for lifecycle management.
    #[cfg(feature = "preview")]
    pub(super) hello_tasks: JoinSet<()>,
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF> {
    /// Add a peer to the delay queue, overwriting an existing one.
    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        // Only insert into delay queue if interval is configured or `sync_now == true`
        let new_key = match cfg.interval {
            _ if cfg.sync_now => Some(self.queue.insert_at(peer, Instant::now())),
            Some(interval) => Some(self.queue.insert(peer, interval)),
            None => None,
        };
        // Preserve last_synced_at from a previous entry if re-adding.
        let prev_last_synced = self.peers.get(&peer).and_then(|s| s.last_synced_at);
        let old = self.peers.insert(
            peer,
            PeerState {
                config: cfg,
                queue_key: new_key,
                last_synced_at: prev_last_synced,
            },
        );
        if let Some(PeerState {
            queue_key: Some(key),
            ..
        }) = old
        {
            self.queue.remove(&key);
        }
    }

    /// Remove a peer from the delay queue.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some(PeerState {
            queue_key: Some(key),
            ..
        }) = self.peers.remove(&peer)
        {
            self.queue.remove(&key);
        }
    }

    /// Get peer caches for test inspection.
    #[cfg(test)]
    pub(crate) fn get_peer_caches(&self) -> crate::aranya::PeerCacheMap {
        self.client.caches_for_test()
    }

    /// Returns a reference to the Aranya client.
    #[cfg(test)]
    pub(crate) fn client(&self) -> &Client<PS, SP> {
        &self.client
    }

    /// Returns a mutable reference to the Aranya client.
    #[cfg(test)]
    pub(crate) fn client_mut(&mut self) -> &mut Client<PS, SP> {
        &mut self.client
    }

    /// Collects sync peer info for a graph, merging interval-based peers
    /// with hello subscription state.
    async fn collect_peers_for_graph(&self, graph_id: GraphId) -> Vec<SyncPeerInfo> {
        #[allow(unused_mut)]
        let mut result: HashMap<super::Addr, SyncPeerInfo> = self
            .peers
            .iter()
            .filter(|(peer, _)| peer.graph_id == graph_id)
            .map(|(peer, state)| {
                (
                    peer.addr,
                    SyncPeerInfo {
                        addr: peer.addr,
                        config: Some(state.config.clone()),
                        last_synced_at: state.last_synced_at,
                        #[cfg(feature = "preview")]
                        has_hello_subscription: false,
                        #[cfg(feature = "preview")]
                        hello_subscription_expires_in: None,
                    },
                )
            })
            .collect();

        #[cfg(feature = "preview")]
        {
            let now = std::time::Instant::now();
            let subscriptions = self.client.lock_hello_subscriptions().await;
            for (peer, sub) in subscriptions.iter() {
                if peer.graph_id != graph_id {
                    continue;
                }
                if now >= sub.expires_at {
                    continue;
                }
                let expires_in = sub.expires_at.duration_since(now);
                if let Some(info) = result.get_mut(&peer.addr) {
                    info.has_hello_subscription = true;
                    info.hello_subscription_expires_in = Some(expires_in);
                } else {
                    result.insert(
                        peer.addr,
                        SyncPeerInfo {
                            addr: peer.addr,
                            config: None,
                            last_synced_at: None,
                            has_hello_subscription: true,
                            hello_subscription_expires_in: Some(expires_in),
                        },
                    );
                }
            }
        }

        result.into_values().collect()
    }
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF>
where
    ST: SyncState<PS, SP, EF>,
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_subscribe(
        &mut self,
        peer: SyncPeer,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        trace!("subscribing to hello notifications from peer");
        ST::sync_hello_subscribe_impl(self, peer, graph_change_debounce, duration, schedule_delay)
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_unsubscribe(&mut self, peer: SyncPeer) -> Result<()> {
        trace!("unsubscribing from hello notifications from peer");
        ST::sync_hello_unsubscribe_impl(self, peer).await
    }
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF>
where
    ST: SyncState<PS, SP, EF>,
    PS: PolicyStore,
    SP: StorageProvider,
    EF: Send + Sync + 'static + TryFrom<PS::Effect>,
    EF::Error: Send + Sync + 'static + std::error::Error,
{
    /// Run the main syncer loop, which will handle syncing with peers.
    pub(crate) async fn run(mut self, ready: ready::Notifier) {
        ready.notify();
        loop {
            if let Err(err) = self.next().await {
                error!(error = %err.report(), "unable to sync with peer");
            }
        }
    }

    /// Syncs with the next peer in the list.
    async fn next(&mut self) -> Result<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // receive added/removed peers.
            Some((msg, tx)) = self.recv.recv() => {
                let reply = match msg {
                    ManagerMessage::SyncNow { peer, cfg: _cfg } => {
                        // sync with peer right now.
                        self.sync(peer).await.map(|_| ())
                    },
                    ManagerMessage::AddPeer { peer, cfg } => {
                        self.add_peer(peer, cfg);
                        Ok(())
                    }
                    ManagerMessage::RemovePeer { peer } => {
                        self.remove_peer(peer);
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloSubscribe {
                        peer,
                        graph_change_debounce,
                        duration,
                        schedule_delay,
                    } => {
                        self.sync_hello_subscribe(peer, graph_change_debounce, duration, schedule_delay)
                            .await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloUnsubscribe { peer } => {
                        self.sync_hello_unsubscribe(peer).await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::SyncOnHello { peer } => {
                        // Check if sync_on_hello is enabled for this peer
                        if let Some(state) = self.peers.get(&peer) {
                            if state.config.sync_on_hello {
                                self.sync(peer).await
                                    .inspect_err(|e| {
                                        warn!(
                                            error = %e,
                                            ?peer,
                                            "SyncOnHello sync failed"
                                        );
                                    })
                                    .map(|_| ())
                            } else {
                                trace!(
                                    ?peer,
                                    "SyncOnHello is not enabled for this peer, ignoring"
                                );
                                Ok(())
                            }
                        } else {
                            warn!(
                                ?peer,
                                "Peer not found in our configuration, ignoring SyncOnHello"
                            );
                            Ok(())
                        }
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::BroadcastHello { graph_id, head } => {
                        ST::broadcast_hello_notifications_impl(self, graph_id, head).await
                    }
                    ManagerMessage::ListPeers { graph_id, reply } => {
                        let peers = self.collect_peers_for_graph(graph_id).await;
                        let _ = reply.send(Ok(peers));
                        Ok(())
                    }
                };
                if let Err(reply) = tx.send(reply) {
                    warn!("syncer operation did not wait for reply");
                    reply?;
                }
            }
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                let peer = expired.into_inner();
                let state = self.peers.get_mut(&peer).assume("peer must exist")?;
                // Re-insert into queue if interval is still configured
                state.queue_key = state.config.interval.map(|interval| self.queue.insert(peer, interval));
                // sync with peer.
                self.sync(peer).await?;
            }
        }
        Ok(())
    }

    /// Sync with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: SyncPeer) -> Result<usize> {
        let mut sink = VecSink::new();

        let cmd_count = ST::sync_impl(self, peer, &mut sink)
            .await
            .inspect_err(|err| {
                warn!(
                    error = %err,
                    ?peer,
                    "ST::sync_impl failed"
                );
                // If a finalization error has occurred, remove all sync peers for that team.
                if err.is_parallel_finalize() {
                    warn!(
                        ?peer,
                        "Parallel finalize error, removing sync peers for graph"
                    );
                    // Remove sync peers for graph that had finalization error.
                    self.peers.retain(|p, state| {
                        let keep = p.graph_id != peer.graph_id;
                        if !keep {
                            if let Some(k) = &state.queue_key {
                                self.queue.remove(k);
                            }
                        }
                        keep
                    });
                    self.client.invalid_graphs().insert(peer.graph_id);
                }
            })
            .with_context(|| format!("peer addr: {}", peer.addr))?;

        // Record successful sync timestamp.
        if let Some(state) = self.peers.get_mut(&peer) {
            state.last_synced_at = Some(SystemTime::now());
        }

        let effects = sink
            .collect()
            .context("could not collect effects from sync")?;
        let n = effects.len();

        self.send_effects
            .send((peer.graph_id, effects))
            .await
            .context("unable to send effects")?;

        info!(
            ?peer,
            cmd_count,
            effects_count = n,
            "Sync completed successfully"
        );
        Ok(cmd_count)
    }
}
