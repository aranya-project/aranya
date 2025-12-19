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
//! See the [`hello`] module for implementation details.

use std::collections::HashMap;
#[cfg(feature = "preview")]
use std::time::Duration;

use anyhow::Context as _;
use aranya_daemon_api::SyncPeerConfig;
use aranya_util::{error::ReportExt as _, ready};
use buggy::BugExt as _;
use futures_util::StreamExt as _;
#[cfg(feature = "preview")]
use tokio::task::JoinSet;
use tokio::{sync::mpsc, time::Instant};
use tokio_util::time::{delay_queue, DelayQueue};
#[cfg(feature = "preview")]
use tracing::trace;
use tracing::{error, info, instrument, warn};

use super::{
    handle::{ManagerMessage, Request},
    transport::SyncState,
    Addr, Client, EffectSender, Result, SyncPeer,
};
use crate::{vm_policy::VecSink, InvalidGraphs};

/// Syncs with each peer after the specified interval.
///
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncHandle`] via mpsc channels.
#[derive(Debug)]
pub(crate) struct SyncManager<ST> {
    /// Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    pub(super) client: Client,
    /// Keeps track of peer info. The Key is None if the peer has no interval configured.
    pub(super) peers: HashMap<SyncPeer, (SyncPeerConfig, Option<delay_queue::Key>)>,
    /// Receives added/removed peers.
    pub(super) recv: mpsc::Receiver<Request>,
    /// Delay queue for getting the next peer to sync with.
    pub(super) queue: DelayQueue<SyncPeer>,
    /// Used to send effects to the API to be processed.
    pub(super) send_effects: EffectSender,
    /// Keeps track of invalid graphs due to finalization errors.
    pub(super) invalid: InvalidGraphs,
    /// Additional state used by the syncer.
    pub(super) state: ST,
    /// Sync server address. Peers will make incoming connections to us on this address.
    pub(super) server_addr: Addr,
    /// Tracks spawned hello notification tasks for lifecycle management.
    #[cfg(feature = "preview")]
    pub(super) hello_tasks: JoinSet<()>,
}

impl<ST> SyncManager<ST> {
    /// Add a peer to the delay queue, overwriting an existing one.
    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        // Only insert into delay queue if interval is configured or `sync_now == true`
        let new_key = match cfg.interval {
            _ if cfg.sync_now => Some(self.queue.insert_at(peer, Instant::now())),
            Some(interval) => Some(self.queue.insert(peer, interval)),
            None => None,
        };
        if let Some((_, Some(key))) = self.peers.insert(peer, (cfg, new_key)) {
            self.queue.remove(&key);
        }
    }

    /// Remove a peer from the delay queue.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, Some(key))) = self.peers.remove(&peer) {
            self.queue.remove(&key);
        }
    }
}

impl<ST: SyncState> SyncManager<ST> {
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
                        graph_change_delay,
                        duration,
                        schedule_delay,
                    } => {
                        self.sync_hello_subscribe(peer, graph_change_delay, duration, schedule_delay)
                            .await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloUnsubscribe { peer } => {
                        self.sync_hello_unsubscribe(peer).await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::SyncOnHello { peer } => {
                        // Check if sync_on_hello is enabled for this peer
                        if let Some((cfg, _)) = self.peers.get(&peer) {
                            if cfg.sync_on_hello {
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
                };
                if let Err(reply) = tx.send(reply) {
                    warn!("syncer operation did not wait for reply");
                    reply?;
                }
            }
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                let peer = expired.into_inner();
                let (cfg, key) = self.peers.get_mut(&peer).assume("peer must exist")?;
                // Re-insert into queue if interval is still configured
                *key = cfg.interval.map(|interval| self.queue.insert(peer, interval));
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
                    self.peers.retain(|p, (_, key)| {
                        let keep = p.graph_id != peer.graph_id;
                        if !keep {
                            if let Some(k) = key {
                                self.queue.remove(k);
                            }
                        }
                        keep
                    });
                    self.invalid.insert(peer.graph_id);
                }
            })
            .with_context(|| format!("peer addr: {}", peer.addr))?;

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

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_subscribe(
        &mut self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        trace!("subscribing to hello notifications from peer");
        ST::sync_hello_subscribe_impl(self, peer, graph_change_delay, duration, schedule_delay)
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_unsubscribe(&mut self, peer: SyncPeer) -> Result<()> {
        trace!("unsubscribing from hello notifications from peer");
        ST::sync_hello_unsubscribe_impl(self, peer).await
    }

    /// Get peer caches for test inspection.
    #[cfg(test)]
    pub(crate) fn get_peer_caches(&self) -> crate::aranya::PeerCacheMap {
        self.client.caches_for_test()
    }

    /// Returns a reference to the Aranya client.
    #[cfg(test)]
    pub fn client(&self) -> &crate::aranya::Client<crate::EN, crate::SP> {
        self.client.client()
    }

    /// Returns a mutable reference to the Aranya client.
    #[cfg(test)]
    pub fn client_mut(&mut self) -> &mut crate::aranya::Client<crate::EN, crate::SP> {
        self.client.client_mut()
    }
}
