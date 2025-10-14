//! TODO(nikki): docs

use std::{collections::HashMap, time::Duration};

use anyhow::Context as _;
use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{Address, GraphId};
use aranya_util::{error::ReportExt as _, ready, Addr};
use buggy::BugExt as _;
use futures_util::StreamExt as _;
use tokio::sync::{mpsc, oneshot};
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::{error, info, instrument, trace, warn};

use super::Result as SyncResult;
#[cfg(test)]
use crate::sync::types::PeerCacheMap;
use crate::{
    sync::{transport::Transport, types::SyncPeer},
    vm_policy::VecSink,
    InvalidGraphs, EF,
};

/// Message sent from [`SyncPeers`] to [`Syncer`] via mpsc.
#[derive(Clone)]
pub(crate) enum ManagerMsg {
    SyncNow {
        peer: SyncPeer,
        cfg: Option<SyncPeerConfig>,
    },
    AddPeer {
        peer: SyncPeer,
        cfg: SyncPeerConfig,
    },
    RemovePeer {
        peer: SyncPeer,
    },
    HelloSubscribe {
        peer: SyncPeer,
        delay: Duration,
        duration: Duration,
    },
    HelloUnsubscribe {
        peer: SyncPeer,
    },
    SyncOnHello {
        peer: SyncPeer,
    },
    BroadcastHello {
        graph_id: GraphId,
        head: Address,
    },
}
pub(crate) type Request = (ManagerMsg, oneshot::Sender<Reply>);
type Reply = SyncResult<()>;

pub(crate) type EffectSender = mpsc::Sender<(GraphId, Vec<EF>)>;

/// Syncs with each peer after the specified interval.
///
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
#[derive(Debug)]
pub struct SyncManager<T> {
    /// Aranya client paired with caches, ensuring safe lock ordering.
    pub(crate) client_with_caches: crate::aranya::ClientWithCaches<crate::EN, crate::SP>,
    /// Keeps track of peer info.
    pub(crate) peers: HashMap<SyncPeer, (SyncPeerConfig, Key)>,
    /// Receives added/removed peers.
    pub(crate) recv: mpsc::Receiver<Request>,
    /// Delay queue for getting the next peer to sync with.
    pub(crate) queue: DelayQueue<SyncPeer>,
    /// Used to send effects to the API to be processed.
    pub(crate) send_effects: EffectSender,
    /// Keeps track of invalid graphs due to finalization errors.
    pub(crate) invalid: InvalidGraphs,
    /// Additional state used by the syncer.
    pub(crate) state: T,
    /// Sync server address.
    pub(crate) server_addr: Addr,
}

impl<T> SyncManager<T> {
    /// Add a peer to the delay queue, overwriting an existing one.
    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        let new_key = self.queue.insert(peer.clone(), cfg.interval);
        if let Some((_, old_key)) = self.peers.insert(peer, (cfg, new_key)) {
            self.queue.remove(&old_key);
        }
    }

    /// Remove a peer from the delay queue.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, key)) = self.peers.remove(&peer) {
            self.queue.remove(&key);
        }
    }

    /// Updates the server address to the actual listening address.
    /// This should be called after the server starts and we know its actual listening address.
    pub fn update_server_addr(&mut self, actual_addr: std::net::SocketAddr) {
        self.server_addr = actual_addr.into();
    }
}

impl<T: Transport> SyncManager<T> {
    pub(crate) async fn run(mut self, ready: ready::Notifier) {
        ready.notify();
        loop {
            if let Err(err) = self.next().await {
                error!(error = %err.report(), "unable to sync with peer");
            }
        }
    }

    /// Syncs with the next peer in the list.
    async fn next(&mut self) -> SyncResult<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // receive added/removed peers.
            Some((msg, tx)) = self.recv.recv() => {
                let reply = match msg {
                    ManagerMsg::SyncNow { peer, cfg: _cfg } => {
                        // sync with peer right now.
                        self.sync(&peer).await.map(|_| ())
                    },
                    ManagerMsg::AddPeer { peer, cfg } => {
                        let mut result = Ok(());
                        if cfg.sync_now {
                            result = self.sync(&peer).await.map(|_| ());
                        }
                        self.add_peer(peer, cfg);
                        result
                    }
                    ManagerMsg::RemovePeer { peer } => {
                        self.remove_peer(peer);
                        Ok(())
                    }
                    ManagerMsg::HelloSubscribe { peer, delay, duration } => {
                        self.sync_hello_subscribe(&peer, delay, duration).await
                    }
                    ManagerMsg::HelloUnsubscribe { peer } => {
                        self.sync_hello_unsubscribe(&peer).await
                    }
                    ManagerMsg::SyncOnHello { peer } => {
                        // Check if sync_on_hello is enabled for this peer
                        let Some((cfg, _)) = self.peers.get(&peer) else {
                            warn!(
                                ?peer,
                                "Peer not found in our configuration, ignoring SyncOnHello"
                            );
                            return Ok(());
                        };

                        if !cfg.sync_on_hello {
                            trace!(
                                ?peer,
                                "SyncOnHello is not enabled for this peer, ignoring"
                            );
                            return Ok(());
                        }

                        self.sync(&peer).await
                            .inspect_err(|e| {
                                warn!(
                                    error = %e,
                                    ?peer,
                                    "SyncOnHello sync failed"
                                );
                            })
                            .map(|_| ())
                    }
                    ManagerMsg::BroadcastHello { graph_id, head } => {
                        T::broadcast_hello_notifications(self, graph_id, head).await
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
                *key = self.queue.insert(peer.clone(), cfg.interval);
                // sync with peer.
                self.sync(&peer).await?;
            }
        }
        Ok(())
    }

    /// Sync with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: &SyncPeer) -> SyncResult<usize> {
        let mut sink = VecSink::new();

        let cmd_count = T::sync_impl(self, peer.graph_id, &mut sink, &peer.addr)
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
                            self.queue.remove(key);
                        }
                        keep
                    });
                    self.invalid.insert(peer.graph_id);
                }
            })?;

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
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_subscribe(
        &mut self,
        peer: &SyncPeer,
        delay: Duration,
        duration: Duration,
    ) -> SyncResult<()> {
        trace!("subscribing to hello notifications from peer");
        T::sync_hello_subscribe_impl(self, peer.graph_id, &peer.addr, delay, duration).await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_unsubscribe(&mut self, peer: &SyncPeer) -> SyncResult<()> {
        trace!("unsubscribing from hello notifications from peer");
        T::sync_hello_unsubscribe_impl(self, peer.graph_id, &peer.addr).await
    }

    /// Get peer caches for test inspection.
    #[cfg(test)]
    pub(crate) fn get_peer_caches(&self) -> PeerCacheMap {
        self.client_with_caches.caches_for_test()
    }

    /// Returns a reference to the Aranya client.
    #[cfg(test)]
    pub fn client(&self) -> &crate::aranya::Client<crate::EN, crate::SP> {
        self.client_with_caches.client()
    }

    /// Returns a mutable reference to the Aranya client.
    #[cfg(test)]
    pub fn client_mut(&mut self) -> &mut crate::aranya::Client<crate::EN, crate::SP> {
        self.client_with_caches.client_mut()
    }
}

/// Handles adding and removing sync peers.
#[derive(Clone, Debug)]
pub struct SyncHandle {
    /// Send messages to add/remove peers.
    sender: mpsc::Sender<Request>,
}

impl SyncHandle {
    /// Create a new peer manager.
    pub(crate) fn new(sender: mpsc::Sender<Request>) -> Self {
        Self { sender }
    }

    async fn send(&self, msg: ManagerMsg) -> Reply {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .assume("syncer peer channel closed")?;
        rx.await.assume("no syncer reply")?
    }

    /// Add peer to [`Syncer`].
    pub(crate) async fn add_peer(
        &self,
        addr: Addr,
        graph_id: GraphId,
        cfg: SyncPeerConfig,
    ) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(ManagerMsg::AddPeer { peer, cfg }).await
    }

    /// Remove peer from [`Syncer`].
    pub(crate) async fn remove_peer(&self, addr: Addr, graph_id: GraphId) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(ManagerMsg::RemovePeer { peer }).await
    }

    /// Sync with a peer immediately.
    pub(crate) async fn sync_now(
        &self,
        addr: Addr,
        graph_id: GraphId,
        cfg: Option<SyncPeerConfig>,
    ) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(ManagerMsg::SyncNow { peer, cfg }).await
    }

    /// Subscribe to hello notifications from a sync peer.
    pub(crate) async fn sync_hello_subscribe(
        &self,
        peer_addr: Addr,
        graph_id: GraphId,
        delay: Duration,
        duration: Duration,
    ) -> Reply {
        let peer = SyncPeer {
            addr: peer_addr,
            graph_id,
        };
        self.send(ManagerMsg::HelloSubscribe {
            peer,
            delay,
            duration,
        })
        .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    pub(crate) async fn sync_hello_unsubscribe(&self, peer_addr: Addr, graph_id: GraphId) -> Reply {
        let peer = SyncPeer {
            addr: peer_addr,
            graph_id,
        };
        self.send(ManagerMsg::HelloUnsubscribe { peer }).await
    }

    /// Trigger sync with a peer based on hello message.
    pub(crate) async fn sync_on_hello(&self, addr: Addr, graph_id: GraphId) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(ManagerMsg::SyncOnHello { peer }).await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    pub(crate) async fn broadcast_hello(&self, graph_id: GraphId, head: Address) -> Reply {
        self.send(ManagerMsg::BroadcastHello { graph_id, head })
            .await
    }
}
