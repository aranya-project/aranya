//! Aranya sync task.
//!
//! A task for syncing with Aranya peers at specified intervals.
//!
//! # Architecture
//!
//! - A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! - [`SyncPeers`] handles adding/removing peers for the [`Syncer`].
//! - [`Syncer`] syncs with the next available peer from the [`DelayQueue`].
//! - [`SyncPeers`] and [`Syncer`] communicate via mpsc channels so they can run independently.
//!
//! This prevents the need for an `Arc<Mutex>` which would lock until the next peer is retrieved from the [`DelayQueue`].
//!
//! # Hello Sync
//!
//! The sync task supports "hello" notifications that allow peers to proactively notify each other
//! when their graph head changes, enabling more responsive synchronization:
//!
//! - **Subscriptions**: Peers can subscribe to hello notifications from other peers using
//!   SyncPeers::sync_hello_subscribe, specifying a delay between notifications and a duration
//!   for the subscription.
//! - **Broadcasting**: When a graph head changes, hello notifications are broadcast to all
//!   subscribers via SyncPeers::broadcast_hello.
//! - **Sync on Hello**: Peers can be configured to automatically sync when they receive a hello
//!   notification by setting `sync_on_hello` in their [`SyncPeerConfig`].
//! - **Unsubscribe**: Peers can unsubscribe from hello notifications using
//!   SyncPeers::sync_hello_unsubscribe.
//!
//! See the [`hello`] module for implementation details.

use std::{collections::HashMap, future::Future, time::Duration};

use anyhow::Context;
use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{storage::GraphId, Address, Engine, Sink};
use aranya_util::{error::ReportExt as _, ready, Addr};
use buggy::BugExt;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::{error, info, instrument, trace, warn};

use super::Result as SyncResult;
use crate::{daemon::EF, vm_policy::VecSink, InvalidGraphs};

pub mod hello;
pub mod quic;

/// Message sent from [`SyncPeers`] to [`Syncer`] via mpsc.
#[derive(Clone)]
enum Msg {
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
type Request = (Msg, oneshot::Sender<Reply>);
type Reply = SyncResult<()>;

/// A sync peer.
///
/// Contains the information needed to sync with a single peer:
/// - network address
/// - Aranya graph id
#[derive(Debug, Clone, Ord, Eq, PartialOrd, PartialEq, Hash)]
pub(crate) struct SyncPeer {
    addr: Addr,
    graph_id: GraphId,
}

impl SyncPeer {
    /// Creates a new `SyncPeer`.
    #[cfg(test)]
    pub fn new(addr: Addr, graph_id: GraphId) -> Self {
        Self { addr, graph_id }
    }
}

/// Handles adding and removing sync peers.
#[derive(Clone, Debug)]
pub struct SyncPeers {
    /// Send messages to add/remove peers.
    sender: mpsc::Sender<Request>,
}

/// A response to a sync request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}

impl SyncPeers {
    /// Create a new peer manager.
    fn new(sender: mpsc::Sender<Request>) -> Self {
        Self { sender }
    }

    async fn send(&self, msg: Msg) -> Reply {
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
        self.send(Msg::AddPeer { peer, cfg }).await
    }

    /// Remove peer from [`Syncer`].
    pub(crate) async fn remove_peer(&self, addr: Addr, graph_id: GraphId) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(Msg::RemovePeer { peer }).await
    }

    /// Sync with a peer immediately.
    pub(crate) async fn sync_now(
        &self,
        addr: Addr,
        graph_id: GraphId,
        cfg: Option<SyncPeerConfig>,
    ) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(Msg::SyncNow { peer, cfg }).await
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
        self.send(Msg::HelloSubscribe {
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
        self.send(Msg::HelloUnsubscribe { peer }).await
    }

    /// Trigger sync with a peer based on hello message.
    /// Will be ignored if `SyncPeerConfig::sync_on_hello` is false.
    pub(crate) async fn sync_on_hello(&self, addr: Addr, graph_id: GraphId) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(Msg::SyncOnHello { peer }).await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    pub(crate) async fn broadcast_hello(&self, graph_id: GraphId, head: Address) -> Reply {
        self.send(Msg::BroadcastHello { graph_id, head }).await
    }
}

type EffectSender = mpsc::Sender<(GraphId, Vec<EF>)>;

/// Key for looking up syncer peer cache in map.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct PeerCacheKey {
    /// The peer address.
    pub addr: Addr,
    /// The Aranya graph ID.
    pub id: GraphId,
}

impl PeerCacheKey {
    fn new(addr: Addr, id: GraphId) -> Self {
        Self { addr, id }
    }
}

/// Syncs with each peer after the specified interval.
///
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
#[derive(Debug)]
pub struct Syncer<ST> {
    /// Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    pub(crate) client: crate::aranya::ClientWithState<crate::EN, crate::SP>,
    /// Keeps track of peer info. The Key is None if the peer has no interval configured.
    peers: HashMap<SyncPeer, (SyncPeerConfig, Option<Key>)>,
    /// Receives added/removed peers.
    recv: mpsc::Receiver<Request>,
    /// Delay queue for getting the next peer to sync with.
    queue: DelayQueue<SyncPeer>,
    /// Used to send effects to the API to be processed.
    send_effects: EffectSender,
    /// Keeps track of invalid graphs due to finalization errors.
    invalid: InvalidGraphs,
    /// Additional state used by the syncer.
    state: ST,
    /// Sync server address.
    server_addr: Addr,
}

/// Types that contain additional data that are part of a [`Syncer`]
/// object.
pub trait SyncState: Sized {
    /// Syncs with the peer.
    ///
    /// Returns the number of commands that were received and successfully processed.
    fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<usize>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send;

    /// Subscribe to hello notifications from a sync peer.
    fn sync_hello_subscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
        delay: Duration,
        duration: Duration,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    /// Unsubscribe from hello notifications from a sync peer.
    fn sync_hello_unsubscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    /// Broadcast hello notifications to all subscribers of a graph.
    fn broadcast_hello_notifications_impl(
        syncer: &mut Syncer<Self>,
        graph_id: GraphId,
        head: Address,
    ) -> impl Future<Output = SyncResult<()>> + Send;
}

impl<ST> Syncer<ST> {
    /// Add a peer to the delay queue, overwriting an existing one.
    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        // Only insert into delay queue if interval is configured
        let new_key = cfg
            .interval
            .map(|interval| self.queue.insert(peer.clone(), interval));
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

    /// Updates the server address to the actual listening address.
    /// This should be called after the server starts and we know its actual listening address.
    pub fn update_server_addr(&mut self, actual_addr: std::net::SocketAddr) {
        self.server_addr = actual_addr.into();
    }
}

impl<ST: SyncState> Syncer<ST> {
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
                    Msg::SyncNow { peer, cfg: _cfg } => {
                        // sync with peer right now.
                        self.sync(&peer).await.map(|_| ())
                    },
                    Msg::AddPeer { peer, cfg } => {
                        let mut result = Ok(());
                        if cfg.sync_now {
                            result = self.sync(&peer).await.map(|_| ());
                        }
                        self.add_peer(peer, cfg);
                        result
                    }
                    Msg::RemovePeer { peer } => {
                        self.remove_peer(peer);
                        Ok(())
                    }
                    Msg::HelloSubscribe { peer, delay, duration } => {
                        self.sync_hello_subscribe(&peer, delay, duration).await
                    }
                    Msg::HelloUnsubscribe { peer } => {
                        self.sync_hello_unsubscribe(&peer).await
                    }
                    Msg::SyncOnHello { peer } => {
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
                    Msg::BroadcastHello { graph_id, head } => {
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
                *key = cfg.interval.map(|interval| self.queue.insert(peer.clone(), interval));
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

        let cmd_count = ST::sync_impl(self, peer.graph_id, &mut sink, &peer.addr)
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
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_subscribe(
        &mut self,
        peer: &SyncPeer,
        delay: Duration,
        duration: Duration,
    ) -> SyncResult<()> {
        trace!("subscribing to hello notifications from peer");
        ST::sync_hello_subscribe_impl(self, peer.graph_id, &peer.addr, delay, duration).await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_unsubscribe(&mut self, peer: &SyncPeer) -> SyncResult<()> {
        trace!("unsubscribing from hello notifications from peer");
        ST::sync_hello_unsubscribe_impl(self, peer.graph_id, &peer.addr).await
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
