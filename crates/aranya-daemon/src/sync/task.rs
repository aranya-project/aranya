//! Aranya sync task.
//! A task for syncing with Aranya peers at specified intervals.
//! A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! [`SyncPeers`] handles adding/removing peers for the [`Syncer`].
//! [`Syncer`] syncs with the next available peer from the [`DelayQueue`].
//! [`SyncPeers`] and [`Syncer`] communicate via mpsc channels so they can run independently.
//! This prevents the need for an `Arc<<Mutex>>` which would lock until the next peer is retrieved from the [`DelayQueue`]

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{storage::GraphId, ClientError, Engine, PeerCache, Sink};
use aranya_util::Addr;
use buggy::BugExt;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::{error, instrument, trace};

use super::Result as SyncResult;
use crate::{
    daemon::{Client, EF},
    sync::error::SyncError,
    vm_policy::VecSink,
    InvalidGraphs,
};

pub mod quic;

/// Message sent from [`SyncPeers`] to [`Syncer`] via mpsc.
#[derive(Clone)]
enum Msg {
    SyncNow { peer: SyncPeer },
    AddPeer { peer: SyncPeer, cfg: SyncPeerConfig },
    RemovePeer { peer: SyncPeer },
}

/// A sync peer.
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
    pub(crate) fn new(addr: Addr, graph_id: GraphId) -> Self {
        Self { addr, graph_id }
    }
}

/// Handles adding and removing sync peers.
#[derive(Clone, Debug)]
pub struct SyncPeers {
    /// Send messages to add/remove peers.
    send: mpsc::Sender<Msg>,
    /// Configuration values for syncing
    cfgs: HashMap<(Addr, GraphId), SyncPeerConfig>,
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
    fn new(send: mpsc::Sender<Msg>) -> Self {
        Self {
            send,
            cfgs: HashMap::new(),
        }
    }

    /// Add peer to [`Syncer`].
    pub(crate) async fn add_peer(
        &mut self,
        addr: Addr,
        graph_id: GraphId,
        cfg: SyncPeerConfig,
    ) -> Result<()> {
        let peer = Msg::AddPeer {
            peer: SyncPeer::new(addr, graph_id),
            cfg: cfg.clone(),
        };
        if let Err(e) = self.send.send(peer).await.context("unable to add peer") {
            error!(?e, "error adding peer to syncer");
            return Err(e);
        }
        if cfg.sync_now {
            self.sync_now(addr, graph_id, Some(cfg.clone())).await?
        }

        self.cfgs.insert((addr, graph_id), cfg);

        Ok(())
    }

    /// Remove peer from [`Syncer`].
    pub(crate) async fn remove_peer(&mut self, addr: Addr, graph_id: GraphId) -> Result<()> {
        if let Err(e) = self
            .send
            .send(Msg::RemovePeer {
                peer: SyncPeer { addr, graph_id },
            })
            .await
            .context("unable to remove peer")
        {
            error!(?e, "error removing peer from syncer");
            return Err(e);
        }

        self.cfgs.remove(&(addr, graph_id));

        Ok(())
    }

    /// Sync with a peer immediately.
    pub(crate) async fn sync_now(
        &self,
        addr: Addr,
        graph_id: GraphId,
        _cfg: Option<SyncPeerConfig>,
    ) -> Result<()> {
        let peer = Msg::SyncNow {
            peer: SyncPeer { addr, graph_id },
        };
        if let Err(e) = self
            .send
            .send(peer)
            .await
            .context("unable to add sync now peer")
        {
            error!(?e, "error adding sync now peer to syncer");
            return Err(e);
        }
        Ok(())
    }
}

type EffectSender = mpsc::Sender<(GraphId, Vec<EF>)>;

/// Key for looking up syncer peer cache in map.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
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

/// Thread-safe map of peer caches
/// For a given peer, there's should only be one cache. If separate caches are used
/// for the server and state it will reduce the efficiency of the syncer.
pub type PeerCacheMap = Arc<Mutex<BTreeMap<PeerCacheKey, PeerCache>>>;

/// Syncs with each peer after the specified interval.
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
pub struct Syncer<ST> {
    /// Aranya client to allow syncing the Aranya graph with another peer.
    pub client: Client,
    /// Keeps track of peer info.
    peers: HashMap<SyncPeer, PeerInfo>,
    /// Receives added/removed peers.
    recv: mpsc::Receiver<Msg>,
    /// Delay queue for getting the next peer to sync with.
    queue: DelayQueue<SyncPeer>,
    /// Used to send effects to the API to be processed.
    send_effects: EffectSender,
    /// Keeps track of invalid graphs due to finalization errors.
    invalid: InvalidGraphs,
    /// Additional state used by the syncer
    state: ST,
    /// Sync server address.
    server_addr: Addr,
    /// Thread-safe reference to an [`Addr`]->[`PeerCache`] map.
    /// Lock must be acquired after [`Self::client`]
    caches: PeerCacheMap,
}

struct PeerInfo {
    /// Sync interval.
    interval: Duration,
    /// Key used to remove peer from queue.
    key: Key,
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
        server_addr: Addr,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<usize>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send;
}

impl<ST> Syncer<ST> {
    /// Creates a new `Syncer`.
    pub(crate) fn new(
        client: Client,
        send_effects: EffectSender,
        invalid: InvalidGraphs,
        state: ST,
        server_addr: Addr,
        caches: PeerCacheMap,
    ) -> (Self, SyncPeers) {
        let (send, recv) = mpsc::channel::<Msg>(128);
        let peers = SyncPeers::new(send);
        (
            Self {
                client,
                peers: HashMap::new(),
                recv,
                queue: DelayQueue::new(),
                send_effects,
                invalid,
                state,
                server_addr,
                caches,
            },
            peers,
        )
    }

    /// Add a peer to the delay queue, overwriting an existing one.
    fn add_peer(&mut self, peer: SyncPeer, cfg: &SyncPeerConfig) {
        let key = self.queue.insert(peer.clone(), cfg.interval);
        self.peers
            .entry(peer)
            .and_modify(|info| {
                self.queue.remove(&info.key);
                info.interval = cfg.interval;
                info.key = key;
            })
            .or_insert(PeerInfo {
                interval: cfg.interval,
                key,
            });
    }

    /// Remove a peer from the delay queue.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some(info) = self.peers.remove(&peer) {
            self.queue.remove(&info.key);
        }
    }
}

impl<ST: SyncState> Syncer<ST> {
    /// Syncs with the next peer in the list.
    pub(crate) async fn next(&mut self) -> SyncResult<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // receive added/removed peers.
            Some(msg) = self.recv.recv() => {
                match msg {
                    Msg::SyncNow{ peer } => {
                        // sync with peer right now.
                        self.sync(&peer).await?;
                    },
                    Msg::AddPeer { peer, cfg } => self.add_peer(peer, &cfg),
                    Msg::RemovePeer { peer } => self.remove_peer(peer),
                }
            }
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                let peer = expired.into_inner();
                let info = self.peers.get_mut(&peer).assume("peer must exist")?;
                info.key = self.queue.insert(peer.clone(), info.interval);
                // sync with peer.
                self.sync(&peer).await?;
            }
        }
        Ok(())
    }

    /// Sync with a peer.
    #[instrument(skip_all, fields(peer = ?peer))]
    pub(crate) async fn sync(&mut self, peer: &SyncPeer) -> SyncResult<usize> {
        trace!("syncing with peer");
        let (effects, cmd_count): (Vec<EF>, usize) = {
            let mut sink = VecSink::new();
            let cmd_count = match <ST as SyncState>::sync_impl(
                self,
                peer.graph_id,
                &mut sink,
                self.server_addr,
                &peer.addr,
            )
            .await
            .context("sync_peer error")
            .inspect_err(|err| error!("{err:?}"))
            {
                Ok(count) => count,
                Err(e) => {
                    // If a finalization error has occurred, remove all sync peers for that team.
                    if e.downcast_ref::<ClientError>()
                        .is_some_and(|err| matches!(err, ClientError::ParallelFinalize))
                    {
                        // Remove sync peers for graph that had finalization error.
                        self.peers.retain(|p, info| {
                            let keep = p.graph_id != peer.graph_id;
                            if !keep {
                                self.queue.remove(&info.key);
                            }
                            keep
                        });
                        self.invalid.insert(peer.graph_id);
                    }
                    return Err(SyncError::Other(e));
                }
            };
            let effects = sink
                .collect()
                .context("could not collect effects from sync")?;
            (effects, cmd_count)
        };
        let n = effects.len();
        self.send_effects
            .send((peer.graph_id, effects))
            .await
            .context("unable to send effects")?;
        trace!(?n, "completed sync");
        Ok(cmd_count)
    }
}
