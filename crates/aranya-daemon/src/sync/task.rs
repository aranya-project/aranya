//! Aranya sync task.
//! A task for syncing with Aranya peers at specified intervals.
//! A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! [`SyncPeers`] handles adding/removing peers for the [`Syncer`].
//! [`Syncer`] syncs with the next available peer from the [`DelayQueue`].
//! [`SyncPeers`] and [`Syncer`] communicate via mpsc channels so they can run independently.
//! This prevents the need for an `Arc<<Mutex>>` which would lock until the next peer is retrieved from the [`DelayQueue`]

use std::{collections::HashMap, future::Future, time::Duration};

use anyhow::{Context, Result};
use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{storage::GraphId, ClientError, Engine, Sink};
use aranya_util::Addr;
use buggy::BugExt;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::{error, instrument, trace};

use crate::{
    daemon::{Client, EF},
    vm_policy::VecSink,
    InvalidGraphs,
};

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
struct SyncPeer {
    addr: Addr,
    graph_id: GraphId,
}

/// Handles adding and removing sync peers.
#[derive(Clone, Debug)]
pub(crate) struct SyncPeers {
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
            peer: SyncPeer { addr, graph_id },
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

/// Syncs with each peer after the specified interval.
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
pub(crate) struct Syncer<ST> {
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
    _state: ST,
}

struct PeerInfo {
    /// Sync interval.
    interval: Duration,
    /// Key used to remove peer from queue.
    key: Key,
}

/// Types that contain additional data that are part of a [`Syncer`]
/// object.
pub(crate) trait SyncState: Sized {
    /// Syncs with the peer.
    fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> impl Future<Output = Result<()>> + Send
    where
        S: Sink<<crate::EN as Engine>::Effect> + Send;
}

impl<ST> Syncer<ST> {
    /// Creates a new `Syncer`.
    pub(crate) fn new(
        client: Client,
        send_effects: EffectSender,
        invalid: InvalidGraphs,
        _state: ST,
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
                _state,
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
    pub(crate) async fn next(&mut self) -> Result<()> {
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
    pub(crate) async fn sync(&mut self, peer: &SyncPeer) -> Result<()> {
        trace!("syncing with peer");
        let effects: Vec<EF> = {
            let mut sink = VecSink::new();
            if let Err(e) = <ST as SyncState>::sync_impl(self, peer.graph_id, &mut sink, &peer.addr)
                .await
                .inspect_err(|err| error!("{err:?}"))
            {
                // If a finalization error has occurred, remove all sync peers for that team.
                if e.downcast_ref::<ClientError>()
                    .is_some_and(|err| matches!(err, ClientError::ParallelFinalize))
                {
                    // Remove sync peers for graph that had finalization error.
                    self.peers.retain(|p, _| p.graph_id != peer.graph_id);
                    self.invalid.insert(peer.graph_id);
                }
                return Err(e);
            }
            sink.collect()?
        };
        let n = effects.len();
        self.send_effects
            .send((peer.graph_id, effects))
            .await
            .context("unable to send effects")?;
        trace!(?n, "completed sync");
        Ok(())
    }
}
