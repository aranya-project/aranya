//! Aranya sync task.
//! A task for syncing with Aranya peers at specified intervals.
//! A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! [`SyncPeers`] handles adding/removing peers for the [`Syncer`].
//! [`Syncer`] syncs with the next available peer from the [`DelayQueue`].
//! [`SyncPeers`] and [`Syncer`] communicate via mpsc channels so they can run independently.
//! This prevents the need for an `Arc<<Mutex>>` which would lock until the next peer is retrieved from the [`DelayQueue`]

use std::{collections::HashMap, future::Future};

use anyhow::{Context, Result};
use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{storage::GraphId, ClientError, Engine, Sink};
use aranya_util::Addr;
use buggy::{Bug, BugExt};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
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
pub struct SyncPeers {
    /// Send messages to add/remove peers.
    sender: mpsc::Sender<Msg>,
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
    fn new(sender: mpsc::Sender<Msg>) -> Self {
        Self { sender }
    }

    async fn send(&self, msg: Msg) -> Result<(), Bug> {
        self.sender
            .send(msg)
            .await
            .assume("syncer peer channel closed")
    }

    /// Add peer to [`Syncer`].
    pub(crate) async fn add_peer(
        &self,
        addr: Addr,
        graph_id: GraphId,
        cfg: SyncPeerConfig,
    ) -> Result<(), Bug> {
        let peer = SyncPeer { addr, graph_id };
        self.send(Msg::AddPeer { peer, cfg }).await
    }

    /// Remove peer from [`Syncer`].
    pub(crate) async fn remove_peer(&self, addr: Addr, graph_id: GraphId) -> Result<(), Bug> {
        let peer = SyncPeer { addr, graph_id };
        self.send(Msg::RemovePeer { peer }).await
    }

    /// Sync with a peer immediately.
    pub(crate) async fn sync_now(
        &self,
        addr: Addr,
        graph_id: GraphId,
        cfg: Option<SyncPeerConfig>,
    ) -> Result<(), Bug> {
        let peer = SyncPeer { addr, graph_id };
        self.send(Msg::SyncNow { peer, cfg }).await
    }
}

type EffectSender = mpsc::Sender<(GraphId, Vec<EF>)>;

/// Syncs with each peer after the specified interval.
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
#[derive(Debug)]
pub struct Syncer<ST> {
    /// Aranya client to allow syncing the Aranya graph with another peer.
    pub client: Client,
    /// Keeps track of peer info.
    peers: HashMap<SyncPeer, (SyncPeerConfig, Key)>,
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
}

/// Types that contain additional data that are part of a [`Syncer`]
/// object.
pub trait SyncState: Sized {
    /// Syncs with the peer.
    fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> impl Future<Output = SyncResult<()>> + Send
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
            },
            peers,
        )
    }

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
                    Msg::SyncNow{ peer, cfg: _cfg } => {
                        // sync with peer right now.
                        self.sync(&peer).await?;
                    },
                    Msg::AddPeer { peer, cfg } => {
                        let mut result = Ok(());
                        if cfg.sync_now {
                            result = self.sync(&peer).await;
                        }
                        self.add_peer(peer, cfg);
                        result?;
                    }
                    Msg::RemovePeer { peer } => {
                        self.remove_peer(peer);
                    }
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
    #[instrument(skip_all, fields(peer = ?peer))]
    pub(crate) async fn sync(&mut self, peer: &SyncPeer) -> SyncResult<()> {
        trace!("syncing with peer");
        let effects: Vec<EF> = {
            let mut sink = VecSink::new();
            if let Err(e) = <ST as SyncState>::sync_impl(self, peer.graph_id, &mut sink, &peer.addr)
                .await
                .context("sync_peer error")
                .inspect_err(|err| error!("{err:?}"))
            {
                // If a finalization error has occurred, remove all sync peers for that team.
                if e.downcast_ref::<ClientError>()
                    .is_some_and(|err| matches!(err, ClientError::ParallelFinalize))
                {
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
                return Err(SyncError::Other(e));
            }
            sink.collect()
                .context("could not collect effects from sync")?
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
