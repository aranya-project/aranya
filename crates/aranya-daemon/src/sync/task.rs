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
use aranya_runtime::{storage::GraphId, Engine, Sink};
use aranya_util::Addr;
use buggy::BugExt;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::{error, instrument, trace};

use super::Result as SyncResult;
use crate::{
    daemon::{Client, EF},
    vm_policy::VecSink,
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
#[derive(Clone, Ord, Eq, PartialOrd, PartialEq, Hash)]
struct SyncPeer {
    addr: Addr,
    graph_id: GraphId,
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
    /// Additional state used by the syncer
    state: ST,
    /// Sync server address.
    server_addr: Addr,
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
    pub fn new(
        client: Client,
        send_effects: EffectSender,
        state: ST,
        server_addr: Addr,
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
                state,
                server_addr,
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
                        let _ = self.sync(&peer.graph_id, &peer.addr).await?;
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
                let _ = self.sync(&peer.graph_id, &peer.addr).await?;
            }
        }
        Ok(())
    }

    /// Sync with a peer.
    ///
    /// Returns the number of commands that were received and successfully processed.
    #[instrument(skip_all, fields(peer = %peer, graph_id = %id))]
    pub async fn sync(&mut self, id: &GraphId, peer: &Addr) -> SyncResult<usize> {
        trace!("syncing with peer");
        let server_addr = self.server_addr;
        let mut sink = VecSink::new();
        let cmd_count = <ST as SyncState>::sync_impl(self, *id, &mut sink, server_addr, peer)
            .await
            .context("sync_peer error")
            .inspect_err(|err| error!("{err:?}"))?;
        trace!(commands_received = cmd_count, "received commands from peer");
        let effects: Vec<EF> = sink.collect().context("could not collect effects")?;
        let n = effects.len();
        self.send_effects
            .send((*id, effects))
            .await
            .context("unable to send effects")?;
        trace!(?n, "completed sync");
        Ok(cmd_count)
    }
}
