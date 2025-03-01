//! Aranya sync task.
//! A task for syncing with Aranya peers at specified intervals.
//! A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! [`SyncPeers`] handles adding/removing peers for the [`Syncer`].
//! [`Syncer`] syncs with the next available peer from the [`DelayQueue`].
//! [`SyncPeers`] and [`Syncer`] communicate via mpsc channels so they can run independently.
//! This prevents the need for an `Arc<<Mutex>>` which would lock until the next peer is retrieved from the [`DelayQueue`]

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use aranya_buggy::BugExt;
use aranya_runtime::storage::GraphId;
use aranya_util::Addr;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::{error, info, instrument};

use crate::{
    daemon::{Client, EF},
    vm_policy::VecSink,
};

/// Message sent from [`SyncPeers`] to [`Syncer`] via mpsc.
#[derive(Clone)]
enum Msg {
    AddPeer { peer: SyncPeer, interval: Duration },
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
#[derive(Clone)]
pub struct SyncPeers {
    /// Send messages to add/remove peers.
    send: mpsc::Sender<Msg>,
}

impl SyncPeers {
    /// Create a new peer manager.
    fn new(send: mpsc::Sender<Msg>) -> Self {
        Self { send }
    }

    /// Add peer to [`Syncer`].
    pub async fn add_peer(&self, addr: Addr, interval: Duration, graph_id: GraphId) -> Result<()> {
        let peer = Msg::AddPeer {
            peer: SyncPeer { addr, graph_id },
            interval,
        };
        if let Err(e) = self.send.send(peer).await.context("unable to add peer") {
            error!(?e, "error adding peer to syncer");
            return Err(e);
        }
        Ok(())
    }

    /// Remove peer from [`Syncer`].
    pub async fn remove_peer(&self, addr: Addr, graph_id: GraphId) -> Result<()> {
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
        Ok(())
    }
}

/// Syncs with each peer after the specified interval.
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
pub struct Syncer {
    /// Aranya client to allow syncing the Aranya graph with another peer.
    client: Arc<Client>,
    /// Keeps track of peer info.
    peers: HashMap<SyncPeer, PeerInfo>,
    /// Receives added/removed peers.
    recv: mpsc::Receiver<Msg>,
    /// Delay queue for getting the next peer to sync with.
    queue: DelayQueue<SyncPeer>,
    /// Used to send effects to the API to be processed.
    send_effects: mpsc::Sender<Vec<EF>>,
}

struct PeerInfo {
    /// Sync interval.
    interval: Duration,
    /// Key used to remove peer from queue.
    key: Key,
}

impl Syncer {
    /// Creates a new `Syncer`.
    pub fn new(client: Arc<Client>, send_effects: mpsc::Sender<Vec<EF>>) -> (Self, SyncPeers) {
        let (send, recv) = mpsc::channel::<Msg>(128);
        let peers = SyncPeers::new(send);
        (
            Self {
                client,
                peers: HashMap::new(),
                recv,
                queue: DelayQueue::new(),
                send_effects,
            },
            peers,
        )
    }

    /// Syncs with the next peer in the list.
    #[instrument(skip_all)]
    pub async fn next(&mut self) -> Result<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // receive added/removed peers.
            Some(msg) = self.recv.recv() => {
                match msg {
                    Msg::AddPeer { peer, interval } => self.add_peer(peer, interval),
                    Msg::RemovePeer { peer } => self.remove_peer(peer),
                }

            }
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                let peer = expired.into_inner();
                let info = self.peers.get_mut(&peer).assume("peer must exist")?;
                info.key = self.queue.insert(peer.clone(), info.interval);
                // sync with peer.
                self.sync(&peer.graph_id, &peer.addr).await?;
            }
        }
        Ok(())
    }

    /// Add a peer to the delay queue, overwriting an existing one.
    fn add_peer(&mut self, peer: SyncPeer, interval: Duration) {
        let key = self.queue.insert(peer.clone(), interval);
        self.peers
            .entry(peer)
            .and_modify(|info| {
                self.queue.remove(&info.key);
                info.interval = interval;
                info.key = key;
            })
            .or_insert(PeerInfo { interval, key });
    }

    /// Remove a peer from the delay queue.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some(info) = self.peers.remove(&peer) {
            self.queue.remove(&info.key);
        }
    }

    #[instrument(skip_all, fields(peer = %peer, graph_id = %id))]
    async fn sync(&mut self, id: &GraphId, peer: &Addr) -> Result<()> {
        info!("syncing with peer");

        let effects: Vec<EF> = {
            let mut sink = VecSink::new();
            self.client
                .sync_peer(*id, &mut sink, peer)
                .await
                .context("sync_peer error")
                .inspect_err(|err| error!("{err:?}"))?;
            sink.collect()?
        };
        let n = effects.len();
        self.send_effects
            .send(effects)
            .await
            .context("unable to send effects")?;
        info!(?n, "completed sync");
        Ok(())
    }
}
