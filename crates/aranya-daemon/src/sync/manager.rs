//! TODO(nikki): docs

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{Address, GraphId};
use aranya_util::{error::ReportExt as _, ready, Addr};
use buggy::BugExt as _;
use dashmap::DashMap;
use futures_util::StreamExt as _;
use metrics::{counter, gauge, histogram};
use tokio::{
    sync::{mpsc, oneshot, Mutex},
    task::JoinSet,
};
use tokio_util::time::delay_queue::{DelayQueue, Key};
use tracing::{debug, error, info, trace, warn};

use super::{
    protocol::{SyncProtocol, SyncResult},
    types::{SyncGuard, SyncType},
    PeerCacheMap, Result, SyncPeer, Transport,
};
use crate::{sync::protocol::ProtocolStore, Client, InvalidGraphs, EF};

pub(crate) type EffectSender = mpsc::Sender<(GraphId, Vec<EF>)>;

#[derive(Debug, Clone)]
pub(super) struct ProtocolConfig {
    pub(super) client: Client,
    pub(super) caches: PeerCacheMap,
    pub(super) server_addr: Addr,
    pub(super) send_effects: EffectSender,
}

#[derive(Debug, Clone)]
struct PeerLocks {
    locks: Arc<DashMap<SyncPeer, Arc<Mutex<SyncGuard>>>>,
}

impl PeerLocks {
    fn new() -> Self {
        Self {
            locks: Arc::default(),
        }
    }

    async fn get(&self, peer: &SyncPeer) -> Arc<Mutex<SyncGuard>> {
        self.locks
            .entry(peer.clone())
            .or_insert_with(|| Arc::new(Mutex::new(SyncGuard::new(peer.clone()))))
            .clone()
    }
}

/// Message sent from [`SyncPeers`] to [`Syncer`] via mpsc.
#[derive(Debug, Clone)]
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
    InvalidateGraph {
        graph_id: GraphId,
    },
}
pub(crate) type Request = (ManagerMsg, oneshot::Sender<Reply>);
type Reply = Result<()>;

#[derive(Debug)]
struct PendingSync {
    peer: SyncPeer,
    sync_type: SyncType,
    queued_at: Instant,
}

/// Syncs with each peer after the specified interval.
///
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncPeers`] via mpsc channels.
#[derive(Debug)]
pub struct SyncManager<T> {
    transport: Arc<T>,
    config: ProtocolConfig,
    /// Keeps track of invalid graphs due to finalization errors.
    pub(crate) invalid: InvalidGraphs,
    max_concurrent: usize,
    /// Receives added/removed peers.
    pub(crate) recv: mpsc::Receiver<Request>,
    /// Keeps track of peer info.
    pub(crate) peers: HashMap<SyncPeer, (SyncPeerConfig, Key)>,
    peer_locks: PeerLocks,
    /// Delay queue for getting the next peer to sync with.
    pub(crate) queue: DelayQueue<SyncPeer>,
    pending: VecDeque<PendingSync>,
    active: JoinSet<()>,
}

impl<T> SyncManager<T> {
    pub fn new(
        transport: Arc<T>,
        config: ProtocolConfig,
        invalid: InvalidGraphs,
        max_concurrent: usize,
    ) -> (Self, SyncHandle) {
        let (send, recv) = mpsc::channel::<Request>(128);
        let handle = SyncHandle::new(send);
        let protocols = ProtocolStore::new(config.clone());

        let manager = Self {
            transport,
            config,
            invalid,
            max_concurrent,
            recv,
            peers: HashMap::new(),
            peer_locks: PeerLocks::new(),
            queue: DelayQueue::new(),
            pending: VecDeque::new(),
            active: JoinSet::new(),
        };

        (manager, handle)
    }

    pub fn update_server_addr(&mut self, actual_addr: std::net::SocketAddr) {
        self.config.server_addr = actual_addr.into();
    }

    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        let new_key = self.queue.insert(peer.clone(), cfg.interval);
        if let Some((_, old_key)) = self.peers.insert(peer, (cfg, new_key)) {
            self.queue.remove(&old_key);
        }
    }

    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, key)) = self.peers.remove(&peer) {
            self.queue.remove(&key);
        }
    }

    fn reschedule_peer(&mut self, peer: &SyncPeer) -> Result<()> {
        let (cfg, key) = self.peers.get_mut(&peer).assume("peer must exist")?;
        *key = self.queue.insert(peer.clone(), cfg.interval);
        Ok(())
    }
}

impl<T: Transport + Send + Sync + 'static> SyncManager<T> {
    pub(crate) async fn run(mut self, ready: ready::Notifier) {
        ready.notify();

        loop {
            if let Err(err) = self.next_event().await {
                error!(error = %err.report(), "manager error");
                counter!("sync.manager_errors").increment(1);
            }
        }
    }

    async fn next_event(&mut self) -> Result<()> {
        tokio::select! {
            // receive added/removed peers.
            Some((msg, tx)) = self.recv.recv() => {
                let reply = self.handle_message(msg).await;
                let _ = tx.send(reply);
            }
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                let peer = expired.into_inner();
                self.reschedule_peer(&peer)?;

                self.pending.push_back(PendingSync {
                    peer, sync_type: SyncType::Poll, queued_at: Instant::now()
                });

                self.spawn_pending();
            }

            Some(_) = self.active.join_next() => {
                gauge!("sync.active_count").decrement(1.0);
                self.spawn_pending();
            }

            else => {
                debug!("all channels closed, idling");
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
        Ok(())
    }

    async fn handle_message(&mut self, msg: ManagerMsg) -> Reply {
        match msg {
            ManagerMsg::SyncNow { peer, .. } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::Poll,
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::AddPeer { peer, cfg } => {
                if cfg.sync_now {
                    self.pending.push_back(PendingSync {
                        peer: peer.clone(),
                        sync_type: SyncType::Poll,
                        queued_at: Instant::now(),
                    });
                    self.spawn_pending();
                }
                self.add_peer(peer, cfg);
            }
            ManagerMsg::RemovePeer { peer } => {
                self.remove_peer(peer);
            }
            ManagerMsg::HelloSubscribe {
                peer,
                delay,
                duration,
            } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::HelloSubscribe { delay, duration },
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::HelloUnsubscribe { peer } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::HelloUnsubscribe,
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::SyncOnHello { peer } => {
                // Check if sync_on_hello is enabled for this peer
                let Some((cfg, _)) = self.peers.get(&peer) else {
                    warn!(?peer, "peer not found for sync_on_hello");
                    return Ok(());
                };

                if !cfg.sync_on_hello {
                    trace!(?peer, "sync_on_hello not enabled for this peer");
                    return Ok(());
                }

                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::Poll,
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::BroadcastHello { graph_id, head } => {
                trace!(?graph_id, ?head, "broadcast hello request");
            }
            ManagerMsg::InvalidateGraph { graph_id } => {
                self.peers.retain(|peer, (_, key)| {
                    if peer.graph_id == graph_id {
                        self.queue.remove(key);
                        false
                    } else {
                        true
                    }
                });
                info!(?graph_id, "invalidated graph, removed all peers");
            }
        }
        Ok(())
    }

    fn spawn_pending(&mut self) {
        while self.active.len() < self.max_concurrent {
            let Some(pending) = self.pending.pop_front() else {
                break;
            };

            let wait_time = pending.queued_at.elapsed();
            histogram!("sync.queue_wait_ms").record(wait_time.as_millis() as f64);

            if wait_time.as_secs() > 10 {
                warn!(
                    peer = %pending.peer.addr,
                    graph = %pending.peer.graph_id,
                    wait_secs = wait_time.as_secs(),
                    "sync waited in queue too long"
                );
            }

            self.spawn_sync(pending.peer, pending.sync_type);
        }
    }

    async fn sync_task(
        peer: SyncPeer,
        sync_type: SyncType,
        transport: Arc<T>,
        config: ProtocolConfig,
        peer_locks: PeerLocks,
        invalid: InvalidGraphs,
    ) {
        let sync_start = Instant::now();

        if invalid.contains(peer.graph_id) {
            trace!(peer = %peer.addr, graph = %peer.graph_id, "skipping invalid graph");
            counter!("sync.skipped_invalid_graph").increment(1);
            return;
        }

        let peer_lock_start = Instant::now();
        let peer_lock = peer_locks.get(&peer).await;
        let _guard = peer_lock.lock().await;
        let peer_lock_wait = peer_lock_start.elapsed();
        histogram!("sync.peer_lock_wait_ms").record(peer_lock_wait.as_millis() as f64);

        let mut protocol = SyncProtocol::new(peer.clone(), config);

        match protocol.execute_sync(&*transport, sync_type).await {
            Ok(result) => {
                let duration = sync_start.elapsed();
                histogram!("sync.duration_ms").record(duration.as_millis() as f64);
                counter!("sync.completed").increment(1);

                match result {
                    SyncResult::CommandsProcessed(count) => {
                        if count > 0 {
                            counter!("sync.commands_received").increment(count as u64);
                            info!(
                                peer = %peer.addr,
                                graph = %peer.graph_id,
                                commands = count,
                                duration_ms = duration.as_millis(),
                                "sync completed"
                            );
                        } else {
                            debug!(
                                peer = %peer.addr,
                                graph = %peer.graph_id,
                                commands = count,
                                duration_ms = duration.as_millis(),
                                "sync complete, no new commands"
                            );
                        }
                    }
                    SyncResult::SubscriptionOk => {
                        debug!(
                            peer = %peer.addr,
                            graph = %peer.graph_id,
                            ?sync_type,
                            duration_ms = duration.as_millis(),
                            "hello operation completed"
                        );
                    }
                }
            }
            Err(err) => {
                let duration = sync_start.elapsed();
                histogram!("sync.duration_ms").record(duration.as_millis() as f64);
                counter!("sync.failed").increment(1);

                if err.is_parallel_finalize() {
                    error!(
                        peer = %peer.addr,
                        graph = %peer.graph_id,
                        error = %err.report(),
                        "parallel finalize error, invalidating graph"
                    );
                    invalid.insert(peer.graph_id);
                } else {
                    warn!(
                        peer = %peer.addr,
                        graph = %peer.graph_id,
                        ?sync_type,
                        duration_ms = duration.as_millis(),
                        error = %err.report(),
                        "sync failed"
                    );
                }
            }
        }
    }

    fn spawn_sync(&mut self, peer: SyncPeer, sync_type: SyncType) {
        let transport = Arc::clone(&self.transport);
        let config = self.config.clone();
        let peer_locks = self.peer_locks.clone();
        let invalid = self.invalid.clone();

        gauge!("sync.active_count").increment(1.0);

        self.active.spawn(Self::sync_task(
            peer, sync_type, transport, config, peer_locks, invalid,
        ));
    }
}

/*impl<T: Transport> SyncManager<T> {
    /// Sync with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: &SyncPeer) -> SyncResult<usize> {
        let mut sink = VecSink::new();

        let cmd_count = T::execute_sync(self, peer.graph_id, &mut sink, &peer.addr)
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
}*/

/// Handle for interacting with the [`SyncManager`].
#[derive(Debug, Clone)]
struct SyncHandle {
    sender: mpsc::Sender<Request>,
}

impl SyncHandle {
    /// Create a new peer manager.
    fn new(sender: mpsc::Sender<Request>) -> Self {
        Self { sender }
    }

    async fn send(&self, msg: ManagerMsg) -> Reply {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .assume("manager channel closed")?;
        rx.await.assume("no manager reply")?
    }

    /// Add peer to [`Syncer`].
    async fn add_peer(&self, peer: SyncPeer, cfg: SyncPeerConfig) -> Reply {
        self.send(ManagerMsg::AddPeer { peer, cfg }).await
    }

    /// Remove peer from [`Syncer`].
    async fn remove_peer(&self, addr: Addr, graph_id: GraphId) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(ManagerMsg::RemovePeer { peer }).await
    }

    /// Sync with a peer immediately.
    async fn sync_now(&self, addr: Addr, graph_id: GraphId, cfg: Option<SyncPeerConfig>) -> Reply {
        let peer = SyncPeer { addr, graph_id };
        self.send(ManagerMsg::SyncNow { peer, cfg }).await
    }

    /// Subscribe to hello notifications from a sync peer.
    async fn sync_hello_subscribe(
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
    async fn sync_hello_unsubscribe(&self, peer: SyncPeer) -> Reply {
        self.send(ManagerMsg::HelloUnsubscribe { peer }).await
    }

    /// Trigger sync with a peer based on hello message.
    async fn sync_on_hello(&self, peer: SyncPeer) -> Reply {
        self.send(ManagerMsg::SyncOnHello { peer }).await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    async fn broadcast_hello(&self, graph_id: GraphId, head: Address) -> Reply {
        self.send(ManagerMsg::BroadcastHello { graph_id, head })
            .await
    }

    async fn invalidate_graph(&self, graph_id: GraphId) -> Reply {
        self.send(ManagerMsg::InvalidateGraph { graph_id }).await
    }
}
