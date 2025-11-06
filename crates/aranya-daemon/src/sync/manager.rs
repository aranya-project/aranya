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

/// Messages sent using a [`SyncHandle`] to the [`SyncManager`].
#[derive(Debug, Clone)]
pub(crate) enum ManagerMsg {
    /// Sync with a peer immediately.
    SyncNow {
        peer: SyncPeer,
        config: Option<SyncPeerConfig>,
    },
    /// Add a peer to the sync schedule.
    AddPeer {
        peer: SyncPeer,
        config: SyncPeerConfig,
    },
    /// Remove a peer from the sync schedule.
    RemovePeer { peer: SyncPeer },
    /// Subscribe to hello notifications from a peer.
    Subscribe {
        peer: SyncPeer,
        delay: Duration,
        duration: Duration,
    },
    /// Unsubscribe from hello notifications from a peer.
    Unsubscribe { peer: SyncPeer },
    /// Send a hello notification to a peer.
    SendNotification { peer: SyncPeer, head: Address },
    /// Trigger a sync after receiving a hello notification.
    TriggerSync { peer: SyncPeer },
    /// Notify all subscribers of a graph about a head change.
    NotifySubscribers { graph_id: GraphId, head: Address },
    /// Mark a graph as invalid due to finalization errors.
    InvalidateGraph { graph_id: GraphId },
}
type ManagerRequest = (ManagerMsg, oneshot::Sender<ManagerReply>);
type ManagerReply = Result<()>;

#[derive(Debug)]
struct PendingSync {
    peer: SyncPeer,
    sync_type: SyncType,
    queued_at: Instant,
}

/// Manages sync operations with peers.
#[derive(Debug)]
pub struct SyncManager<T> {
    transport: Arc<T>,
    config: ProtocolConfig,
    protocols: Arc<ProtocolStore>,

    peers: HashMap<SyncPeer, (SyncPeerConfig, Key)>,
    queue: DelayQueue<SyncPeer>,
    peer_locks: PeerLocks,

    pending: VecDeque<PendingSync>,
    active: JoinSet<()>,
    max_concurrent: usize,

    invalid: InvalidGraphs,

    recv: mpsc::Receiver<ManagerRequest>,
}

impl<T> SyncManager<T> {
    pub fn new(
        transport: Arc<T>,
        config: ProtocolConfig,
        invalid: InvalidGraphs,
        max_concurrent: usize,
    ) -> (Self, SyncHandle) {
        let (send, recv) = mpsc::channel::<ManagerRequest>(128);
        let protocols = Arc::new(ProtocolStore::new(config.clone()));
        let handle = SyncHandle::new(send, Arc::clone(&protocols));

        let manager = Self {
            transport,
            config,
            protocols,

            peers: HashMap::new(),
            queue: DelayQueue::new(),
            peer_locks: PeerLocks::new(),

            pending: VecDeque::new(),
            active: JoinSet::new(),
            max_concurrent,

            invalid,

            recv,
        };

        (manager, handle)
    }

    pub fn update_server_addr<A: Into<Addr>>(&mut self, actual_addr: A) {
        self.config.server_addr = actual_addr.into();
    }

    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        let interval = cfg.interval;
        let new_key = self.queue.insert(peer, interval);
        if let Some((_, old_key)) = self.peers.insert(peer, (cfg, new_key)) {
            self.queue.remove(&old_key);
        }
        debug!(peer = %peer.addr, graph = %peer.graph_id, ?interval, "added peer");
    }

    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, key)) = self.peers.remove(&peer) {
            self.queue.remove(&key);
        }
        self.protocols.remove(&peer);
        debug!(peer = %peer.addr, graph = %peer.graph_id, "removed peer");
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

    async fn handle_message(&mut self, msg: ManagerMsg) -> ManagerReply {
        match msg {
            ManagerMsg::SyncNow { peer, .. } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::Poll,
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::AddPeer { peer, config: cfg } => {
                if cfg.sync_now {
                    self.pending.push_back(PendingSync {
                        peer,
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
            ManagerMsg::Subscribe {
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
            ManagerMsg::Unsubscribe { peer } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::HelloUnsubscribe,
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::SendNotification { peer, head } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::HelloNotification { head },
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::TriggerSync { peer } => {
                self.pending.push_back(PendingSync {
                    peer,
                    sync_type: SyncType::Poll,
                    queued_at: Instant::now(),
                });
                self.spawn_pending();
            }
            ManagerMsg::NotifySubscribers { graph_id, head } => {
                trace!(?graph_id, ?head, "notify subscribers message received");
            }
            ManagerMsg::InvalidateGraph { graph_id } => {
                self.invalid.insert(graph_id);
                debug!(?graph_id, "invalidated graph");
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

            if self.invalid.contains(pending.peer.graph_id) {
                warn!(peer = %pending.peer.addr, graph = %pending.peer.graph_id, "skipping sync for invalid graph");
                counter!("sync.skipped_invalid_graph").increment(1);
                continue;
            }

            if wait_time.as_secs() > 10 {
                warn!(
                    peer = %pending.peer.addr,
                    graph = %pending.peer.graph_id,
                    wait_secs = wait_time.as_secs(),
                    "sync waited in queue too long"
                );
            }

            gauge!("sync.active_count").increment(1.0);

            self.active.spawn(Self::sync_task(
                pending.peer,
                pending.sync_type,
                Arc::clone(&self.transport),
                self.protocols.get(&pending.peer),
                self.peer_locks.clone(),
                self.invalid.clone(),
            ));
        }
    }

    async fn sync_task(
        peer: SyncPeer,
        sync_type: SyncType,
        transport: Arc<T>,
        protocol: Arc<Mutex<SyncProtocol>>,
        peer_locks: PeerLocks,
        invalid: InvalidGraphs,
    ) {
        let sync_start = Instant::now();

        let peer_lock_start = Instant::now();
        let peer_lock = peer_locks.get(&peer).await;
        let _guard = peer_lock.lock().await;
        let peer_lock_wait = peer_lock_start.elapsed();
        histogram!("sync.peer_lock_wait_ms").record(peer_lock_wait.as_millis() as f64);

        let mut protocol = protocol.lock().await;

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
}

/// Handle for interacting with the [`SyncManager`].
#[derive(Debug, Clone)]
pub(crate) struct SyncHandle {
    sender: mpsc::Sender<ManagerRequest>,
    protocols: Arc<ProtocolStore>,
}

impl SyncHandle {
    /// Create a new sync handle to send requests.
    fn new(sender: mpsc::Sender<ManagerRequest>, protocols: Arc<ProtocolStore>) -> Self {
        Self { sender, protocols }
    }

    fn protocols(&self) -> &Arc<ProtocolStore> {
        &self.protocols
    }

    /// Send a [`ManagerMsg`] request.
    async fn send(&self, msg: ManagerMsg) -> ManagerReply {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send((msg, tx))
            .await
            .assume("manager channel closed")?;
        rx.await.assume("no manager reply")?
    }

    /// Sync with a peer immediately.
    async fn sync_now(&self, peer: SyncPeer, config: Option<SyncPeerConfig>) -> ManagerReply {
        self.send(ManagerMsg::SyncNow { peer, config }).await
    }

    /// Add a new peer to the sync schedule.
    async fn add_peer(&self, peer: SyncPeer, config: SyncPeerConfig) -> ManagerReply {
        self.send(ManagerMsg::AddPeer { peer, config }).await
    }

    /// Remove a peer from the sync schedule.
    async fn remove_peer(&self, peer: SyncPeer) -> ManagerReply {
        self.send(ManagerMsg::RemovePeer { peer }).await
    }

    /// Subscribe to hello notifications from a peer.
    async fn subscribe(&self, peer: SyncPeer, delay: Duration, duration: Duration) -> ManagerReply {
        self.send(ManagerMsg::Subscribe {
            peer,
            delay,
            duration,
        })
        .await
    }

    /// Unsubscribe from hello notifications from a peer.
    async fn unsubscribe(&self, peer: SyncPeer) -> ManagerReply {
        self.send(ManagerMsg::Unsubscribe { peer }).await
    }

    /// Send a hello notification to a peer.
    pub(super) async fn send_notification(&self, peer: SyncPeer, head: Address) -> ManagerReply {
        self.send(ManagerMsg::SendNotification { peer, head }).await
    }

    /// Trigger sync after receiving a hello notification.
    pub(super) async fn trigger_sync(&self, peer: SyncPeer) -> ManagerReply {
        self.send(ManagerMsg::TriggerSync { peer }).await
    }

    /// Notify all subscribers of a graph about a head change.
    async fn notify_subscribers(&self, graph_id: GraphId, head: Address) -> ManagerReply {
        self.send(ManagerMsg::NotifySubscribers { graph_id, head })
            .await
    }

    /// Mark a graph as invalid due to finalization errors.
    async fn invalidate_graph(&self, graph_id: GraphId) -> ManagerReply {
        self.send(ManagerMsg::InvalidateGraph { graph_id }).await
    }
}
