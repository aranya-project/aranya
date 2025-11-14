use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{Address, GraphId, SyncHelloType, SyncType, MAX_SYNC_MESSAGE_SIZE};
use aranya_util::ready;
use dashmap::DashMap;
use futures_util::StreamExt as _;
use tokio::{
    sync::mpsc,
    task::{JoinError, JoinSet},
};
use tokio_util::time::{delay_queue::Key, DelayQueue};

use super::SyncPeer;

#[derive(Debug, thiserror::Error)]
enum SyncError {
    #[error("This peer hasn't been registered yet")]
    PeerNotRegistered,
    #[error("There's already an active sync for this peer")]
    AlreadyActive,
    #[error("Unable to send manager a message")]
    ManagerShutdown,
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
}
type Result<T> = core::result::Result<T, SyncError>;

struct HelloConfig {
    graph_change_delay: Duration,
    duration: Duration,
    schedule_delay: Duration,
}

enum ManagerMessage {
    /// Add a peer to the sync schedule.
    AddPeer {
        peer: SyncPeer,
        config: SyncPeerConfig,
    },
    /// Remove a peer from the sync schedule.
    RemovePeer { peer: SyncPeer },
    /// Request to sync with a peer now (bypasses `DelayQueue`).
    SyncNow { peer: SyncPeer },
    /// Subscribe to sending hello notifications to this peer.
    HelloSubscribe { peer: SyncPeer, config: HelloConfig },
    /// Unsubscribe from sending hello notifications to this peer.
    HelloUnsubscribe { peer: SyncPeer },

    /// Send a hello notification to this peer.
    SendHello { peer: SyncPeer, head: Address },
    /// Received a hello notification from a peer.
    HelloReceived { peer: SyncPeer, head: Address },
    /// Our graph head changed, so notify all subscribed peers.
    GraphHeadChanged { graph_id: GraphId, head: Address },
}

enum ActiveSync {
    PullSync { started_at: Instant },
    HelloSend { started_at: Instant },
}

enum TaskResult {
    PullSync { peer: SyncPeer, result: Result<()> },
    HelloSend { peer: SyncPeer, result: Result<()> },
}

struct PeerEntry {
    config: SyncPeerConfig,
    queue_key: Key,
    buffer: Vec<u8>,
}

pub struct SyncManager<T, H> {
    active: DashMap<SyncPeer, ActiveSync>,
    tasks: JoinSet<TaskResult>,
    messages: mpsc::Receiver<ManagerMessage>,
    peers: DashMap<SyncPeer, PeerEntry>,
    queue: DelayQueue<SyncPeer>,
    hello_service: HelloService,
    transport: T,
    handler: H,
}

impl<T, H> SyncManager<T, H> {
    pub fn new<const BUFFER: usize>(transport: T, handler: H) -> (Self, Arc<SyncHandle>) {
        let (tx, messages) = mpsc::channel(BUFFER);

        let handle = Arc::new(SyncHandle { tx });
        let hello_service = HelloService::new(Arc::clone(&handle));

        let manager = Self {
            active: DashMap::new(),
            tasks: JoinSet::new(),
            messages,
            peers: DashMap::new(),
            queue: DelayQueue::new(),
            hello_service,
            transport,
            handler,
        };

        (manager, handle)
    }
}

impl<T: Transport, H: Handler> SyncManager<T, H> {
    pub async fn run(mut self, ready: ready::Notifier) {
        ready.notify();

        loop {
            tokio::select! {
                Some(result) = self.tasks.join_next() => {
                    self.handle_task_done(result).await;
                }

                Some(msg) = self.messages.recv() => {
                    self.handle_message(msg).await;
                }

                Some(expired) = self.queue.next() => {
                    let peer = expired.into_inner();

                    if !self.active.contains_key(&peer) {
                        self.start_sync(peer).await;
                    }
                }

                Some(expired) = self.hello_service.queue.next() => {
                    self.hello_service.handle_expired_subscription(expired.into_inner()).await;
                }

                // No tasks ready, sleep briefly.
                else => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_task_done(&mut self, result: core::result::Result<TaskResult, JoinError>) {
        if let Ok(result) = result {
            match result {
                TaskResult::PullSync { peer, .. } => {
                    self.active.remove(&peer);
                    if let Some(mut entry) = self.peers.get_mut(&peer) {
                        entry.queue_key = self.queue.insert(peer, entry.config.interval);
                    }
                }
                TaskResult::HelloSend { peer, .. } => {
                    self.active.remove(&peer);
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: ManagerMessage) {
        match msg {
            ManagerMessage::AddPeer { peer, config } => {
                self.add_peer(peer, config).await;
            }
            ManagerMessage::RemovePeer { peer } => {
                self.remove_peer(peer);
            }
            ManagerMessage::SyncNow { peer } => {
                self.start_sync(peer).await;
            }
            ManagerMessage::HelloSubscribe { peer, config } => {
                self.hello_service.subscribe(peer, config);
            }
            ManagerMessage::HelloUnsubscribe { peer } => {
                self.hello_service.unsubscribe(peer);
            }
            ManagerMessage::SendHello { peer, head } => {
                self.send_hello(peer, head).await;
            }
            ManagerMessage::HelloReceived { peer, head } => {
                // TODO(nikki): move this to hello_service? Just adds another layer of indirection.
                self.handle_hello_received(peer, head).await;
            }
            ManagerMessage::GraphHeadChanged { graph_id, head } => {
                self.hello_service.graph_head_changed(graph_id, head).await;
            }
        }
    }

    async fn add_peer(&mut self, peer: SyncPeer, config: SyncPeerConfig) {
        let queue_key = self.queue.insert(peer, config.interval);

        let buffer = match self.peers.remove(&peer) {
            Some((_, old)) => {
                self.queue.remove(&old.queue_key);
                old.buffer
            }
            None => {
                let mut buffer = Vec::with_capacity(MAX_SYNC_MESSAGE_SIZE);
                buffer.resize(MAX_SYNC_MESSAGE_SIZE, 0);
                buffer
            }
        };

        self.peers.insert(
            peer,
            PeerEntry {
                config: config.clone(),
                queue_key,
                buffer,
            },
        );

        if config.sync_now {
            Box::pin(self.handle_message(ManagerMessage::SyncNow { peer })).await;
        }
    }

    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, entry)) = self.peers.remove(&peer) {
            self.queue.remove(&entry.queue_key);
        }
    }

    async fn start_sync(&mut self, peer: SyncPeer) -> Result<()> {
        if self.active.contains_key(&peer) {
            return Err(SyncError::AlreadyActive);
        }

        // TODO(nikki): limit max concurrent syncs?

        let buffer = self
            .peers
            .get(&peer)
            .map(|entry| entry.buffer.clone())
            .ok_or(SyncError::PeerNotRegistered)?;

        self.active.insert(
            peer,
            ActiveSync::PullSync {
                started_at: Instant::now(),
            },
        );

        let transport = self.transport.clone();
        let handler = self.handler.clone();
        self.tasks.spawn(async move {
            let result = Self::sync_task(peer, transport, handler, buffer).await;
            TaskResult::PullSync { peer, result }
        });

        Ok(())
    }

    async fn sync_task(peer: SyncPeer, mut t: T, mut h: H, mut buf: Vec<u8>) -> Result<()> {
        t.run_sync(&mut buf, peer).await?;
        h.handle_sync(&mut buf, peer).await?;
        Ok(())
    }

    async fn send_hello(&mut self, peer: SyncPeer, head: Address) -> Result<()> {
        if self.active.contains_key(&peer) {
            return Err(SyncError::AlreadyActive);
        }

        // TODO(nikki): distinguish between push, pull, and hello?
        self.active.insert(
            peer,
            ActiveSync::HelloSend {
                started_at: Instant::now(),
            },
        );

        let msg = SyncType::Hello(SyncHelloType::Hello {
            head,
            address: peer.addr,
        });

        let mut transport = self.transport.clone();
        let data = postcard::to_allocvec(&msg)?;
        self.tasks.spawn(async move {
            let result = transport.send_message(&data, peer).await;
            TaskResult::HelloSend { peer, result }
        });

        Ok(())
    }

    async fn handle_hello_received(&mut self, peer: SyncPeer, _head: Address) {
        // TODO(nikki): do stuff with the new head.
        let sync_on_hello = {
            if let Some(entry) = self.peers.get(&peer) {
                entry.config.sync_on_hello
            } else {
                false
            }
        };

        if sync_on_hello {
            self.start_sync(peer).await;
        }
    }
}

pub struct SyncHandle {
    tx: mpsc::Sender<ManagerMessage>,
}

impl SyncHandle {
    pub async fn add_peer(&self, peer: SyncPeer, config: SyncPeerConfig) -> Result<()> {
        self.tx
            .send(ManagerMessage::AddPeer { peer, config })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    pub async fn remove_peer(&self, peer: SyncPeer) -> Result<()> {
        self.tx
            .send(ManagerMessage::RemovePeer { peer })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    pub async fn sync_now(&self, peer: SyncPeer) -> Result<()> {
        self.tx
            .send(ManagerMessage::SyncNow { peer })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    pub async fn hello_subscribe(&self, peer: SyncPeer, config: HelloConfig) -> Result<()> {
        self.tx
            .send(ManagerMessage::HelloSubscribe { peer, config })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    pub async fn hello_unsubscribe(&self, peer: SyncPeer) -> Result<()> {
        self.tx
            .send(ManagerMessage::HelloUnsubscribe { peer })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn send_hello(&self, peer: SyncPeer, head: Address) -> Result<()> {
        self.tx
            .send(ManagerMessage::SendHello { peer, head })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn hello_received(&self, peer: SyncPeer, head: Address) -> Result<()> {
        self.tx
            .send(ManagerMessage::HelloReceived { peer, head })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn graph_head_changed(&self, graph_id: GraphId, head: Address) -> Result<()> {
        self.tx
            .send(ManagerMessage::GraphHeadChanged { graph_id, head })
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }
}

#[async_trait::async_trait]
trait Transport: Send + Clone + 'static {
    /// Sync with a peer.
    async fn run_sync(&mut self, buffer: &mut Vec<u8>, peer: SyncPeer) -> Result<()>;

    /// Send a one-way message to a peer.
    async fn send_message(&mut self, data: &[u8], peer: SyncPeer) -> Result<()>;
}

#[async_trait::async_trait]
trait Handler: Send + Clone + 'static {
    async fn handle_sync(&mut self, buffer: &mut Vec<u8>, peer: SyncPeer) -> Result<()>;
}

struct HelloSubscription {
    config: HelloConfig,
    queue_key: Key,
    last_sent: Option<Instant>,
    current_head: Option<Address>,
}

struct HelloService {
    subscriptions: DashMap<SyncPeer, HelloSubscription>,
    queue: DelayQueue<SyncPeer>,
    handle: Arc<SyncHandle>,
}

impl HelloService {
    fn new(handle: Arc<SyncHandle>) -> Self {
        Self {
            subscriptions: DashMap::new(),
            queue: DelayQueue::new(),
            handle,
        }
    }

    fn subscribe(&mut self, peer: SyncPeer, config: HelloConfig) {
        let queue_key = self.queue.insert(peer, config.schedule_delay);
        let state = HelloSubscription {
            config,
            queue_key,
            last_sent: None,
            current_head: None,
        };
        if let Some(state) = self.subscriptions.insert(peer, state) {
            self.queue.remove(&state.queue_key);
        }
    }

    fn unsubscribe(&mut self, peer: SyncPeer) {
        if let Some((_, sub)) = self.subscriptions.remove(&peer) {
            self.queue.remove(&sub.queue_key);
        }
    }

    async fn handle_expired_subscription(&mut self, peer: SyncPeer) {
        if let Some(mut entry) = self.subscriptions.get_mut(&peer) {
            if let Some(head) = entry.current_head {
                entry.last_sent = Some(Instant::now());
                self.handle.send_hello(peer, head).await;
                entry.queue_key = self.queue.insert(peer, entry.config.schedule_delay);
            }
        }
    }

    async fn graph_head_changed(&mut self, graph_id: GraphId, head: Address) {
        for mut entry in self.subscriptions.iter_mut() {
            let peer = *entry.key();

            if peer.graph_id != graph_id {
                continue;
            }

            let state = entry.value_mut();
            state.current_head = Some(head);

            let should_send = match state.last_sent {
                Some(last) => last.elapsed() >= state.config.graph_change_delay,
                None => true,
            };

            if should_send {
                self.handle.send_hello(peer, head).await;
                state.last_sent = Some(Instant::now());
                self.queue.remove(&state.queue_key);
                state.queue_key = self.queue.insert(peer, state.config.graph_change_delay);
            }
        }
    }
}

/*
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
use tokio_util::{
    sync::CancellationToken,
    time::delay_queue::{DelayQueue, Key},
};
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

struct ActiveSync {
    started_at: Instant,
    config: SyncPeerConfig,
    cancel: CancellationToken,
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
*/
