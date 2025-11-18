use core::error;
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
    task::{self, AbortHandle, JoinError, JoinSet},
};
use tokio_util::time::{delay_queue::Key, DelayQueue};
use tracing::error;

use super::SyncPeer;

#[derive(Debug, thiserror::Error)]
enum SyncError {
    #[error("This peer hasn't been registered yet")]
    PeerNotRegistered,
    #[error("There's already an active sync for this peer")]
    AlreadyActive,
    #[error("Unable to send manager a message")]
    ManagerShutdown,
    #[error("The buffer for this peer is already being used")]
    BufferInUse,
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
}
type Result<T> = core::result::Result<T, SyncError>;

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
    /// A [`HelloService`]-specific message.
    Hello(HelloMessage),
}

enum HelloMessage {
    /// Subscribe to hello notifications from this peer.
    Subscribe { peer: SyncPeer, config: HelloConfig },
    /// Unsubscribe from hello notifications from this peer.
    Unsubscribe { peer: SyncPeer },

    /// A peer wants to subscribe to hello notifications.
    PeerSubscribed { peer: SyncPeer, config: HelloConfig },
    /// A peer wants to unsubscribe from hello notifiactions.
    PeerUnsubscribed { peer: SyncPeer },

    /// Send a hello notification to this peer.
    SendNotification { peer: SyncPeer, head: Address },
    /// Received a hello notification from a peer.
    HelloReceived { peer: SyncPeer, head: Address },
    /// Our graph head changed, so notify all subscribed peers.
    GraphHeadChanged { graph_id: GraphId, head: Address },
}

// TODO(nikki): not happy having to keep 3 enums synced (ActiveSync, TaskResult, ProtocolMessage).
enum ActiveSync {
    /// Sync message that requires a response.
    Message {
        started_at: Instant,
        handle: AbortHandle,
    },
    /// Single request that expects an ack.
    Request {
        started_at: Instant,
        handle: AbortHandle,
    },
}

impl ActiveSync {
    fn abort_handle(&self) -> &AbortHandle {
        match self {
            Self::Message { handle, .. } => handle,
            Self::Request { handle, .. } => handle,
        }
    }

    fn task_id(&self) -> task::Id {
        match self {
            Self::Message { handle, .. } => handle.id(),
            Self::Request { handle, .. } => handle.id(),
        }
    }
}

enum MessageType {
    PollSync,
}

enum TaskResult {
    /// Sync message that requires a response.
    Message {
        peer: SyncPeer,
        result: Result<()>,
        buffer: Vec<u8>,
        msg_type: MessageType,
    },
    /// Single request that expects an ack.
    Request {
        peer: SyncPeer,
        result: Result<()>,
        buffer: Vec<u8>,
    },
}

struct PeerEntry {
    config: SyncPeerConfig,
    queue_key: Key,
    // Option<T> so that it can be taken when running a sync task and reused.
    buffer: Option<Vec<u8>>,
}

/// Orchestrates sync tasks for all registered peers.
///
/// There are two kinds of syncs supported:
/// - a `message` task that requires both a request and a response.
/// - a `request` task that only sends a request, response is an ack.
pub struct SyncManager<T, H> {
    /// Keeps track of all active sync tasks and their associated peer.
    active: DashMap<SyncPeer, ActiveSync>,
    /// Holds all in-progress sync tasks for later cleanup.
    tasks: JoinSet<TaskResult>,
    /// Accept messages from a [`SyncHandle`] for various events.
    messages: mpsc::Receiver<ManagerMessage>,
    /// Keeps track of registered peers' configuration info.
    peers: DashMap<SyncPeer, PeerEntry>,
    /// Maintains a rolling sync queue with all registered peers.
    queue: DelayQueue<SyncPeer>,
    /// Handles all "hello sync" task management.
    hello_service: HelloService,
    /// The [`SyncProtocol`] serialization for this SyncManager.
    protocol: SyncProtocol,
    /// The [`Transport`] client for this SyncManager.
    transport: T,
    /// The [`Handler`] server for this SyncManager.
    handler: H,
}

impl<T, H> SyncManager<T, H> {
    /// Creates a new [`SyncManager`] with a given [`Transport`], [`Handler`], and message buffer size.
    pub fn new<const BUFFER: usize>(transport: T, handler: H) -> (Self, Arc<SyncHandle>) {
        let (tx, messages) = mpsc::channel(BUFFER);

        let handle = Arc::new(SyncHandle { tx });
        let hello_service = HelloService::new(Arc::clone(&handle));
        let protocol = SyncProtocol;

        let manager = Self {
            active: DashMap::new(),
            tasks: JoinSet::new(),
            messages,
            peers: DashMap::new(),
            queue: DelayQueue::new(),
            hello_service,
            protocol,
            transport,
            handler,
        };

        (manager, handle)
    }
}

impl<T: Transport, H: Handler> SyncManager<T, H> {
    /// The main loop used to drive a [`SyncManager`] and its various sub-tasks.
    pub async fn run(mut self, ready: ready::Notifier) {
        ready.notify();

        loop {
            tokio::select! {
                // We have a completed sync task, clean it up.
                Some(result) = self.tasks.join_next() => {
                    self.handle_task_done(result).await;
                }

                // We got a new message, handle its request.
                Some(msg) = self.messages.recv() => {
                    self.handle_message(msg).await;
                }

                // Ready to sync with a new peer, spawn its task.
                Some(expired) = self.queue.next() => {
                    let peer = expired.into_inner();

                    if !self.active.contains_key(&peer) {
                        let message = ProtocolMessage::SyncRequest { peer };
                        let _ = self.send_message(peer, message).await;
                    }
                }

                // Ready to notify a subscribed peer, spawn its task.
                Some(expired) = self.hello_service.queue.next() => {
                    self.hello_service.send_scheduled_hello(expired.into_inner()).await;
                }

                // No tasks ready, sleep briefly.
                else => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Handles any cleanup needed by finished sync tasks.
    async fn handle_task_done(&mut self, result: core::result::Result<TaskResult, JoinError>) {
        match result {
            Ok(TaskResult::Message {
                peer,
                result,
                buffer,
                msg_type,
            }) => {
                // Remove the finished task from the active list.
                self.active.remove(&peer);

                // Store the leftover buffer we need to own.
                if let Some(mut entry) = self.peers.get_mut(&peer) {
                    entry.buffer = Some(buffer);
                }

                // Handle any message-specific side effects.
                match msg_type {
                    // TODO(nikki): push sync
                    MessageType::PollSync => {
                        if let Some(mut entry) = self.peers.get_mut(&peer) {
                            entry.queue_key = self.queue.insert(peer, entry.config.interval);
                        }
                    }
                }

                // If the message failed, log the error.
                if let Err(error) = result {
                    error!("message failed for peer {peer:?}: {error:?}");
                }
            }
            Ok(TaskResult::Request {
                peer,
                result,
                buffer,
            }) => {
                // Remove the finished task from the active list.
                self.active.remove(&peer);

                // Store the leftover buffer we need to own.
                if let Some(mut entry) = self.peers.get_mut(&peer) {
                    entry.buffer = Some(buffer);
                }

                // If the request failed, log the error.
                if let Err(error) = result {
                    error!("request failed for peer {peer:?}: {error:?}");
                }
            }
            Err(error) => {
                // Look up which active task panicked (if it's registered).
                let panicked_peer = self.active.iter().find_map(|entry| {
                    if entry.value().task_id() == error.id() {
                        Some(*entry.key())
                    } else {
                        None
                    }
                });

                if let Some(peer) = panicked_peer {
                    error!("sync task for peer {peer:?} panicked: {error:?}");

                    // Remove the panicked peer from our active syncs.
                    self.active.remove(&peer);

                    // If the task failed and we "lost" the buffer, we need to allocate a new one.
                    if let Some(mut entry) = self.peers.get_mut(&peer) {
                        if entry.buffer.is_none() {
                            let mut buffer = Vec::with_capacity(MAX_SYNC_MESSAGE_SIZE);
                            buffer.resize(MAX_SYNC_MESSAGE_SIZE, 0);
                            entry.buffer = Some(buffer);
                        }
                    }
                } else {
                    error!("sync task for unknown peer panicked: {error:?}");
                }
            }
        }
    }

    /// Handles the side effects of a received [`ManagerMessage`].
    async fn handle_message(&mut self, msg: ManagerMessage) {
        match msg {
            ManagerMessage::AddPeer { peer, config } => {
                self.add_peer(peer, config).await;
            }
            ManagerMessage::RemovePeer { peer } => {
                self.remove_peer(peer);
            }
            ManagerMessage::SyncNow { peer } => {
                let message = ProtocolMessage::SyncRequest { peer };
                let _ = self.send_message(peer, message).await;
            }
            ManagerMessage::Hello(hello_msg) => {
                // TODO(nikki): resolve borrowing issues later.
                self.hello_service
                    .handle_message(hello_msg, &mut self.protocol, self)
                    .await;
            }
        }
    }

    /// Handle a request to add a new peer to the schedule.
    async fn add_peer(&mut self, peer: SyncPeer, config: SyncPeerConfig) {
        // Schedule the next peer sync.
        let queue_key = self.queue.insert(peer, config.interval);

        // Check if this peer already has an allocated buffer, or create one.
        let buffer = match self.peers.remove(&peer) {
            Some((_, old)) => {
                self.queue.remove(&old.queue_key);
                old.buffer
            }
            None => {
                let mut buffer = Vec::with_capacity(MAX_SYNC_MESSAGE_SIZE);
                buffer.resize(MAX_SYNC_MESSAGE_SIZE, 0);
                Some(buffer)
            }
        };

        // Register the peer's information.
        self.peers.insert(
            peer,
            PeerEntry {
                config: config.clone(),
                queue_key,
                buffer,
            },
        );

        // If we need to sync now, do that directly.
        if config.sync_now {
            Box::pin(self.handle_message(ManagerMessage::SyncNow { peer })).await;
        }
    }

    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, entry)) = self.peers.remove(&peer) {
            self.queue.remove(&entry.queue_key);
        }
    }

    async fn send_message(&mut self, peer: SyncPeer, message: ProtocolMessage) -> Result<()> {
        if self.active.contains_key(&peer) {
            return Err(SyncError::AlreadyActive);
        }

        // TODO(nikki): limit max concurrent syncs?

        let msg_type = match &message {
            ProtocolMessage::SyncRequest { .. } => MessageType::PollSync,
            _ => unreachable!(),
        };

        let mut buffer = {
            let mut entry = self
                .peers
                .get_mut(&peer)
                .ok_or(SyncError::PeerNotRegistered)?;

            entry.buffer.take().ok_or(SyncError::BufferInUse)?
        };

        self.protocol.create_message(message, &mut buffer)?;

        let mut transport = self.transport.clone();
        let mut handler = self.handler.clone();
        let handle = self.tasks.spawn(async move {
            let result = async {
                transport.run_sync(&mut buffer, peer).await?;
                handler.handle_sync(&mut buffer, peer).await?;
                Ok(())
            }
            .await;
            TaskResult::Message {
                peer,
                result,
                buffer,
                msg_type,
            }
        });

        self.active.insert(
            peer,
            ActiveSync::Message {
                started_at: Instant::now(),
                handle,
            },
        );

        Ok(())
    }

    async fn send_request(&mut self, peer: SyncPeer, message: ProtocolMessage) -> Result<()> {
        if self.active.contains_key(&peer) {
            return Err(SyncError::AlreadyActive);
        }

        // TODO(nikki): limit max concurrent syncs?

        let mut buffer = {
            let mut entry = self
                .peers
                .get_mut(&peer)
                .ok_or(SyncError::PeerNotRegistered)?;

            entry.buffer.take().ok_or(SyncError::BufferInUse)?
        };

        self.protocol.create_message(message, &mut buffer)?;

        let mut transport = self.transport.clone();
        let handle = self.tasks.spawn(async move {
            let result = transport.run_sync(&mut buffer, peer).await;
            TaskResult::Request {
                peer,
                result,
                buffer,
            }
        });

        self.active.insert(
            peer,
            ActiveSync::Request {
                started_at: Instant::now(),
                handle,
            },
        );

        Ok(())
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
            .send(ManagerMessage::Hello(HelloMessage::Subscribe {
                peer,
                config,
            }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    pub async fn hello_unsubscribe(&self, peer: SyncPeer) -> Result<()> {
        self.tx
            .send(ManagerMessage::Hello(HelloMessage::Unsubscribe { peer }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn graph_head_changed(&self, graph_id: GraphId, head: Address) -> Result<()> {
        self.tx
            .send(ManagerMessage::Hello(HelloMessage::GraphHeadChanged {
                graph_id,
                head,
            }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn send_hello(&self, peer: SyncPeer, head: Address) -> Result<()> {
        self.tx
            .send(ManagerMessage::Hello(HelloMessage::SendNotification {
                peer,
                head,
            }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn hello_received(&self, peer: SyncPeer, head: Address) -> Result<()> {
        self.tx
            .send(ManagerMessage::Hello(HelloMessage::HelloReceived {
                peer,
                head,
            }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn hello_peer_subscribed(&self, peer: SyncPeer, config: HelloConfig) -> Result<()> {
        self.tx
            .send(ManagerMessage::Hello(HelloMessage::PeerSubscribed {
                peer,
                config,
            }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }

    async fn hello_peer_unsubscribed(&self, peer: SyncPeer) -> Result<()> {
        self.tx
            .send(ManagerMessage::Hello(HelloMessage::PeerUnsubscribed {
                peer,
            }))
            .await
            .map_err(|_| SyncError::ManagerShutdown)
    }
}

enum ProtocolMessage {
    SyncRequest { peer: SyncPeer },
    Subscribe { peer: SyncPeer, config: HelloConfig },
    Unsubscribe { peer: SyncPeer },
    HelloNotification { peer: SyncPeer, head: Address },
}

struct SyncProtocol;

impl SyncProtocol {
    fn create_message(&self, message: ProtocolMessage, buffer: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    // TODO(nikki): parse_message()
}

// TODO(nikki): just combine these two?
#[async_trait::async_trait]
trait Transport: Send + Clone + 'static {
    async fn run_sync(&mut self, buffer: &mut Vec<u8>, peer: SyncPeer) -> Result<()>;
}

#[async_trait::async_trait]
trait Handler: Send + Clone + 'static {
    async fn handle_sync(&mut self, buffer: &mut Vec<u8>, peer: SyncPeer) -> Result<()>;
}

struct HelloConfig {
    graph_change_delay: Duration,
    duration: Duration,
    schedule_delay: Duration,
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

    async fn handle_message<T: Transport, H: Handler>(
        &mut self,
        msg: HelloMessage,
        protocol: &mut SyncProtocol,
        manager: &mut SyncManager<T, H>,
    ) {
        match msg {
            HelloMessage::Subscribe { peer, config } => {
                let message = ProtocolMessage::Subscribe { peer, config };
                let _ = manager.send_request(peer, message).await;
            }
            HelloMessage::Unsubscribe { peer } => {
                let message = ProtocolMessage::Unsubscribe { peer };
                let _ = manager.send_request(peer, message).await;
            }

            HelloMessage::PeerSubscribed { peer, config } => {
                self.subscribe(peer, config);
            }

            HelloMessage::PeerUnsubscribed { peer } => {
                self.unsubscribe(peer);
            }

            HelloMessage::HelloReceived { peer, head } => {
                self.handle_hello_received(peer, head, manager).await;
            }

            HelloMessage::SendNotification { peer, head } => {
                let message = ProtocolMessage::HelloNotification { peer, head };
                let _ = manager.send_request(peer, message).await;
            }

            HelloMessage::GraphHeadChanged { graph_id, head } => {
                self.graph_head_changed(graph_id, head).await;
            }
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

    async fn send_scheduled_hello(&mut self, peer: SyncPeer) {
        if let Some(mut entry) = self.subscriptions.get_mut(&peer) {
            if let Some(head) = entry.current_head {
                entry.last_sent = Some(Instant::now());
                let _ = self.handle.send_hello(peer, head).await;
                entry.queue_key = self.queue.insert(peer, entry.config.schedule_delay);
            }
        }
    }

    async fn handle_hello_received<T: Transport, H: Handler>(
        &mut self,
        peer: SyncPeer,
        _head: Address,
        manager: &mut SyncManager<T, H>,
    ) {
        let sync_on_hello = {
            if let Some(entry) = manager.peers.get(&peer) {
                entry.config.sync_on_hello
            } else {
                false
            }
        };

        if sync_on_hello {
            let message = ProtocolMessage::SyncRequest { peer };
            let _ = manager.send_message(peer, message).await;
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
