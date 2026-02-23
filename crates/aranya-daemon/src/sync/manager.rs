//! This module contains the [`SyncManager`] that drives the majority of the syncer, including all
//! client-side tasks.
//!
//! # Architecture
//! The manager operates by continually syncing with peers, as well as additional requests sent by
//! the [`SyncHandle`]. This includes both "poll sync" tasks, that simply sync on an interval, as
//! well as "hello sync" tasks, which allows a peer to broadcast its current graph head to all
//! subscribed peers, as well as syncing with a peer upon being notified of their graph head
//! changing.

use std::collections::HashMap;
#[cfg(feature = "preview")]
use std::time::Duration;

use anyhow::Context as _;
use aranya_crypto::Rng;
use aranya_daemon_api::SyncPeerConfig;
#[cfg(feature = "preview")]
use aranya_runtime::{Address, Storage as _, SyncHelloType, SyncType};
use aranya_runtime::{
    Command as _, PolicyStore, Sink, StorageProvider, SyncRequester, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready};
use buggy::BugExt as _;
use derive_where::derive_where;
use futures_util::StreamExt as _;
use tokio::{sync::mpsc, time::Instant};
use tokio_util::time::{delay_queue, DelayQueue};
#[cfg(feature = "preview")]
use tracing::{debug, trace};
use tracing::{error, info, instrument, warn};

use super::{
    handle::{Callback, ManagerMessage},
    GraphId, Result, SyncPeer,
};
#[cfg(feature = "preview")]
use crate::sync::HelloSubscription;
use crate::{
    aranya::Client,
    sync::{
        transport::{SyncStream as _, SyncTransport},
        Error, SyncResponse,
    },
    vm_policy::VecSink,
};

#[derive(Debug)]
pub(super) enum ScheduledTask {
    Sync(SyncPeer),
    #[cfg(feature = "preview")]
    HelloNotify(SyncPeer),
}

/// Manages sync scheduling and sending/receiving data on a transport.
///
/// Uses a [`DelayQueue`] to handle scheduling sync tasks, and uses [`SyncHandle`] to receive
/// requests from the server and any clients.
#[derive_where(Debug; ST)]
pub(crate) struct SyncManager<ST, PS, SP, EF> {
    /// The Aranya client and peer cache, alongside invalid graph tracking.
    pub(super) client: Client<PS, SP>,
    /// The transport used to send and receive sync data.
    pub(super) transport: ST,

    /// Receives requests from the [`SyncHandle`].
    pub(super) recv: mpsc::Receiver<Callback>,
    /// Used to send effects to the API to be processed.
    pub(super) send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,

    /// Sync peer lookup info, used for storing configuration and delay queue info.
    pub(super) peers: HashMap<SyncPeer, (SyncPeerConfig, Option<delay_queue::Key>)>,
    /// Handles waiting on future sync tasks.
    pub(super) queue: DelayQueue<ScheduledTask>,

    /// Holds all active hello subscriptions.
    #[cfg(feature = "preview")]
    pub(super) hello_subscriptions: HashMap<SyncPeer, HelloSubscription>,
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF> {
    /// Creates a new [`SyncManager`].
    pub(crate) fn new(
        client: Client<PS, SP>,
        transport: ST,
        recv: mpsc::Receiver<Callback>,
        send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
    ) -> Result<Self> {
        Ok(Self {
            client,
            transport,
            recv,
            send_effects,
            peers: HashMap::new(),
            queue: DelayQueue::new(),
            #[cfg(feature = "preview")]
            hello_subscriptions: HashMap::new(),
        })
    }

    /// Registers a new peer with the manager, optionally adding it to the sync schedule.
    fn add_peer(&mut self, peer: SyncPeer, cfg: SyncPeerConfig) {
        // Only insert into delay queue if interval is configured or `sync_now == true`
        let new_key = match cfg.interval {
            _ if cfg.sync_now => Some(
                self.queue
                    .insert_at(ScheduledTask::Sync(peer), Instant::now()),
            ),
            Some(interval) => Some(self.queue.insert(ScheduledTask::Sync(peer), interval)),
            None => None,
        };
        if let Some((_, Some(key))) = self.peers.insert(peer, (cfg, new_key)) {
            self.queue.remove(&key);
        }
    }

    /// Unregisters a peer with the manager.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, Some(key))) = self.peers.remove(&peer) {
            self.queue.remove(&key);
        }
    }

    /// Registers a new hello subscription and adds it to the sync schedule.
    #[cfg(feature = "preview")]
    fn add_hello_subscription(
        &mut self,
        peer: SyncPeer,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) {
        // Check if there was an existing subscription for this peer and remove it.
        if let Some(sub) = self.hello_subscriptions.remove(&peer) {
            self.queue.remove(&sub.queue_key);
        }

        // Schedule a hello sync immediately after we register a subscription.
        let queue_key = self
            .queue
            .insert_at(ScheduledTask::Sync(peer), Instant::now());
        let subscription = HelloSubscription {
            graph_change_debounce,
            schedule_delay,
            last_notified: Instant::now() - graph_change_debounce,
            expires_at: Instant::now() + duration,
            queue_key,
        };

        debug!(?peer, ?subscription, "created hello subscription");
        self.hello_subscriptions.insert(peer, subscription);
    }

    /// Unregisters a hello subscription with the manager.
    #[cfg(feature = "preview")]
    fn remove_hello_subscription(&mut self, peer: SyncPeer) {
        if let Some(old) = self.hello_subscriptions.remove(&peer) {
            self.queue.remove(&old.queue_key);
        }
        debug!(?peer, "removed hello subscription");
    }

    /// Handles checking for parallel finalization errors, as they're considered a fatal error.
    fn handle_sync_error(&mut self, peer: SyncPeer, err: &Error) {
        if err.is_parallel_finalize() {
            warn!(?peer, "parallel finalize error, removing all peers");

            // Unregister all sync peers for the graph, and remove them from the `DelayQueue`.
            self.peers.retain(|p, (_, key)| {
                let keep = p.graph_id != peer.graph_id;
                if !keep {
                    if let Some(k) = key {
                        self.queue.remove(k);
                    }
                }
                keep
            });

            // Unregister all hello subscriptions for the graph, and remove them from the `DelayQueue`.
            #[cfg(feature = "preview")]
            self.hello_subscriptions.retain(|p, sub| {
                let keep = p.graph_id != peer.graph_id;
                if !keep {
                    self.queue.remove(&sub.queue_key);
                }
                keep
            });

            // Tell the client that we encountered an invalid graph.
            self.client.invalid_graphs().insert(peer.graph_id);
        }
    }

    /// Returns the peer cache map for tests that need it.
    #[cfg(test)]
    pub(crate) fn get_peer_caches(&self) -> crate::aranya::PeerCacheMap {
        self.client.caches_for_test()
    }

    /// Returns a reference to the Aranya client for tests that need it.
    #[cfg(test)]
    pub(crate) const fn client(&self) -> &Client<PS, SP> {
        &self.client
    }

    /// Returns a mutable reference to the Aranya client for tests that need it.
    #[cfg(test)]
    pub(crate) const fn client_mut(&mut self) -> &mut Client<PS, SP> {
        &mut self.client
    }
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF>
where
    ST: SyncTransport,
    SP: StorageProvider,
{
    /// Send a hello message to a peer and wait for a response.
    #[cfg(feature = "preview")]
    pub(super) async fn send_hello_request(
        &self,
        peer: SyncPeer,
        sync_type: SyncType,
    ) -> Result<()> {
        // Connect to the peer
        let mut stream = self
            .transport
            .connect(peer)
            .await
            .map_err(Error::transport)?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        // Send the message
        let data =
            postcard::to_slice(&sync_type, &mut buf).context("postcard serialization failed")?;
        stream.send(data).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        // Read the response to avoid a race condition with the server
        match stream.receive(&mut buf).await {
            Ok(0) => Err(Error::EmptyResponse),
            Ok(_) => Ok(()),
            Err(e) => Err(Error::transport(e)),
        }
    }

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    async fn send_hello_subscribe(
        &self,
        peer: SyncPeer,
        graph_change_debounce: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        trace!(?peer, "subscribing to hello notifications from peer");
        // TODO(nikki): update aranya_core with the new name.
        let message = SyncType::Hello(SyncHelloType::Subscribe {
            graph_change_delay: graph_change_debounce,
            duration,
            schedule_delay,
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, message).await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    async fn send_hello_unsubscribe(&self, peer: SyncPeer) -> Result<()> {
        trace!(?peer, "unsubscribing from hello notifications from peer");
        let message = SyncType::Hello(SyncHelloType::Unsubscribe {
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, message).await
    }

    /// Send a hello notification to a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn send_hello_notification(&mut self, peer: SyncPeer, head: Address) -> Result<()> {
        trace!(?peer, "sending hello notifications to peer");

        let message = SyncType::Hello(SyncHelloType::Hello {
            head,
            graph_id: peer.graph_id,
        });
        self.send_hello_request(peer, message).await?;

        // Update the last time we notified the peer.
        if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
            sub.last_notified = Instant::now();
        }

        Ok(())
    }

    /// Send a hello notification to all peers that are subscribed to updates on this graph.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(graph = %graph_id))]
    async fn broadcast_hello(&mut self, graph_id: GraphId, head: Address) {
        let now = Instant::now();

        let mut subscribers = Vec::new();
        self.hello_subscriptions.retain(|peer, sub| {
            // Retain all peers that are subscribed to different GraphIds
            if peer.graph_id != graph_id {
                return true;
            }

            // If this subscription has expired, remove it
            if now >= sub.expires_at {
                self.queue.remove(&sub.queue_key);
                debug!(?peer, "removed expired subscription");
                return false;
            }

            // Check if enough time has passed since last notification.
            if now - sub.last_notified >= sub.graph_change_debounce {
                // This is for the correct GraphId and hasn't expired or throttled.
                subscribers.push(*peer);
            }
            true
        });

        // Loop through all subscribers and send them a hello notification.
        for peer in &subscribers {
            if let Err(error) = self.send_hello_notification(*peer, head).await {
                warn!(?peer, %error, "failed to send hello notification");
            }
        }

        debug!(
            ?graph_id,
            ?head,
            subscriber_count = subscribers.len(),
            "Completed broadcast_hello_notifications"
        );
    }

    // Handle sending a hello notification to a scheduled peer (possibly from initial registration).
    #[cfg(feature = "preview")]
    async fn handle_scheduled_hello(&mut self, peer: SyncPeer) -> Result<()> {
        // Get the current head for the peer's graph.
        let head = self
            .client
            .lock_aranya()
            .await
            .provider()
            .get_storage(peer.graph_id)
            .map_or(None, |storage| storage.get_head_address().ok());

        // If it's valid, send them a hello notification.
        if let Some(head) = head {
            if let Err(error) = self.send_hello_notification(peer, head).await {
                warn!(?peer, %error, "failed to send hello notification");
            }
        } else {
            warn!(?peer, "tried to send hello notification, no head exists!");
        }

        if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
            // Check if the subscription will expire before our next scheduled sync.
            if Instant::now() + sub.schedule_delay < sub.expires_at {
                sub.queue_key = self
                    .queue
                    .insert(ScheduledTask::HelloNotify(peer), sub.schedule_delay);
            } else {
                self.hello_subscriptions.remove(&peer);
            }
        }

        Ok(())
    }
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF>
where
    ST: SyncTransport,
    PS: PolicyStore,
    SP: StorageProvider,
    EF: Send + Sync + 'static + TryFrom<PS::Effect>,
    EF::Error: Send + Sync + 'static + std::error::Error,
{
    /// Runs the sync manager, processing [`SyncHandle`] requests and scheduled tasks.
    pub(crate) async fn run(mut self, ready: ready::Notifier) {
        ready.notify();
        loop {
            if let Err(err) = self.next().await {
                error!(error = %err.report(), "unable to sync with peer");
            }
        }
    }

    /// Handles either a [`SyncHandle`] request or a scheduled task.
    async fn next(&mut self) -> Result<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // Received a message from the [`SyncHandle`], handle it.
            Some((msg, tx)) = self.recv.recv() => {
                let reply = match msg {
                    // NOTE: cfg is unused but included to avoid needing to change the API surface.
                    ManagerMessage::SyncNow { peer, cfg: _cfg } => self.sync(peer).await.map(|_| ()),
                    ManagerMessage::AddPeer { peer, cfg } => {
                        self.add_peer(peer, cfg);
                        Ok(())
                    }
                    ManagerMessage::RemovePeer { peer } => {
                        self.remove_peer(peer);
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloSubscribe { peer, graph_change_debounce, duration, schedule_delay } => {
                        self.send_hello_subscribe(peer, graph_change_debounce, duration, schedule_delay).await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloUnsubscribe { peer } => self.send_hello_unsubscribe(peer).await,
                    #[cfg(feature = "preview")]
                    ManagerMessage::BroadcastHello { graph_id, head } => {
                        self.broadcast_hello(graph_id, head).await;
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloSubscribeRequest { peer, graph_change_debounce, duration, schedule_delay } => {
                        self.add_hello_subscription(peer, graph_change_debounce, duration, schedule_delay);
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloUnsubscribeRequest { peer } => {
                        self.remove_hello_subscription(peer);
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::SyncOnHello { peer, head } => self.sync_on_hello(peer, head).await,
                };

                if let Err(reply) = tx.send(reply) {
                    warn!("syncer operation did not wait for reply");
                    reply?;
                }
            }

            // Get the next peer from the `DelayQueue` and handle it.
            Some(expired) = self.queue.next() => {
                match expired.into_inner() {
                    ScheduledTask::Sync(peer) => self.handle_scheduled_sync(peer).await?,
                    #[cfg(feature = "preview")]
                    ScheduledTask::HelloNotify(peer) => self.handle_scheduled_hello(peer).await?,
                }
            }
        }
        Ok(())
    }

    /// Handles a sync exchange with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: SyncPeer) -> Result<usize> {
        // Connect to the peer.
        let mut stream = self
            .transport
            .connect(peer)
            .await
            .map_err(Error::transport)?;

        let mut requester = SyncRequester::new(peer.graph_id, &mut Rng);
        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        // Process a poll request, and get back the length/number of commands.
        let (len, _cmds) = {
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            requester
                .poll(&mut buf, aranya.provider(), caches.entry(peer).or_default())
                .context("failed to process poll sync request")
        }?;

        // Send along our request message.
        let buffer = buf.get(..len).assume("valid offset")?;
        stream.send(buffer).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        // Process the response message.
        let len = stream.receive(&mut buf).await.map_err(Error::transport)?;
        let buffer = buf.get(..len).assume("valid offset")?;
        let resp = postcard::from_bytes(buffer).context("failed to deserialize sync response")?;

        // Destructure the sync response.
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };

        // Process the response data.
        let mut sink = VecSink::new();
        let cmd_result = self
            .process_sync_data(peer, &data, &mut requester, &mut sink)
            .await;

        // Send all processed effects to the Daemon API.
        let effects = sink.collect().context("could not collect effects")?;
        let effects_count = effects.len();
        self.send_effects
            .send((peer.graph_id, effects))
            .await
            .context("unable to send effects")?;

        // Handle any sync error (including parallel finalization).
        let cmd_count = cmd_result.inspect_err(|err| {
            self.handle_sync_error(peer, err);
        })?;

        info!(?peer, cmd_count, effects_count, "sync completed");
        Ok(cmd_count)
    }

    // Process the sync response data and add a new transaction to the Aranya client.
    async fn process_sync_data<S: Sink<PS::Effect>>(
        &self,
        peer: SyncPeer,
        data: &[u8],
        requester: &mut SyncRequester,
        sink: &mut S,
    ) -> Result<usize> {
        // Check if there's even anything to process
        if data.is_empty() {
            return Ok(0);
        }

        // Check if we actually received any command data.
        let cmds = match requester.receive(data)? {
            Some(cmds) if !cmds.is_empty() => cmds,
            _ => return Ok(0),
        };

        // Create a new transaction and add all received commands.
        let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
        let mut trx = aranya.transaction(peer.graph_id);
        aranya
            .add_commands(&mut trx, sink, &cmds)
            .context("unable to add received commands")?;
        aranya.commit(&mut trx, sink).context("commit failed")?;

        // Update our peer cache with the new commands.
        aranya
            .update_heads(
                peer.graph_id,
                cmds.iter().filter_map(|cmd| cmd.address().ok()),
                caches.entry(peer).or_default(),
            )
            .context("failed to update cache heads")?;

        Ok(cmds.len())
    }

    // Handle a scheduled sync task, updating the `DelayQueue` and syncing.
    async fn handle_scheduled_sync(&mut self, peer: SyncPeer) -> Result<()> {
        let (cfg, key) = self.peers.get_mut(&peer).assume("peer must exist")?;
        // Re-insert into queue if interval is still configured
        *key = cfg
            .interval
            .map(|interval| self.queue.insert(ScheduledTask::Sync(peer), interval));
        self.sync(peer).await?;
        Ok(())
    }

    /// Handle a received hello message by syncing with the peer if we're missing their current head.
    #[cfg(feature = "preview")]
    async fn sync_on_hello(&mut self, peer: SyncPeer, head: Address) -> Result<()> {
        debug!(?peer, ?head, "received hello notification message");

        // Update the peer cache with the received head_id.
        {
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();
            aranya.update_heads(peer.graph_id, [head], cache)?;
        }

        // Check if we're missing this head and need it synced.
        let dominated = self
            .client
            .lock_aranya()
            .await
            .command_exists(peer.graph_id, head);
        if !dominated {
            match self.peers.get(&peer) {
                Some((cfg, _)) if cfg.sync_on_hello => {
                    if let Err(error) = self.sync(peer).await {
                        warn!(%error, ?peer, "failed to sync with peer");
                    }
                }
                Some(_) => trace!(?peer, "SyncOnHello is not enabled, ignoring"),
                None => warn!(?peer, "Peer not found, ignoring SyncOnHello"),
            }
        }

        Ok(())
    }
}
