//! This module contains the [`SyncManager`] that drives the majority of the syncer, including all
//! client-side tasks.
//!
//! See the [`SyncServer`](super::SyncServer) for the other half of the syncer, which is responsible
//! for responding to syncs.
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

use aranya_daemon_api::SyncPeerConfig;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{PolicyStore, StorageProvider, MAX_SYNC_MESSAGE_SIZE};
use aranya_util::{error::ReportExt as _, ready};
use buggy::BugExt as _;
use derive_where::derive_where;
use futures_util::StreamExt as _;
use tokio::{sync::mpsc, time::Instant};
use tokio_util::time::{delay_queue, DelayQueue};
#[cfg(feature = "preview")]
use tracing::instrument;
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "preview")]
use super::GraphId;
use super::{
    handle::{Callback, ManagerMessage},
    Result, SyncClient, SyncPeer,
};
#[cfg(test)]
use crate::aranya::Client;
#[cfg(feature = "preview")]
use crate::sync::HelloSubscription;
use crate::sync::{transport::SyncConnector, Error};

#[derive(Debug)]
pub(super) enum ScheduledTask {
    Sync(SyncPeer),
    #[cfg(feature = "preview")]
    HelloNotify(SyncPeer),
}

/// Manages sync scheduling and sending/receiving data on a transport.
///
/// Uses a [`DelayQueue`] to handle scheduling sync tasks, and uses
/// [`SyncHandle`](super::SyncHandle) to receive requests from the server and any clients.
#[derive_where(Debug; C)]
pub(crate) struct SyncManager<C, PS, SP, EF> {
    pub(crate) client: SyncClient<C, PS, SP, EF>,

    /// Receives requests from the `SyncHandle`.
    pub(super) recv: mpsc::Receiver<Callback>,

    /// Sync peer lookup info, used for storing configuration and delay queue info.
    pub(super) peers: HashMap<SyncPeer, (SyncPeerConfig, Option<delay_queue::Key>)>,
    /// Handles waiting on future sync tasks.
    pub(super) queue: DelayQueue<ScheduledTask>,

    /// Holds all active hello subscriptions.
    #[cfg(feature = "preview")]
    pub(super) hello_subscriptions: HashMap<SyncPeer, HelloSubscription>,
}

impl<C, PS, SP, EF> SyncManager<C, PS, SP, EF> {
    /// Creates a new [`SyncManager`].
    pub(crate) fn new(
        client: SyncClient<C, PS, SP, EF>,
        recv: mpsc::Receiver<Callback>,
    ) -> Result<Self> {
        Ok(Self {
            client,
            recv,
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
        if let Some((_, Some(key))) = self.peers.insert(peer, (cfg.clone(), new_key)) {
            self.queue.remove(&key);
            info!(?peer, ?cfg, "replaced existing peer registration");
        } else {
            info!(?peer, ?cfg, "registered new peer");
        }
    }

    /// Unregisters a peer with the manager.
    fn remove_peer(&mut self, peer: SyncPeer) {
        match self.peers.remove(&peer) {
            Some((_, Some(key))) => {
                self.queue.remove(&key);
                info!(?peer, "removed peer and cancelled scheduled sync");
            }
            Some((_, None)) => info!(?peer, "removed peer (no scheduled sync)"),
            None => warn!(?peer, "attempted to remove unknown peer"),
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
    ) -> Result<()> {
        // Check if there was an existing subscription for this peer and remove it.
        if let Some(sub) = self.hello_subscriptions.remove(&peer) {
            self.queue.remove(&sub.queue_key);
        }

        // Schedule the next hello sync.
        let queue_key = self
            .queue
            .insert(ScheduledTask::HelloNotify(peer), schedule_delay);

        // Note that last_notified is ~now, since we send a hello request after this function.
        let subscription = HelloSubscription {
            graph_change_debounce,
            schedule_delay,
            last_notified: Instant::now()
                .checked_sub(graph_change_debounce)
                .assume("valid debounce received")?,
            expires_at: Instant::now()
                .checked_add(duration)
                .assume("valid duration received")?,
            queue_key,
        };

        debug!(?peer, ?subscription, "created hello subscription");
        self.hello_subscriptions.insert(peer, subscription);
        Ok(())
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
            error!(?peer, "parallel finalize error, removing all peers");

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
        self.client.client.caches_for_test()
    }

    /// Returns a reference to the Aranya client for tests that need it.
    #[cfg(test)]
    pub(crate) const fn client(&self) -> &Client<PS, SP> {
        &self.client.client
    }
}

impl<C, PS, SP, EF> SyncManager<C, PS, SP, EF>
where
    C: SyncConnector,
    PS: PolicyStore,
    SP: StorageProvider,
    EF: Send + Sync + 'static + TryFrom<PS::Effect>,
    EF::Error: Send + Sync + 'static + std::error::Error,
{
    /// Runs the [`SyncManager`], processing [`SyncHandle`](super::SyncHandle) requests and
    /// scheduled tasks.
    pub(crate) async fn run(mut self, ready: ready::Notifier) {
        info!("sync manager starting");
        ready.notify();

        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE].into_boxed_slice();
        loop {
            match self.next(&mut buffer).await {
                Ok(()) => {}
                Err(Error::SyncerShutdown) => {
                    info!("sync manager shutting down");
                    break;
                }
                Err(err) => error!(error = %err.report(), "unable to sync with peer"),
            }
        }
    }

    /// Handles either a [`SyncHandle`](super::SyncHandle) request or a scheduled task.
    async fn next(&mut self, buffer: &mut [u8]) -> Result<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // Received a message from the SyncHandle, handle it.
            msg = self.recv.recv() => {
                match msg {
                    Some((msg, tx)) => {
                        let reply = self.handle_message(msg, buffer).await;
                        if let Err(reply) = tx.send(reply) {
                            warn!("syncer operation did not wait for reply");
                            reply?;
                        }
                    }
                    None => return Err(Error::SyncerShutdown),
                }
            }

            // Get the next peer from the `DelayQueue` and handle it.
            Some(expired) = self.queue.next() => {
                self.handle_scheduled(expired.into_inner(), buffer).await?;
            }
        }
        Ok(())
    }

    async fn handle_message(&mut self, msg: ManagerMessage, buffer: &mut [u8]) -> Result<()> {
        debug!(?msg, "processing handle message");
        match msg {
            ManagerMessage::AddPeer { peer, cfg } => {
                self.add_peer(peer, cfg);
                Ok(())
            }
            ManagerMessage::RemovePeer { peer } => {
                self.remove_peer(peer);
                Ok(())
            }
            // NOTE: cfg is unused but included to avoid needing to change the API surface.
            ManagerMessage::SyncNow { peer, cfg: _cfg } => {
                self.do_sync(peer, buffer).await?;
                Ok(())
            }
            #[cfg(feature = "preview")]
            ManagerMessage::HelloSubscribe {
                peer,
                graph_change_debounce,
                duration,
                schedule_delay,
            } => {
                self.client
                    .send_hello_subscribe(
                        peer,
                        graph_change_debounce,
                        duration,
                        schedule_delay,
                        buffer,
                    )
                    .await
            }
            #[cfg(feature = "preview")]
            ManagerMessage::HelloUnsubscribe { peer } => {
                self.client.send_hello_unsubscribe(peer, buffer).await
            }
            #[cfg(feature = "preview")]
            ManagerMessage::BroadcastHello { graph_id, head } => {
                self.broadcast_hello(graph_id, head, buffer).await;
                Ok(())
            }
            #[cfg(feature = "preview")]
            ManagerMessage::HelloSubscribeRequest {
                peer,
                graph_change_debounce,
                duration,
                schedule_delay,
            } => self.add_hello_subscription(peer, graph_change_debounce, duration, schedule_delay),
            #[cfg(feature = "preview")]
            ManagerMessage::HelloUnsubscribeRequest { peer } => {
                self.remove_hello_subscription(peer);
                Ok(())
            }
            #[cfg(feature = "preview")]
            ManagerMessage::SyncOnHello { peer, head } => {
                self.sync_on_hello(peer, head, buffer).await
            }
        }
    }

    async fn handle_scheduled(&mut self, task: ScheduledTask, buffer: &mut [u8]) -> Result<()> {
        match task {
            ScheduledTask::Sync(peer) => {
                debug!(?peer, "scheduled sync triggered");
                self.handle_scheduled_sync(peer, buffer).await
            }
            #[cfg(feature = "preview")]
            ScheduledTask::HelloNotify(peer) => {
                debug!(?peer, "scheduled hello triggered");
                self.handle_scheduled_hello(peer, buffer).await
            }
        }
    }

    // Handle a scheduled sync task, updating the `DelayQueue` and syncing.
    async fn handle_scheduled_sync(&mut self, peer: SyncPeer, buffer: &mut [u8]) -> Result<()> {
        let (cfg, key) = self.peers.get_mut(&peer).assume("peer must exist")?;
        // Re-insert into queue if interval is still configured
        *key = cfg.interval.map(|interval| {
            trace!(?peer, ?interval, "rescheduling next sync");
            self.queue.insert(ScheduledTask::Sync(peer), interval)
        });

        self.do_sync(peer, buffer).await?;
        Ok(())
    }

    // Handle sending a hello notification to a scheduled peer (possibly from initial registration).
    #[cfg(feature = "preview")]
    async fn handle_scheduled_hello(&mut self, peer: SyncPeer, buffer: &mut [u8]) -> Result<()> {
        // Get the current head for the peer's graph.
        let head = self.client.get_head(peer.graph_id).await;

        // If it's valid, send them a hello notification.
        if let Some(head) = head {
            if let Err(error) = self
                .client
                .send_hello_notification(peer, head, buffer)
                .await
            {
                warn!(?peer, %error, "failed to send hello notification");
            }
        } else {
            warn!(?peer, "tried to send hello notification, no head exists!");
        }

        if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
            // Check if the subscription will expire before our next scheduled sync.
            if Instant::now()
                .checked_add(sub.schedule_delay)
                .assume("valid schedule delay")?
                < sub.expires_at
            {
                sub.queue_key = self
                    .queue
                    .insert(ScheduledTask::HelloNotify(peer), sub.schedule_delay);
            } else {
                self.hello_subscriptions.remove(&peer);
            }
        }

        Ok(())
    }

    /// Sync with a peer, handling errors (including parallel finalize).
    async fn do_sync(&mut self, peer: SyncPeer, buffer: &mut [u8]) -> Result<usize> {
        self.client.sync(peer, buffer).await.inspect_err(|err| {
            self.handle_sync_error(peer, err);
        })
    }

    /// Handle a received hello message by syncing with the peer if we're missing their current head.
    #[cfg(feature = "preview")]
    async fn sync_on_hello(
        &mut self,
        peer: SyncPeer,
        head: Address,
        buffer: &mut [u8],
    ) -> Result<()> {
        debug!(?peer, ?head, "received hello notification message");

        // Check if we're missing this head and need it synced.
        let dominated = self.client.command_exists(peer.graph_id, head).await;
        if !dominated {
            match self.peers.get(&peer) {
                Some((cfg, _)) if cfg.sync_on_hello => {
                    if let Err(error) = self.do_sync(peer, buffer).await {
                        warn!(%error, ?peer, "failed to sync with peer");
                    }
                }
                Some(_) => trace!(?peer, "SyncOnHello is not enabled, ignoring"),
                None => warn!(?peer, "Peer not found, ignoring SyncOnHello"),
            }
        }

        Ok(())
    }

    /// Send a hello notification to all peers that are subscribed to updates on this graph.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(graph = %graph_id))]
    async fn broadcast_hello(&mut self, graph_id: GraphId, head: Address, buffer: &mut [u8]) {
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
            if now
                .checked_duration_since(sub.last_notified)
                .unwrap_or_default()
                >= sub.graph_change_debounce
            {
                // This is for the correct GraphId and hasn't expired or throttled.
                subscribers.push(*peer);
            }
            true
        });

        // Loop through all subscribers and send them a hello notification.
        for peer in &subscribers {
            if let Err(error) = self
                .client
                .send_hello_notification(*peer, head, buffer)
                .await
            {
                warn!(?peer, %error, "failed to send hello notification");
            }
            // Always update last_notified even if it fails so we respect the debounce.
            if let Some(sub) = self.hello_subscriptions.get_mut(peer) {
                sub.last_notified = Instant::now();
            }
        }

        debug!(
            ?graph_id,
            ?head,
            subscriber_count = subscribers.len(),
            "Completed broadcast_hello_notifications"
        );
    }
}
