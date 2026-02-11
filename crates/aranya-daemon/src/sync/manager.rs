//! This module handles the [`SyncManager`] used to manage sync tasks.
//!
//! # Architecture
//!
//! - A [`DelayQueue`] is used to retrieve the next peer to sync with at the specified interval.
//! - [`SyncHandle`] handles adding/removing peers for the [`SyncManager`].
//! - [`SyncManager`] syncs with the next available peer from the [`DelayQueue`].
//! - [`SyncHandle`] and [`SyncManager`] communicate via mpsc channels so they can run independently.
//!
//! This prevents the need for an `Arc<Mutex>` which would lock until the next peer is retrieved from the [`DelayQueue`].
//!
//! # Hello Sync
//!
//! The sync task supports "hello" notifications that allow peers to proactively notify each other
//! when their graph head changes, enabling more responsive synchronization:
//!
//! - **Subscriptions**: Peers can subscribe to hello notifications from other peers using
//!   SyncHandle::sync_hello_subscribe, specifying a delay between notifications and a duration
//!   for the subscription.
//! - **Broadcasting**: When a graph head changes, hello notifications are broadcast to all
//!   subscribers via SyncHandle::broadcast_hello.
//! - **Sync on Hello**: Peers can be configured to automatically sync when they receive a hello
//!   notification by setting `sync_on_hello` in their [`SyncPeerConfig`].
//! - **Unsubscribe**: Peers can unsubscribe from hello notifications using
//!   SyncHandle::sync_hello_unsubscribe.
//!
//! [`SyncHandle`]: super::SyncHandle

use std::collections::HashMap;
#[cfg(feature = "preview")]
use std::time::Duration;

use anyhow::Context as _;
use aranya_crypto::Rng;
use aranya_daemon_api::SyncPeerConfig;
#[cfg(feature = "preview")]
use aranya_runtime::{Address, Storage as _, SyncHelloType, SyncType};
use aranya_runtime::{
    Command as _, PolicyStore, StorageProvider, SyncRequester, MAX_SYNC_MESSAGE_SIZE,
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
use crate::sync::{HelloSubscription, HelloSubscriptions};
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

/// Syncs with each peer after the specified interval.
///
/// Uses a [`DelayQueue`] to obtain the next peer to sync with.
/// Receives added/removed peers from [`SyncHandle`] via mpsc channels.
///
/// [`SyncHandle`]: super::SyncHandle
#[derive_where(Debug; ST)]
pub(crate) struct SyncManager<ST, PS, SP, EF> {
    /// Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    pub(super) client: Client<PS, SP>,
    /// Keeps track of peer info. The Key is None if the peer has no interval configured.
    pub(super) peers: HashMap<SyncPeer, (SyncPeerConfig, Option<delay_queue::Key>)>,
    /// Receives added/removed peers.
    pub(super) recv: mpsc::Receiver<Callback>,
    /// Delay queue for getting the next peer to sync with.
    pub(super) queue: DelayQueue<ScheduledTask>,
    /// Used to send effects to the API to be processed.
    pub(super) send_effects: mpsc::Sender<(GraphId, Vec<EF>)>,
    /// Additional state used by the syncer.
    pub(super) transport: ST,
    /// Holds all active hello subscriptions.
    #[cfg(feature = "preview")]
    pub(super) hello_subscriptions: HelloSubscriptions,
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF> {
    /// Add a peer to the delay queue, overwriting an existing one.
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

    /// Remove a peer from the delay queue.
    fn remove_peer(&mut self, peer: SyncPeer) {
        if let Some((_, Some(key))) = self.peers.remove(&peer) {
            self.queue.remove(&key);
        }
    }

    #[cfg(feature = "preview")]
    fn add_hello_subscription(
        &mut self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) {
        if let Some(sub) = self.hello_subscriptions.remove(&peer) {
            self.queue.remove(&sub.queue_key);
        }

        let queue_key = self
            .queue
            .insert(ScheduledTask::HelloNotify(peer), schedule_delay);
        let subscription = HelloSubscription {
            graph_change_delay,
            last_notified: None,
            schedule_delay,
            expires_at: Instant::now() + duration,
            queue_key,
        };

        debug!(?peer, ?subscription, "created hello subscription");
        self.hello_subscriptions.insert(peer, subscription);
    }

    #[cfg(feature = "preview")]
    fn remove_hello_subscription(&mut self, peer: SyncPeer) {
        if let Some(old) = self.hello_subscriptions.remove(&peer) {
            self.queue.remove(&old.queue_key);
        }
        debug!(?peer, "removed hello subscription");
    }

    fn handle_sync_error(&mut self, peer: SyncPeer, err: &Error) {
        if err.is_parallel_finalize() {
            warn!(?peer, "parallel finalize error, removing all peers");
            // Remove sync peers for graph that had finalization error.
            self.peers.retain(|p, (_, key)| {
                let keep = p.graph_id != peer.graph_id;
                if !keep {
                    if let Some(k) = key {
                        self.queue.remove(k);
                    }
                }
                keep
            });
            self.client.invalid_graphs().insert(peer.graph_id);
        }
    }

    /// Get peer caches for test inspection.
    #[cfg(test)]
    pub(crate) fn get_peer_caches(&self) -> crate::aranya::PeerCacheMap {
        self.client.caches_for_test()
    }

    /// Returns a reference to the Aranya client.
    #[cfg(test)]
    pub(crate) fn client(&self) -> &Client<PS, SP> {
        &self.client
    }

    /// Returns a mutable reference to the Aranya client.
    #[cfg(test)]
    pub(crate) fn client_mut(&mut self) -> &mut Client<PS, SP> {
        &mut self.client
    }
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF>
where
    ST: SyncTransport,
    SP: StorageProvider,
{
    /// Send a hello message to a peer and wait for a response.
    ///
    /// This is a helper method that handles the common logic for sending hello messages,
    /// including serialization, connection management, and response handling.
    ///
    /// # Arguments
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `sync_type` - The hello message to send
    ///
    /// # Returns
    /// * `Ok(())` if the message was sent successfully
    /// * `Err(SyncError)` if there was an error
    #[instrument(skip_all)]
    #[cfg(feature = "preview")]
    pub(super) async fn send_hello_request(
        &self,
        peer: SyncPeer,
        sync_type: SyncType,
    ) -> Result<()> {
        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let mut stream = self
            .transport
            .connect(peer)
            .await
            .map_err(Error::transport)?;

        // Send the message
        stream.send(&data).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        stream
            .receive(&mut response_buf)
            .await
            .map_err(Error::transport)?;
        match response_buf.is_empty() {
            true => Err(Error::EmptyResponse),
            false => Ok(()),
        }
    }

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    async fn send_hello_subscribe(
        &mut self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        trace!(?peer, "subscribing to hello notifications from peer");
        let message = SyncType::Hello(SyncHelloType::Subscribe {
            graph_change_delay,
            duration,
            schedule_delay,
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, message).await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    async fn send_hello_unsubscribe(&mut self, peer: SyncPeer) -> Result<()> {
        trace!(?peer, "unsubscribing from hello notifications from peer");
        let message = SyncType::Hello(SyncHelloType::Unsubscribe {
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, message).await
    }

    #[cfg(feature = "preview")]
    async fn send_hello_notification(&mut self, peer: SyncPeer, head: Address) -> Result<()> {
        trace!(?peer, "sending hello notifications to peer");

        let message = SyncType::Hello(SyncHelloType::Hello {
            head,
            graph_id: peer.graph_id,
        });
        self.send_hello_request(peer, message).await?;

        if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
            sub.last_notified = Some(Instant::now());
        }

        Ok(())
    }

    #[cfg(feature = "preview")]
    async fn broadcast_hello(&mut self, graph_id: GraphId, head: Address) {
        let now = Instant::now();

        let mut subscribers = Vec::new();
        self.hello_subscriptions.retain(|peer, sub| {
            if peer.graph_id != graph_id {
                return true;
            }

            if now >= sub.expires_at {
                self.queue.remove(&sub.queue_key);
                debug!(?peer, "removed expired subscription");
                return false;
            }
            subscribers.push((*peer, sub.graph_change_delay, sub.last_notified));
            true
        });

        // Send hello notification to each valid subscriber
        for (peer, debounce, last_notified) in &subscribers {
            // Check if enough time has passed since last notification
            if let Some(last) = last_notified {
                if now - *last < *debounce {
                    continue;
                }
            }

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

    #[cfg(feature = "preview")]
    async fn handle_scheduled_hello(&mut self, peer: SyncPeer) {
        // Check whether the peer already got removed via hello unsubscribe.
        let Some(sub) = self.hello_subscriptions.get(&peer) else {
            return;
        };
        // Check whether the subscription expired.
        if Instant::now() >= sub.expires_at {
            self.hello_subscriptions.remove(&peer);
            return;
        }
        let schedule_delay = sub.schedule_delay;
        let graph_id = peer.graph_id;

        let head = {
            let mut aranya = self.client.lock_aranya().await;
            match aranya.provider().get_storage(graph_id) {
                Ok(storage) => storage.get_head_address().ok(),
                Err(_) => None,
            }
        };

        if let Some(head) = head {
            if let Err(error) = self.send_hello_notification(peer, head).await {
                warn!(?peer, %error, "failed to send hello notification");
            }
        }

        let key = self
            .queue
            .insert(ScheduledTask::HelloNotify(peer), schedule_delay);
        if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
            sub.queue_key = key;
        }
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
    /// Run the main syncer loop, which will handle syncing with peers.
    pub(crate) async fn run(mut self, ready: ready::Notifier) {
        ready.notify();
        loop {
            if let Err(err) = self.next().await {
                error!(error = %err.report(), "unable to sync with peer");
            }
        }
    }

    /// Syncs with the next peer in the list.
    async fn next(&mut self) -> Result<()> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // receive added/removed peers.
            Some((msg, tx)) = self.recv.recv() => {
                let reply = match msg {
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
                    ManagerMessage::HelloSubscribe { peer, graph_change_delay, duration, schedule_delay } => {
                        self.send_hello_subscribe(peer, graph_change_delay, duration, schedule_delay).await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloUnsubscribe { peer } => self.send_hello_unsubscribe(peer).await,
                    #[cfg(feature = "preview")]
                    ManagerMessage::BroadcastHello { graph_id, head } => {
                        self.broadcast_hello(graph_id, head).await;
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloSubscribeRequest { peer, graph_change_delay, duration, schedule_delay } => {
                        self.add_hello_subscription(peer, graph_change_delay, duration, schedule_delay);
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
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                match expired.into_inner() {
                    ScheduledTask::Sync(peer) => self.handle_scheduled_sync(peer).await?,
                    #[cfg(feature = "preview")]
                    ScheduledTask::HelloNotify(peer) => self.handle_scheduled_hello(peer).await,
                }
            }
        }
        Ok(())
    }

    /// Sync with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: SyncPeer) -> Result<usize> {
        let mut sink = VecSink::new();

        let mut stream = self
            .transport
            .connect(peer)
            .await
            .map_err(Error::transport)?;

        let mut requester = SyncRequester::new(peer.graph_id, &mut Rng);

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();
            let (len, _) = requester
                .poll(&mut buf, aranya.provider(), cache)
                .context("sync poll failed")?;
            len
        };
        buf.truncate(len);

        stream.send(&buf).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        buf.clear();
        stream.receive(&mut buf).await.map_err(Error::transport)?;

        // process the sync response.
        let resp = postcard::from_bytes(&buf).context("failed to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };
        if data.is_empty() {
            let cmd_count = 0;
            info!(?peer, cmd_count, effects_count = 0, "sync completed");
            return Ok(cmd_count);
        }
        let cmds = match requester.receive(&data)? {
            Some(cmds) if !cmds.is_empty() => cmds,
            _ => {
                let cmd_count = 0;
                info!(?peer, cmd_count, effects_count = 0, "sync completed");
                return Ok(cmd_count);
            }
        };

        let result: Result<()> = async {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let mut trx = aranya.transaction(peer.graph_id);
            aranya
                .add_commands(&mut trx, &mut sink, &cmds)
                .context("unable to add received commands")?;
            aranya
                .commit(&mut trx, &mut sink)
                .context("commit failed")?;
            let cache = caches.entry(peer).or_default();
            aranya
                .update_heads(
                    peer.graph_id,
                    cmds.iter().filter_map(|cmd| cmd.address().ok()),
                    cache,
                )
                .context("failed to update cache heads")?;
            Ok(())
        }
        .await;

        if let Err(err) = result {
            self.handle_sync_error(peer, &err);
            return Err(err);
        }

        let effects = sink.collect().context("could not collect effects")?;
        let cmd_count = cmds.len();
        let effects_count = effects.len();

        self.send_effects
            .send((peer.graph_id, effects))
            .await
            .context("unable to send effects")?;

        info!(?peer, cmd_count, effects_count, "sync completed");
        Ok(cmd_count)
    }

    async fn handle_scheduled_sync(&mut self, peer: SyncPeer) -> Result<()> {
        let (cfg, key) = self.peers.get_mut(&peer).assume("peer must exist")?;
        // Re-insert into queue if interval is still configured
        *key = cfg
            .interval
            .map(|interval| self.queue.insert(ScheduledTask::Sync(peer), interval));
        self.sync(peer).await?;
        Ok(())
    }

    #[cfg(feature = "preview")]
    async fn sync_on_hello(&mut self, peer: SyncPeer, head: Address) -> Result<()> {
        debug!(?peer, ?head, "received hello notification message");

        {
            // Update the peer cache with the received head_id.
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();
            aranya.update_heads(peer.graph_id, [head], cache)?;
        }

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
