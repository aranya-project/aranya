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
//! See the [`hello`](super::hello) module for implementation details.
//!
//! [`SyncHandle`]: super::SyncHandle

use std::collections::HashMap;
#[cfg(feature = "preview")]
use std::time::Duration;

use anyhow::Context as _;
use aranya_crypto::Rng;
use aranya_daemon_api::SyncPeerConfig;
use aranya_runtime::{
    Address, Command as _, PolicyStore, Sink, Storage as _, StorageProvider, SyncHelloType,
    SyncRequester, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready};
use buggy::BugExt as _;
use bytes::Bytes;
use derive_where::derive_where;
use futures_util::StreamExt as _;
use tokio::{sync::mpsc, time::Instant};
use tokio_util::time::{delay_queue, DelayQueue};
#[cfg(feature = "preview")]
use tracing::trace;
use tracing::{debug, error, info, instrument, warn};

use super::{
    handle::{Callback, ManagerMessage},
    GraphId, Result, SyncPeer,
};
use crate::{
    aranya::Client,
    sync::{
        transport::{SyncStream as _, SyncTransport},
        Error, HelloSubscription, HelloSubscriptions, SyncResponse,
    },
    vm_policy::VecSink,
};

#[derive(Debug)]
enum ScheduledTask {
    Sync(SyncPeer),
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
    /// Sync server address. Peers will make incoming connections to us on this address.
    pub(super) return_address: Bytes,
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
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_subscribe(
        &mut self,
        peer: SyncPeer,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> Result<()> {
        trace!("subscribing to hello notifications from peer");
        // Create the subscribe message
        let hello_msg = SyncHelloType::Subscribe {
            graph_change_delay,
            duration,
            schedule_delay,
            graph_id: peer.graph_id,
        };
        let sync_type = SyncType::Hello(hello_msg);

        self.send_hello_request(peer, sync_type).await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    async fn sync_hello_unsubscribe(&mut self, peer: SyncPeer) -> Result<()> {
        trace!("unsubscribing from hello notifications from peer");
        debug!("client sending unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let sync_type: SyncType = SyncType::Hello(SyncHelloType::Unsubscribe {
            graph_id: peer.graph_id,
        });

        self.send_hello_request(peer, sync_type).await
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
                    ManagerMessage::SyncNow { peer, cfg: _cfg } => {
                        // sync with peer right now.
                        self.sync(peer).await.map(|_| ())
                    },
                    ManagerMessage::AddPeer { peer, cfg } => {
                        self.add_peer(peer, cfg);
                        Ok(())
                    }
                    ManagerMessage::RemovePeer { peer } => {
                        self.remove_peer(peer);
                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloSubscribe {
                        peer,
                        graph_change_delay,
                        duration,
                        schedule_delay,
                    } => {
                        self.sync_hello_subscribe(peer, graph_change_delay, duration, schedule_delay)
                            .await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::HelloUnsubscribe { peer } => {
                        self.sync_hello_unsubscribe(peer).await
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::SyncOnHello { peer, head } => {
                        debug!(?peer, ?head, "received hello notification message");

                        let dominated = self.client.lock_aranya().await.command_exists(peer.graph_id, head);
                        if !dominated {
                            match self.peers.get(&peer) {
                                Some((cfg, _)) => {
                                    match cfg.sync_on_hello {
                                        true => self.sync(peer).await
                                            .inspect_err(|error| {
                                                warn!(%error, ?peer, "failed to sync with peer");
                                            })
                                            .map(|_| ())?,
                                        false => trace!(?peer, "SyncOnHello is not enabled, ignoring"),
                                    }
                                }
                                None => warn!(?peer, "Peer not found, ignoring SyncOnHello"),
                            }
                        }

                        // Update the peer cache with the received head_id.
                        let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
                        let cache = caches.entry(peer).or_default();
                        aranya.update_heads(peer.graph_id, [head], cache)?;

                        Ok(())
                    }
                    #[cfg(feature = "preview")]
                    ManagerMessage::BroadcastHello { graph_id, head } => async {
                        let now = Instant::now();

                        // Get all valid (non-expired) subscribers for this graph
                        let subscribers = {
                            // Remove expired subscriptions and collect valid ones
                            let mut valid_subscribers = Vec::new();
                            self.hello_subscriptions.retain(|peer, subscription| {
                                if peer.graph_id == graph_id {
                                    if now >= subscription.expires_at {
                                        // Subscription has expired, remove it
                                        debug!(?peer, "Removed expired subscription");
                                        false
                                    } else {
                                        // Subscription is valid, collect it
                                        valid_subscribers.push((*peer, subscription.clone()));
                                        true
                                    }
                                } else {
                                    // Keep subscriptions for other graphs
                                    true
                                }
                            });

                            valid_subscribers
                        };
                        let subscriber_count = subscribers.len();

                        // Send hello notification to each valid subscriber
                        for (peer, subscription) in subscribers {
                            // Check if enough time has passed since last notification
                            if let Some(last_notified) = subscription.last_notified {
                                if now - last_notified < subscription.graph_change_delay {
                                    continue;
                                }
                            }

                            // Send the notification
                            match self.send_hello_notification_to_subscriber(peer, head).await {
                                Ok(()) => {
                                    // Update the last notified time
                                    if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
                                        sub.last_notified = Some(now);
                                    } else {
                                        warn!(?peer, "Failed to find subscription to update last_notified");
                                    }
                                }
                                Err(error) => {
                                    warn!(
                                        ?peer,
                                        ?head,
                                        %error,
                                        "Failed to send hello notification"
                                    );
                                }
                            }
                        }

                        trace!(
                            ?graph_id,
                            ?head,
                            subscriber_count,
                            "Completed broadcast_hello_notifications"
                        );
                        Ok(())
                    }.await,
                    ManagerMessage::HelloSubscribeRequest { peer, graph_change_delay, duration, schedule_delay } => {
                        if let Some(sub) = self.hello_subscriptions.remove(&peer) {
                            self.queue.remove(&sub.queue_key);
                        }

                        let queue_key = self.queue.insert(ScheduledTask::HelloNotify(peer), schedule_delay);
                        let subscription = HelloSubscription {
                            graph_change_delay,
                            last_notified: None,
                            schedule_delay,
                            expires_at: Instant::now() + duration,
                            queue_key,
                        };
                        let subscription_debug = format!("{subscription:?}");

                        self.hello_subscriptions.insert(peer, subscription);
                        debug!(?peer, ?subscription_debug, "created hello subscription");
                        Ok(())
                    }
                    ManagerMessage::HelloUnsubscribeRequest { peer } => {
                        if let Some(sub) = self.hello_subscriptions.remove(&peer) {
                            self.queue.remove(&sub.queue_key);
                        }
                        debug!(?peer, "removed hello subscription");
                        Ok(())
                    }
                };
                if let Err(reply) = tx.send(reply) {
                    warn!("syncer operation did not wait for reply");
                    reply?;
                }
            }
            // get next peer from delay queue.
            Some(expired) = self.queue.next() => {
                match expired.into_inner() {
                    ScheduledTask::Sync(peer) => {
                        let (cfg, key) = self.peers.get_mut(&peer).assume("peer must exist")?;
                        // Re-insert into queue if interval is still configured
                        *key = cfg.interval.map(|interval| self.queue.insert(ScheduledTask::Sync(peer), interval));
                        // sync with peer.
                        self.sync(peer).await?;
                    }
                    ScheduledTask::HelloNotify(peer) => {
                        // Check whether the peer already got removed via hello unsubscribe.
                        let Some(sub) = self.hello_subscriptions.get(&peer) else {
                            return Ok(());
                        };
                        // Check whether the subscription expired.
                        if Instant::now() >= sub.expires_at {
                            self.hello_subscriptions.remove(&peer);
                            return Ok(());
                        }
                        let schedule_delay = sub.schedule_delay;

                        let head = {
                            let mut aranya = self.client.lock_aranya().await;
                            match aranya.provider().get_storage(peer.graph_id) {
                                Ok(storage) => storage.get_head_address().ok(),
                                Err(_) => None,
                            }
                        };

                        if let Some(head) = head {
                            match self.send_hello_notification_to_subscriber(peer, head).await {
                                Ok(()) => trace!(?peer, ?head, "Sent scheduled hello notification"),
                                Err(error) => warn!(?peer, %error, "failed to broadcast scheduled hello"),
                            }
                        }

                        let key = self.queue.insert(ScheduledTask::HelloNotify(peer), schedule_delay);
                        if let Some(sub) = self.hello_subscriptions.get_mut(&peer) {
                            sub.queue_key = key;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Sync with a peer.
    #[instrument(skip_all, fields(peer = %peer.addr, graph = %peer.graph_id))]
    pub(crate) async fn sync(&mut self, peer: SyncPeer) -> Result<usize> {
        let mut sink = VecSink::new();

        let cmd_count = async {
            let mut stream = self
                .transport
                .connect(peer)
                .await
                .inspect_err(|e| error!(error = %e.report(), "Could not create connection"))
                .map_err(|e| Error::Transport(e.into()))?;

            let mut sync_requester = SyncRequester::new(peer.graph_id, &mut Rng);

            // send sync request.
            self.send_sync_request(&mut stream, &mut sync_requester, peer)
                .await
                .map_err(|e| Error::SendSyncRequest(e.into()))?;

            // receive sync response.
            let cmd_count = self
                .receive_sync_response(&mut stream, &mut sync_requester, &mut sink, peer)
                .await
                .map_err(|e| Error::ReceiveSyncResponse(e.into()))?;

            Ok(cmd_count)
        }
        .await
        .inspect_err(|err: &Error| {
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
                        if let Some(k) = key {
                            self.queue.remove(k);
                        }
                    }
                    keep
                });
                self.client.invalid_graphs().insert(peer.graph_id);
            }
        })
        .with_context(|| format!("peer addr: {}", peer.addr))?;

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
}

impl<ST, PS, SP, EF> SyncManager<ST, PS, SP, EF>
where
    ST: SyncTransport,
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Sends a sync request to a peer over an established QUIC stream.
    ///
    /// This method uses the SyncRequester to generate the sync request data,
    /// serializes it, and sends it over the provided QUIC send stream.
    ///
    /// # Arguments
    /// * `send` - The QUIC send stream to use for sending the request
    /// * `syncer` - The SyncRequester instance that generates the sync request
    /// * `peer` - The unique identifier of the peer to send the message to
    ///
    /// # Returns
    /// * `Ok(())` if the sync request was sent successfully
    /// * `Err(SyncError)` if there was an error generating or sending the request
    #[instrument(skip_all)]
    async fn send_sync_request(
        &self,
        stream: &mut ST::Stream,
        syncer: &mut SyncRequester,
        peer: SyncPeer,
    ) -> Result<()> {
        trace!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();
            let (len, _) = syncer
                .poll(&mut send_buf, aranya.provider(), cache)
                .context("sync poll failed")?;
            trace!(?len, "sync poll finished");
            len
        };
        send_buf.truncate(len);

        stream
            .send(&send_buf)
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        trace!("sent sync request");

        Ok(())
    }

    #[instrument(skip_all)]
    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    async fn receive_sync_response<S>(
        &self,
        stream: &mut ST::Stream,
        syncer: &mut SyncRequester,
        sink: &mut S,
        peer: SyncPeer,
    ) -> Result<usize>
    where
        S: Sink<PS::Effect>,
    {
        trace!("client receiving sync response from QUIC sync server");

        let mut recv_buf = Vec::new();
        stream
            .receive(&mut recv_buf)
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        trace!(n = recv_buf.len(), "received sync response");

        // process the sync response.
        let resp = postcard::from_bytes(&recv_buf)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };
        if data.is_empty() {
            trace!("nothing to sync");
            return Ok(0);
        }
        if let Some(cmds) = syncer.receive(&data)? {
            trace!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                // Lock both aranya and caches in the correct order.
                let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
                let mut trx = aranya.transaction(peer.graph_id);
                aranya
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                aranya.commit(&mut trx, sink).context("commit failed")?;
                trace!("committed");
                let cache = caches.entry(peer).or_default();
                aranya
                    .update_heads(
                        peer.graph_id,
                        cmds.iter().filter_map(|cmd| cmd.address().ok()),
                        cache,
                    )
                    .context("failed to update cache heads")?;
                return Ok(cmds.len());
            }
        }

        Ok(0)
    }

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
            .map_err(|e| Error::Transport(e.into()))?;

        // Send the message
        stream
            .send(&data)
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::Transport(e.into()))?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        stream
            .receive(&mut response_buf)
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        match response_buf.is_empty() {
            true => Err(Error::EmptyResponse),
            false => Ok(()),
        }
    }

    /// Sends a hello notification to a specific subscriber.
    ///
    /// This method sends a `SyncHelloType::Hello` message to the specified subscriber,
    /// notifying them that the graph head has changed. Uses the existing connection
    /// infrastructure to efficiently reuse connections.
    ///
    /// # Arguments
    /// * `peer` - The unique identifier of the peer to send the message to
    /// * `head` - The new head address to include in the notification
    ///
    /// # Returns
    /// * `Ok(())` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    pub(super) async fn send_hello_notification_to_subscriber(
        &self,
        peer: SyncPeer,
        head: Address,
    ) -> Result<()> {
        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            graph_id: peer.graph_id,
        };
        let sync_type: SyncType = SyncType::Hello(hello_msg);
        // TODO(nikki): handle Err(EmptyResponse) and inline this into both call sites.
        self.send_hello_request(peer, sync_type);
        Ok(())
    }
}
