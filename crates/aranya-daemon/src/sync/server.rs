use std::{collections::HashMap, time::Duration};

use anyhow::Context as _;
use aranya_runtime::{
    PolicyStore, Storage, StorageError, StorageProvider, SyncHelloType, SyncRequestMessage,
    SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready};
use buggy::bug;
use derive_where::derive_where;
use futures_util::StreamExt as _;
use tokio::time::Instant;
use tokio_util::time::{delay_queue, DelayQueue};
use tracing::{debug, error, info, instrument, trace, warn};

use super::{
    transport::{SyncListener, SyncStream},
    Error, GraphId, HelloSubscription, SyncHandle, SyncPeer,
};
use crate::{aranya::Client, sync::SyncResponse};

struct HelloEntry {
    queue_key: delay_queue::Key,
    schedule_delay: Duration,
    expires_at: Instant,
    graph_change_delay: Duration,
}

/// The Aranya QUIC sync server.
///
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive_where(Debug; SL)]
pub(crate) struct SyncServer<SL, PS, SP> {
    /// The listener that yields incoming streams.
    listener: SL,
    /// Thread-safe Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    client: Client<PS, SP>,
    /// Interface to trigger sync operations
    handle: SyncHandle,
}

impl<SL, PS, SP> SyncServer<SL, PS, SP>
where
    SL: SyncListener + Sync,
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
{
    pub(crate) fn new(listener: SL, client: Client<PS, SP>, handle: SyncHandle) -> Self {
        Self {
            listener,
            client,
            handle,
        }
    }

    pub(crate) fn local_addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr()
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.local_addr()))]
    #[allow(clippy::disallowed_macros)]
    pub(crate) async fn serve(mut self, ready: ready::Notifier) {
        info!("sync server listening for incoming connections");
        ready.notify();

        let mut hello_queue: DelayQueue<SyncPeer> = DelayQueue::new();
        let mut queue_keys: HashMap<SyncPeer, delay_queue::Key> = HashMap::new();

        loop {
            tokio::select! {
                biased;

                // NB: hello queue will be empty if hello sync isn't enabled
                Some(expired) = hello_queue.next() => {
                    let peer = expired.into_inner();
                    #[cfg(feature = "preview")]
                    self.handle_scheduled_hello(peer, &mut hello_queue, &mut queue_keys).await;
                }

                Some(stream_result) = self.listener.accept() => {
                    match stream_result {
                        Ok(stream) => {
                            let peer = stream.peer();
                            if let Err(e) = self.handle_stream(
                                stream,
                                &mut hello_queue,
                                &mut queue_keys,
                            ).await {
                                warn!(?peer, error = %e.report(), "error handling sync request");
                            }
                        }
                        Err(error) => {
                            warn!(%error, "error accepting stream");
                        }
                    }
                }

                else => break,
            }
        }

        error!("sync server terminated");
    }

    // TODO(nikki): the server shouldn't be handling hello sync scheduling, we need to refactor this into the manager so we can use its delay_queue.
    #[cfg(feature = "preview")]
    async fn handle_scheduled_hello(
        &self,
        peer: SyncPeer,
        hello_queue: &mut DelayQueue<SyncPeer>,
        queue_keys: &mut HashMap<SyncPeer, delay_queue::Key>,
    ) {
        // Check our subscription cache, is this subscription still valid?
        let schedule_delay = {
            let subs = self.client.lock_hello_subscriptions().await;
            match subs.get(&peer) {
                Some(sub) if Instant::now() < sub.expires_at => Some(sub.schedule_delay),
                _ => None,
            }
        };

        // If this subscription has expired, let's remove it from the list.
        let Some(delay) = schedule_delay else {
            debug!(?peer, "hello subscription expired or removed");
            queue_keys.remove(&peer);
            self.client.lock_hello_subscriptions().await.remove(&peer);
            return;
        };

        // Try to get the current head of our graph.
        let head = {
            let mut aranya = self.client.lock_aranya().await;
            match aranya.provider().get_storage(peer.graph_id) {
                Ok(storage) => storage.get_head_address().ok(),
                Err(_) => None,
            }
        };

        // Broadcast hello notifications to all our peers.
        if let Some(head) = head {
            match self.handle.broadcast_hello(peer.graph_id, head).await {
                Ok(()) => trace!(?peer, ?head, "Sent scheduled hello notification"),
                Err(error) => warn!(?peer, %error, "failed to broadcast scheduled hello"),
            }
        }

        // Schedule next hello sync for this peer.
        queue_keys.insert(peer, hello_queue.insert(peer, delay));
    }

    #[instrument(skip_all)]
    async fn handle_stream<S: SyncStream>(
        &self,
        mut stream: S,
        hello_queue: &mut DelayQueue<SyncPeer>,
        queue_keys: &mut HashMap<SyncPeer, delay_queue::Key>,
    ) -> Result<(), Error> {
        trace!("received sync request");

        let mut recv_buf = Vec::new();
        stream
            .receive(&mut recv_buf)
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        trace!(n = recv_buf.len(), "received request bytes");

        let peer = stream.peer();

        let sync_type: SyncType = postcard::from_bytes(&recv_buf).map_err(|error| {
            error!(
                %error,
                ?peer,
                request_len = recv_buf.len(),
                "Failed to deserialize sync request"
            );
            anyhow::anyhow!(error)
        })?;

        let response: SyncResponse = match sync_type {
            SyncType::Poll { request } => match self.process_poll_message(peer, request).await {
                Ok(data) => SyncResponse::Ok(data),
                Err(e) => {
                    error!(error = %e.report(), "error processing poll message");
                    SyncResponse::Err(e.report().to_string())
                }
            },
            SyncType::Hello(hello_msg) => {
                #[cfg(not(feature = "preview"))]
                {
                    let _ = hello_msg;
                    bug!("sync hello not enabled")
                }
                #[cfg(feature = "preview")]
                {
                    match self
                        .process_hello_message(peer, hello_msg, hello_queue, queue_keys)
                        .await
                    {
                        Ok(()) => SyncResponse::Ok(Box::new([])),
                        Err(e) => {
                            error!(error = %e.report(), "error processing hello message");
                            SyncResponse::Err(e.report().to_string())
                        }
                    }
                }
            }
            SyncType::Subscribe { .. } => {
                bug!("Push subscribe messages are not implemented")
            }
            SyncType::Unsubscribe { .. } => {
                bug!("Push unsubscribe messages are not implemented")
            }
            SyncType::Push { .. } => {
                bug!("Push messages are not implemented")
            }
        };

        let data = postcard::to_allocvec(&response).context("postcard serialization failed")?;
        stream
            .send(&data)
            .await
            .map_err(|e| Error::Transport(e.into()))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::Transport(e.into()))?;

        trace!(n = data.len(), "sent response");
        Ok(())
    }

    /// Processes a poll message.
    ///
    /// Handles sync poll requests and generates sync responses.
    #[instrument(skip_all)]
    async fn process_poll_message(
        &self,
        peer: SyncPeer,
        request: SyncRequestMessage,
    ) -> Result<Box<[u8]>, Error> {
        let SyncRequestMessage::SyncRequest {
            graph_id: message_id,
            ..
        } = request
        else {
            bug!("Should be a SyncRequest")
        };
        check_request(peer.graph_id, message_id)?;

        let mut resp = SyncResponder::new();
        resp.receive(request).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();

            resp.poll(&mut buf, aranya.provider(), cache)
                .or_else(|err| {
                    if matches!(
                        err,
                        aranya_runtime::SyncError::Storage(StorageError::NoSuchStorage)
                    ) {
                        warn!(team = %peer.graph_id, "missing requested graph");
                        Ok(0)
                    } else {
                        Err(err)
                    }
                })
                .context("sync resp poll failed")?
        };
        buf.truncate(len);
        Ok(buf.into())
    }

    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    pub(super) async fn process_hello_message(
        &self,
        peer: SyncPeer,
        hello_msg: SyncHelloType,
        hello_queue: &mut DelayQueue<SyncPeer>,
        queue_keys: &mut HashMap<SyncPeer, delay_queue::Key>,
    ) -> Result<(), Error> {
        match hello_msg {
            SyncHelloType::Subscribe {
                graph_change_delay,
                duration,
                schedule_delay,
                graph_id,
            } => {
                check_request(peer.graph_id, graph_id)?;

                if let Some(old_key) = queue_keys.remove(&peer) {
                    hello_queue.remove(&old_key);
                }

                let subscription = HelloSubscription {
                    graph_change_delay,
                    schedule_delay,
                    last_notified: None,
                    expires_at: Instant::now() + duration,
                };
                let subscription_debug = format!("{:?}", subscription);

                // Store subscription (replaces any existing subscription for this peer+team)
                self.client
                    .lock_hello_subscriptions()
                    .await
                    .insert(peer, subscription);

                queue_keys.insert(peer, hello_queue.insert(peer, schedule_delay));
                debug!(?peer, ?subscription_debug, "created hello subscription");
            }
            SyncHelloType::Unsubscribe { graph_id } => {
                check_request(peer.graph_id, graph_id)?;
                debug!(?peer, "received message to unsubscribe from hello messages");

                // Remove subscription for this peer and team
                self.client.lock_hello_subscriptions().await.remove(&peer);
                if let Some(key) = queue_keys.remove(&peer) {
                    hello_queue.remove(&key);
                }
                debug!(?peer, "removed hello subscriotion");
            }
            SyncHelloType::Hello { head, graph_id } => {
                check_request(peer.graph_id, graph_id)?;
                debug!(?peer, ?head, "received hello notification message");

                if !self
                    .client
                    .lock_aranya()
                    .await
                    .command_exists(graph_id, head)
                {
                    self.handle.sync_on_hello(peer).await?;
                }

                // Update the peer cache with the received head_id.
                let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
                let cache = caches.entry(peer).or_default();
                aranya.update_heads(graph_id, [head], cache)?;
            }
        }

        Ok(())
    }
}

fn check_request(graph_id: GraphId, message_id: GraphId) -> Result<GraphId, Error> {
    if graph_id.as_bytes() != message_id.as_bytes() {
        return Err(Error::Transport(
            anyhow::anyhow!("The sync message's GraphId doesn't match the current GraphId!").into(),
        ));
    }

    Ok(graph_id)
}
