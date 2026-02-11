use anyhow::Context as _;
use aranya_runtime::{
    PolicyStore, StorageError, StorageProvider, SyncHelloType, SyncRequestMessage, SyncResponder,
    SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready};
use buggy::bug;
use derive_where::derive_where;
use tracing::{error, info, instrument, trace, warn};

use super::{
    transport::{SyncListener, SyncStream},
    Error, GraphId, SyncHandle, SyncPeer,
};
use crate::{aranya::Client, sync::SyncResponse};

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

        while let Some(stream_result) = self.listener.accept().await {
            match stream_result {
                Ok(stream) => {
                    let peer = stream.peer();
                    if let Err(e) = self.handle_stream(stream).await {
                        warn!(?peer, error = %e.report(), "error handling sync request");
                    }
                }
                Err(error) => warn!(%error, "error accepting stream"),
            }
        }

        error!("sync server terminated");
    }

    #[instrument(skip_all)]
    async fn handle_stream<S: SyncStream>(&self, mut stream: S) -> Result<(), Error> {
        trace!("received sync request");

        let mut buf = Vec::with_capacity(MAX_SYNC_MESSAGE_SIZE);
        stream.receive(&mut buf).await.map_err(Error::transport)?;
        trace!(n = buf.len(), "received request bytes");

        let peer = stream.peer();
        let sync_type: SyncType = postcard::from_bytes(&buf).map_err(|error| {
            error!(
                %error,
                ?peer,
                request_len = buf.len(),
                "Failed to deserialize sync request"
            );
            anyhow::anyhow!(error)
        })?;

        let response: SyncResponse = match sync_type {
            SyncType::Poll { request } => {
                match self.process_poll_message(peer, request, &mut buf).await {
                    Ok(data) => SyncResponse::Ok(data),
                    Err(e) => {
                        error!(error = %e.report(), "error processing poll message");
                        SyncResponse::Err(e.report().to_string())
                    }
                }
            }
            SyncType::Hello(hello_msg) => {
                #[cfg(not(feature = "preview"))]
                {
                    let _ = hello_msg;
                    bug!("sync hello not enabled")
                }
                #[cfg(feature = "preview")]
                {
                    match self.process_hello_message(peer, hello_msg).await {
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

        buf.clear();
        postcard::to_io(&response, &mut buf).context("postcard serialization failed")?;
        stream.send(&buf).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        trace!(n = buf.len(), "sent response");
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
        buf: &mut Vec<u8>,
    ) -> Result<Box<[u8]>, Error> {
        match request {
            SyncRequestMessage::SyncRequest { graph_id, .. } => {
                check_request(peer.graph_id, graph_id)?;

                let mut resp = SyncResponder::new();
                resp.receive(request).context("sync recv failed")?;

                buf.clear();
                buf.resize(MAX_SYNC_MESSAGE_SIZE, 0);
                let len = {
                    let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
                    let cache = caches.entry(peer).or_default();

                    resp.poll(buf, aranya.provider(), cache)
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
                Ok(buf.split_off(0).into_boxed_slice())
            }
            SyncRequestMessage::RequestMissing { .. } => bug!("Should be a SyncRequest"),
            SyncRequestMessage::SyncResume { .. } => bug!("Should be a SyncRequest"),
            SyncRequestMessage::EndSession { .. } => bug!("Should be a SyncRequest"),
        }
    }

    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    pub(super) async fn process_hello_message(
        &self,
        peer: SyncPeer,
        hello_msg: SyncHelloType,
    ) -> Result<(), Error> {
        match hello_msg {
            SyncHelloType::Subscribe {
                graph_change_delay,
                duration,
                schedule_delay,
                graph_id,
            } => {
                check_request(peer.graph_id, graph_id)?;
                self.handle
                    .hello_subscribe_request(peer, graph_change_delay, duration, schedule_delay)
                    .await?;
            }
            SyncHelloType::Unsubscribe { graph_id } => {
                check_request(peer.graph_id, graph_id)?;
                self.handle.hello_unsubscribe_request(peer).await?;
            }
            SyncHelloType::Hello { head, graph_id } => {
                check_request(peer.graph_id, graph_id)?;
                self.handle.sync_on_hello(peer, head).await?;
            }
        }

        Ok(())
    }
}

fn check_request(graph_id: GraphId, message_id: GraphId) -> Result<GraphId, Error> {
    if graph_id.as_bytes() != message_id.as_bytes() {
        // TODO(nikki): this isn't really a transport error, this is a protocol error. Change as
        // part of a larger refactor?
        return Err(Error::Transport(
            anyhow::anyhow!("The sync message's GraphId doesn't match the current GraphId!").into(),
        ));
    }

    Ok(graph_id)
}
