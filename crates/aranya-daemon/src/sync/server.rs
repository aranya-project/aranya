//! This module contains the [`SyncServer`] that handles incoming sync requests from peers.
//!
//! The server listens for incoming connections and processes requests. This includes poll syncing,
//! in which we respond with a sampling of missing commands, as well as hello syncing, which we
//! defer to the [`SyncManager`] for scheduling.
use anyhow::Context as _;
#[cfg(feature = "preview")]
use aranya_runtime::SyncHelloType;
use aranya_runtime::{
    PolicyStore, StorageError, StorageProvider, SyncRequestMessage, SyncResponder, SyncType,
    MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready};
use buggy::{bug, BugExt as _};
use derive_where::derive_where;
use tracing::{error, info, instrument, trace, warn};

use super::{
    transport::{SyncListener, SyncStream},
    Addr, Error, SyncHandle, SyncPeer,
};
use crate::{aranya::Client, sync::SyncResponse};

/// Handles listening for connections from peers and responding to them.
///
/// Uses a [`SyncHandle`] to offload hello sync scheduling and operations to the [`SyncManager`].
#[derive_where(Debug; SL)]
pub(crate) struct SyncServer<SL, PS, SP> {
    /// The Aranya client and peer cache, alongside invalid graph tracking.
    client: Client<PS, SP>,
    /// The listener that yields incoming streams.
    listener: SL,
    /// Handle to allow sending messages to the [`SyncManager`].
    #[allow(dead_code, reason = "only used in preview right now")]
    handle: SyncHandle,
}

impl<SL, PS, SP> SyncServer<SL, PS, SP>
where
    SL: SyncListener + Sync,
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
{
    /// Creates a new [`SyncServer`].
    pub(crate) const fn new(listener: SL, client: Client<PS, SP>, handle: SyncHandle) -> Self {
        Self {
            client,
            listener,
            handle,
        }
    }

    /// Returns the local address that this listener is bound to.
    pub(crate) fn local_addr(&self) -> Addr {
        self.listener.local_addr()
    }

    /// Runs the [`SyncServer`], processing incoming connections and sync requests.
    #[allow(clippy::disallowed_macros)]
    #[instrument(skip_all, fields(addr = ?self.local_addr()))]
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

    /// Handles an incoming connection, reading data from the peer and responding as needed.
    #[instrument(skip_all, fields(peer = %stream.peer().addr, graph = %stream.peer().graph_id))]
    async fn handle_stream<S: SyncStream>(&self, mut stream: S) -> Result<(), Error> {
        trace!("received sync request");

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE].into_boxed_slice();
        let len = stream.receive(&mut buf).await.map_err(Error::transport)?;
        trace!(len, "received request bytes");

        let buffer = buf.get(..len).assume("valid offset")?;
        let sync_type = postcard::from_bytes(buffer).context("failed to deserialize request")?;

        let response = match sync_type {
            SyncType::Poll { request } => {
                match self
                    .process_poll_request(stream.peer(), request, &mut buf)
                    .await
                {
                    Ok(len) => SyncResponse::Ok(buf.get(..len).assume("valid offset")?.into()),
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
                    match self.process_hello_request(stream.peer(), hello_msg).await {
                        Ok(()) => SyncResponse::Ok(Box::new([])),
                        Err(e) => {
                            error!(error = %e.report(), "error processing hello message");
                            SyncResponse::Err(e.report().to_string())
                        }
                    }
                }
            }
            SyncType::Subscribe { .. } | SyncType::Unsubscribe { .. } | SyncType::Push { .. } => {
                bug!("message type not currently implemented!")
            }
        };

        let data =
            postcard::to_slice(&response, &mut buf).context("postcard serialization failed")?;
        stream.send(data).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        trace!(n = data.len(), "sent response");
        Ok(())
    }

    /// Processes a poll request, generating a response with a sampling of commands.
    async fn process_poll_request(
        &self,
        peer: SyncPeer,
        request: SyncRequestMessage,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        match request {
            SyncRequestMessage::SyncRequest { graph_id, .. } => {
                peer.check_request(graph_id)?;

                let mut resp = SyncResponder::new();
                resp.receive(request).context("sync recv failed")?;

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
                    .map_err(Error::Runtime)
            }
            SyncRequestMessage::RequestMissing { .. }
            | SyncRequestMessage::SyncResume { .. }
            | SyncRequestMessage::EndSession { .. } => bug!("should be a SyncRequest"),
        }
    }

    /// Processes a hello request, dispatching an internal message to the [`SyncManager`].
    #[cfg(feature = "preview")]
    pub(super) async fn process_hello_request(
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
                peer.check_request(graph_id)?;
                self.handle
                    .hello_subscribe_request(peer, graph_change_delay, duration, schedule_delay)
                    .await?;
            }
            SyncHelloType::Unsubscribe { graph_id } => {
                peer.check_request(graph_id)?;
                self.handle.hello_unsubscribe_request(peer).await?;
            }
            SyncHelloType::Hello { head, graph_id } => {
                peer.check_request(graph_id)?;
                self.handle.sync_on_hello(peer, head).await?;
            }
        }

        Ok(())
    }
}
