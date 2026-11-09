//! This module contains the [`SyncServer`] that handles accepting and responding to incoming sync
//! requests.
//!
//! The main operations the syncer has to respond to include poll syncing, which requires responding
//! with a number of commands that the peer may be missing, as well as hello sync, where the peer is
//! requesting to subscribe to our hello notifications or sending us their own hello notification.
//!
//! See the [`SyncManager`](super::SyncManager) for the other half of the syncer, which is
//! responsible for initiating syncs.
#[cfg(feature = "preview")]
use aranya_runtime::SyncHello;
use aranya_runtime::{
    MAX_SYNC_MESSAGE_SIZE, PolicyStore, PollIncoming, StorageError, StorageProvider, SyncIncoming,
    SyncResponder, TraversalBuffers,
};
use aranya_util::{error::ReportExt as _, ready};
use buggy::{BugExt as _, bug};
use derive_where::derive_where;
use tracing::{debug, error, info, instrument, trace, warn};

use super::{
    Addr, Error, SyncHandle, SyncPeer,
    transport::{SyncListener, SyncStream},
};
use crate::{aranya::Client, sync::SyncResponse};

/// Handles listening for connections from peers and responding to them.
///
/// Uses a [`SyncHandle`] to offload hello sync scheduling and operations to the
/// [`SyncManager`](super::SyncManager).
#[derive_where(Debug; SL)]
pub(crate) struct SyncServer<SL, PS, SP> {
    /// The Aranya client and peer cache, alongside invalid graph tracking.
    client: Client<PS, SP>,
    /// The listener that yields incoming streams.
    listener: SL,
    /// Handle to allow sending messages to the manager.
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

        aranya_util::task::scope(async |s| {
            while let Some(stream) = self.listener.accept().await {
                let peer = stream.peer();
                trace!(?peer, "accepted stream");
                let client = self.client.clone();
                let handle = self.handle.clone();
                s.spawn(async move {
                    if let Err(e) = Self::handle_stream(client, handle, stream).await {
                        warn!(?peer, error = %e.report(), "error handling sync request");
                    }
                });
            }
        })
        .await;

        error!("sync server terminated");
    }

    /// Handles an incoming connection, reading data from the peer and responding as needed.
    #[instrument(skip_all, fields(peer = %stream.peer().addr, graph = %stream.peer().graph_id))]
    #[cfg_attr(not(feature = "preview"), expect(unused_variables))]
    async fn handle_stream<S: SyncStream>(
        client: Client<PS, SP>,
        handle: SyncHandle,
        mut stream: S,
    ) -> Result<(), Error> {
        trace!("received sync request");

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE].into_boxed_slice();
        let len = stream.receive(&mut buf).await.map_err(Error::transport)?;
        trace!(len, "received request bytes");

        let buffer = buf.get(..len).assume("valid offset")?;
        let sync_type = SyncIncoming::decode(buffer)?;

        debug!(sync_type = ?std::mem::discriminant(&sync_type), "processing request");

        let response = match sync_type {
            SyncIncoming::Poll(request) => {
                match Self::process_poll_request(&client, stream.peer(), request, &mut buf).await {
                    Ok(len) => {
                        debug!(response_bytes = len, "poll request succeeded");
                        SyncResponse::Ok(buf.get(..len).assume("valid offset")?.into())
                    }
                    Err(e) => {
                        error!(error = %e.report(), "error processing poll message");
                        SyncResponse::Err(e.report().to_string())
                    }
                }
            }
            SyncIncoming::Hello(hello_msg) => {
                #[cfg(not(feature = "preview"))]
                {
                    let _ = hello_msg;
                    bug!("sync hello not enabled")
                }
                #[cfg(feature = "preview")]
                {
                    match Self::process_hello_request(&handle, stream.peer(), hello_msg).await {
                        Ok(()) => {
                            debug!("hello request succeeded");
                            SyncResponse::Ok(Box::new([]))
                        }
                        Err(e) => {
                            error!(error = %e.report(), "error processing hello message");
                            SyncResponse::Err(e.report().to_string())
                        }
                    }
                }
            }
            SyncIncoming::Subscribe { .. }
            | SyncIncoming::Unsubscribe { .. }
            | SyncIncoming::Push { .. } => {
                bug!("message type not currently implemented!")
            }
        };

        let data = postcard::to_slice(&response, &mut buf)?;
        stream.send(data).await.map_err(Error::transport)?;
        stream.finish().await.map_err(Error::transport)?;

        trace!(n = data.len(), "sent response");
        Ok(())
    }

    /// Processes a poll request, generating a response with a sampling of commands.
    async fn process_poll_request(
        client: &Client<PS, SP>,
        peer: SyncPeer,
        request: PollIncoming,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        // peer.check_request(graph_id)?; // TODO: Need to expose graph ID
        let mut resp = SyncResponder::new();
        resp.receive(request)?;
        let (mut aranya, mut caches) = client.lock_aranya_and_caches().await;
        let cache = caches.entry(peer).or_default();

        let len = resp
            .poll(buf, aranya.provider(), cache, &mut TraversalBuffers::new())
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
            .map_err(Error::Runtime)?;

        trace!(response_bytes = len, "generated poll response");
        Ok(len)
    }

    /// Processes a hello request, dispatching an internal message to the
    /// [`SyncManager`](super::SyncManager).
    #[cfg(feature = "preview")]
    pub(super) async fn process_hello_request(
        handle: &SyncHandle,
        peer: SyncPeer,
        hello_msg: SyncHello,
    ) -> Result<(), Error> {
        match hello_msg {
            SyncHello::Subscribe(sub) => {
                peer.check_request(sub.graph_id())?;
                handle
                    .hello_subscribe_request(
                        peer,
                        sub.graph_change_delay(),
                        sub.duration(),
                        sub.schedule_delay(),
                    )
                    .await?;
            }
            SyncHello::Unsubscribe(unsub) => {
                peer.check_request(unsub.graph_id())?;
                handle.hello_unsubscribe_request(peer).await?;
            }
            SyncHello::Hello(hello) => {
                peer.check_request(hello.graph_id())?;
                handle.sync_on_hello(peer, hello.head()).await?;
            }
        }

        Ok(())
    }
}
