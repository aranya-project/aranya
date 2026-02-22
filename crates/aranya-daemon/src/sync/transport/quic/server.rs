use std::{future::Future, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context as _};
use aranya_daemon_api::TeamId;
use aranya_runtime::{
    PolicyStore, StorageError, StorageProvider, SyncRequestMessage, SyncResponder, SyncType,
    MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{
    error::ReportExt as _, ready, rustls::NoCertResolver, s2n_quic::get_conn_identity, task::scope,
};
use buggy::{bug, BugExt as _};
use bytes::Bytes;
use derive_where::derive_where;
use futures_util::{AsyncReadExt as _, TryFutureExt as _};
use s2n_quic::{
    application,
    connection::StreamAcceptor,
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{
            self as rustls_provider,
            rustls::{server::PresharedKeySelection, ServerConfig},
        },
    },
    stream::BidirectionalStream,
};
use tokio::sync::mpsc;
use tracing::{error, info, info_span, instrument, trace, warn, Instrument as _};

use super::{ConnectionUpdate, PskStore, SharedConnectionMap, ALPN_QUIC_SYNC};
use crate::{
    aranya::Client,
    sync::{
        transport::quic, Addr, Callback, Error, GraphId, Result, SyncHandle, SyncPeer, SyncResponse,
    },
};

/// Upper bound for wire-encoded sync request/response envelopes.
///
/// `MAX_SYNC_MESSAGE_SIZE` bounds runtime sync payloads; the wire envelope adds a small
/// serialization overhead.
const MAX_SYNC_WIRE_MESSAGE_SIZE: usize = MAX_SYNC_MESSAGE_SIZE.saturating_add(1024);

/// The Aranya QUIC sync server.
///
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive_where(Debug)]
pub(crate) struct Server<PS, SP> {
    /// Thread-safe Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    client: Client<PS, SP>,
    /// QUIC server to handle sync requests and send sync responses.
    server: s2n_quic::Server,
    server_keys: Arc<PskStore>,
    /// Connection map shared with [`super::SyncManager`]
    conns: SharedConnectionMap,
    /// Receives updates for connections inserted into the [connection map][`Self::conns`].
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    /// Interface to trigger sync operations
    handle: SyncHandle,
    /// The address we're currently serving on.
    local_addr: SocketAddr,
}

impl<PS, SP> Server<PS, SP>
where
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
{
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Creates a new `Server`.
    ///
    /// # Panics
    ///
    /// Will panic if called outside tokio runtime.
    ///
    /// Will panic on poisoned internal mutexes.
    #[inline]
    #[allow(deprecated)]
    pub(crate) async fn new(
        client: Client<PS, SP>,
        addr: &Addr,
        server_keys: Arc<PskStore>,
    ) -> Result<(
        Self,
        SyncHandle,
        SharedConnectionMap,
        mpsc::Receiver<Callback>,
    )> {
        // Create shared connection map and channel for connection updates
        let (conns, server_conn_rx) = SharedConnectionMap::new();

        // Create channel for SyncHandle communication with SyncManager
        let (send, syncer_recv) = mpsc::channel::<Callback>(128);
        let sync_peers = SyncHandle::new(send);

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        let tls_server_provider = rustls_provider::Server::new(server_config);

        let addr = tokio::net::lookup_host(addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .assume("invalid server address")?;
        // Use the rustls server provider
        let server = s2n_quic::Server::builder()
            .with_tls(tls_server_provider)?
            .with_io(addr)
            .assume("can set sync server addr")?
            .with_congestion_controller(Bbr::default())?
            .start()
            .map_err(quic::Error::ServerStart)?;

        let local_addr = server
            .local_addr()
            .context("unable to get server local address")?;

        let server_instance = Self {
            client,
            server,
            server_keys,
            conns: conns.clone(),
            conn_rx: server_conn_rx,
            handle: sync_peers.clone(),
            local_addr,
        };

        Ok((server_instance, sync_peers, conns, syncer_recv))
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.local_addr))]
    #[allow(clippy::disallowed_macros, reason = "tokio::select! uses unreachable!")]
    pub(crate) async fn serve(mut self, ready: ready::Notifier) {
        info!("QUIC sync server listening for incoming connections");

        ready.notify();

        scope(async |s| {
            loop {
                tokio::select! {
                    // Accept incoming QUIC connections.
                    Some(conn) = self.server.accept() => {
                        self.accept_connection(conn).await;
                    },
                    // Handle new connections inserted in the map
                    Some((peer, acceptor)) = self.conn_rx.recv() => {
                        s.spawn(self.serve_connection(peer, acceptor));
                    }
                    else => break,
                }
            }
        })
        .await;

        error!("server terminated");
    }

    fn accept_connection(
        &mut self,
        mut conn: s2n_quic::Connection,
    ) -> impl Future<Output = ()> + use<'_, PS, SP> {
        let handle = conn.handle();
        async {
            trace!("received incoming QUIC connection");
            conn.keep_alive(true)
                .context("unable to keep connection alive")?;
            let identity = get_conn_identity(&mut conn)?;
            let active_team = self
                .server_keys
                .get_team_for_identity(&identity)
                .context("no active team for accepted connection")?;
            let peer = SyncPeer::new(
                extract_return_address(&mut conn)
                    .await
                    .context("could not get peer's return address")?,
                GraphId::transmute(active_team),
            );
            self.conns.insert(peer, conn).await;
            anyhow::Ok(())
        }
        .unwrap_or_else(move |err| {
            error!(error = ?err, "server unable to accept connection");
            handle.close(application::Error::UNKNOWN);
        })
    }

    fn serve_connection(
        &mut self,
        peer: SyncPeer,
        mut acceptor: StreamAcceptor,
    ) -> impl Future<Output = ()> {
        let active_team = TeamId::transmute(peer.graph_id);
        let conn_source = peer.addr;
        let client = self.client.clone();
        let sync_peers = self.handle.clone();
        async move {
            // Accept incoming streams.
            while let Some(stream) = acceptor
                .accept_bidirectional_stream()
                .await
                .context("could not receive QUIC stream")?
            {
                trace!("received incoming QUIC stream");
                Self::sync(
                    client.clone(),
                    stream,
                    active_team,
                    sync_peers.clone(),
                    conn_source,
                )
                .await
                .context("failed to process sync request")?;
            }
            anyhow::Ok(())
        }
        .unwrap_or_else(|err| {
            error!(error = ?err, "server unable to respond to sync request from peer");
        })
        .instrument(info_span!("serve_connection", %conn_source))
    }

    /// Responds to a sync.
    #[instrument(skip_all)]
    async fn sync(
        client: Client<PS, SP>,
        stream: BidirectionalStream,
        active_team: TeamId,
        handle: SyncHandle,
        peer_server_addr: Addr,
    ) -> Result<()> {
        trace!("server received a sync request");

        let mut recv_buf = Vec::new();
        let (recv, mut send) = stream.split();
        recv.take((MAX_SYNC_WIRE_MESSAGE_SIZE as u64) + 1)
            .read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync request")?;
        if recv_buf.len() > MAX_SYNC_WIRE_MESSAGE_SIZE {
            return Err(anyhow!(
                "sync request too large: {} > {} bytes",
                recv_buf.len(),
                MAX_SYNC_WIRE_MESSAGE_SIZE
            )
            .into());
        }
        trace!(n = recv_buf.len(), "received sync request");

        // Generate a sync response for a sync request.
        let sync_response_res =
            Self::sync_respond(client, &recv_buf, active_team, handle, peer_server_addr).await;
        let resp: SyncResponse = match sync_response_res {
            Ok(data) => SyncResponse::Ok(data),
            Err(err) => {
                let error = err.report().to_string();
                error!(%error, "error responding to sync request");
                SyncResponse::Err(error)
            }
        };

        let data_len = {
            let data = postcard::to_allocvec(&resp).context("postcard serialization failed")?;
            let data_len = data.len();
            send.send(Bytes::from(data))
                .await
                .context("Could not send sync response")?;
            data_len
        };
        send.close().await.ok();
        trace!(n = data_len, "server sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: Client<PS, SP>,
        request_data: &[u8],
        active_team: TeamId,
        _handle: SyncHandle,
        peer_server_addr: Addr,
    ) -> Result<Box<[u8]>> {
        trace!("server responding to sync request");

        let sync_type: SyncType = postcard::from_bytes(request_data).map_err(|e| {
            error!(
                error = %e,
                request_data_len = request_data.len(),
                ?active_team,
                "Failed to deserialize sync request"
            );
            anyhow::anyhow!(e)
        })?;

        match sync_type {
            SyncType::Poll {
                request: request_msg,
            } => {
                Self::process_poll_message(request_msg, client, peer_server_addr, &active_team)
                    .await
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
            SyncType::Hello(_hello_msg) => {
                #[cfg(feature = "preview")]
                {
                    if let Err(error) = Self::process_hello_message(
                        _hello_msg,
                        client,
                        &active_team,
                        _handle,
                        peer_server_addr,
                    )
                    .await
                    {
                        // TODO: Respond with error or don't respond?
                        error!(%error, "Failed to process hello message");
                    }
                    // Hello messages are fire-and-forget, return empty response
                    // Note: returning empty response which will be ignored by client
                    return Ok(Box::new([]));
                }
                #[cfg(not(feature = "preview"))]
                bug!("sync hello not enabled")
            }
        }
    }

    /// Processes a poll message.
    ///
    /// Handles sync poll requests and generates sync responses.
    #[instrument(skip_all)]
    async fn process_poll_message(
        request_msg: SyncRequestMessage,
        client: Client<PS, SP>,
        peer_server_addr: Addr,
        active_team: &TeamId,
    ) -> Result<Box<[u8]>> {
        let mut resp = SyncResponder::new();
        let storage_id = check_request(*active_team, &request_msg)?;
        let peer = SyncPeer::new(peer_server_addr, storage_id);

        resp.receive(request_msg).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = client.lock_aranya_and_caches().await;
            let cache = caches.entry(peer).or_default();

            resp.poll(&mut buf, aranya.provider(), cache)
                .or_else(|err| {
                    if matches!(
                        err,
                        aranya_runtime::SyncError::Storage(StorageError::NoSuchStorage)
                    ) {
                        warn!(team = %active_team, "missing requested graph, we likely have not synced yet");
                        Ok(0)
                    } else {
                        Err(err)
                    }
                })
                .context("sync resp poll failed")?
        };
        trace!(len = len, "sync poll finished");
        buf.truncate(len);
        Ok(buf.into())
    }
}

async fn extract_return_address(conn: &mut s2n_quic::Connection) -> anyhow::Result<Addr> {
    let ip = conn
        .remote_addr()
        .context("cannot get remote address")?
        .ip();
    let port = {
        let mut recv = conn
            .accept_receive_stream()
            .await?
            .context("no stream for return port")?;
        let bytes = recv.receive().await?.context("no return port sent")?;
        u16::from_be_bytes(
            bytes
                .as_ref()
                .try_into()
                .context("bad return port message")?,
        )
    };
    Ok(Addr::from((ip, port)))
}

fn check_request(team_id: TeamId, request: &SyncRequestMessage) -> Result<GraphId> {
    let SyncRequestMessage::SyncRequest { graph_id, .. } = request else {
        bug!("Should be a SyncRequest")
    };
    if team_id.as_bytes() != graph_id.as_bytes() {
        return Err(Error::QuicSync(quic::Error::InvalidPSK));
    }

    Ok(*graph_id)
}
