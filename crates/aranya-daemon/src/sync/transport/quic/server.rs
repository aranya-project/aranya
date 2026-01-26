//! QUIC server for accepting sync requests from peers.

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context as _;
use aranya_runtime::{
    Engine, StorageError, StorageProvider, SyncRequestMessage, SyncResponder, SyncType,
    MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready, task::scope, Addr};
use buggy::{bug, BugExt as _};
use derive_where::derive_where;
use futures_util::TryFutureExt;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::mpsc;
#[cfg(feature = "preview")]
use tokio::sync::Mutex;
use tracing::{debug, error, info, info_span, instrument, trace, warn, Instrument as _};

use super::{
    certs, keep_alive_transport_config, CertConfig, ConnectionKey, ConnectionUpdate, Error,
    SharedConnectionMap, ALPN_QUIC_SYNC,
};
#[cfg(feature = "preview")]
use crate::sync::HelloSubscriptions;
use crate::{
    aranya::Client,
    sync::{Callback, Result, SyncHandle, SyncPeer, SyncResponse},
};

/// The Aranya QUIC sync server.
///
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive_where(Debug)]
pub(crate) struct Server<EN, SP> {
    /// Thread-safe Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    client: Client<EN, SP>,
    /// QUIC endpoint for accepting connections.
    endpoint: Endpoint,
    /// Connection map shared with [`SyncManager`]
    conns: SharedConnectionMap,
    /// Receives updates for connections inserted into the [connection map][`Self::conns`].
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    /// Handle for triggering sync on hello notifications.
    /// Only used when the "preview" feature is enabled for hello sync protocol.
    hello_sync_handle: SyncHandle,
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Returns the local address the server is listening on.
    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Returns a reference to the hello subscriptions for hello notification broadcasting.
    #[cfg(feature = "preview")]
    #[allow(dead_code)]
    pub fn hello_subscriptions(&self) -> Arc<Mutex<HelloSubscriptions>> {
        self.client.hello_subscriptions()
    }

    /// Creates a new `Server`.
    ///
    /// Creates a unified QUIC endpoint that serves both as a server (accepting incoming
    /// connections) and can be used by the SyncManager as a client (making outbound connections).
    /// Using a single endpoint bound to the server address ensures that when we connect
    /// to peers, our source address is our server address, enabling bidirectional
    /// connection reuse.
    ///
    /// # Panics
    ///
    /// Will panic if called outside tokio runtime.
    pub(crate) async fn new(
        client: Client<EN, SP>,
        addr: &Addr,
        cert_config: &CertConfig,
    ) -> Result<(
        Self,
        SyncHandle,
        SharedConnectionMap,
        mpsc::Receiver<Callback>,
        Endpoint,
        quinn::ClientConfig,
    )> {
        // Create shared connection map and channel for connection updates
        let (conns, server_conn_rx) = SharedConnectionMap::new();

        // Create channel for SyncHandle communication with SyncManager
        let (send, syncer_recv) = mpsc::channel::<Callback>(128);
        let sync_peers = SyncHandle::new(send);

        // Load certificates once for both client and server configs
        let (root_store, device_certs, device_key) =
            certs::load_certs(cert_config).map_err(Error::from)?;

        // Build server TLS config for mTLS (requires client certs)
        let mut server_tls_config = certs::build_server_config(
            root_store.clone(),
            device_certs.clone(),
            device_key.clone_key(),
        )
        .map_err(Error::from)?;
        server_tls_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()];

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)
                .map_err(|e| Error::EndpointError(format!("invalid QUIC TLS config: {e}")))?,
        ));

        server_config.transport_config(keep_alive_transport_config());

        // Build client TLS config for mTLS (for outbound connections)
        let mut client_tls_config =
            certs::build_client_config(root_store, device_certs, device_key)
                .map_err(Error::from)?;
        client_tls_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()];

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_config)
                .map_err(|e| Error::EndpointError(format!("invalid QUIC TLS config: {e}")))?,
        ));

        client_config.transport_config(keep_alive_transport_config());

        let bind_addr = tokio::net::lookup_host(addr.to_socket_addrs())
            .await
            .context("DNS lookup for server address")?
            .next()
            .assume("invalid server address")?;

        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| Error::EndpointError(format!("failed to create server endpoint: {e}")))?;

        let local_addr = endpoint
            .local_addr()
            .map_err(|e| Error::EndpointError(format!("unable to get local address: {e}")))?;

        debug!("created unified QUIC endpoint with mTLS at {}", local_addr);

        let server_instance = Self {
            client,
            endpoint: endpoint.clone(),
            conns: conns.clone(),
            conn_rx: server_conn_rx,
            hello_sync_handle: sync_peers.clone(),
        };

        Ok((
            server_instance,
            sync_peers,
            conns,
            syncer_recv,
            endpoint,
            client_config,
        ))
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.endpoint.local_addr().ok()))]
    #[allow(clippy::disallowed_macros, reason = "tokio::select! uses unreachable!")]
    pub(crate) async fn serve(mut self, ready: ready::Notifier) {
        info!("QUIC sync server listening for incoming connections");

        ready.notify();

        scope(async |s| {
            loop {
                tokio::select! {
                    // Accept incoming QUIC connections.
                    Some(incoming) = self.endpoint.accept() => {
                        self.accept_connection(incoming, s).await;
                    },
                    // Handle new connections inserted in the map
                    Some((key, conn)) = self.conn_rx.recv() => {
                        s.spawn(self.serve_connection(key, conn));
                    }
                    else => break,
                }
            }
        })
        .await;

        error!("server terminated");
    }

    async fn accept_connection(
        &mut self,
        incoming: quinn::Incoming,
        s: &mut aranya_util::task::Scope,
    ) {
        let conns = self.conns.clone();
        let client = self.client.clone();
        let sync_peers = self.hello_sync_handle.clone();

        s.spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    trace!("received incoming QUIC connection");
                    let peer = conn.remote_address();
                    let key = ConnectionKey::new(peer);

                    // Insert connection into map
                    let mut conns = conns;
                    let conn = conns.insert(key, conn).await;

                    // Serve the connection
                    Self::serve_connection_inner(key, conn, client, sync_peers).await;
                }
                Err(e) => {
                    error!(error = %e, "failed to accept QUIC connection");
                }
            }
        });
    }

    fn serve_connection(
        &mut self,
        key: ConnectionKey,
        conn: Connection,
    ) -> impl std::future::Future<Output = ()> {
        let client = self.client.clone();
        let sync_peers = self.hello_sync_handle.clone();
        Self::serve_connection_inner(key, conn, client, sync_peers)
    }

    async fn serve_connection_inner(
        key: ConnectionKey,
        conn: Connection,
        client: Client<EN, SP>,
        sync_peers: SyncHandle,
    ) {
        let peer = key.addr;
        async move {
            // Accept incoming streams.
            while let Ok((send, recv)) = conn.accept_bi().await {
                trace!("received incoming QUIC stream");
                if let Err(e) =
                    Self::sync(client.clone(), peer.into(), send, recv, sync_peers.clone()).await
                {
                    error!(error = %e.report(), "failed to process sync request");
                }
            }
            debug!("connection closed");
            anyhow::Ok(())
        }
        .unwrap_or_else(|err: anyhow::Error| {
            error!(error = %err, "server unable to respond to sync request from peer");
        })
        .instrument(info_span!("serve_connection", %peer))
        .await
    }

    /// Responds to a sync.
    #[instrument(skip_all)]
    pub(crate) async fn sync(
        client: Client<EN, SP>,
        peer: Addr,
        mut send: SendStream,
        mut recv: RecvStream,
        sync_peers: SyncHandle,
    ) -> Result<()> {
        trace!("server received a sync request");

        let recv_buf = recv
            .read_to_end(MAX_SYNC_MESSAGE_SIZE)
            .await
            .map_err(Error::QuicReadError)?;
        trace!(n = recv_buf.len(), "received sync request");

        // Generate a sync response for a sync request.
        let sync_response_res = Self::sync_respond(client, peer, &recv_buf, sync_peers).await;
        let resp = match sync_response_res {
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
            send.write_all(&data).await.map_err(Error::QuicWriteError)?;
            data_len
        };
        send.finish().ok();
        trace!(n = data_len, "server sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: Client<EN, SP>,
        addr: Addr,
        request_data: &[u8],
        _sync_peers: SyncHandle,
    ) -> Result<Box<[u8]>> {
        trace!("server responding to sync request");

        let sync_type: SyncType<Addr> = postcard::from_bytes(request_data).map_err(|e| {
            error!(
                error = %e,
                request_data_len = request_data.len(),
                ?addr,
                "Failed to deserialize sync request"
            );
            anyhow::anyhow!(e)
        })?;

        match sync_type {
            SyncType::Poll {
                request: request_msg,
                address: peer_server_addr,
            } => Self::process_poll_message(request_msg, client, addr, peer_server_addr).await,
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
                    Self::process_hello_message(_hello_msg, client, addr, _sync_peers).await;
                    // Hello messages are fire-and-forget, return empty response
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
        client: Client<EN, SP>,
        peer_addr: Addr,
        peer_server_addr: Addr,
    ) -> Result<Box<[u8]>> {
        trace!("server responding to sync request");

        // Extract the storage_id (GraphId) from the request
        let SyncRequestMessage::SyncRequest { storage_id, .. } = &request_msg else {
            bug!("Should be a SyncRequest")
        };
        let storage_id = *storage_id;

        let mut resp = SyncResponder::new(peer_addr);

        resp.receive(request_msg).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = client.lock_aranya_and_caches().await;
            let peer = SyncPeer {
                addr: peer_server_addr,
                graph_id: storage_id,
            };
            let cache = caches.entry(peer).or_default();

            resp.poll(&mut buf, aranya.provider(), cache)
                .or_else(|err| {
                    if matches!(
                        err,
                        aranya_runtime::SyncError::Storage(StorageError::NoSuchStorage)
                    ) {
                        warn!(storage_id = %storage_id, "missing requested graph, we likely have not synced yet");
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
