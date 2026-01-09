//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with mutual TLS (mTLS) authentication.
//! Both client and server verify each other's certificates against a shared
//! set of trusted root CAs.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::net::SocketAddr;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use aranya_crypto::Rng;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{
    Command, Engine, GraphId, Sink, StorageError, StorageProvider, SyncRequestMessage,
    SyncRequester, SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{error::ReportExt as _, ready, task::{scope, Scope}, Addr};
use buggy::{bug, BugExt as _};
use derive_where::derive_where;
use futures_util::TryFutureExt;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "preview")]
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;
use tracing::{debug, error, info, info_span, instrument, trace, warn, Instrument as _};

use super::{Request, SyncPeers, SyncResponse, SyncState};
use crate::{
    aranya::{ClientWithState, PeerCacheMap},
    daemon::EN,
    sync::{
        task::{PeerCacheKey, Syncer},
        Result as SyncResult, SyncError,
    },
    InvalidGraphs,
};

mod certs;
mod connections;

pub(crate) use connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap};

#[cfg(feature = "preview")]
pub(crate) use super::hello::HelloSubscriptions;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// QUIC Connection error
    #[error("QUIC connection error: {0}")]
    QuicConnectionError(#[from] quinn::ConnectionError),
    /// QUIC Write error
    #[error("QUIC write error: {0}")]
    QuicWriteError(#[from] quinn::WriteError),
    /// QUIC Read error
    #[error("QUIC read error: {0}")]
    QuicReadError(#[from] quinn::ReadToEndError),
    /// QUIC Connect error
    #[error("QUIC connect error: {0}")]
    QuicConnectError(#[from] quinn::ConnectError),
    /// Certificate loading error
    #[error("certificate loading error: {0}")]
    CertificateError(#[source] anyhow::Error),
    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfigError(#[source] anyhow::Error),
    /// QUIC endpoint error
    #[error("QUIC endpoint error: {0}")]
    EndpointError(String),
    /// QUIC connection timeout
    #[error("QUIC connection timed out")]
    QuicConnectionTimeout,
}

/// Certificate configuration for mTLS.
#[derive(Clone, Debug)]
pub struct CertConfig {
    /// Directory containing root CA certificates.
    pub root_certs_dir: PathBuf,
    /// Path to device certificate.
    pub device_cert: PathBuf,
    /// Path to device private key.
    pub device_key: PathBuf,
}

/// Sync configuration for setting up Aranya.
pub(crate) struct SyncParams {
    pub(crate) cert_config: CertConfig,
    pub(crate) server_addr: Addr,
    pub(crate) caches: PeerCacheMap,
}

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub struct State {
    /// QUIC endpoint for both client and server operations.
    endpoint: Endpoint,
    /// Client TLS configuration for outbound connections.
    client_config: quinn::ClientConfig,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    conns: SharedConnectionMap,
}

impl SyncState for State {
    /// Syncs with the peer.
    ///
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    #[instrument(skip_all)]
    async fn sync_impl<S>(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> SyncResult<usize>
    where
        S: Sink<<EN as Engine>::Effect> + Send,
    {
        let (send, recv) = syncer
            .connect(peer)
            .await
            .inspect_err(|e| error!(error = %e.report(), "Could not create connection"))?;

        let mut send = send;
        let mut recv = recv;

        let mut sync_requester = SyncRequester::new(id, &mut Rng, syncer.server_addr);

        // send sync request.
        syncer
            .send_sync_request(&mut send, &mut sync_requester, id, peer)
            .await
            .map_err(|e| SyncError::SendSyncRequest(Box::new(e)))?;

        // receive sync response.
        let cmd_count = syncer
            .receive_sync_response(&mut recv, &mut sync_requester, id, sink, peer)
            .await
            .map_err(|e| SyncError::ReceiveSyncResponse(Box::new(e)))?;

        Ok(cmd_count)
    }

    /// Subscribe to hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn sync_hello_subscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
    ) -> SyncResult<()> {
        syncer
            .send_sync_hello_subscribe_request(
                peer,
                id,
                graph_change_delay,
                duration,
                schedule_delay,
                syncer.server_addr,
            )
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn sync_hello_unsubscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()> {
        syncer
            .send_hello_unsubscribe_request(peer, id, syncer.server_addr)
            .await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[cfg(feature = "preview")]
    #[instrument(skip_all)]
    async fn broadcast_hello_notifications_impl(
        syncer: &mut Syncer<Self>,
        graph_id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        syncer.broadcast_hello_notifications(graph_id, head).await
    }
}

impl State {
    /// Creates a new instance with mTLS configuration.
    async fn new(
        cert_config: &CertConfig,
        conns: SharedConnectionMap,
        client_addr: Addr,
    ) -> SyncResult<Self> {
        // Load certificates
        let root_store = certs::load_root_certs(&cert_config.root_certs_dir)
            .map_err(Error::CertificateError)?;
        let (device_certs, device_key) =
            certs::load_device_cert(&cert_config.device_cert, &cert_config.device_key)
                .map_err(Error::CertificateError)?;

        // Build client TLS config for mTLS
        let mut client_tls_config =
            certs::build_client_config(root_store, device_certs, device_key)
                .map_err(Error::TlsConfigError)?;
        client_tls_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()];

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_config)
                .map_err(|e| Error::TlsConfigError(anyhow::anyhow!("invalid TLS config: {}", e)))?,
        ));

        // Configure transport settings for faster connection handling
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(10)
                .try_into()
                .expect("10 seconds is a valid idle timeout"),
        ));
        client_config.transport_config(Arc::new(transport_config));

        // Create client-only endpoint
        let addr = tokio::net::lookup_host(client_addr.to_socket_addrs())
            .await
            .context("DNS lookup for client address")
            .map_err(|e| SyncError::Other(e.into()))?
            .next()
            .context("could not resolve client address")
            .map_err(|e| SyncError::Other(e.into()))?;

        let endpoint = Endpoint::client(addr)
            .map_err(|e| Error::EndpointError(format!("failed to create client endpoint: {e}")))?;

        debug!("created QUIC client endpoint with mTLS");

        Ok(Self {
            endpoint,
            client_config,
            conns,
        })
    }
}

impl Syncer<State> {
    /// Creates a new [`Syncer`].
    pub(crate) async fn new(
        client: ClientWithState<EN, crate::SP>,
        send_effects: super::EffectSender,
        invalid: InvalidGraphs,
        cert_config: &CertConfig,
        (server_addr, client_addr): (Addr, Addr),
        recv: mpsc::Receiver<Request>,
        conns: SharedConnectionMap,
    ) -> SyncResult<Self> {
        let state = State::new(cert_config, conns.clone(), client_addr).await?;

        Ok(Self {
            client,
            peers: HashMap::new(),
            recv,
            queue: DelayQueue::new(),
            send_effects,
            invalid,
            state,
            server_addr,
            #[cfg(feature = "preview")]
            hello_tasks: tokio::task::JoinSet::new(),
        })
    }

    /// Establishes a QUIC connection to a peer and opens a bidirectional stream.
    ///
    /// This method first checks if there's an existing connection to the peer.
    /// If not, it creates a new QUIC connection. Then it opens a bidirectional
    /// stream for sending sync requests and receiving responses.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to connect to
    ///
    /// # Returns
    /// * `Ok((SendStream, RecvStream))` if the connection and stream were established successfully
    /// * `Err(SyncError)` if there was an error connecting or opening the stream
    #[instrument(skip_all)]
    pub(crate) async fn connect(&mut self, peer: &Addr) -> SyncResult<(SendStream, RecvStream)> {
        trace!("client connecting to QUIC sync server");

        let addr = tokio::net::lookup_host(peer.to_socket_addrs())
            .await
            .context("DNS lookup for peer address")?
            .next()
            .context("could not resolve peer address")?;

        let key = ConnectionKey::new(addr);
        let endpoint = &self.state.endpoint;
        let client_config = self.state.client_config.clone();

        let conn = self
            .state
            .conns
            .get_or_try_insert_with(key, async || {
                let connecting = endpoint
                    .connect_with(client_config, addr, &addr.ip().to_string())
                    .map_err(Error::from)?;

                // Add timeout to connection attempt to avoid hanging on failed TLS handshakes
                let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
                    .await
                    .map_err(|_| Error::QuicConnectionTimeout)?
                    .map_err(Error::from)?;

                debug!("established new QUIC connection to peer");
                Ok::<_, Error>(conn)
            })
            .await?;

        trace!("client connected to QUIC sync server");

        let (send, recv) = conn
            .open_bi()
            .await
            .inspect_err(|e| error!(error = %e, "unable to open bidi stream"))
            .map_err(|e| {
                // If the stream fails to open, the connection may be closed
                if conn.close_reason().is_some() {
                    // Remove the closed connection
                    let mut conns = self.state.conns.clone();
                    let conn_clone = conn.clone();
                    tokio::spawn(async move {
                        conns.remove(key, conn_clone).await;
                    });
                }
                SyncError::QuicSync(Error::QuicConnectionError(e))
            })?;

        trace!("client opened bidi stream with QUIC sync server");
        Ok((send, recv))
    }

    /// Sends a sync request to a peer over an established QUIC stream.
    #[instrument(skip_all)]
    pub(crate) async fn send_sync_request<A>(
        &self,
        send: &mut SendStream,
        syncer: &mut SyncRequester<A>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()>
    where
        A: Serialize + DeserializeOwned + Clone,
    {
        trace!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = self.client.lock_aranya_and_caches().await;
            let key = PeerCacheKey::new(*peer, id);
            let cache = caches.entry(key).or_default();
            let (len, _) = syncer
                .poll(&mut send_buf, aranya.provider(), cache)
                .context("sync poll failed")?;
            trace!(?len, "sync poll finished");
            len
        };
        send_buf.truncate(len);

        send.write_all(&send_buf)
            .await
            .map_err(Error::QuicWriteError)?;
        send.finish().map_err(|_| {
            Error::QuicWriteError(quinn::WriteError::ConnectionLost(
                quinn::ConnectionError::LocallyClosed,
            ))
        })?;
        trace!("sent sync request");

        Ok(())
    }

    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    #[instrument(skip_all)]
    pub async fn receive_sync_response<S, A>(
        &self,
        recv: &mut RecvStream,
        syncer: &mut SyncRequester<A>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> SyncResult<usize>
    where
        S: Sink<<EN as Engine>::Effect>,
        A: Serialize + DeserializeOwned + Clone,
    {
        trace!("client receiving sync response from QUIC sync server");

        let recv_buf = recv
            .read_to_end(MAX_SYNC_MESSAGE_SIZE)
            .await
            .map_err(Error::QuicReadError)?;
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
                let mut trx = aranya.transaction(id);
                aranya
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                aranya.commit(&mut trx, sink).context("commit failed")?;
                trace!("committed");
                let key = PeerCacheKey::new(*peer, id);
                let cache = caches.entry(key).or_default();
                aranya
                    .update_heads(id, cmds.iter().filter_map(|cmd| cmd.address().ok()), cache)
                    .context("failed to update cache heads")?;
                return Ok(cmds.len());
            }
        }

        Ok(0)
    }
}

/// The Aranya QUIC sync server.
///
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive_where(Debug)]
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client paired with caches and hello subscriptions, ensuring safe lock ordering.
    client: ClientWithState<EN, SP>,
    /// QUIC endpoint for accepting connections.
    endpoint: Endpoint,
    /// Connection map shared with [`super::Syncer`]
    conns: SharedConnectionMap,
    /// Receives updates for connections inserted into the [connection map][`Self::conns`].
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    /// Interface to trigger sync operations
    _sync_peers: SyncPeers,
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Returns a reference to the hello subscriptions for hello notification broadcasting.
    #[cfg(feature = "preview")]
    pub fn hello_subscriptions(&self) -> Arc<Mutex<HelloSubscriptions>> {
        Arc::clone(self.client.hello_subscriptions())
    }

    /// Creates a new `Server`.
    ///
    /// # Panics
    ///
    /// Will panic if called outside tokio runtime.
    pub(crate) async fn new(
        client: ClientWithState<EN, SP>,
        addr: &Addr,
        cert_config: &CertConfig,
    ) -> SyncResult<(
        Self,
        SyncPeers,
        SharedConnectionMap,
        mpsc::Receiver<Request>,
        SocketAddr,
    )> {
        // Create shared connection map and channel for connection updates
        let (conns, server_conn_rx) = SharedConnectionMap::new();

        // Create channel for SyncPeers communication with Syncer
        let (send, syncer_recv) = mpsc::channel::<Request>(128);
        let sync_peers = SyncPeers::new(send);

        // Load certificates
        let root_store = certs::load_root_certs(&cert_config.root_certs_dir)
            .map_err(Error::CertificateError)?;
        let (device_certs, device_key) =
            certs::load_device_cert(&cert_config.device_cert, &cert_config.device_key)
                .map_err(Error::CertificateError)?;

        // Build server TLS config for mTLS (requires client certs)
        let mut server_tls_config =
            certs::build_server_config(root_store, device_certs, device_key)
                .map_err(Error::TlsConfigError)?;
        server_tls_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()];

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)
                .map_err(|e| Error::TlsConfigError(anyhow::anyhow!("invalid TLS config: {}", e)))?,
        ));

        // Configure transport settings for faster connection handling
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(10)
                .try_into()
                .expect("10 seconds is a valid idle timeout"),
        ));
        server_config.transport_config(Arc::new(transport_config));

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

        debug!("created QUIC server endpoint with mTLS at {}", local_addr);

        let server_instance = Self {
            client,
            endpoint,
            conns: conns.clone(),
            conn_rx: server_conn_rx,
            _sync_peers: sync_peers.clone(),
        };

        Ok((server_instance, sync_peers, conns, syncer_recv, local_addr))
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.endpoint.local_addr().ok()))]
    #[allow(clippy::disallowed_macros, reason = "tokio::select! uses unreachable!")]
    pub async fn serve(mut self, ready: ready::Notifier) {
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
        s: &mut Scope,
    ) {
        let conns = self.conns.clone();
        let client = self.client.clone();
        let sync_peers = self._sync_peers.clone();

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
        let sync_peers = self._sync_peers.clone();
        Self::serve_connection_inner(key, conn, client, sync_peers)
    }

    async fn serve_connection_inner(
        key: ConnectionKey,
        conn: Connection,
        client: ClientWithState<EN, SP>,
        sync_peers: SyncPeers,
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
        client: ClientWithState<EN, SP>,
        peer: Addr,
        mut send: SendStream,
        mut recv: RecvStream,
        sync_peers: SyncPeers,
    ) -> SyncResult<()> {
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
            send.write_all(&data)
                .await
                .map_err(Error::QuicWriteError)?;
            data_len
        };
        send.finish().ok();
        trace!(n = data_len, "server sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: ClientWithState<EN, SP>,
        addr: Addr,
        request_data: &[u8],
        _sync_peers: SyncPeers,
    ) -> SyncResult<Box<[u8]>> {
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
            } => {
                Self::process_poll_message(request_msg, client, addr, peer_server_addr).await
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
        client: ClientWithState<EN, SP>,
        peer_addr: Addr,
        peer_server_addr: Addr,
    ) -> SyncResult<Box<[u8]>> {
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
            let key = PeerCacheKey::new(peer_server_addr, storage_id);
            let cache = caches.entry(key).or_default();

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
