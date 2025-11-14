//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::net::SocketAddr;
#[cfg(feature = "preview")]
use std::time::Duration;
use std::{collections::HashMap, convert::Infallible, future::Future, sync::Arc};

use anyhow::Context;
use aranya_crypto::Rng;
use aranya_daemon_api::TeamId;
#[cfg(feature = "preview")]
use aranya_runtime::Address;
use aranya_runtime::{
    Command, Engine, GraphId, Sink, StorageError, StorageProvider, SyncRequestMessage,
    SyncRequester, SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{
    error::ReportExt as _,
    ready,
    rustls::{NoCertResolver, SkipServerVerification},
    s2n_quic::get_conn_identity,
    task::scope,
    Addr,
};
use buggy::{bug, BugExt as _};
use bytes::Bytes;
use derive_where::derive_where;
use futures_util::TryFutureExt;
#[allow(deprecated)]
use s2n_quic::provider::tls::rustls::rustls::{
    server::PresharedKeySelection, ClientConfig, ServerConfig,
};
use s2n_quic::{
    application::Error as AppError,
    client::Connect,
    connection::{Error as ConnErr, StreamAcceptor},
    provider::{congestion_controller::Bbr, tls::rustls as rustls_provider, StartError},
    stream::{BidirectionalStream, ReceiveStream, SendStream},
    Client as QuicClient, Server as QuicServer,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::time::DelayQueue;
use tracing::{error, info, info_span, instrument, trace, warn, Instrument as _};

use super::{Request, SyncPeers, SyncResponse, SyncState};
use crate::{
    aranya::Client,
    daemon::EN,
    sync::{
        task::{PeerCacheKey, Syncer},
        Result as SyncResult, SyncError,
    },
    SP,
};

mod connections;
mod psk;

pub(crate) use connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap};
pub(crate) use psk::PskSeed;
pub use psk::PskStore;

#[cfg(feature = "preview")]
pub(crate) use super::hello::HelloSubscriptions;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// QUIC Connection error
    #[error(transparent)]
    QuicConnectionError(#[from] s2n_quic::connection::Error),
    /// QUIC Stream error
    #[error(transparent)]
    QuicStreamError(#[from] s2n_quic::stream::Error),
    /// Invalid PSK used for syncing
    #[error("invalid PSK used when attempting to sync")]
    InvalidPSK,
    /// QUIC client endpoint start error
    #[error("could not start QUIC client")]
    ClientStart(#[source] StartError),
    /// QUIC server endpoint start error
    #[error("could not start QUIC server")]
    ServerStart(#[source] StartError),
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

/// Sync configuration for setting up Aranya.
pub(crate) struct SyncParams {
    pub(crate) psk_store: Arc<PskStore>,
    pub(crate) server_addr: Addr,
}

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub struct State {
    /// QUIC client to make sync requests to another peer's sync server and handle sync responses.
    client: QuicClient,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    conns: SharedConnectionMap,
    /// PSK store shared between the daemon API server and QUIC syncer client and server.
    /// This store is modified by [`crate::api::DaemonApiServer`].
    store: Arc<PskStore>,
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
        // Sets the active team before starting a QUIC connection
        syncer.state.store.set_team(TeamId::transmute(id));

        let stream = syncer
            .connect(peer, id)
            .await
            .inspect_err(|e| error!(error = %e.report(), "Could not create connection"))?;
        // TODO: spawn a task for send/recv?
        let (mut recv, mut send) = stream.split();

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
        syncer.state.store().set_team(TeamId::transmute(id));
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
        syncer.state.store().set_team(TeamId::transmute(id));
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
    /// Get a reference to the PSK store
    pub fn store(&self) -> &Arc<PskStore> {
        &self.store
    }

    /// Creates a new instance
    fn new(
        psk_store: Arc<PskStore>,
        conns: SharedConnectionMap,
        client_addr: Addr,
    ) -> SyncResult<Self> {
        // Create client config (INSECURE: skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = psk_store.clone(); // Pass the Arc<ClientPresharedKeys>

        // Client builder doesn't support adding preshared keys
        #[allow(deprecated)]
        let provider = rustls_provider::Client::new(client_config);

        let client = QuicClient::builder()
            .with_tls(provider)?
            .with_io((client_addr.host(), client_addr.port()))
            .assume("can set quic client address")?
            .start()
            .map_err(Error::ClientStart)?;

        Ok(Self {
            client,
            conns,
            store: psk_store,
        })
    }
}

impl Syncer<State> {
    /// Creates a new [`Syncer`].
    pub(crate) fn new(
        client: Client<EN, SP>,
        send_effects: super::EffectSender,
        psk_store: Arc<PskStore>,
        (server_addr, client_addr): (Addr, Addr),
        recv: mpsc::Receiver<Request>,
        conns: SharedConnectionMap,
    ) -> SyncResult<Self> {
        let state = State::new(psk_store, conns.clone(), client_addr)?;

        Ok(Self {
            client,
            peers: HashMap::new(),
            recv,
            queue: DelayQueue::new(),
            send_effects,
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
    /// * `id` - The graph ID for the team/graph to sync with
    ///
    /// # Returns
    /// * `Ok(BidirectionalStream)` if the connection and stream were established successfully
    /// * `Err(SyncError)` if there was an error connecting or opening the stream
    #[instrument(skip_all)]
    pub(crate) async fn connect(
        &mut self,
        peer: &Addr,
        id: GraphId,
    ) -> SyncResult<BidirectionalStream> {
        trace!("client connecting to QUIC sync server");
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.

        let addr = tokio::net::lookup_host(peer.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .context("could not resolve peer address")?;

        let key = ConnectionKey { addr, id };
        let client = &self.state.client;

        let mut handle = self
            .state
            .conns
            .get_or_try_insert_with(key, async || {
                let mut conn = client
                    .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                    .await?;
                conn.keep_alive(true)?;
                Ok(conn)
            })
            .await?;

        trace!("client connected to QUIC sync server");

        let open_stream_res = handle
            .open_bidirectional_stream()
            .await
            .inspect_err(|e| error!(error = %e.report(), "unable to open bidi stream"));
        let stream = match open_stream_res {
            Ok(stream) => stream,
            // Retry for these errors?
            Err(e @ ConnErr::StatelessReset { .. })
            | Err(e @ ConnErr::StreamIdExhausted { .. })
            | Err(e @ ConnErr::MaxHandshakeDurationExceeded { .. }) => {
                return Err(SyncError::QuicSync(e.into()));
            }
            // Other errors means the stream has closed
            Err(e) => {
                self.state.conns.remove(key, handle).await;
                return Err(SyncError::QuicSync(e.into()));
            }
        };

        trace!("client opened bidi stream with QUIC sync server");
        Ok(stream)
    }

    /// Sends a sync request to a peer over an established QUIC stream.
    ///
    /// This method uses the SyncRequester to generate the sync request data,
    /// serializes it, and sends it over the provided QUIC send stream.
    ///
    /// # Arguments
    /// * `send` - The QUIC send stream to use for sending the request
    /// * `syncer` - The SyncRequester instance that generates the sync request
    /// * `id` - The graph ID for the team/graph to sync
    /// * `peer` - The network address of the peer
    ///
    /// # Returns
    /// * `Ok(())` if the sync request was sent successfully
    /// * `Err(SyncError)` if there was an error generating or sending the request
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

        send.send(Bytes::from(send_buf))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;
        trace!("sent sync request");

        Ok(())
    }

    #[instrument(skip_all)]
    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    pub async fn receive_sync_response<S, A>(
        &self,
        recv: &mut ReceiveStream,
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

        let mut recv_buf = Vec::new();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync response")?;
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
    client: Client<EN, SP>,
    /// QUIC server to handle sync requests and send sync responses.
    server: QuicServer,
    server_keys: Arc<PskStore>,
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
        client: Client<EN, SP>,
        addr: &Addr,
        server_keys: Arc<PskStore>,
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
        let server = QuicServer::builder()
            .with_tls(tls_server_provider)?
            .with_io(addr)
            .assume("can set sync server addr")?
            .with_congestion_controller(Bbr::default())?
            .start()
            .map_err(Error::ServerStart)?;

        let local_addr = server
            .local_addr()
            .context("unable to get server local address")?;

        let server_instance = Self {
            client,
            server,
            server_keys,
            conns: conns.clone(),
            conn_rx: server_conn_rx,
            _sync_peers: sync_peers.clone(),
        };

        Ok((server_instance, sync_peers, conns, syncer_recv, local_addr))
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.server.local_addr().ok()))]
    #[allow(clippy::disallowed_macros, reason = "tokio::select! uses unreachable!")]
    pub async fn serve(mut self, ready: ready::Notifier) {
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
                    Some((key, acceptor)) = self.conn_rx.recv() => {
                        s.spawn(self.serve_connection(key, acceptor));
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
    ) -> impl Future<Output = ()> + use<'_, EN, SP> {
        let handle = conn.handle();
        async {
            trace!("received incoming QUIC connection");
            let identity = get_conn_identity(&mut conn)?;
            let active_team = self
                .server_keys
                .get_team_for_identity(&identity)
                .context("no active team for accepted connection")?;
            let peer = conn
                .remote_addr()
                .context("unable to get peer address from connection")?;
            conn.keep_alive(true)
                .context("unable to keep connection alive")?;
            let key = ConnectionKey {
                addr: peer,
                id: GraphId::transmute(active_team),
            };
            self.conns.insert(key, conn).await;
            anyhow::Ok(())
        }
        .unwrap_or_else(move |err| {
            error!(error = ?err, "server unable to accept connection");
            handle.close(AppError::UNKNOWN);
        })
    }

    fn serve_connection(
        &mut self,
        key: ConnectionKey,
        mut acceptor: StreamAcceptor,
    ) -> impl Future<Output = ()> {
        let active_team = TeamId::transmute(key.id);
        let peer = key.addr;
        let client = self.client.clone();
        let sync_peers = self._sync_peers.clone();
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
                    peer.into(),
                    stream,
                    active_team,
                    sync_peers.clone(),
                )
                .await
                .context("failed to process sync request")?;
            }
            anyhow::Ok(())
        }
        .unwrap_or_else(|err| {
            error!(error = ?err, "server unable to respond to sync request from peer");
        })
        .instrument(info_span!("serve_connection", %peer))
    }

    /// Responds to a sync.
    #[instrument(skip_all)]
    pub(crate) async fn sync(
        client: Client<EN, SP>,
        peer: Addr,
        stream: BidirectionalStream,
        active_team: TeamId,
        sync_peers: SyncPeers,
    ) -> SyncResult<()> {
        trace!("server received a sync request");

        let mut recv_buf = Vec::new();
        let (mut recv, mut send) = stream.split();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync request")?;
        trace!(n = recv_buf.len(), "received sync request");

        // Generate a sync response for a sync request.
        let sync_response_res =
            Self::sync_respond(client, peer, &recv_buf, active_team, sync_peers).await;
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
        client: Client<EN, SP>,
        addr: Addr,
        request_data: &[u8],
        active_team: TeamId,
        _sync_peers: SyncPeers,
    ) -> SyncResult<Box<[u8]>> {
        trace!("server responding to sync request");

        let sync_type: SyncType<Addr> = postcard::from_bytes(request_data).map_err(|e| {
            error!(
                error = %e,
                request_data_len = request_data.len(),
                ?addr,
                ?active_team,
                "Failed to deserialize sync request"
            );
            anyhow::anyhow!(e)
        })?;

        match sync_type {
            SyncType::Poll {
                request: request_msg,
                address: peer_server_addr,
            } => {
                Self::process_poll_message(
                    request_msg,
                    client,
                    addr,
                    peer_server_addr,
                    &active_team,
                )
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
                    Self::process_hello_message(
                        _hello_msg,
                        client,
                        addr,
                        &active_team,
                        _sync_peers,
                    )
                    .await;
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
        client: Client<EN, SP>,
        peer_addr: Addr,
        peer_server_addr: Addr,
        active_team: &TeamId,
    ) -> SyncResult<Box<[u8]>> {
        let mut resp = SyncResponder::new(peer_addr);
        let storage_id = check_request(*active_team, &request_msg)?;

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

fn check_request(team_id: TeamId, request: &SyncRequestMessage) -> SyncResult<GraphId> {
    let SyncRequestMessage::SyncRequest { storage_id, .. } = request else {
        bug!("Should be a SyncRequest")
    };
    if team_id.as_bytes() != storage_id.as_bytes() {
        return Err(SyncError::QuicSync(Error::InvalidPSK));
    }

    Ok(*storage_id)
}
