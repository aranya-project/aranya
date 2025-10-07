//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::net::SocketAddr;
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_crypto::Rng;
use aranya_daemon_api::TeamId;
use aranya_runtime::{
    Address, Command, Engine, GraphId, Sink, StorageError, StorageProvider, SyncRequestMessage,
    SyncRequester, SyncResponder, SyncResponseMessage, SyncType, MAX_SYNC_MESSAGE_SIZE,
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
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
};
use tokio_util::time::DelayQueue;
use tracing::{debug, error, info, info_span, instrument, warn, Instrument as _};

use super::{Request, SyncPeers, SyncResponse, SyncState};
use crate::{
    aranya::Client as AranyaClient,
    sync::{
        task::{PeerCacheKey, PeerCacheMap, Syncer},
        Result as SyncResult, SyncError,
    },
    InvalidGraphs,
};

mod connections;
mod psk;

pub(crate) use connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap};
pub(crate) use psk::PskSeed;
pub use psk::PskStore;

pub(crate) use super::{
    hello::{HelloInfo, HelloSubscriptions},
    push::{PushInfo, PushSubscriptions},
};

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
    pub(crate) caches: PeerCacheMap,
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
    /// Shared reference to hello subscriptions for broadcasting notifications
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
    /// Shared reference to push subscriptions for broadcasting push notifications
    push_subscriptions: Arc<Mutex<PushSubscriptions>>,
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
        S: Sink<<crate::EN as Engine>::Effect> + Send,
    {
        // Sets the active team before starting a QUIC connection
        syncer.state.store().set_team(id.into_id().into());

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
            .receive_sync_response(&mut recv, &mut sync_requester, &id, sink, peer)
            .await
            .map_err(|e| SyncError::ReceiveSyncResponse(Box::new(e)))?;

        Ok(cmd_count)
    }

    /// Subscribe to hello notifications from a sync peer.
    #[instrument(skip_all)]
    async fn sync_hello_subscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
        delay: Duration,
        duration: Duration,
    ) -> SyncResult<()> {
        syncer.state.store().set_team(id.into_id().into());
        syncer
            .send_sync_hello_subscribe_request(peer, id, delay, duration, syncer.server_addr)
            .await
    }

    /// Unsubscribe from hello notifications from a sync peer.
    #[instrument(skip_all)]
    async fn sync_hello_unsubscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()> {
        syncer.state.store().set_team(id.into_id().into());
        syncer
            .send_hello_unsubscribe_request(peer, id, syncer.server_addr)
            .await
    }

    /// Broadcast hello notifications to all subscribers of a graph.
    #[instrument(skip_all)]
    async fn broadcast_hello_notifications(
        syncer: &mut Syncer<Self>,
        graph_id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        super::hello::broadcast_hello_notifications(syncer, graph_id, head).await
    }

    /// Subscribe to push notifications from a sync peer.
    #[instrument(skip_all)]
    async fn sync_push_subscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
        remain_open: u64,
        max_bytes: u64,
        commands: Vec<Address>,
    ) -> SyncResult<()> {
        syncer.state.store().set_team(id.into_id().into());
        syncer
            .send_push_subscribe_request(
                peer,
                id,
                remain_open,
                max_bytes,
                commands,
                syncer.server_addr,
            )
            .await
    }

    /// Unsubscribe from push notifications from a sync peer.
    #[instrument(skip_all)]
    async fn sync_push_unsubscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()> {
        syncer.state.store().set_team(id.into_id().into());
        syncer
            .send_push_unsubscribe_request(peer, id, syncer.server_addr)
            .await
    }

    /// Broadcast push notifications to all subscribers of a graph.
    #[instrument(skip_all)]
    async fn broadcast_push_notifications(
        syncer: &mut Syncer<Self>,
        graph_id: GraphId,
    ) -> SyncResult<()> {
        super::push::broadcast_push_notifications(syncer, graph_id).await
    }
}

impl State {
    /// Get a reference to the PSK store
    pub fn store(&self) -> &Arc<PskStore> {
        &self.store
    }

    /// Get a reference to the hello subscriptions
    pub fn hello_subscriptions(&self) -> &Arc<Mutex<HelloSubscriptions>> {
        &self.hello_subscriptions
    }

    /// Get a reference to the push subscriptions
    pub fn push_subscriptions(&self) -> &Arc<Mutex<PushSubscriptions>> {
        &self.push_subscriptions
    }

    /// Creates a new instance
    fn new(
        psk_store: Arc<PskStore>,
        conns: SharedConnectionMap,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        push_subscriptions: Arc<Mutex<PushSubscriptions>>,
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
            .with_io((Ipv4Addr::UNSPECIFIED, 0))
            .assume("can set quic client address")?
            .start()
            .map_err(Error::ClientStart)?;

        Ok(Self {
            client,
            conns,
            store: psk_store,
            hello_subscriptions,
            push_subscriptions,
        })
    }
}

impl Syncer<State> {
    /// Creates a new [`Syncer`].
    pub(crate) fn new(
        client: super::Client,
        send_effects: super::EffectSender,
        invalid: InvalidGraphs,
        psk_store: Arc<PskStore>,
        server_addr: Addr,
        caches: PeerCacheMap,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        push_subscriptions: Arc<Mutex<PushSubscriptions>>,
    ) -> SyncResult<(
        Self,
        SyncPeers,
        SharedConnectionMap,
        mpsc::Receiver<ConnectionUpdate>,
    )> {
        let (send, recv) = mpsc::channel::<Request>(128);
        let peers = SyncPeers::new(send);

        let (conns, conn_rx) = SharedConnectionMap::new();
        let state = State::new(
            psk_store,
            conns.clone(),
            hello_subscriptions,
            push_subscriptions,
        )?;

        Ok((
            Self {
                client,
                peers: HashMap::new(),
                recv,
                queue: DelayQueue::new(),
                send_effects,
                invalid,
                state,
                server_addr,
                caches,
            },
            peers,
            conns,
            conn_rx,
        ))
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
        debug!("client connecting to QUIC sync server");
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

        debug!("client connected to QUIC sync server");

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

        debug!("client opened bidi stream with QUIC sync server");
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
        debug!("client sending sync request to QUIC sync server");
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let len = {
            // Must lock aranya then caches to prevent deadlock.
            let mut aranya = self.client.aranya.lock().await;
            let key = PeerCacheKey::new(*peer, id);
            let mut caches = self.caches.lock().await;
            let cache = caches.entry(key).or_default();
            let (len, _) = syncer
                .poll(&mut send_buf, aranya.provider(), cache)
                .context("sync poll failed")?;
            debug!(?len, "sync poll finished");
            len
        };
        send_buf.truncate(len);

        send.send(Bytes::from(send_buf))
            .await
            .map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;
        debug!("sent sync request");

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
        id: &GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> SyncResult<usize>
    where
        S: Sink<<crate::EN as Engine>::Effect>,
        A: Serialize + DeserializeOwned + Clone,
    {
        debug!("client receiving sync response from QUIC sync server");

        let mut recv_buf = Vec::new();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync response")?;
        debug!(n = recv_buf.len(), "received sync response");

        // Check for empty response (which indicates a hello message response)
        if recv_buf.is_empty() {
            debug!("received empty response, likely from hello message - ignoring");
            return Ok(0);
        }

        // process the sync response.
        let resp = postcard::from_bytes(&recv_buf)
            .context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => return Err(anyhow::anyhow!("sync error: {msg}").into()),
        };
        if data.is_empty() {
            debug!("nothing to sync");
            return Ok(0);
        }
        if let Some(cmds) = syncer.receive(&data)? {
            debug!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                let mut aranya = self.client.aranya.lock().await;
                let mut trx = aranya.transaction(*id);
                aranya
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                aranya.commit(&mut trx, sink).context("commit failed")?;
                debug!("committed");
                let key = PeerCacheKey::new(*peer, *id);
                let mut caches = self.caches.lock().await;
                let cache = caches.entry(key).or_default();
                aranya
                    .update_heads(*id, cmds.iter().filter_map(|cmd| cmd.address().ok()), cache)
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
    /// Thread-safe Aranya client reference.
    aranya: AranyaClient<EN, SP>,
    /// QUIC server to handle sync requests and send sync responses.
    server: QuicServer,
    server_keys: Arc<PskStore>,
    /// Thread-safe reference to an [`Addr`]->[`PeerCache`] map.
    /// Lock must be acquired after [`Self::aranya`]
    caches: PeerCacheMap,
    /// Connection map shared with [`super::Syncer`]
    conns: SharedConnectionMap,
    /// Receives updates for connections inserted into the [connection map][`Self::conns`].
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    /// Storage for sync hello subscriptions
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
    /// Storage for sync push subscriptions
    push_subscriptions: Arc<Mutex<PushSubscriptions>>,
    /// Interface to trigger sync operations
    sync_peers: SyncPeers,
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.server.local_addr()?)
    }

    /// Returns a reference to the hello subscriptions for hello notification broadcasting.
    pub fn hello_subscriptions(&self) -> Arc<Mutex<HelloSubscriptions>> {
        Arc::clone(&self.hello_subscriptions)
    }

    /// Returns a reference to the push subscriptions for push notification broadcasting.
    pub fn push_subscriptions(&self) -> Arc<Mutex<PushSubscriptions>> {
        Arc::clone(&self.push_subscriptions)
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
        aranya: AranyaClient<EN, SP>,
        addr: &Addr,
        server_keys: Arc<PskStore>,
        conns: SharedConnectionMap,
        conn_rx: mpsc::Receiver<ConnectionUpdate>,
        caches: PeerCacheMap,
        hello_info: HelloInfo,
        push_info: PushInfo,
    ) -> SyncResult<Self> {
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

        Ok(Self {
            aranya,
            server,
            server_keys,
            conns,
            conn_rx,
            caches,
            hello_subscriptions: hello_info.subscriptions,
            push_subscriptions: push_info.subscriptions,
            sync_peers: hello_info.sync_peers,
        })
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.local_addr()))]
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
            debug!("received incoming QUIC connection");
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
                id: active_team.into_id().into(),
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
        let active_team = key.id.into_id().into();
        let peer = key.addr;
        let client = self.aranya.clone();
        let caches = self.caches.clone();
        let hello_subscriptions = self.hello_subscriptions.clone();
        let push_subscriptions = self.push_subscriptions.clone();
        let sync_peers = self.sync_peers.clone();
        async move {
            // Accept incoming streams.
            while let Some(stream) = acceptor
                .accept_bidirectional_stream()
                .await
                .context("could not receive QUIC stream")?
            {
                debug!("received incoming QUIC stream");
                Self::sync(
                    client.clone(),
                    caches.clone(),
                    peer.into(),
                    stream,
                    &active_team,
                    hello_subscriptions.clone(),
                    push_subscriptions.clone(),
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
    pub async fn sync(
        client: AranyaClient<EN, SP>,
        caches: PeerCacheMap,
        peer: Addr,
        stream: BidirectionalStream,
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        push_subscriptions: Arc<Mutex<PushSubscriptions>>,
        sync_peers: SyncPeers,
    ) -> SyncResult<()> {
        let mut recv_buf = Vec::new();
        let (mut recv, mut send) = stream.split();
        recv.read_to_end(&mut recv_buf)
            .await
            .context("failed to read sync request")?;

        // Generate a sync response for a sync request.
        let sync_response_res = Self::sync_respond(
            client,
            caches,
            peer,
            &recv_buf,
            active_team,
            hello_subscriptions,
            push_subscriptions,
            sync_peers,
        )
        .await;
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
        debug!(n = data_len, "server sent sync response");
        send.close().await.map_err(Error::from)?;

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: AranyaClient<EN, SP>,
        caches: PeerCacheMap,
        addr: Addr,
        request_data: &[u8],
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        push_subscriptions: Arc<Mutex<PushSubscriptions>>,
        sync_peers: SyncPeers,
    ) -> SyncResult<Box<[u8]>> {
        debug!(
            request_data_len = request_data.len(),
            ?addr,
            ?active_team,
            "Server received sync request"
        );

        let (sync_type, remaining): (SyncType<Addr>, &[u8]) =
            postcard::take_from_bytes(request_data).map_err(|e| {
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
                    caches,
                    addr,
                    peer_server_addr,
                    active_team,
                )
                .await
            }
            SyncType::Push {
                message,
                storage_id,
                address,
            } => {
                Self::process_push_message(
                    message,
                    storage_id,
                    address,
                    remaining,
                    client,
                    caches,
                    push_subscriptions,
                    sync_peers,
                )
                .await;
                // Push messages are fire-and-forget, return empty response
                // Note: returning empty response which will be ignored by client
                Ok(Box::new([]))
            }
            SyncType::Hello(hello_msg) => {
                Self::process_hello_message(
                    hello_msg,
                    client,
                    caches,
                    addr,
                    active_team,
                    hello_subscriptions,
                    sync_peers,
                )
                .await;
                // Hello messages are fire-and-forget, return empty response
                // Note: returning empty response which will be ignored by client
                Ok(Box::new([]))
            }
            SyncType::Subscribe {
                remain_open,
                max_bytes,
                commands,
                address,
                storage_id,
            } => {
                Self::process_subscribe_message(
                    remain_open,
                    max_bytes,
                    commands,
                    address,
                    storage_id,
                    client,
                    caches,
                    push_subscriptions,
                    active_team,
                )
                .await;
                // Subscribe messages are fire-and-forget, return empty response
                Ok(Box::new([]))
            }
            SyncType::Unsubscribe { address } => {
                Self::process_unsubscribe_message(address, push_subscriptions, active_team).await;
                // Unsubscribe messages are fire-and-forget, return empty response
                Ok(Box::new([]))
            }
        }
    }

    /// Processes a poll message.
    ///
    /// Handles sync poll requests and generates sync responses.
    #[instrument(skip_all)]
    async fn process_poll_message(
        request_msg: SyncRequestMessage,
        client: AranyaClient<EN, SP>,
        caches: PeerCacheMap,
        peer_addr: Addr,
        peer_server_addr: Addr,
        active_team: &TeamId,
    ) -> SyncResult<Box<[u8]>> {
        let mut resp = SyncResponder::new(peer_addr);
        let storage_id = check_request(active_team, &request_msg)?;

        resp.receive(request_msg).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            // Must lock aranya then caches to prevent deadlock.
            let mut aranya = client.aranya.lock().await;
            let key = PeerCacheKey::new(peer_server_addr, storage_id);
            let mut caches = caches.lock().await;
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
        debug!(len = len, "sync poll finished");
        buf.truncate(len);
        Ok(buf.into())
    }

    /// Processes a push notification message.
    ///
    /// Handles incoming push notifications by triggering a sync with the sender.
    /// Similar to hello notifications, this triggers a sync operation rather than
    /// directly processing commands, since the server context doesn't have access
    /// to the effect sink.
    #[instrument(skip_all)]
    async fn process_push_message(
        message: SyncResponseMessage,
        storage_id: GraphId,
        sender_addr: Addr,
        _remaining: &[u8],
        _client: AranyaClient<EN, SP>,
        _caches: PeerCacheMap,
        _push_subscriptions: Arc<Mutex<PushSubscriptions>>,
        sync_peers: SyncPeers,
    ) {
        debug!(
            ?storage_id,
            ?sender_addr,
            "Received Push notification message"
        );

        // Extract any heads from the push message to update cache
        if let SyncResponseMessage::SyncResponse { commands, .. } = &message {
            if !commands.is_empty() {
                debug!(
                    cmd_count = commands.len(),
                    ?storage_id,
                    ?sender_addr,
                    "Push notification indicates new commands available"
                );

                // Trigger a sync to fetch the new commands
                // This is similar to sync_on_hello - we trigger a sync operation
                // which will properly handle command processing with the effect sink
                match sync_peers.sync_on_hello(sender_addr, storage_id).await {
                    Ok(()) => {
                        debug!(
                            ?sender_addr,
                            ?storage_id,
                            "Successfully triggered sync from push notification"
                        );
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            ?sender_addr,
                            ?storage_id,
                            "Failed to trigger sync from push notification"
                        );
                    }
                }
            } else {
                debug!(
                    ?storage_id,
                    ?sender_addr,
                    "Push notification contained no commands"
                );
            }
        }
    }

    /// Processes a subscribe request for push notifications.
    ///
    /// Handles subscription management for push notifications.
    #[instrument(skip_all)]
    async fn process_subscribe_message(
        remain_open: u64,
        max_bytes: u64,
        commands: heapless::Vec<Address, 100>,
        subscriber_addr: Addr,
        storage_id: GraphId,
        client: AranyaClient<EN, SP>,
        caches: PeerCacheMap,
        push_subscriptions: Arc<Mutex<PushSubscriptions>>,
        _active_team: &TeamId,
    ) {
        debug!(
            ?subscriber_addr,
            ?storage_id,
            remain_open,
            max_bytes,
            "Received Subscribe push message"
        );

        // Convert Addr to SocketAddr for the subscription storage
        let subscriber_socket_addr = match subscriber_addr.host().parse() {
            Ok(ip) => SocketAddr::new(ip, subscriber_addr.port()),
            Err(e) => {
                warn!(
                    error = %e,
                    ?subscriber_addr,
                    "Failed to parse subscriber address, ignoring subscription"
                );
                return;
            }
        };

        // Calculate close time
        let close_time = Instant::now() + Duration::from_secs(remain_open);

        let subscription = super::push::PushSubscription {
            close_time,
            remaining_bytes: max_bytes,
        };

        // Update the remote heads cache with the subscriber's commands
        let key = PeerCacheKey::new(subscriber_addr, storage_id);
        {
            let mut aranya = match client.aranya.try_lock() {
                Ok(lock) => lock,
                Err(_) => client.aranya.lock().await,
            };
            let mut caches = caches.lock().await;
            let cache = caches.entry(key).or_default();

            // Update heads with the commands from the subscriber
            // This helps us know what the subscriber already has
            if let Err(e) = aranya.update_heads(storage_id, commands.iter().copied(), cache) {
                warn!(
                    error = %e,
                    ?subscriber_addr,
                    ?storage_id,
                    "Failed to update heads for push subscription"
                );
                return;
            }
        }

        // Store subscription (replaces any existing subscription for this peer+team)
        let sub_key = (storage_id, subscriber_socket_addr);
        let mut subscriptions = push_subscriptions.lock().await;
        subscriptions.insert(sub_key, subscription);

        debug!(
            ?subscriber_addr,
            ?storage_id,
            "Successfully added push subscription"
        );
    }

    /// Processes an unsubscribe request for push notifications.
    ///
    /// Removes a push notification subscription.
    #[instrument(skip_all)]
    async fn process_unsubscribe_message(
        subscriber_addr: Addr,
        push_subscriptions: Arc<Mutex<PushSubscriptions>>,
        active_team: &TeamId,
    ) {
        debug!(
            ?subscriber_addr,
            ?active_team,
            "Received Unsubscribe push message"
        );

        // Convert Addr to SocketAddr for the subscription lookup
        let subscriber_socket_addr = match subscriber_addr.host().parse() {
            Ok(ip) => SocketAddr::new(ip, subscriber_addr.port()),
            Err(e) => {
                warn!(
                    error = %e,
                    ?subscriber_addr,
                    "Failed to parse subscriber address, ignoring unsubscribe"
                );
                return;
            }
        };

        // Remove subscription for this peer and team
        let storage_id: GraphId = active_team.into_id().into();
        let key = (storage_id, subscriber_socket_addr);
        let mut subscriptions = push_subscriptions.lock().await;
        if subscriptions.remove(&key).is_some() {
            debug!(
                ?subscriber_addr,
                ?storage_id,
                "Removed push subscription successfully"
            );
        } else {
            debug!(
                ?subscriber_addr,
                ?storage_id,
                "No push subscription found to remove"
            );
        }
    }
}

fn check_request(team_id: &TeamId, request: &SyncRequestMessage) -> SyncResult<GraphId> {
    let SyncRequestMessage::SyncRequest { storage_id, .. } = request else {
        bug!("Should be a SyncRequest")
    };
    if team_id.as_bytes() != storage_id.as_bytes() {
        return Err(SyncError::QuicSync(Error::InvalidPSK));
    }

    Ok(*storage_id)
}
