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
    Address, Command, Engine, GraphId, Sink, StorageError, StorageProvider, SyncHelloType,
    SyncRequestMessage, SyncRequester, SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
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

use super::{Request, SyncPeers, SyncResponse};
use crate::{
    aranya::Client as AranyaClient,
    sync::{
        task::{PeerCacheKey, PeerCacheMap, SyncState, Syncer},
        Result as SyncResult, SyncError,
    },
    InvalidGraphs,
};

mod connections;
mod psk;

pub(crate) use connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap};
pub(crate) use psk::PskSeed;
pub use psk::PskStore;

/// Storage for sync hello subscriptions
#[derive(Debug, Clone)]
pub struct HelloSubscription {
    /// Delay in milliseconds between notifications to this subscriber
    delay_milliseconds: u64,
    /// Last notification time for delay management
    last_notified: Option<Instant>,
}

/// Type alias for hello subscription storage
/// Maps from (team_id, subscriber_address) to subscription details
pub type HelloSubscriptions = HashMap<(GraphId, SocketAddr), HelloSubscription>;

/// Hello-related information combining subscriptions and sync peers.
#[derive(Debug, Clone)]
pub struct HelloInfo {
    /// Storage for sync hello subscriptions
    pub subscriptions: Arc<Mutex<HelloSubscriptions>>,
    /// Interface to trigger sync operations
    pub sync_peers: SyncPeers,
}

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
        syncer.state.store.set_team(id.into_id().into());

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

    /// Subscribe to hello notifications from a peer.
    #[instrument(skip_all)]
    async fn hello_subscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
        delay_milliseconds: u64,
    ) -> SyncResult<()> {
        syncer.state.store.set_team(id.into_id().into());
        syncer
            .send_hello_subscribe_request(peer, id, delay_milliseconds, syncer.server_addr)
            .await
    }

    /// Unsubscribe from hello notifications from a peer.
    #[instrument(skip_all)]
    async fn hello_unsubscribe_impl(
        syncer: &mut Syncer<Self>,
        id: GraphId,
        peer: &Addr,
    ) -> SyncResult<()> {
        syncer.state.store.set_team(id.into_id().into());
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
        // Get all subscribers for this graph
        let subscribers = {
            let subscriptions = syncer.state.hello_subscriptions.lock().await;

            let filtered: Vec<_> = subscriptions
                .iter()
                .filter(|((sub_graph_id, _), _)| *sub_graph_id == graph_id)
                .map(|((_, addr), subscription)| (*addr, subscription.clone()))
                .collect();

            filtered
        };

        // Send hello notification to each subscriber
        for (subscriber_addr, subscription) in subscribers.iter() {
            // Check if enough time has passed since last notification
            if let Some(last_notified) = subscription.last_notified {
                let delay = Duration::from_millis(subscription.delay_milliseconds);
                let elapsed = last_notified.elapsed();
                if elapsed < delay {
                    continue;
                }
            }

            // Send the notification
            // Convert SocketAddr to Addr for the syncer method
            let peer_addr = Addr::from(*subscriber_addr);
            match syncer
                .send_hello_notification_to_subscriber(&peer_addr, graph_id, head)
                .await
            {
                Ok(()) => {
                    // Update the last notified time
                    let mut subscriptions = syncer.state.hello_subscriptions.lock().await;
                    if let Some(sub) = subscriptions.get_mut(&(graph_id, *subscriber_addr)) {
                        sub.last_notified = Some(Instant::now());
                    } else {
                        warn!(
                            ?subscriber_addr,
                            ?graph_id,
                            "Failed to find subscription to update last_notified"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        ?subscriber_addr,
                        ?head,
                        "Failed to send hello notification"
                    );
                }
            }
        }

        debug!(
            ?graph_id,
            ?head,
            subscriber_count = subscribers.len(),
            "Completed broadcast_hello_notifications"
        );
        Ok(())
    }
}

impl State {
    /// Creates a new instance
    fn new(
        psk_store: Arc<PskStore>,
        conns: SharedConnectionMap,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
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
    ) -> SyncResult<(
        Self,
        SyncPeers,
        SharedConnectionMap,
        mpsc::Receiver<ConnectionUpdate>,
    )> {
        let (send, recv) = mpsc::channel::<Request>(128);
        let peers = SyncPeers::new(send);

        let (conns, conn_rx) = SharedConnectionMap::new();
        let state = State::new(psk_store, conns.clone(), hello_subscriptions)?;

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

    #[instrument(skip_all)]
    async fn connect(&mut self, peer: &Addr, id: GraphId) -> SyncResult<BidirectionalStream> {
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

    #[instrument(skip_all)]
    async fn send_sync_request<A>(
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

    /// Sends a subscribe request to a peer for hello notifications.
    ///
    /// This method sends a `SyncHelloType::Subscribe` message to the specified peer,
    /// requesting to be notified when the peer's graph head changes. The peer will
    /// send hello notifications with the specified delay between them.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the subscribe request to
    /// * `id` - The graph ID for the team/graph to subscribe to
    /// * `delay_milliseconds` - Delay in milliseconds between notifications (0 = immediate)
    /// * `subscriber_server_addr` - The address where this subscriber's QUIC sync server is listening
    ///
    /// # Returns
    /// * `Ok(())` if the subscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    async fn send_hello_subscribe_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        delay_milliseconds: u64,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        debug!(
            ?peer,
            ?id,
            delay_milliseconds,
            ?subscriber_server_addr,
            "client sending subscribe request to QUIC sync server"
        );

        // Create the subscribe message
        let hello_msg = SyncHelloType::Subscribe {
            delay_milliseconds,
            address: subscriber_server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(Bytes::from(data)).await.map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello subscribe response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello subscribe response"
        );

        debug!("sent subscribe request");
        Ok(())
    }

    /// Sends an unsubscribe request to a peer to stop hello notifications.
    ///
    /// This method sends a `SyncHelloType::Unsubscribe` message to the specified peer,
    /// requesting to stop receiving hello notifications when the peer's graph head changes.
    ///
    /// # Arguments
    /// * `peer` - The network address of the peer to send the unsubscribe request to
    /// * `id` - The graph ID for the team/graph to unsubscribe from
    /// * `subscriber_server_addr` - The subscriber's server address to identify which subscription to remove
    ///
    /// # Returns
    /// * `Ok(())` if the unsubscribe request was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    async fn send_hello_unsubscribe_request(
        &mut self,
        peer: &Addr,
        id: GraphId,
        subscriber_server_addr: Addr,
    ) -> SyncResult<()> {
        debug!("client sending unsubscribe request to QUIC sync server");

        // Create the unsubscribe message
        let hello_msg = SyncHelloType::Unsubscribe {
            address: subscriber_server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        // Serialize the message
        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        // Connect to the peer
        let stream = self.connect(peer, id).await?;
        let (mut recv, mut send) = stream.split();

        // Send the message
        send.send(Bytes::from(data)).await.map_err(Error::from)?;
        send.close().await.map_err(Error::from)?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello unsubscribe response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello unsubscribe response"
        );

        debug!("sent unsubscribe request");
        Ok(())
    }

    /// Sends a hello notification to a specific subscriber.
    ///
    /// This method sends a `SyncHelloType::Hello` message to the specified subscriber,
    /// notifying them that the graph head has changed. Uses the existing connection
    /// infrastructure to efficiently reuse connections.
    ///
    /// # Arguments
    /// * `peer` - The network address of the subscriber to send the notification to
    /// * `id` - The graph ID for the team/graph
    /// * `head` - The new head address to include in the notification
    ///
    /// # Returns
    /// * `Ok(())` if the notification was sent successfully
    /// * `Err(SyncError)` if there was an error connecting or sending the message
    #[instrument(skip_all)]
    async fn send_hello_notification_to_subscriber(
        &mut self,
        peer: &Addr,
        id: GraphId,
        head: Address,
    ) -> SyncResult<()> {
        // Set the team for this graph
        let team_id = id.into_id().into();
        self.state.store.set_team(team_id);

        // Create the hello message
        let hello_msg = SyncHelloType::Hello {
            head,
            address: self.server_addr,
        };
        let sync_type: SyncType<Addr> = SyncType::Hello(hello_msg);

        let data = postcard::to_allocvec(&sync_type).context("postcard serialization failed")?;

        let stream = self.connect(peer, id).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                ?id,
                "Failed to connect to peer"
            );
            e
        })?;
        let (mut recv, mut send) = stream.split();

        send.send(Bytes::from(data)).await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                "Failed to send hello message"
            );
            Error::from(e)
        })?;

        send.close().await.map_err(|e| {
            warn!(
                error = %e,
                ?peer,
                "Failed to close send stream"
            );
            Error::from(e)
        })?;

        // Read the response to avoid race condition with server
        let mut response_buf = Vec::new();
        recv.read_to_end(&mut response_buf)
            .await
            .context("failed to read hello notification response")?;
        debug!(
            response_len = response_buf.len(),
            "received hello notification response"
        );

        Ok(())
    }

    #[instrument(skip_all)]
    /// Receives and processes a sync response from the server.
    ///
    /// Returns the number of commands that were received and successfully processed.
    async fn receive_sync_response<S, A>(
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
    /// Interface to trigger sync operations
    sync_peers: SyncPeers,
}

impl<EN, SP> Server<EN, SP> {
    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.server.local_addr()?)
    }

    /// Returns a reference to the hello subscriptions for hello notification broadcasting.
    pub fn hello_subscriptions(&self) -> Arc<Mutex<HelloSubscriptions>> {
        Arc::clone(&self.hello_subscriptions)
    }
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
        aranya: AranyaClient<EN, SP>,
        addr: &Addr,
        server_keys: Arc<PskStore>,
        conns: SharedConnectionMap,
        conn_rx: mpsc::Receiver<ConnectionUpdate>,
        caches: PeerCacheMap,
        hello_info: HelloInfo,
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
        sync_peers: SyncPeers,
    ) -> SyncResult<Box<[u8]>> {
        debug!(
            request_data_len = request_data.len(),
            ?addr,
            ?active_team,
            "Server received sync request"
        );

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
                let mut resp = SyncResponder::new(addr);
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
            SyncType::Subscribe { .. } => {
                bug!("Subscribe messages are not implemented")
            }
            SyncType::Unsubscribe { .. } => {
                bug!("Unsubscribe messages are not implemented")
            }
            SyncType::Push { .. } => {
                bug!("Push messages are not implemented")
            }
            SyncType::Hello(hello_msg) => {
                debug!(?hello_msg, ?addr, ?active_team, "Processing hello message");
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
        }
    }

    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    async fn process_hello_message(
        hello_msg: SyncHelloType<Addr>,
        client: AranyaClient<EN, SP>,
        caches: PeerCacheMap,
        peer_addr: Addr,
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        sync_peers: SyncPeers,
    ) {
        use aranya_runtime::SyncHelloType;

        let graph_id = active_team.into_id().into();

        match hello_msg {
            SyncHelloType::Subscribe {
                delay_milliseconds,
                address,
            } => {
                // Use the subscriber server address directly from the message
                // Convert Addr to SocketAddr for the subscription storage
                let subscriber_address = match address.host().parse() {
                    Ok(ip) => SocketAddr::new(ip, address.port()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            ?address,
                            "Failed to parse subscriber address, ignoring subscription"
                        );
                        return;
                    }
                };

                let subscription = HelloSubscription {
                    delay_milliseconds,
                    last_notified: None,
                };

                // Store subscription (replaces any existing subscription for this peer+team)
                let key = (graph_id, subscriber_address);

                let mut subscriptions = hello_subscriptions.lock().await;
                subscriptions.insert(key, subscription);
            }
            SyncHelloType::Unsubscribe { address } => {
                debug!(
                    ?address,
                    ?peer_addr,
                    ?graph_id,
                    "Received Unsubscribe hello message"
                );

                // Use the address from the message
                // Convert Addr to SocketAddr for the subscription lookup
                let subscriber_address = match address.host().parse() {
                    Ok(ip) => SocketAddr::new(ip, address.port()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            ?address,
                            "Failed to parse subscriber address, ignoring unsubscribe"
                        );
                        return;
                    }
                };

                // Remove subscription for this peer and team
                let key = (graph_id, subscriber_address);
                let mut subscriptions = hello_subscriptions.lock().await;
                if subscriptions.remove(&key).is_some() {
                    debug!(
                        team_id = ?active_team,
                        ?subscriber_address,
                        "Removed hello subscription successfully"
                    );
                } else {
                    debug!(
                        team_id = ?active_team,
                        ?subscriber_address,
                        "No subscription found to remove"
                    );
                }
            }
            SyncHelloType::Hello { head, address } => {
                debug!(
                    ?head,
                    ?peer_addr,
                    ?address,
                    ?graph_id,
                    "Received Hello notification message"
                );

                // Check if we have this command in our graph
                let command_exists = {
                    let mut aranya = match client.aranya.try_lock() {
                        Ok(lock) => lock,
                        Err(_) => client.aranya.lock().await,
                    };
                    aranya.command_exists(graph_id, head)
                };

                if !command_exists {
                    // Use the address from the Hello message for sync_on_hello
                    let server_addr_for_sync = address;

                    match sync_peers
                        .sync_on_hello(server_addr_for_sync, graph_id)
                        .await
                    {
                        Ok(()) => {
                            debug!(
                                ?server_addr_for_sync,
                                ?peer_addr,
                                ?graph_id,
                                ?head,
                                "Successfully sent sync_on_hello message"
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                ?head,
                                ?server_addr_for_sync,
                                ?peer_addr,
                                ?graph_id,
                                "Failed to send sync_on_hello message"
                            );
                        }
                    }
                }

                // Update the peer cache with the received head_id
                let key = PeerCacheKey::new(peer_addr, graph_id);

                // Must lock aranya then caches to prevent deadlock.
                let mut aranya = client.aranya.lock().await;
                let mut caches = caches.lock().await;
                let cache = caches.entry(key).or_default();

                // Update the cache with the received head_id
                if let Err(e) = aranya.update_heads(graph_id, [head], cache) {
                    warn!(
                        error = %e,
                        ?head,
                        ?peer_addr,
                        ?graph_id,
                        "Failed to update peer cache with hello head_id"
                    );
                } else {
                    debug!(
                        ?head,
                        ?peer_addr,
                        ?graph_id,
                        "Successfully updated peer cache with hello head"
                    );
                }
            }
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
