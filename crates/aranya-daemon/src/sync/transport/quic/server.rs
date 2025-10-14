use core::net::SocketAddr;
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_daemon_api::TeamId;
use aranya_runtime::{
    Engine, GraphId, StorageError, StorageProvider, SyncHelloType, SyncRequestMessage,
    SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{
    error::ReportExt as _, ready, rustls::NoCertResolver, s2n_quic::get_conn_identity, task::scope,
    Addr,
};
use buggy::{bug, BugExt as _};
use bytes::Bytes;
use derive_where::derive_where;
use futures_util::TryFutureExt;
use s2n_quic::{
    application::Error as AppError,
    connection::StreamAcceptor,
    provider::{
        congestion_controller::Bbr,
        tls::{
            rustls as rustls_provider,
            rustls::rustls::{server::PresharedKeySelection, ServerConfig},
        },
    },
    stream::BidirectionalStream,
    Server as QuicServer,
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, info_span, instrument, warn, Instrument as _};

use crate::{
    aranya::ClientWithCaches,
    sync::{
        services::hello::{HelloInfo, HelloSubscription, HelloSubscriptions},
        task::SyncPeers,
        transport::quic::{
            connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap},
            psk::PskStore,
            Error, ALPN_QUIC_SYNC,
        },
        types::{SyncPeer, SyncResponse},
        Result as SyncResult, SyncError,
    },
};

/// The Aranya QUIC sync server.
///
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive_where(Debug)]
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client paired with caches, ensuring safe lock ordering.
    client_with_caches: ClientWithCaches<EN, SP>,
    /// QUIC server to handle sync requests and send sync responses.
    server: QuicServer,
    server_keys: Arc<PskStore>,
    /// Connection map shared with [`super::Syncer`]
    conns: SharedConnectionMap,
    /// Receives updates for connections inserted into the [connection map][`Self::conns`].
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    /// Storage for sync hello subscriptions
    hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
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
        client_with_caches: ClientWithCaches<EN, SP>,
        addr: &Addr,
        server_keys: Arc<PskStore>,
        conns: SharedConnectionMap,
        conn_rx: mpsc::Receiver<ConnectionUpdate>,
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
            client_with_caches,
            server,
            server_keys,
            conns,
            conn_rx,
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
        let client_with_caches = self.client_with_caches.clone();
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
                    client_with_caches.clone(),
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
        client_with_caches: ClientWithCaches<EN, SP>,
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
            client_with_caches,
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
        client_with_caches: ClientWithCaches<EN, SP>,
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
                Self::process_poll_message(
                    request_msg,
                    client_with_caches,
                    addr,
                    peer_server_addr,
                    active_team,
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
            SyncType::Hello(hello_msg) => {
                Self::process_hello_message(
                    hello_msg,
                    client_with_caches,
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

    /// Processes a poll message.
    ///
    /// Handles sync poll requests and generates sync responses.
    #[instrument(skip_all)]
    async fn process_poll_message(
        request_msg: SyncRequestMessage,
        client_with_caches: ClientWithCaches<EN, SP>,
        peer_addr: Addr,
        peer_server_addr: Addr,
        active_team: &TeamId,
    ) -> SyncResult<Box<[u8]>> {
        let mut resp = SyncResponder::new(peer_addr);
        let storage_id = check_request(active_team, &request_msg)?;

        resp.receive(request_msg).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = {
            // Lock both aranya and caches in the correct order.
            let (mut aranya, mut caches) = client_with_caches.lock_aranya_and_caches().await;
            let key = SyncPeer::new(peer_server_addr, storage_id);
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

    /// Processes a hello message.
    ///
    /// Handles subscription management and hello notifications.
    #[instrument(skip_all)]
    pub async fn process_hello_message(
        hello_msg: SyncHelloType<Addr>,
        client_with_caches: ClientWithCaches<EN, SP>,
        peer_addr: Addr,
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        sync_peers: SyncPeers,
    ) {
        let graph_id = active_team.into_id().into();

        match hello_msg {
            SyncHelloType::Subscribe {
                delay_milliseconds,
                duration_milliseconds,
                address,
            } => {
                // Calculate expiration time
                let expires_at = Instant::now() + Duration::from_millis(duration_milliseconds);

                let subscription = HelloSubscription {
                    delay_milliseconds,
                    last_notified: None,
                    expires_at,
                };

                // Store subscription (replaces any existing subscription for this peer+team)
                let key = (graph_id, address);

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

                // Remove subscription for this peer and team
                let key = (graph_id, address);
                let mut subscriptions = hello_subscriptions.lock().await;
                if subscriptions.remove(&key).is_some() {
                    debug!(
                        team_id = ?active_team,
                        ?address,
                        "Removed hello subscription successfully"
                    );
                } else {
                    debug!(
                        team_id = ?active_team,
                        ?address,
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

                if !client_with_caches
                    .client()
                    .aranya
                    .lock()
                    .await
                    .command_exists(graph_id, head)
                {
                    match sync_peers.sync_on_hello(address, graph_id).await {
                        Ok(()) => {
                            debug!(
                                ?address,
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
                                ?address,
                                ?peer_addr,
                                ?graph_id,
                                "Failed to send sync_on_hello message"
                            );
                        }
                    }
                }

                // Update the peer cache with the received head_id
                let key = SyncPeer::new(peer_addr, graph_id);

                // Lock both aranya and caches in the correct order.
                let (mut aranya, mut caches) = client_with_caches.lock_aranya_and_caches().await;
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
