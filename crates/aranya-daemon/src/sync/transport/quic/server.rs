use core::net::SocketAddr;
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use aranya_daemon_api::TeamId;
use aranya_runtime::{GraphId, SyncHelloType, SyncRequestMessage, SyncType};
use aranya_util::{
    error::ReportExt as _, ready, rustls::NoCertResolver, s2n_quic::get_conn_identity, task::scope,
    Addr,
};
use buggy::{bug, BugExt as _};
use bytes::Bytes;
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
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, info_span, instrument, warn, Instrument as _};

use super::{
    connections::{ConnectionUpdate, SharedConnections},
    psk::PskStore,
    QuicError, ALPN_QUIC_SYNC,
};
use crate::{
    aranya::ClientWithCaches,
    sync::{
        manager::{EffectSender, ProtocolConfig, SyncHandle},
        services::hello::{HelloService, HelloSubscription, HelloSubscriptions},
        types::{SyncPeer, SyncResponse},
        PeerCacheMap, Result, SyncError,
    },
    Client,
};

/// The Aranya QUIC sync server.
///
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
#[derive(Debug)]
pub struct QuicServer {
    /// QUIC server to handle sync requests and send sync responses.
    server: s2n_quic::Server,
    server_keys: Arc<PskStore>,
    /// Connection map shared with [`super::Syncer`]
    conns: SharedConnections,
    /// Receives updates for connections inserted into the [connection map][`Self::conns`].
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    hello_service: HelloService,
    config: ProtocolConfig,
    server_addr: Addr,
}

impl QuicServer {
    /// Creates a new `QuicServer`.
    pub(crate) async fn new(
        aranya: Client,
        addr: &Addr,
        server_keys: Arc<PskStore>,
        conns: SharedConnections,
        conn_rx: mpsc::Receiver<ConnectionUpdate>,
        caches: PeerCacheMap,
        hello_service: HelloService,
        send_effects: EffectSender,
    ) -> Result<Self> {
        let addr = tokio::net::lookup_host(addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .assume("invalid server address")?;

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        #[allow(deprecated)]
        let tls_provider = rustls_provider::Server::new(server_config);
        // Use the rustls server provider
        let server = s2n_quic::Server::builder()
            .with_tls(tls_provider)?
            .with_io(addr)
            .assume("can set sync server addr")?
            .with_congestion_controller(Bbr::default())?
            .start()
            .map_err(QuicError::ServerStart)?;

        let protocol_config = ProtocolConfig {
            client: aranya,
            caches,
            send_effects,
            server_addr: addr.into(),
        };

        Ok(Self {
            client_with_caches,
            server,
            server_keys,
            conns,
            conn_rx,
            hello_subscriptions: hello_service.subscriptions,
            sync_peers: hello_service.sync_peers,
        })
    }

    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.server.local_addr()?)
    }

    /// Begins accepting incoming requests.
    #[instrument(skip_all, fields(addr = ?self.local_addr()))]
    #[allow(clippy::disallowed_macros, reason = "tokio::select! uses unreachable!")]
    pub async fn serve(mut self, ready: ready::Notifier) {
        ready.notify();
        info!("QUIC server started");

        loop {
            tokio::select! {
                Some(conn) = self.server.accept() => {
                    self.accept_connection(conn).await;
                }
                Some((peer, acceptor)) = self.conn_rx.recv() => {
                    tokio::spawn(self.serve_connection(peer, acceptor));
                }
                else => {
                    error!("all server channels closed");
                    break;
                }
            }
        }

        error!("QUIC server terminated");
    }

    async fn accept_connection(&mut self, mut conn: s2n_quic::Connection) {
        let handle = conn.handle();
        let result: anyhow::Result<()> = async {
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
            let key = SyncPeer {
                addr: peer.into(),
                graph_id: active_team.into_id().into(),
            };
            self.conns.insert(key, conn).await;
            anyhow::Ok(())
        }
        .await;

        if let Err(error) = result {
            error!(?error, "server unable to accept connection");
            handle.close(AppError::UNKNOWN);
        }
    }

    fn serve_connection(
        &mut self,
        peer: SyncPeer,
        mut acceptor: StreamAcceptor,
    ) -> impl Future<Output = ()> {
        let active_team = peer.graph_id.into_id().into();
        let peer = peer.addr;
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
        client_with_caches: Client,
        peer: Addr,
        stream: BidirectionalStream,
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        sync_peers: SyncHandle,
    ) -> Result<()> {
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
        send.close().await.map_err(QuicError::from)?;

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client_with_caches: Client,
        addr: Addr,
        request_data: &[u8],
        active_team: &TeamId,
        hello_subscriptions: Arc<Mutex<HelloSubscriptions>>,
        sync_peers: SyncHandle,
    ) -> Result<Box<[u8]>> {
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
                /*Self::process_poll_message(
                    request_msg,
                    client_with_caches,
                    addr,
                    peer_server_addr,
                    active_team,
                )
                .await*/
                bug!("todo(nikki): finish this");
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
        sync_peers: SyncHandle,
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
                    graph_change_delay,
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

fn check_request(team_id: &TeamId, request: &SyncRequestMessage) -> Result<GraphId> {
    let SyncRequestMessage::SyncRequest { storage_id, .. } = request else {
        bug!("Should be a SyncRequest")
    };
    if team_id.as_bytes() != storage_id.as_bytes() {
        return Err(SyncError::QuicSync(QuicError::InvalidPSK));
    }

    Ok(*storage_id)
}
