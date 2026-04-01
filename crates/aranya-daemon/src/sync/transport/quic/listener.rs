//! This module implements [`QuicListener`] to allow accepting connections from QUIC clients.
use std::{collections::btree_map::Entry, sync::Arc};

use anyhow::Context as _;
use aranya_daemon_api::DeviceId;
use aranya_util::{rustls::NoCertResolver, s2n_quic::get_conn_identity};
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{
    application::{self, Error as AppError},
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
use tokio::{task::JoinSet, time::Duration};
use tracing::{debug, error, trace, warn};

use super::{
    connections::ListenerPool, ConnectionInfo, Error, PskStore, QuicStream, SyncListener,
    ALPN_QUIC_SYNC,
};
use crate::sync::{Addr, GraphId, SyncPeer};

/// The amount of time we wait trying to accept a bidirectional stream from the peer connecting to
/// us before we time out (they may be really really slow, or busy doing other things).
const PENDING_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The amount of time we wait trying to resolve the connecting peer's address (and waiting for them
/// to send the port they want) before we time out.
const RESOLVE_PEER_ADDR_TIMEOUT: Duration = Duration::from_secs(5);

enum AcceptResult {
    /// Got a stream, acceptor is still live.
    Stream(SyncPeer, StreamAcceptor, BidirectionalStream),
    /// Transient error or timeout, acceptor is still live.
    Retry(SyncPeer, StreamAcceptor),
    /// Acceptor returned None, connection is finished.
    Done(SyncPeer),
}

#[derive(Debug)]
pub(crate) struct QuicListener {
    /// The local address of the server, since it should be infallible.
    local_addr: Addr,
    /// The QUIC server we use to accept raw connections.
    server: s2n_quic::Server,
    /// Allows authenticating the identity of a given `GraphId`.
    server_keys: Arc<PskStore>,
    /// Receiver to register new connections from the [`QuicConnector`](super::QuicConnector).
    pool: ListenerPool,
    /// Queue to allow awaiting a number of potential streams concurrently until one resolves.
    pending_accepts: JoinSet<AcceptResult>,
}

impl QuicListener {
    /// Creates a new [`QuicListener`].
    pub(crate) async fn new(
        addr: Addr,
        server_keys: Arc<PskStore>,
        pool: ListenerPool,
    ) -> Result<Self, Error> {
        // Build up the `ServerConfig` so we can initialize the TLS server.
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        #[allow(deprecated)]
        let tls_server_provider = rustls_provider::Server::new(server_config);

        // Obtain the address for the server.
        let addr = tokio::net::lookup_host(addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .assume("invalid server address")?;

        // Start up a new QUIC server.
        let server = s2n_quic::Server::builder()
            .with_tls(tls_server_provider)?
            .with_io(addr)
            .assume("can set sync server addr")?
            .with_congestion_controller(Bbr::default())?
            .start()
            .map_err(Error::ServerStart)?;

        // Grab our local address now that we've binded to a specific port.
        let local_addr = server
            .local_addr()
            .context("unable to get server local address")?
            .into();

        Ok(Self {
            local_addr,
            server,
            server_keys,
            pool,
            pending_accepts: JoinSet::new(),
        })
    }

    /// Accepts an incoming bidirectional stream from this [`SyncPeer`].
    async fn accept_pending_stream(peer: SyncPeer, mut acceptor: StreamAcceptor) -> AcceptResult {
        trace!(?peer, "waiting for bidirectional stream");

        match tokio::time::timeout(
            PENDING_ACCEPT_TIMEOUT,
            acceptor.accept_bidirectional_stream(),
        )
        .await
        {
            Ok(Ok(Some(stream))) => {
                debug!(?peer, "accepted bidirectional stream");
                AcceptResult::Stream(peer, acceptor, stream)
            }
            Ok(Ok(None)) => {
                debug!(?peer, "acceptor returned None, connection finished");
                AcceptResult::Done(peer)
            }
            Ok(Err(error)) => {
                warn!(?peer, %error, "error accepting bidirectional stream");
                AcceptResult::Retry(peer, acceptor)
            }
            Err(_) => {
                warn!(?peer, "timed out waiting for bidirectional stream");
                AcceptResult::Retry(peer, acceptor)
            }
        }
    }

    /// Sets up the connection with a keep alive, constructs and validates a [`SyncPeer`], and
    /// registers it as a new connection.
    async fn register_connection(&mut self, mut conn: s2n_quic::Connection) -> Result<(), Error> {
        let remote = conn.remote_addr().ok();
        trace!(?remote, "received incoming QUIC connection");

        if let Err(error) = conn.keep_alive(true) {
            debug!(?remote, %error, "connection already closed, skipping");
            return Ok(());
        }

        let identity = get_conn_identity(&mut conn)?;
        let active_team = self
            .server_keys
            .get_team_for_identity(&identity)
            .context("no active team for accepted connection")?;

        debug!(?remote, ?active_team, "authenticated incoming connection");

        let (peer_addr, remote_device_id) = match tokio::time::timeout(
            RESOLVE_PEER_ADDR_TIMEOUT,
            exchange_conn_info(&mut conn, self.pool.local_device_id),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                warn!(?remote, error = %e, "failed to exchange connection info, closing");
                conn.close(application::Error::UNKNOWN);
                return Err(e.into());
            }
            Err(_) => {
                warn!(?remote, "timed out exchanging connection info, closing");
                conn.close(application::Error::UNKNOWN);
                return Err(anyhow::anyhow!("timed out waiting for connection info").into());
            }
        };
        let peer = SyncPeer::new(peer_addr, GraphId::transmute(active_team));

        // Insert with tie-breaking using device IDs. When both peers connect
        // simultaneously, the peer with the lower device ID keeps its outbound
        // connection. Device IDs are cryptographically unique, transport-agnostic,
        // and work regardless of NAT or network topology.
        let (new_handle, new_acceptor) = conn.split();
        let local_device_id = self.pool.local_device_id;
        let acceptor = {
            let mut map = self.pool.conns.lock().await;
            match map.entry(peer) {
                Entry::Vacant(e) => {
                    e.insert(new_handle.clone());
                    Some(new_acceptor)
                }
                Entry::Occupied(mut e) => {
                    let existing_alive = e.get_mut().ping().is_ok();
                    // The inbound connection wins if the remote peer has the lower
                    // device ID (they keep their outbound, which is our inbound).
                    let inbound_wins = !existing_alive || remote_device_id < local_device_id;
                    if inbound_wins {
                        if existing_alive {
                            debug!(?peer, "replacing existing connection (tie-break)");
                            e.get_mut().close(AppError::UNKNOWN);
                        }
                        e.insert(new_handle.clone());
                        Some(new_acceptor)
                    } else {
                        debug!(?peer, "keeping existing outbound connection (tie-break)");
                        new_handle.close(AppError::UNKNOWN);
                        None
                    }
                }
            }
        };

        if let Some(acceptor) = acceptor {
            self.pending_accepts
                .spawn(Self::accept_pending_stream(peer, acceptor));
            debug!(?peer, "accepted and inserted QUIC connection");
        }

        Ok(())
    }
}

impl SyncListener for QuicListener {
    type Stream = QuicStream;

    fn local_addr(&self) -> Addr {
        self.local_addr
    }

    #[allow(
        clippy::disallowed_macros,
        reason = "tokio::select! uses core::unreachable"
    )]
    async fn accept(&mut self) -> Option<Self::Stream> {
        loop {
            tokio::select! {
                Some(result) = self.pending_accepts.join_next() => {
                    match result {
                        Ok(AcceptResult::Stream(peer, acceptor, stream)) => {
                            debug!(?peer, "accepted stream, re-queueing acceptor");
                            self.pending_accepts.spawn(Self::accept_pending_stream(peer, acceptor));
                            return Some(QuicStream::new(peer, stream));
                        }
                        Ok(AcceptResult::Retry(peer, acceptor)) => {
                            self.pending_accepts.spawn(Self::accept_pending_stream(peer, acceptor));
                        }
                        Ok(AcceptResult::Done(peer)) => {
                            debug!(?peer, "connection finished, dropping acceptor");
                        }
                        Err(error) => error!(%error, "stream acceptor task panicked"),
                    }
                }

                Some(conn) = self.server.accept() => {
                    let handle = conn.handle();
                    let remote = conn.remote_addr().ok();
                    trace!(?remote, "raw connection accepted from server");

                    if let Err(error) = self.register_connection(conn).await {
                        error!(?remote, ?error, "failed to accept connection");
                        handle.close(application::Error::UNKNOWN);
                    }
                }

                Some((peer, acceptor)) = self.pool.rx.recv() => {
                    debug!(?peer, "registering connection for stream accepts");
                    self.pending_accepts.spawn(Self::accept_pending_stream(peer, acceptor));
                }

                else => {
                    debug!("all accept sources exhausted, shutting down listener");
                    return None;
                }
            }
        }
    }
}

/// Exchanges connection info with the connecting peer.
///
/// Receives [`ConnectionInfo`] from the connector (containing return port and device ID),
/// sends back the local device ID, and returns the peer's address and device ID.
async fn exchange_conn_info(
    conn: &mut s2n_quic::Connection,
    local_device_id: DeviceId,
) -> anyhow::Result<(Addr, DeviceId)> {
    let ip = conn.remote_addr().assume("valid connection")?.ip();
    trace!(%ip, "exchanging connection info");

    let bytes = conn
        .accept_receive_stream()
        .await?
        .context("unable to accept receive stream")?
        .receive()
        .await?
        .context("peer didn't send connection info")?;
    let info: ConnectionInfo =
        postcard::from_bytes(bytes.as_ref()).context("invalid connection info")?;

    // Send back our device ID so the connector can tie-break.
    let id_bytes =
        postcard::to_allocvec(&local_device_id).context("failed to serialize device ID")?;
    conn.open_send_stream()
        .await?
        .send(Bytes::from(id_bytes))
        .await?;

    debug!(%ip, port = %info.port, "resolved peer connection info");
    Ok((Addr::from((ip, info.port)), info.device_id))
}
