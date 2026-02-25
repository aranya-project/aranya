//! This module implements [`QuicListener`] to allow accepting connections from QUIC clients.
use std::sync::Arc;

use anyhow::Context as _;
use aranya_util::{rustls::NoCertResolver, s2n_quic::get_conn_identity};
use buggy::BugExt as _;
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
use tokio::{task::JoinSet, time::Duration};
use tracing::{debug, error, trace, warn};

use super::{
    ConnectionReceiver, Error, PskStore, QuicStream, SharedConnectionMap, SyncListener,
    ALPN_QUIC_SYNC,
};
use crate::sync::{Addr, GraphId, SyncPeer};

type AcceptResult = (SyncPeer, StreamAcceptor, Option<BidirectionalStream>);

#[derive(Debug)]
pub(crate) struct QuicListener {
    server: s2n_quic::Server,
    server_keys: Arc<PskStore>,
    conns: SharedConnectionMap,
    conn_rx: ConnectionReceiver,
    pending_accepts: JoinSet<AcceptResult>,
    local_addr: Addr,
}

impl QuicListener {
    /// Creates a new [`QuicListener`].
    pub(crate) async fn new(
        addr: Addr,
        server_keys: Arc<PskStore>,
    ) -> Result<(Self, SharedConnectionMap), Error> {
        // Create a `SharedConnectionMap` to allow for reusing QUIC connections.
        let (conns, conn_rx) = SharedConnectionMap::new(32);

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

        Ok((
            Self {
                server,
                server_keys,
                conns: conns.clone(),
                conn_rx,
                pending_accepts: JoinSet::new(),
                local_addr,
            },
            conns,
        ))
    }

    /// Accepts an incoming bidirectional stream from this [`SyncPeer`].
    async fn accept_pending_stream(peer: SyncPeer, mut acceptor: StreamAcceptor) -> AcceptResult {
        let stream = acceptor.accept_bidirectional_stream().await.ok().flatten();
        (peer, acceptor, stream)
    }

    /// Sets up the connection with a keep alive, constructs and validates a [`SyncPeer`], and
    /// registers it as a new connection.
    async fn register_connection(&self, mut conn: s2n_quic::Connection) -> Result<(), Error> {
        trace!("received incoming QUIC connection");

        conn.keep_alive(true).assume("connection is still alive")?;

        let identity = get_conn_identity(&mut conn)?;
        let active_team = self
            .server_keys
            .get_team_for_identity(&identity)
            .context("no active team for accepted connection")?;

        let peer_addr =
            tokio::time::timeout(Duration::from_secs(5), extract_return_address(&mut conn))
                .await
                .context("timed out waiting for return address")?
                .context("unable to extract return address")?;
        let peer = SyncPeer::new(peer_addr, GraphId::transmute(active_team));

        self.conns.insert(peer, conn).await;

        debug!(?peer, "accepted and inserted QUIC connection");
        Ok(())
    }
}

impl SyncListener for QuicListener {
    type Error = Error;
    type Stream = QuicStream;

    fn local_addr(&self) -> Addr {
        self.local_addr
    }

    #[allow(
        clippy::disallowed_macros,
        reason = "tokio::select! uses core::unreachable"
    )]
    async fn accept(&mut self) -> Option<Result<Self::Stream, Self::Error>> {
        loop {
            tokio::select! {
                Some(result) = self.pending_accepts.join_next() => {
                    match result {
                        Ok((peer, acceptor, Some(stream))) => {
                            self.pending_accepts.spawn(Self::accept_pending_stream(peer, acceptor));
                            return Some(Ok(QuicStream::new(peer, stream)));
                        }
                        Ok((peer, _acceptor, None)) => debug!(?peer, "connection closed"),
                        Err(error) => warn!(%error, "stream acceptor task panicked"),
                    }
                }

                Some(conn) = self.server.accept() => {
                    let handle = conn.handle();

                    if let Err(error) = self.register_connection(conn).await {
                        error!(?error, "failed to accept connection");
                        handle.close(application::Error::UNKNOWN);
                    }
                }

                Some((peer, acceptor)) = self.conn_rx.next() => {
                    debug!(?peer, "registering connection for stream accepts");
                    self.pending_accepts.spawn(Self::accept_pending_stream(peer, acceptor));
                }

                else => return None,
            }
        }
    }
}

/// Grabs the remote address of the connected peer, and accepts a message containing the port they
/// want to be connected on.
async fn extract_return_address(conn: &mut s2n_quic::Connection) -> anyhow::Result<Addr> {
    let ip = conn.remote_addr().assume("valid connection")?.ip();
    let bytes = conn
        .accept_receive_stream()
        .await?
        .context("unable to accept receive stream")?
        .receive()
        .await?
        .context("peer didn't sent return port")?;
    let port = u16::from_be_bytes(bytes.as_ref().try_into().context("invalid return port")?);
    Ok(Addr::from((ip, port)))
}
