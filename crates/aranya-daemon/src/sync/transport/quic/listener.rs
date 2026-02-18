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
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error, trace, warn};

use super::{ConnectionUpdate, Error, PskStore, SharedConnectionMap, ALPN_QUIC_SYNC};
use crate::sync::{quic::QuicStream, transport::SyncListener, Addr, GraphId, SyncPeer};

type AcceptResult = (SyncPeer, StreamAcceptor, Option<BidirectionalStream>);

#[derive(Debug)]
pub(crate) struct QuicListener {
    server: s2n_quic::Server,
    server_keys: Arc<PskStore>,
    conns: SharedConnectionMap,
    conn_rx: mpsc::Receiver<ConnectionUpdate>,
    pending_accepts: JoinSet<AcceptResult>,
    local_addr: Addr,
}

impl QuicListener {
    pub(crate) async fn new(
        addr: Addr,
        server_keys: Arc<PskStore>,
    ) -> Result<(Self, SharedConnectionMap), Error> {
        // Create shared connection map and channel for connection updates
        let (conns, conn_rx) = SharedConnectionMap::new();

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        #[allow(deprecated)]
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
            .map_err(Error::ServerStart)?;

        let local_addr = server
            .local_addr()
            .context("unable to get server local address")?
            .into();

        let server_instance = Self {
            server,
            server_keys,
            conns: conns.clone(),
            conn_rx,
            pending_accepts: JoinSet::new(),
            local_addr,
        };

        Ok((server_instance, conns))
    }

    fn spawn_stream_accept(&mut self, peer: SyncPeer, mut acceptor: StreamAcceptor) {
        self.pending_accepts.spawn(async move {
            let stream = acceptor.accept_bidirectional_stream().await.ok().flatten();
            (peer, acceptor, stream)
        });
    }

    async fn accept_connection(&self, mut conn: s2n_quic::Connection) -> Result<(), Error> {
        let handle = conn.handle();

        let result: Result<(), anyhow::Error> = async {
            trace!("received incoming QUIC connection");

            conn.keep_alive(true)
                .context("unable to keep connection alive")?;

            let identity = get_conn_identity(&mut conn)?;
            let active_team = self
                .server_keys
                .get_team_for_identity(&identity)
                .context("no active team for accepted connection")?;

            let peer_addr = extract_return_address(&mut conn)
                .await
                .context("could not get peer's return address")?;
            let peer = SyncPeer::new(peer_addr, GraphId::transmute(active_team));

            self.conns.insert(peer, conn).await;

            debug!(?peer, "accepted and inserted QUIC connection");
            Ok(())
        }
        .await;

        if let Err(error) = &result {
            error!(?error, "failed to accept connection");
            handle.close(application::Error::UNKNOWN);
        }

        result.map_err(Into::into)
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
                            self.spawn_stream_accept(peer, acceptor);
                            return Some(Ok(QuicStream::new(peer, stream)));
                        }
                        Ok((peer, _acceptor, None)) => debug!(?peer, "connection closed"),
                        Err(error) => warn!(%error, "stream acceptor task panicked"),
                    }
                }

                Some(conn) = self.server.accept() => {
                    if let Err(error) = self.accept_connection(conn).await {
                        warn!(%error, "stream acceptor task panicked");
                    }
                }

                Some((peer, acceptor)) = self.conn_rx.recv() => {
                    debug!(?peer, "registering connection for stream accepts");
                    self.spawn_stream_accept(peer, acceptor);
                }

                else => return None,
            }
        }
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
