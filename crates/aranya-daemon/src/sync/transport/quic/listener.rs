//! This module implements [`QuicListener`] to allow accepting connections from QUIC clients.
use std::{collections::btree_map::Entry, future::Future, net::SocketAddr, pin::Pin, task::Poll};

use aranya_util::error::ReportExt as _;
use derive_where::derive_where;
use futures_util::{
    stream::{FuturesUnordered, SelectAll},
    Stream, StreamExt as _,
};
use quinn::{Connection, Incoming, VarInt};
use tokio::time::Duration;
use tracing::{debug, error, info_span, warn, Instrument as _};

use super::{connections::ListenerPool, QuicStream, SyncListener};
use crate::sync::{Addr, GraphId, SyncPeer};

/// The amount of time we wait to receive the connecting peer's graph ID.
const RESOLVE_GRAPH_ID_TIMEOUT: Duration = Duration::from_secs(5);

#[derive_where(Debug)]
pub(crate) struct QuicListener {
    /// The local address of the server, since it should be infallible.
    local_addr: SocketAddr,
    /// The QUIC server we use to accept raw connections.
    endpoint: quinn::Endpoint,
    /// Receiver to register new connections from the [`QuicConnector`](super::QuicConnector).
    pool: ListenerPool,
    /// Queue to allow awaiting a number of potential streams concurrently until one resolves.
    #[derive_where(skip(Debug))]
    accepting: SelectAll<Accepting>,
    /// Set of incoming connections which have not yet completed.
    #[derive_where(skip(Debug))]
    connecting: FlattenOption<FuturesUnordered<Connecting>>,
}

impl QuicListener {
    pub(super) fn new(
        local_addr: SocketAddr,
        endpoint: quinn::Endpoint,
        pool: ListenerPool,
    ) -> Self {
        Self {
            local_addr,
            endpoint,
            pool,
            accepting: SelectAll::new(),
            connecting: FlattenOption(FuturesUnordered::new()),
        }
    }

    fn accept_incoming(&mut self, incoming: Incoming) {
        let remote = incoming.remote_address();
        match incoming.accept() {
            Ok(connecting) => self
                .connecting
                .0
                .push(resolve_connecting(remote, connecting)),
            Err(error) => error!(%remote, error = %error.report(), "failed to accept connection"),
        }
    }

    /// Sets up the connection with a keep alive, constructs and validates a [`SyncPeer`], and
    /// registers it as a new connection.
    async fn register_connection(&mut self, conn: Connection, graph_id: GraphId) {
        let remote = conn.remote_address();

        // TODO(mtls): Key just on addr?
        let peer = SyncPeer::new(Addr::from(remote), graph_id);

        // Insert with tie-breaking. The peer initiated this connection,
        // so it wins if peer.addr < local_addr.
        let acceptor = {
            let mut map = self.pool.conns.lock().await;
            match map.entry(peer) {
                Entry::Vacant(e) => {
                    e.insert(conn.clone());
                    Some(conn)
                }
                Entry::Occupied(mut e) => {
                    let existing_alive = e.get_mut().close_reason().is_none();
                    let inbound_wins = !existing_alive || remote < self.local_addr;
                    if inbound_wins {
                        if existing_alive {
                            debug!(?peer, "replacing existing connection (tie-break)");
                            e.get().close(
                                VarInt::from_u32(0),
                                b"replacing existing connection (tie-break)",
                            );
                        }
                        e.insert(conn.clone());
                        Some(conn)
                    } else {
                        debug!(?peer, "keeping existing outbound connection (tie-break)");
                        conn.close(
                            VarInt::from_u32(0),
                            b"keeping existing outbound connection (tie-break)",
                        );
                        None
                    }
                }
            }
        };

        if let Some(acceptor) = acceptor {
            self.accepting.push(accepting(peer, acceptor));
            debug!(?peer, "accepted and inserted QUIC connection");
        }
    }
}

impl SyncListener for QuicListener {
    type Stream = QuicStream;

    fn local_addr(&self) -> Addr {
        self.local_addr.into()
    }

    #[allow(
        clippy::disallowed_macros,
        reason = "tokio::select! uses core::unreachable"
    )]
    async fn accept(&mut self) -> Option<Self::Stream> {
        loop {
            tokio::select! {
                Some(stream) = self.accepting.next() => {
                    return Some(stream);
                }
                Some(incoming) = self.endpoint.accept() => {
                    self.accept_incoming(incoming);
                }
                Some((conn, graph_id)) = self.connecting.next() => {
                    self.register_connection(conn, graph_id).await;
                }
                Some((peer, acceptor)) = self.pool.rx.recv() => {
                    debug!(?peer, "registering connection for stream accepts");
                    self.accepting.push(accepting(peer, acceptor));
                }
                else => {
                    debug!("all accept sources exhausted, shutting down listener");
                    return None;
                }
            }
        }
    }
}

type Accepting = Pin<Box<dyn Stream<Item = QuicStream> + Send + Sync>>;

/// Produce a [`Stream`] of accepted [`QuicStream`]s.
fn accepting(peer: SyncPeer, conn: Connection) -> Accepting {
    Box::pin(futures_util::stream::unfold(
        (peer, conn),
        |(peer, conn)| {
            async move {
                match conn.accept_bi().await {
                    Ok(stream) => {
                        debug!("accepted bidirectional stream");
                        Some((QuicStream::new(peer, stream), (peer, conn)))
                    }
                    Err(error) => {
                        warn!(error = %error.report(), "error accepting bidirectional stream");
                        None
                    }
                }
            }
            .instrument(info_span!("accepting", ?peer))
        },
    ))
}

type Connecting = Pin<Box<dyn Future<Output = Option<(Connection, GraphId)>> + Send + Sync>>;

/// A pending QUIC connection.
fn resolve_connecting(remote: SocketAddr, inner: quinn::Connecting) -> Connecting {
    Box::pin(
        async {
            let mut conn = inner
                .await
                .inspect_err(|error| {
                    error!(error = %error.report(), "failed to resolve connection");
                })
                .ok()?;

            let graph_id =
                tokio::time::timeout(RESOLVE_GRAPH_ID_TIMEOUT, extract_graph_id(&mut conn))
                    .await
                    .inspect_err(|_| {
                        error!("timeout resolving graph ID");
                        conn.close(VarInt::from_u32(0), b"timeout resolving graph ID");
                    })
                    .ok()?
                    .inspect_err(|error| {
                        error!(%error, "failed to read graph ID");
                        conn.close(VarInt::from_u32(0), b"failed to read graph ID");
                    })
                    .ok()?;

            Some((conn, graph_id))
        }
        .instrument(info_span!("resolve_connecting", %remote)),
    )
}

/// Flattens `Stream<Item=Option<T>>` to `Stream<Item=T>`.
struct FlattenOption<St>(St);

impl<St, T> Stream for FlattenOption<St>
where
    St: Stream<Item = Option<T>> + Unpin,
{
    type Item = T;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match std::task::ready!(self.0.poll_next_unpin(cx)) {
                Some(Some(item)) => return Poll::Ready(Some(item)),
                Some(None) => {}
                None => return Poll::Ready(None),
            }
        }
    }
}

/// Extracts the graph ID from the connection.
async fn extract_graph_id(conn: &mut Connection) -> anyhow::Result<GraphId> {
    let mut recv = conn.accept_uni().await?;
    let mut buf = [0u8; 32];
    recv.read_exact(&mut buf).await?;
    Ok(GraphId::from_bytes(buf))
}
