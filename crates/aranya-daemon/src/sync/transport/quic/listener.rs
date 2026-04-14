//! This module implements [`QuicListener`] to allow accepting connections from QUIC clients.
use std::{collections::btree_map::Entry, future::Future, net::SocketAddr, pin::Pin, task::Poll};

use anyhow::Context as _;
use aranya_util::error::ReportExt as _;
use derive_where::derive_where;
use futures_util::{
    stream::{FuturesUnordered, SelectAll},
    Stream, StreamExt as _,
};
use quinn::{Connection, Incoming, VarInt};
use tokio::time::Duration;
use tracing::{debug, error, info_span, warn, Instrument as _};

use super::{connections::ListenerPool, Error, QuicStream, SyncListener};
use crate::sync::{Addr, GraphId, SyncPeer};

/// The amount of time we wait trying to resolve the connecting peer's address (and waiting for them
/// to send the port they want) before we time out.
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
            Ok(connecting) => self.connecting.0.push(Connecting {
                remote,
                inner: connecting,
            }),
            Err(error) => error!(%remote, error = %error.report(), "failed to accept connection"),
        }
    }

    /// Sets up the connection with a keep alive, constructs and validates a [`SyncPeer`], and
    /// registers it as a new connection.
    async fn register_connection(&mut self, mut conn: Connection) -> Result<(), Error> {
        let remote = conn.remote_address();

        let graph_id = tokio::time::timeout(RESOLVE_GRAPH_ID_TIMEOUT, extract_graph_id(&mut conn))
            .await
            .context("timed out waiting for graph ID")?
            .context("unable to extract graph ID")?;
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

        Ok(())
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
                Some(conn) = self.connecting.next() => {
                    if let Err(error) = self.register_connection(conn.clone()).await {
                        error!(
                            remote = %conn.remote_address(),
                            error = %error.report(),
                            "failed to register connection",
                        );
                        conn.close(VarInt::from_u32(0), b"failed to register connection");
                    }
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

/// A pending QUIC connection.
struct Connecting {
    remote: SocketAddr,
    inner: quinn::Connecting,
}

impl Future for Connecting {
    type Output = Option<Connection>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(|r| {
            r.inspect_err(|error| {
                error!(
                    remote = %self.remote,
                    error = %error.report(),
                    "failed to resolve connection",
                );
            })
            .ok()
        })
    }
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
