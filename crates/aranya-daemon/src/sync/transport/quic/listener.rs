//! This module implements [`QuicListener`] to allow accepting connections from QUIC clients.
use std::{collections::btree_map::Entry, net::SocketAddr};

use anyhow::Context as _;
use aranya_util::error::ReportExt as _;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::{task::JoinSet, time::Duration};
use tracing::{debug, error, trace, warn};

use super::{connections::ListenerPool, Error, QuicStream, SyncListener};
use crate::sync::{Addr, GraphId, SyncPeer};

/// The amount of time we wait trying to resolve the connecting peer's address (and waiting for them
/// to send the port they want) before we time out.
const RESOLVE_GRAPH_ID_TIMEOUT: Duration = Duration::from_secs(5);

enum AcceptResult {
    /// Got a stream, acceptor is still live.
    Stream(SyncPeer, Connection, (SendStream, RecvStream)),
    /// Acceptor returned None, connection is finished.
    Done(SyncPeer),
}

#[derive(Debug)]
pub(crate) struct QuicListener {
    /// The local address of the server, since it should be infallible.
    local_addr: SocketAddr,
    /// The QUIC server we use to accept raw connections.
    endpoint: quinn::Endpoint,
    /// Receiver to register new connections from the [`QuicConnector`](super::QuicConnector).
    pool: ListenerPool,
    /// Queue to allow awaiting a number of potential streams concurrently until one resolves.
    pending_accepts: JoinSet<AcceptResult>,
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
            pending_accepts: JoinSet::new(),
        }
    }

    /// Accepts an incoming bidirectional stream from this [`SyncPeer`].
    async fn accept_pending_stream(peer: SyncPeer, connection: Connection) -> AcceptResult {
        trace!(?peer, "waiting for bidirectional stream");

        match connection.accept_bi().await {
            Ok(stream) => {
                debug!(?peer, "accepted bidirectional stream");
                AcceptResult::Stream(peer, connection, stream)
            }
            Err(error) => {
                warn!(?peer, error = %error.report(), "error accepting bidirectional stream");
                AcceptResult::Done(peer)
            }
        }
    }

    /// Sets up the connection with a keep alive, constructs and validates a [`SyncPeer`], and
    /// registers it as a new connection.
    async fn register_connection(&mut self, mut conn: Connection) -> Result<(), Error> {
        let remote = conn.remote_address();
        trace!(?remote, "received incoming QUIC connection");

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
        self.local_addr.into()
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
                        Ok(AcceptResult::Done(peer)) => {
                            debug!(?peer, "connection finished, dropping acceptor");
                        }
                        Err(error) => error!(error = %error.report(), "stream acceptor task panicked"),
                    }
                }

                Some(incoming) = self.endpoint.accept() => {
                    let remote = incoming.remote_address();

                    // TODO(mtls): don't block here?
                    let conn = match incoming.await {
                        Ok(conn) => conn,
                        Err(error) => {
                            error!(?remote, error = %error.report(), "failed to accept incoming connection");
                            continue;
                        },
                    };

                    trace!(?remote, "raw connection accepted from server");

                    if let Err(error) = self.register_connection(conn.clone()).await {
                        error!(?remote, error = %error.report(), "failed to register connection");
                        conn.close(VarInt::from_u32(0), b"failed to register connection");
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

/// Extracts the graph ID from the connection.
async fn extract_graph_id(conn: &mut Connection) -> anyhow::Result<GraphId> {
    let mut recv = conn.accept_uni().await?;
    let mut buf = [0u8; 32];
    recv.read_exact(&mut buf).await?;
    Ok(GraphId::from_bytes(buf))
}
