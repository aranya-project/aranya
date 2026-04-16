//! This module implements [`QuicConnector`] to allow connecting to other peers.
use std::{collections::btree_map::Entry, net::SocketAddr};

use anyhow::Context as _;
use aranya_util::error::ReportExt as _;
use quinn::{ClientConfig, Endpoint, VarInt};
use tracing::{debug, error, instrument, trace, warn};

use super::{connections::ConnectorPool, Error, QuicStream, SyncConnector};
use crate::sync::SyncPeer;

#[derive(Debug)]
pub(crate) struct QuicConnector {
    /// The local address of the server, since it should be infallible.
    local_addr: SocketAddr,
    /// The QUIC client we use to connect to other peers.
    endpoint: Endpoint,
    /// Configuration for making connections.
    ///
    /// This is currently a single instance since we don't distinguish teams.
    config: ClientConfig,
    /// Allows sending new connections to the [`QuicListener`].
    pool: ConnectorPool,
}

impl QuicConnector {
    pub(super) fn new(
        local_addr: SocketAddr,
        endpoint: Endpoint,
        config: ClientConfig,
        pool: ConnectorPool,
    ) -> Self {
        Self {
            local_addr,
            endpoint,
            config,
            pool,
        }
    }
}

impl SyncConnector for QuicConnector {
    type Error = Error;
    type Stream = QuicStream;

    #[instrument(skip(self))]
    async fn connect(&self, peer: SyncPeer) -> Result<Self::Stream, Self::Error> {
        debug!("connecting to peer");

        // Obtain the address for the other peer.
        let addrs = tokio::net::lookup_host(peer.addr.to_socket_addrs())
            .await
            .context("DNS lookup for peer address")?;
        let addr = find_matching_ip_version(addrs, self.local_addr)
            .context("no resolved address matches local endpoint IP version")?;
        trace!(%addr, "resolved peer address");

        // Check for an existing live connection, cleaning up dead ones.
        let reuse = self.pool.conns.with_map(|map| match map.entry(peer) {
            Entry::Occupied(e) => match e.get().close_reason() {
                None => {
                    debug!("reusing existing connection");
                    Some(e.get().clone())
                }
                Some(error) => {
                    warn!(error = %error.report(), "existing connection dead, removing");
                    e.remove();
                    None
                }
            },
            Entry::Vacant(_) => None,
        });

        let handle = if let Some(handle) = reuse {
            handle
        } else {
            // Create a new outbound connection.
            trace!("establishing new QUIC connection");

            // This is where we could create/select a per-team config.
            let config = self.config.clone();

            // TODO(mtls): timeout?
            let new_conn = self
                .endpoint
                .connect_with(config, addr, peer.addr.host())?
                .await?;
            new_conn
                .open_uni()
                .await?
                .write_all(peer.graph_id.as_bytes())
                .await?;

            debug!("QUIC handshake complete and sent graph ID");

            // Re-acquire the lock and insert using tie-breaking logic. Between dropping the lock
            // above and now, the listener may have inserted an inbound connection for this peer.
            let (handle, acceptor) = self.pool.conns.with_map(|map| {
                match map.entry(peer) {
                    Entry::Vacant(e) => {
                        e.insert(new_conn.clone());
                        (new_conn.clone(), Some(new_conn))
                    }
                    Entry::Occupied(mut e) => {
                        let existing_alive = e.get().close_reason().is_none();
                        // We initiated this connection, so it wins if we're the lower-addressed peer.
                        // TODO(nikki): This semi-fixes an existing bug, but we need a better way
                        // than raw addresses, this will break with NAT.
                        // https://github.com/aranya-project/aranya/issues/754
                        let outbound_wins = !existing_alive || self.local_addr < addr;
                        if outbound_wins {
                            if existing_alive {
                                debug!("replacing existing connection (tie-break)");
                                e.get_mut().close(
                                    VarInt::from_u32(0),
                                    b"replacing existing connection (tie-break)",
                                );
                            }
                            e.insert(new_conn.clone());
                            (new_conn.clone(), Some(new_conn))
                        } else {
                            // Existing inbound wins — discard ours.
                            debug!("keeping existing inbound connection (tie-break)");
                            let existing = e.get().clone();
                            new_conn.close(
                                VarInt::from_u32(0),
                                b"keeping existing inbound connection (tie-break)",
                            );
                            (existing, None)
                        }
                    }
                }
            });

            // Forward acceptor to the listener if we kept our connection.
            if let Some(acceptor) = acceptor {
                trace!("forwarding acceptor to listener");
                self.pool.tx.send((peer, acceptor)).await.ok();
            }

            handle
        };

        trace!("client connected to QUIC sync server");

        // Open a new bidirectional stream on our new connection.
        let stream = match handle.open_bi().await {
            Ok(stream) => stream,
            Err(error) => {
                error!(error = %error.report(), "failed to open bidirectional stream");
                self.pool.conns.with_map(|map| {
                    if let Entry::Occupied(e) = map.entry(peer) {
                        if e.get().stable_id() == handle.stable_id() {
                            e.remove()
                                .close(VarInt::from_u32(0), b"failed to open stream");
                        }
                    }
                });
                return Err(Error::Connection(error));
            }
        };

        debug!("connected and opened stream");

        Ok(QuicStream::new(peer, stream))
    }
}

/// Finds a resolved address that matches the IP version of the local endpoint.
///
/// QUIC connections require both endpoints to use the same IP version - an IPv4-bound
/// endpoint cannot connect to an IPv6 address and vice versa. When a hostname resolves
/// to multiple addresses (both A and AAAA records), we must select one that matches
/// our local endpoint's IP version.
///
/// # Arguments
/// * `addrs` - List of resolved socket addresses from DNS lookup
/// * `local_addr` - The local endpoint's bound address
///
/// # Returns
/// * `Some(SocketAddr)` - A resolved address matching the local IP version
/// * `None` - No matching address found
fn find_matching_ip_version(
    addrs: impl IntoIterator<Item = SocketAddr>,
    local_addr: SocketAddr,
) -> Option<SocketAddr> {
    if local_addr.is_ipv4() {
        addrs.into_iter().find(|a| a.is_ipv4())
    } else {
        addrs.into_iter().find(|a| a.is_ipv6())
    }
}
