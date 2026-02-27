//! This module implements [`QuicTransport`] to allow connecting to other peers.
use std::{collections::btree_map::Entry, sync::Arc};

use anyhow::Context as _;
use aranya_daemon_api::TeamId;
use aranya_util::rustls::SkipServerVerification;
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{
    application::Error as AppError, client::Connect, provider::tls::rustls::rustls::ClientConfig,
};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use super::{
    listener::{ConnectionUpdate, SharedConnectionMap},
    Error, PskStore, QuicStream, SyncTransport, ALPN_QUIC_SYNC,
};
use crate::sync::{Addr, SyncPeer};

#[derive(Clone, Debug)]
pub(crate) struct QuicTransport {
    /// The QUIC client we use to connect to other peers.
    client: s2n_quic::Client,
    /// Handle to the `SharedConnectionMap` to send new acceptors to the `QuicListener`.
    conns: SharedConnectionMap,
    /// Sender for forwarding new acceptors to the `SyncListener` for incoming connections.
    conn_tx: mpsc::Sender<ConnectionUpdate>,
    /// Allows authenticating the identity of a given `GraphId`.
    psk_store: Arc<PskStore>,
    /// The return port we want the peer to connect to us on.
    return_port: Bytes,
    /// The local address of the server, since it should be infallible.
    local_addr: Addr,
}

impl QuicTransport {
    /// Creates a new [`QuicTransport`].
    pub(crate) fn new(
        client_addr: Addr,
        server_addr: Addr,
        conns: SharedConnectionMap,
        conn_tx: mpsc::Sender<ConnectionUpdate>,
        psk_store: Arc<PskStore>,
        local_addr: Addr,
    ) -> Result<Self, Error> {
        // Build up the `ClientConfig` so we can initialize the TLS client.
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = Arc::<PskStore>::clone(&psk_store); // Pass the Arc<ClientPresharedKeys>

        #[allow(deprecated)]
        let provider = s2n_quic::provider::tls::rustls::Client::new(client_config);

        // Start up a new QUIC client.
        let client = s2n_quic::Client::builder()
            .with_tls(provider)?
            .with_io((client_addr.host(), client_addr.port()))
            .assume("can set quic client address")?
            .start()
            .map_err(Error::ClientStart)?;

        // Build up our return port to send to any peers we connect to.
        let return_port = Bytes::copy_from_slice(&server_addr.port().to_be_bytes());

        Ok(Self {
            client,
            conns,
            conn_tx,
            psk_store,
            return_port,
            local_addr,
        })
    }
}

impl SyncTransport for QuicTransport {
    type Error = Error;
    type Stream = QuicStream;

    async fn connect(&self, peer: SyncPeer) -> Result<Self::Stream, Self::Error> {
        // Set the current `GraphId` we're operating on in the PSK store.
        self.psk_store.set_team(TeamId::transmute(peer.graph_id));
        debug!(?peer, "connecting to peer");

        // Obtain the address for the other peer.
        let addr = tokio::net::lookup_host(peer.addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .context("could not resolve peer address")?;
        trace!(?peer, %addr, "resolved peer address");

        // Check for an existing live connection, cleaning up dead ones.
        // Drops the lock before doing async connection work.
        let reuse = {
            // Hold the lock across this entire operation
            let mut map = self.conns.lock().await;
            match map.entry(peer) {
                Entry::Occupied(mut e) => {
                    if e.get_mut().ping().is_ok() {
                        debug!(?peer, "reusing existing connection");
                        Some(e.get().clone())
                    } else {
                        warn!(?peer, "existing connection dead, removing");
                        e.remove().close(AppError::UNKNOWN);
                        None
                    }
                }
                Entry::Vacant(_) => None,
            }
        };

        let mut handle = if let Some(handle) = reuse {
            handle
        } else {
            // Create a new outbound connection.
            trace!(?peer, "establishing new QUIC connection");
            let mut conn = self
                .client
                .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                .await?;
            conn.keep_alive(true)?;
            conn.open_send_stream()
                .await?
                .send(self.return_port.clone())
                .await?;
            debug!(?peer, "QUIC handshake complete, sent return port");

            // Re-acquire the lock and insert using tie-breaking logic. Between dropping the lock
            // above and now, the listener may have inserted an inbound connection for this peer.
            let (new_handle, new_acceptor) = conn.split();
            let (handle, acceptor) = {
                // Hold the lock across this entire operation
                let mut map = self.conns.lock().await;
                match map.entry(peer) {
                    Entry::Vacant(e) => {
                        e.insert(new_handle.clone());
                        (new_handle, Some(new_acceptor))
                    }
                    Entry::Occupied(mut e) => {
                        let existing_alive = e.get_mut().ping().is_ok();
                        // We initiated this connection, so it wins if we're the lower-addressed peer.
                        let outbound_wins = !existing_alive || self.local_addr < peer.addr;
                        if outbound_wins {
                            if existing_alive {
                                debug!(?peer, "replacing existing connection (tie-break)");
                                e.get_mut().close(AppError::UNKNOWN);
                            }
                            e.insert(new_handle.clone());
                            (new_handle, Some(new_acceptor))
                        } else {
                            // Existing inbound wins — discard ours.
                            debug!(?peer, "keeping existing inbound connection (tie-break)");
                            let existing = e.get().clone();
                            new_handle.close(AppError::UNKNOWN);
                            (existing, None)
                        }
                    }
                }
            };

            // Forward acceptor to the listener if we kept our connection.
            if let Some(acceptor) = acceptor {
                trace!(?peer, "forwarding acceptor to listener");
                self.conn_tx.send((peer, acceptor)).await.ok();
            }

            handle
        };

        trace!("client connected to QUIC sync server");

        // Open a new bidirectional stream on our new connection.
        let stream = match handle.open_bidirectional_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                error!(?peer, %error, "failed to open bidirectional stream");
                let mut map = self.conns.lock().await;
                if let Entry::Occupied(e) = map.entry(peer) {
                    if e.get().id() == handle.id() {
                        e.remove().close(AppError::UNKNOWN);
                    }
                }
                return Err(Error::QuicConnection(error));
            }
        };

        debug!(?peer, "connected and opened stream");

        Ok(QuicStream::new(peer, stream))
    }
}
