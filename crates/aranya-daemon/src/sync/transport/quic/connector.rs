//! This module implements [`QuicConnector`] to allow connecting to other peers.
use std::{collections::btree_map::Entry, sync::Arc};

use anyhow::Context as _;
use aranya_daemon_api::TeamId;
use aranya_util::rustls::SkipServerVerification;
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{
    application::Error as AppError, client::Connect, provider::tls::rustls::rustls::ClientConfig,
};
use tracing::{debug, error, trace, warn};

use super::{
    connections::ConnectorPool, ConnectionInfo, Error, PskStore, QuicStream, SyncConnector,
    ALPN_QUIC_SYNC,
};
use crate::sync::{Addr, SyncPeer};

#[derive(Debug)]
pub(crate) struct QuicConnector {
    /// The QUIC client we use to connect to other peers.
    client: s2n_quic::Client,
    /// Allows sending new connections to the [`QuicListener`].
    pool: ConnectorPool,
    /// Allows authenticating the identity of a given `GraphId`.
    psk_store: Arc<PskStore>,
    /// Serialized connection info to send to peers.
    conn_info_bytes: Bytes,
}

impl QuicConnector {
    /// Creates a new [`QuicConnector`].
    pub(crate) fn new(
        client_addr: Addr,
        server_addr: Addr,
        pool: ConnectorPool,
        psk_store: Arc<PskStore>,
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

        // Build up the connection info to send to any peers we connect to.
        let conn_info = ConnectionInfo {
            port: server_addr.port(),
            device_id: pool.local_device_id,
        };
        let conn_info_bytes = Bytes::from(
            postcard::to_allocvec(&conn_info)
                .map_err(|e| Error::Other(anyhow::anyhow!("failed to serialize ConnectionInfo: {e}")))?,
        );

        Ok(Self {
            client,
            pool,
            psk_store,
            conn_info_bytes,
        })
    }
}

impl SyncConnector for QuicConnector {
    type Error = Error;
    type Stream = QuicStream;

    async fn connect(&self, peer: SyncPeer) -> Result<Self::Stream, Self::Error> {
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
            let mut map = self.pool.conns.lock().await;
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
            let mut conn = {
                // Set the current `GraphId` we're operating on in the PSK store.
                let _guard = self
                    .psk_store
                    .set_team(TeamId::transmute(peer.graph_id))
                    .await;
                self.client
                    .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                    .await?
            };
            conn.keep_alive(true)?;
            // Send our connection info (return port + device ID).
            conn.open_send_stream()
                .await?
                .send(self.conn_info_bytes.clone())
                .await?;
            // Receive the listener's device ID for tie-breaking.
            let remote_id_bytes = conn
                .accept_receive_stream()
                .await?
                .context("unable to accept device ID stream")?
                .receive()
                .await?
                .context("peer didn't send device ID")?;
            let remote_device_id: [u8; 32] = remote_id_bytes
                .as_ref()
                .try_into()
                .context("invalid device ID length")?;
            debug!(?peer, "QUIC handshake complete, exchanged connection info");

            // Re-acquire the lock and insert using tie-breaking logic. Between dropping the lock
            // above and now, the listener may have inserted an inbound connection for this peer.
            // Tie-break using device IDs — the peer with the lower device ID keeps its outbound.
            let local_device_id = self.pool.local_device_id;
            let (new_handle, new_acceptor) = conn.split();
            let (handle, acceptor) = {
                // Hold the lock across this entire operation
                let mut map = self.pool.conns.lock().await;
                match map.entry(peer) {
                    Entry::Vacant(e) => {
                        e.insert(new_handle.clone());
                        (new_handle, Some(new_acceptor))
                    }
                    Entry::Occupied(mut e) => {
                        let existing_alive = e.get_mut().ping().is_ok();
                        // The outbound connection wins if we have the lower device ID.
                        let outbound_wins =
                            !existing_alive || local_device_id < remote_device_id;
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
                self.pool.tx.send((peer, acceptor)).await.ok();
            }

            handle
        };

        trace!("client connected to QUIC sync server");

        // Open a new bidirectional stream on our new connection.
        let stream = match handle.open_bidirectional_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                error!(?peer, %error, "failed to open bidirectional stream");
                let mut map = self.pool.conns.lock().await;
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
