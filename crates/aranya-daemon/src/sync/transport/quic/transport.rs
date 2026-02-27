//! This module implements [`QuicTransport`] to allow connecting to other peers.
use std::sync::Arc;

use anyhow::Context as _;
use aranya_daemon_api::TeamId;
use aranya_util::rustls::SkipServerVerification;
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{client::Connect, provider::tls::rustls::rustls::ClientConfig};
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

use super::{
    ConnectionUpdate, Error, PskStore, QuicStream, SharedConnectionMap, SyncTransport,
    ALPN_QUIC_SYNC,
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
}

impl QuicTransport {
    /// Creates a new [`QuicTransport`].
    pub(crate) fn new(
        client_addr: Addr,
        server_addr: Addr,
        conns: SharedConnectionMap,
        conn_tx: mpsc::Sender<ConnectionUpdate>,
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

        // Build up our return port to send to any peers we connect to.
        let return_port = Bytes::copy_from_slice(&server_addr.port().to_be_bytes());

        Ok(Self {
            client,
            conns,
            conn_tx,
            psk_store,
            return_port,
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

        // Obtain the handle and acceptor for this peer, potentially reusing a connection.
        let (mut handle, acceptor) = self
            .conns
            .get_or_connect(peer, async || {
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
                Ok(conn)
            })
            .await?;

        // If this is a new connection, forward an acceptor to the `QuicListener`.
        if let Some(acceptor) = acceptor {
            trace!(?peer, "forwarding acceptor to listener");
            self.conn_tx.send((peer, acceptor)).await.ok();
        }

        trace!("client connected to QUIC sync server");

        // Open a new bidirectional stream on our new connection.
        let stream = match handle.open_bidirectional_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                error!(?peer, %error, "failed to open bidirectional stream");
                self.conns.remove(peer, handle).await;
                return Err(Error::QuicConnection(error));
            }
        };

        debug!(?peer, "connected and opened stream");

        Ok(QuicStream::new(peer, stream))
    }
}
