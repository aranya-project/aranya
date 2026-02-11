use std::sync::Arc;

use anyhow::Context as _;
use aranya_daemon_api::TeamId;
use aranya_util::rustls::SkipServerVerification;
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{client::Connect, provider::tls::rustls::rustls::ClientConfig};
use tracing::trace;

use super::{Error, PskStore, SharedConnectionMap, ALPN_QUIC_SYNC};
use crate::sync::{quic::QuicStream, transport::SyncTransport, Addr, SyncPeer};

#[derive(Clone, Debug)]
pub(crate) struct QuicTransport {
    client: s2n_quic::Client,
    conns: SharedConnectionMap,
    psk_store: Arc<PskStore>,
    return_address: Bytes,
}

impl QuicTransport {
    pub(crate) fn new(
        client_addr: Addr,
        conns: SharedConnectionMap,
        psk_store: Arc<PskStore>,
        return_address: Bytes,
    ) -> Result<Self, Error> {
        // Create client config (INSECURE: skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = Arc::<PskStore>::clone(&psk_store); // Pass the Arc<ClientPresharedKeys>

        // Client builder doesn't support adding preshared keys
        #[allow(deprecated)]
        let provider = s2n_quic::provider::tls::rustls::Client::new(client_config);

        let client = s2n_quic::Client::builder()
            .with_tls(provider)?
            .with_io((client_addr.host(), client_addr.port()))
            .assume("can set quic client address")?
            .start()
            .map_err(Error::ClientStart)?;

        Ok(Self {
            client,
            conns,
            psk_store,
            return_address,
        })
    }
}

#[async_trait::async_trait]
impl SyncTransport for QuicTransport {
    type Error = Error;
    type Stream = QuicStream;

    async fn connect(&self, peer: SyncPeer) -> Result<Self::Stream, Self::Error> {
        // Sets the active team before starting a QUIC connection
        self.psk_store.set_team(TeamId::transmute(peer.graph_id));

        trace!("client connecting to QUIC sync server");
        // Check if there is an existing connection with the peer.
        // If not, create a new connection.

        let addr = tokio::net::lookup_host(peer.addr.to_socket_addrs())
            .await
            .context("DNS lookup on for peer address")?
            .next()
            .context("could not resolve peer address")?;

        let mut handle = self
            .conns
            .get_or_try_insert_with(peer, async || {
                let mut conn = self
                    .client
                    .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                    .await?;
                conn.keep_alive(true)?;
                conn.open_send_stream()
                    .await?
                    .send(self.return_address.clone())
                    .await?;
                Ok(conn)
            })
            .await?;

        trace!("client connected to QUIC sync server");

        let stream = match handle.open_bidirectional_stream().await {
            Ok(stream) => stream,
            // Retry for these errors?
            Err(
                e @ (s2n_quic::connection::Error::StatelessReset { .. }
                | s2n_quic::connection::Error::StreamIdExhausted { .. }
                | s2n_quic::connection::Error::MaxHandshakeDurationExceeded { .. }),
            ) => {
                return Err(Error::QuicConnection(e));
            }
            // Other errors means the stream has closed
            Err(e) => {
                self.conns.remove(peer, handle).await;
                return Err(Error::QuicConnection(e));
            }
        };

        trace!("client opened bidi stream with QUIC sync server");

        Ok(QuicStream::new(peer, stream))
    }
}
