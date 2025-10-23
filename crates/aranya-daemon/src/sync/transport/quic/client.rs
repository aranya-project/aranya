use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Context as _;
use aranya_util::{error::ReportExt as _, rustls::SkipServerVerification};
use buggy::BugExt as _;
use futures_util::AsyncWriteExt as _;
use s2n_quic::{
    client::Connect,
    connection::Error as ConnectionError,
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{rustls::ClientConfig, Client},
        StartError,
    },
    stream::{BidirectionalStream, Error as StreamError},
    Client as QuicClient,
};
use tokio::io::AsyncReadExt;
use tracing::{debug, error};

use super::{connections::SharedConnections, psk::PskStore, ALPN_QUIC_SYNC};
use crate::sync::{Result, SyncPeer, Transport};

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// QUIC Connection error
    #[error(transparent)]
    QuicConnectionError(#[from] ConnectionError),
    /// QUIC Stream error
    #[error(transparent)]
    QuicStreamError(#[from] StreamError),
    /// QUIC client endpoint start error
    #[error("could not start QUIC client")]
    ClientStart(#[source] StartError),
    /// QUIC server endpoint start error
    #[error("could not start QUIC server")]
    ServerStart(#[source] StartError),
    /// Invalid PSK used for syncing
    #[error("invalid PSK used when attempting to sync")]
    InvalidPSK,
}

/// QUIC syncer state used for sending sync requests and processing sync responses
#[derive(Debug)]
pub struct QuicTransport {
    /// QUIC client to make sync requests to another peer's sync server and handle sync responses.
    client: QuicClient,
    /// Address -> Connection map to lookup existing connections before creating a new connection.
    connections: SharedConnections,
    /// PSK store shared between the daemon API server and QUIC syncer client and server.
    /// This store is modified by [`crate::api::DaemonApiServer`].
    store: Arc<PskStore>,
}

impl QuicTransport {
    /// Creates a new instance
    fn new(psk_store: Arc<PskStore>, connections: SharedConnections) -> Result<Self> {
        // Create client config (INSECURE: skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()]; // Set field directly
        client_config.preshared_keys = psk_store.clone(); // Pass the Arc<PskStore>

        // Client builder doesn't support adding preshared keys
        #[allow(deprecated)]
        let provider = Client::new(client_config);

        let client = QuicClient::builder()
            .with_tls(provider)?
            .with_io((Ipv4Addr::UNSPECIFIED, 0))
            .assume("can set quic client address")?
            .with_congestion_controller(Bbr::default())?
            .start()
            .map_err(QuicError::ClientStart)?;

        Ok(Self {
            client,
            connections,
            store: psk_store,
        })
    }

    /// Get a reference to the PSK store
    pub fn store(&self) -> &Arc<PskStore> {
        &self.store
    }

    /// Establishes a QUIC connection to a peer and opens a bidirectional stream.
    ///
    /// This method first checks if there's an existing connection to the peer.
    /// If not, it creates a new QUIC connection. Then it opens a bidirectional
    /// stream for sending sync requests and receiving responses.
    pub(crate) async fn connect(&self, peer: &SyncPeer) -> Result<BidirectionalStream> {
        debug!("connecting to peer via QUIC");

        // Sets the active team before starting a QUIC connection
        self.store.set_team(peer.graph_id.into_id().into());

        // DNS lookup
        let addr = tokio::net::lookup_host(peer.addr.to_socket_addrs())
            .await
            .context("DNS lookup failed")?
            .next()
            .context("could not resolve peer address")?;

        let key = SyncPeer {
            addr: addr.into(),
            graph_id: peer.graph_id,
        };

        let mut handle = self
            .connections
            .get_or_try_insert_with(key, async || {
                let mut conn = self
                    .client
                    .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
                    .await?;
                conn.keep_alive(true)?;
                Ok(conn)
            })
            .await?;

        debug!("connected to peer");

        let stream = match handle.open_bidirectional_stream().await {
            Ok(stream) => stream,
            // Retry for these errors?
            Err(e @ ConnectionError::StatelessReset { .. })
            | Err(e @ ConnectionError::StreamIdExhausted { .. })
            | Err(e @ ConnectionError::MaxHandshakeDurationExceeded { .. }) => {
                return Err(QuicError::from(e).into());
            }
            // Other errors means the stream has closed
            Err(e) => {
                error!(error = %e.report(), "unable to open bidi stream");
                self.connections.remove(key, handle).await;
                return Err(QuicError::from(e).into());
            }
        };

        debug!("opened bidirectional stream");
        Ok(stream)
    }
}

#[async_trait::async_trait]
impl Transport for QuicTransport {
    async fn execute_sync(
        &self,
        peer: &SyncPeer,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize> {
        let stream = self
            .connect(peer)
            .await
            .inspect_err(|e| error!(error = %e.report(), "could not create connection"))?;
        // TODO: spawn a task for send/recv?
        let (mut recv, mut send) = stream.split();

        send.write_all(request)
            .await
            .context("failed to send request")?;
        send.finish().context("failed to finish sending request")?;
        debug!(len = request.len(), "sent request");

        let mut temp_buf = Vec::new();
        recv.read_to_end(&mut temp_buf)
            .await
            .context("failed to read response")?;
        debug!(len = temp_buf.len(), "received response");

        let len = temp_buf.len().min(response.len());
        response[..len].copy_from_slice(&temp_buf[..len]);

        if temp_buf.len() > response.len() {
            error!(
                response_len = temp_buf.len(),
                buffer_len = response.len(),
                peer = %peer.addr,
                graph = %peer.graph_id,
                "response larger than buffer, truncated"
            );
        }

        Ok(len)
    }
}
