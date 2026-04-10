//! This module contains the QUIC transport code to allow syncing with other clients.

mod certs;
mod connections;
mod connector;
mod listener;
mod stream;
mod tests;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context as _;
use aranya_util::Addr;
use buggy::BugExt as _;
use quinn::{Endpoint, TransportConfig};
use tracing::debug;

use self::{
    super::{SyncConnector, SyncListener, SyncStream},
    stream::QuicStream,
};
pub(crate) use self::{connector::QuicConnector, listener::QuicListener};

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Errors specific to the QUIC transport.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),

    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),

    /// Failed to send data on a QUIC stream.
    #[error(transparent)]
    Send(#[from] quinn::WriteError),

    /// Failed to receive data from a QUIC stream.
    #[error(transparent)]
    Receive(#[from] quinn::ReadExactError),

    /// Unable to communicate that the connection is finished.
    #[error(transparent)]
    Finish(quinn::ClosedStream),

    /// Certificate or TLS configuration error
    #[error(transparent)]
    Cert(#[from] certs::CertError),

    #[error("endpoint error: {0}")]
    Endpoint(String),

    /// A peer tried to send a message that was larger than we can handle.
    #[error("message exceeds buffer capacity")]
    MessageTooLarge,

    /// Encountered a bug in the program.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Something has gone wrong.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::convert::Infallible> for Error {
    fn from(err: std::convert::Infallible) -> Self {
        match err {}
    }
}

/// Certificate configuration for mTLS.
#[derive(Clone, Debug)]
pub struct CertConfig {
    /// Directory containing root CA certificates.
    pub root_certs_dir: PathBuf,
    /// Path to device certificate.
    pub device_cert: PathBuf,
    /// Path to device private key.
    pub device_key: PathBuf,
}

pub(crate) async fn new(
    addr: Addr,
    cert_config: &CertConfig,
) -> Result<(QuicConnector, QuicListener), Error> {
    // Load certificates once for both client and server configs
    let (root_store, device_certs, device_key) = certs::load_certs(cert_config)?;

    let server_config = {
        // Build server TLS config for mTLS (requires client certs)
        let mut tls_config = certs::build_server_config(
            root_store.clone(),
            device_certs.clone(),
            device_key.clone_key(),
        )?;
        tls_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()];

        let crypto_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| Error::Endpoint(format!("invalid QUIC TLS config: {e}")))?;

        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto_config));
        config.transport_config(transport_config());
        config
    };

    let client_config = {
        // Build client TLS config for mTLS (for outbound connections)
        let mut tls_config = certs::build_client_config(root_store, device_certs, device_key)?;
        tls_config.alpn_protocols = vec![ALPN_QUIC_SYNC.to_vec()];

        let crypto_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| Error::Endpoint(format!("invalid QUIC TLS config: {e}")))?;

        let mut config = quinn::ClientConfig::new(Arc::new(crypto_config));
        config.transport_config(transport_config());
        config
    };

    let bind_addr = tokio::net::lookup_host(addr.to_socket_addrs())
        .await
        .context("DNS lookup for server address")?
        .next()
        .assume("invalid server address")?;

    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| Error::Endpoint(format!("failed to create server endpoint: {e}")))?;

    let local_addr = endpoint
        .local_addr()
        .map_err(|e| Error::Endpoint(format!("unable to get local address: {e}")))?;

    debug!("created unified QUIC endpoint with mTLS at {}", local_addr);

    let (connector_pool, listener_pool) = connections::pool(32);

    let connector = QuicConnector::new(local_addr, endpoint.clone(), client_config, connector_pool);
    let listener = QuicListener::new(local_addr, endpoint, listener_pool);

    Ok((connector, listener))
}

/// Creates a QUIC transport configuration with no idle timeout.
///
/// Connections are kept open indefinitely without keep-alive pings.
/// This is appropriate for daemon-to-daemon connections where resources
/// are not constrained and connection reuse is desired.
fn transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    // Disable idle timeout - connections stay open forever.
    transport_config.max_idle_timeout(None);
    // No keep-alive pings needed since there's no idle timeout.
    transport_config.keep_alive_interval(None);
    Arc::new(transport_config)
}
