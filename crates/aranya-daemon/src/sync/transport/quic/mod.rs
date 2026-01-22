//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with mutual TLS (mTLS) authentication.
//! Both client and server verify each other's certificates against a shared
//! set of trusted root CAs.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use std::{convert::Infallible, path::PathBuf, sync::Arc};

use quinn::TransportConfig;

mod certs;
mod client;
mod connections;
mod server;

pub(crate) use client::QuicState;
pub(crate) use connections::{ConnectionKey, ConnectionUpdate, SharedConnectionMap};
pub(crate) use server::Server;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Creates a QUIC transport configuration that keeps connections alive indefinitely.
///
/// Disables idle timeout so connections can be reused across multiple sync operations.
fn keep_alive_transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(None);
    Arc::new(transport_config)
}

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Error {
    /// QUIC Connection error
    #[error("QUIC connection error: {0}")]
    QuicConnectionError(#[from] quinn::ConnectionError),
    /// QUIC Write error
    #[error("QUIC write error: {0}")]
    QuicWriteError(#[from] quinn::WriteError),
    /// QUIC Read error
    #[error("QUIC read error: {0}")]
    QuicReadError(#[from] quinn::ReadToEndError),
    /// QUIC Connect error
    #[error("QUIC connect error: {0}")]
    QuicConnectError(#[from] quinn::ConnectError),
    /// Certificate or TLS configuration error
    #[error(transparent)]
    Cert(#[from] certs::CertError),
    /// QUIC endpoint error
    #[error("QUIC endpoint error: {0}")]
    EndpointError(String),
    /// QUIC connection timeout
    #[error("QUIC connection timed out")]
    QuicConnectionTimeout,
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
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

/// Sync configuration for setting up Aranya.
pub(crate) struct SyncParams {
    pub(crate) cert_config: CertConfig,
    pub(crate) server_addr: crate::sync::Addr,
}
