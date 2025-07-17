//! Configuration for a TCP server that streams metrics to clients using [`protobuf`].
//!
//! [`protobuf`]: https://protobuf.dev/

use std::net::SocketAddr;

use anyhow::{Context as _, Result};
use metrics_exporter_tcp::TcpBuilder;
use tracing::info;

/// Configuration info for the TCP exporter/server.
///
/// This includes the address to listen for TCP connections on, as well as the internal buffer size
/// used when sending protobuf data to any connected clients.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct TcpConfig {
    /// The address to listen on for TCP connections.
    listen_addr: SocketAddr,
    /// The size of the internal buffer used for processing metrics.
    buffer_size: Option<usize>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 5000)),
            buffer_size: Some(1024),
        }
    }
}

impl TcpConfig {
    /// Configures and installs the TCP server using the provided config info.
    pub(super) fn install(&self) -> Result<()> {
        info!("Setting up TCP metrics server: {}", self.listen_addr);

        TcpBuilder::new()
            .listen_address(self.listen_addr)
            .buffer_size(self.buffer_size)
            .install()
            .context("Failed to install TCP exporter")?;

        Ok(())
    }
}
