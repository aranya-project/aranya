//! QUIC-based networking.

mod client;
mod server;

#[cfg(test)]
mod tests;

use std::{
    io::{Error, ErrorKind, Result, Write},
    net::{SocketAddr, UdpSocket},
};

use anyhow::Context;
pub use client::*;
use quinn::Connecting;
pub use server::*;
use tracing::{debug, instrument, trace, warn};

use crate::Transport;

/// Quic implementation of [`Transport`].
pub struct QuicTransport {
    server: QuicServer,
    client: QuicClient,
    connecting: Option<Connecting>,
}

impl QuicTransport {
    /// Creates a `QuicServer` using `socket`.
    pub fn new(srv_cfg: ServerConfig, cli_cfg: ClientConfig, sock: UdpSocket) -> Result<Self> {
        let server = QuicServer::new(srv_cfg, sock)
            .context("unable to create quic server")
            .map_err(Error::other)?;
        let client = QuicClient::from_endpoint(cli_cfg, server.endpoint.clone())
            .context("unable to create quic client")
            .map_err(Error::other)?;
        Ok(Self {
            server,
            client,
            connecting: None,
        })
    }
}

impl Transport for QuicTransport {
    /// Waits for transport to be readable.
    #[instrument(skip_all)]
    async fn readable(&mut self) -> Result<()> {
        if self.connecting.is_none() {
            trace!("accepting...");
            self.connecting = self.server.endpoint.accept().await;
            trace!("accepted");
            if self.connecting.is_none() {
                warn!("endpoint is closed");
            }
        }
        Ok(())
    }

    /// Try to receive data via transport.
    async fn try_recv_from(&mut self, mut buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let Some(c) = self.connecting.take() else {
            return Err(Error::new(ErrorKind::WouldBlock, "no connecting stream"));
        };
        let conn = c.await?;
        let addr = conn.remote_address();
        let (_, mut recv) = conn.accept_bi().await?;
        let v = recv
            .read_to_end(buf.len())
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        buf.write_all(&v)?;
        debug!(n = v.len(), %addr, "recv_from");
        Ok((v.len(), addr))
    }

    /// Send data via transport.
    async fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let stream = self.client.connect(&addr).await.map_err(Error::other)?;
        stream.send_bytes(buf).await.map_err(Error::other)?;
        debug!(n = buf.len(), addr = %addr, "send_to");
        Ok(buf.len())
    }
}
