//! UDP networking.

#[cfg(test)]
mod tests;

use std::{io::Result, net::SocketAddr};

use tokio::net::UdpSocket;

use crate::Transport;

/// UDP implementation of [`Transport`].
pub struct UdpTransport(UdpSocket);

impl Transport for UdpTransport {
    /// Waits for transport to be readable.
    async fn readable(&mut self) -> Result<()> {
        self.0.readable().await
    }
    /// Try to receive data via transport.
    async fn try_recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.try_recv_from(buf)
    }
    /// Send data via transport.
    async fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.0.send_to(buf, addr).await
    }
}

impl From<UdpSocket> for UdpTransport {
    fn from(sock: UdpSocket) -> Self {
        UdpTransport(sock)
    }
}
