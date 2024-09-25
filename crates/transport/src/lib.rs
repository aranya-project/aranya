//! Generic transport trait.

#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub use quic::*;

#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "udp")]
pub mod udp;
use std::{future::Future, io::Result, net::SocketAddr};

use serde::{Deserialize, Serialize};
#[cfg(feature = "udp")]
pub use udp::*;

/// Transport type.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransportType {
    /// QUIC transport.
    #[cfg(feature = "quic")]
    Quic,
    /// TCP transport.
    #[cfg(feature = "tcp")]
    Tcp,
    /// UDP transport.
    #[cfg(feature = "udp")]
    Udp,
}

/// Generic network transport trait.
pub trait Transport: Send + 'static {
    /// Waits for transport to be readable.
    fn readable(&mut self) -> impl Future<Output = Result<()>> + Send;
    /// Try to receive data via transport.
    fn try_recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(usize, SocketAddr)>> + Send;
    /// Send data via transport.
    fn send_to(
        &mut self,
        buf: &[u8],
        addr: SocketAddr,
    ) -> impl Future<Output = Result<usize>> + Send;
}

/// Checks if type implements [`Transport`] trait.
#[cfg(test)]
pub fn is_transport<T: Transport>() {}
