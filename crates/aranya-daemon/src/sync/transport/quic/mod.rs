//! This module contains the QUIC transport code to allow syncing with other clients.

mod connections;
mod listener;
mod psk;
mod stream;
mod transport;

use self::{
    super::{SyncListener, SyncStream, SyncTransport},
    connections::{ConnectionReceiver, SharedConnectionMap},
    stream::QuicStream,
};
pub(crate) use self::{
    listener::QuicListener,
    psk::{PskSeed, PskStore},
    transport::QuicTransport,
};

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Errors specific to the QUIC transport.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// An error occurred when trying to use a QUIC connection.
    #[error(transparent)]
    QuicConnection(#[from] s2n_quic::connection::Error),

    /// An error occurred when trying to use a QUIC stream.
    #[error(transparent)]
    QuicStream(#[from] s2n_quic::stream::Error),

    /// Unable to start a new QUIC client.
    #[error("could not start QUIC client")]
    ClientStart(#[source] s2n_quic::provider::StartError),

    /// Unable to start a new QUIC server.
    #[error("could not start QUIC server")]
    ServerStart(#[source] s2n_quic::provider::StartError),

    /// Failed to send data on a QUIC stream.
    #[error(transparent)]
    Send(s2n_quic::stream::Error),

    /// Failed to receive data from a QUIC stream.
    #[error(transparent)]
    Receive(std::io::Error),

    /// Unable to communicate that the connection is finished.
    #[error(transparent)]
    Finish(s2n_quic::stream::Error),

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
