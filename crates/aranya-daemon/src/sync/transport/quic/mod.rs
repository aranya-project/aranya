//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use std::{convert::Infallible, sync::Arc};

use tracing::error;

use crate::sync::Addr;

mod client;
mod connections;
mod psk;
mod server;
mod stream;
mod transport;

pub(crate) use connections::{ConnectionUpdate, SharedConnectionMap};
pub(crate) use psk::{PskSeed, PskStore};
pub(crate) use server::Server;
pub(crate) use stream::QuicStream;
pub(crate) use transport::QuicTransport;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Errors specific to the QUIC syncer
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// QUIC Connection error
    #[error(transparent)]
    QuicConnection(#[from] s2n_quic::connection::Error),
    /// QUIC Stream error
    #[error(transparent)]
    QuicStream(#[from] s2n_quic::stream::Error),
    /// Invalid PSK used for syncing
    #[error("invalid PSK used when attempting to sync")]
    InvalidPSK,
    /// QUIC server endpoint start error
    #[error("could not start QUIC server")]
    ServerStart(#[source] s2n_quic::provider::StartError),

    #[error(transparent)]
    Send(s2n_quic::stream::Error),
    #[error(transparent)]
    Receive(std::io::Error),
    #[error(transparent)]
    Finish(s2n_quic::stream::Error),

    /// QUIC client endpoint start error
    #[error("could not start QUIC client")]
    ClientStart(#[source] s2n_quic::provider::StartError),

    /// Encountered a bug in the program.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Something has gone wrong.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

/// Sync configuration for setting up Aranya.
pub(crate) struct SyncParams {
    pub(crate) psk_store: Arc<PskStore>,
    pub(crate) server_addr: Addr,
}
