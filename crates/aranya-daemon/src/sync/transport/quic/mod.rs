//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

mod client;
mod connections;
mod psk;
mod server;

use std::sync::Arc;

pub(crate) use client::QuicTransport;
pub(crate) use psk::PskSeed;
pub use psk::PskStore;
use s2n_quic::{
    connection::Error as ConnectionError, provider::StartError, stream::Error as StreamError,
};
pub(crate) use server::QuicServer;

pub(super) use crate::sync::SyncPeer;
use crate::Addr;

/// ALPN protocol identifier for Aranya QUIC sync.
const ALPN_QUIC_SYNC: &[u8] = b"quic-sync-unstable";

/// Sync configuration for setting up Aranya.
pub(crate) struct SyncParams {
    pub(crate) psk_store: Arc<PskStore>,
    pub(crate) server_addr: Addr,
}

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// QUIC Connection Error
    #[error(transparent)]
    QuicConnectionError(#[from] ConnectionError),

    /// QUIC Stream Error
    #[error(transparent)]
    QuicStreamError(#[from] StreamError),

    /// QUIC Client Builder Error
    #[error("unable to start QUIC client")]
    ClientStart(#[source] StartError),

    /// QUIC Server Builder Error
    #[error("unable to start QUIC server")]
    ServerStart(#[source] StartError),

    /// Invalid PSK use for syncing
    #[error("invalid PSK used when attempting to sync")]
    InvalidPSK,
}

pub(super) type Result<T, E = QuicError> = core::result::Result<T, E>;
