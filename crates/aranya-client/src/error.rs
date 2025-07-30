//! Client API errors.

use std::{convert::Infallible, io};

use aranya_daemon_api as api;
use tarpc::client::RpcError;

/// The type returned by fallible Aranya operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Possible errors that could happen in the Aranya client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to communicate with the daemon.
    #[error("IPC error")]
    Ipc(#[from] IpcError),

    /// The daemon returned an error.
    #[error("daemon error")]
    Aranya(#[from] AranyaError),

    /// A configuration error happened.
    #[error("configuration error")]
    Config(#[from] ConfigError),

    /// An Aranya QUIC Channel error happened.
    #[error("AQC error")]
    Aqc(#[from] AqcError),

    /// An unexpected internal error happened.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Some other error occurred.
    #[error(transparent)]
    Other(#[from] OtherError),
}

/// Some other error occurred.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct OtherError {
    #[from]
    err: anyhow::Error,
}

pub(crate) fn other<E>(err: E) -> OtherError
where
    E: Into<anyhow::Error>,
{
    OtherError { err: err.into() }
}

/// An Aranya error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AranyaError {
    #[from]
    err: api::Error,
}

pub(crate) fn aranya_error(err: api::Error) -> Error {
    Error::Aranya(err.into())
}

/// Possible errors that could happen when creating configuration info.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// An invalid argument was provided.
    #[error(transparent)]
    InvalidArg(#[from] InvalidArg),
}

/// An invalid argument.
#[derive(Debug, thiserror::Error)]
#[error("invalid argument `{arg}`: {reason}")]
pub struct InvalidArg {
    arg: &'static str,
    reason: &'static str,
}

impl InvalidArg {
    pub(crate) const fn new(arg: &'static str, reason: &'static str) -> Self {
        Self { arg, reason }
    }
}

/// An IPC error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IpcError(#[from] pub(crate) IpcRepr);

impl IpcError {
    pub(crate) fn new<E>(err: E) -> Self
    where
        E: Into<IpcRepr>,
    {
        Self(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) enum IpcRepr {
    InvalidArg(#[from] InvalidArg),
    Io(#[from] io::Error),
    Tarpc(#[from] RpcError),
    Other(#[from] anyhow::Error),
}

/// Possible errors that could happen when using Aranya QUIC Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AqcError {
    /// The server connection was terminated.
    #[error("the server connection was terminated")]
    ServerConnectionTerminated,

    /// No channel info found.
    #[error("no channel info found")]
    NoChannelInfoFound,

    /// The connection was closed.
    #[error("the connection was closed")]
    ConnectionClosed,

    /// The AQC channel was closed.
    #[error("the AQC channel was closed")]
    ChannelClosed,

    /// A connection error.
    #[error(transparent)]
    ConnectionError(#[from] s2n_quic::connection::Error),

    /// A stream error.
    #[error(transparent)]
    StreamError(#[from] s2n_quic::stream::Error),

    /// Failed to resolve address.
    #[error("failed to resolve address")]
    AddrResolution(io::Error),

    /// Endpoint start error.
    #[error("failed to start the client or server endpoint")]
    EndpointStart(#[from] s2n_quic::provider::StartError),

    /// Error parsing control message.
    #[error("failed to parse control message")]
    InvalidCtrlMessage(postcard::Error),

    /// Peer could not process control message.
    #[error("peer could not process control message")]
    PeerCtrl,

    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),
}

impl From<Infallible> for AqcError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

pub(crate) fn no_addr() -> AqcError {
    AqcError::AddrResolution(io::Error::new(io::ErrorKind::NotFound, "no address found"))
}
