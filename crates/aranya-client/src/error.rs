use std::io;

use aranya_daemon_api as api;
use tarpc::client::RpcError;

pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Possible errors that could happen in the Aranya client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to communicate with the daemon.
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    /// The daemon returned an error.
    #[error("daemon error: {0}")]
    Aranya(#[from] AranyaError),

    /// A configuration error happened.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    /// An Aranya QUIC Channel error happened.
    #[error("AQC error: {0}")]
    Aqc(#[from] AqcError),

    /// An unexpected internal error happened.
    #[error("unexpected internal error: {0}")]
    Bug(#[from] buggy::Bug),
}

/// An Aranya error.
#[derive(Debug, thiserror::Error)]
#[error("{err}")]
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
    #[error("{0}")]
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
#[error("{0}")]
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
#[error("{0}")]
pub(crate) enum IpcRepr {
    InvalidArg(#[from] InvalidArg),
    Io(#[from] io::Error),
    Tarpc(#[from] RpcError),
}

/// Possible errors that could happen when using Aranya QUIC Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AqcError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] buggy::Bug),

    /// Some other error.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
