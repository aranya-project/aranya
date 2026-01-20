//! Client API errors.

use std::io;

use aranya_daemon_api as api;
use tarpc::client::RpcError;

#[cfg(feature = "afc")]
use crate::afc::Error as AfcError;

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

    /// An Aranya Fast Channel error happened.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    #[error("AFC error")]
    Afc(#[from] AfcError),

    /// An unexpected internal error happened.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Some other error occurred.
    #[error(transparent)]
    Other(#[from] OtherError),
}

impl From<core::convert::Infallible> for Error {
    fn from(value: core::convert::Infallible) -> Self {
        match value {}
    }
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
