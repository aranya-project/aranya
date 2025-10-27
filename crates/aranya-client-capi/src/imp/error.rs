use core::{ffi::c_char, mem::MaybeUninit};

use aranya_capi_core::{write_c_str, ExtendedError, InvalidArg, WriteCStrError};
#[cfg(feature = "afc")]
use aranya_client::afc;
use buggy::Bug;
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Bug(#[from] Bug),

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),

    /// An invalid argument was provided.
    #[error(transparent)]
    InvalidArg(#[from] InvalidArg<'static>),

    #[error("component is not enabled")]
    NotEnabled,

    #[error("buffer too small")]
    BufferTooSmall,

    #[error("haven't received any data yet")]
    WouldBlock,

    #[error("connection was unexpectedly closed")]
    Closed,

    #[cfg(feature = "afc")]
    #[error("wrong channel type provided")]
    WrongChannelType,

    #[error(transparent)]
    Utf8(#[from] core::str::Utf8Error),

    #[error(transparent)]
    Addr(#[from] aranya_util::AddrError),

    #[error(transparent)]
    Client(#[from] aranya_client::Error),

    #[error(transparent)]
    Config(#[from] aranya_client::ConfigError),

    #[error("serialization error")]
    Serialization(#[from] postcard::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(feature = "afc")]
impl From<afc::Error> for Error {
    fn from(value: afc::Error) -> Self {
        Self::Client(aranya_client::Error::Afc(value))
    }
}

impl From<WriteCStrError> for Error {
    fn from(err: WriteCStrError) -> Self {
        match err {
            WriteCStrError::Bug(bug) => Self::Bug(bug),
            WriteCStrError::BufferTooSmall => Self::BufferTooSmall,
        }
    }
}

/// Underlying type for [`ExtError`][crate::api::ExtError].
#[derive(Debug, Default)]
pub struct ExtError {
    err: Option<Error>,
}

impl ExtError {
    /// Creates an `ExtError`.
    pub const fn new(err: Error) -> Self {
        Self { err: Some(err) }
    }

    /// Copies the error message to `msg` as a null-terminated
    /// C string.
    pub fn copy_msg(&self, msg: &mut [MaybeUninit<c_char>], len: &mut usize) -> Result<(), Error> {
        if let Some(err) = &self.err {
            write_c_str(msg, err, len).map_err(Into::into)
        } else {
            warn!("empty extended error empty");
            write_c_str(msg, &"", len).map_err(Into::into)
        }
    }
}

impl ExtendedError for ExtError {
    type Error = Error;

    fn set<E>(&mut self, err: Option<E>)
    where
        E: Into<Self::Error>,
    {
        self.err = err.map(Into::into)
    }
}
