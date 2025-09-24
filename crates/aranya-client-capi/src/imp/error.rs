use core::{ffi::c_char, mem::MaybeUninit};

use aranya_capi_core::{
    safe::{TypeId, Typed},
    write_c_str, ExtendedError, InvalidArg, WriteCStrError,
};
#[cfg(feature = "afc")]
use aranya_client::afc;
#[cfg(feature = "aqc")]
use aranya_client::{aqc::TryReceiveError, error::AqcError};
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

    #[cfg(feature = "afc")]
    #[error("wrong channel type provided")]
    WrongChannelType,

    #[cfg(feature = "aqc")]
    #[error("connection was unexpectedly closed")]
    Closed,

    #[cfg(feature = "aqc")]
    #[error("haven't received any data yet")]
    WouldBlock,

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

#[cfg(feature = "aqc")]
impl From<AqcError> for Error {
    fn from(value: AqcError) -> Self {
        Self::Client(aranya_client::Error::Aqc(value))
    }
}

#[cfg(feature = "aqc")]
impl From<TryReceiveError<AqcError>> for Error {
    fn from(value: TryReceiveError<AqcError>) -> Self {
        match value {
            TryReceiveError::Closed => Self::Closed,
            TryReceiveError::Empty => Self::WouldBlock,
            TryReceiveError::Error(e) => Self::Client(aranya_client::Error::Aqc(e)),
        }
    }
}

#[cfg(feature = "aqc")]
impl From<TryReceiveError<aranya_client::Error>> for Error {
    fn from(value: TryReceiveError<aranya_client::Error>) -> Self {
        match value {
            TryReceiveError::Closed => Self::Closed,
            TryReceiveError::Empty => Self::WouldBlock,
            TryReceiveError::Error(e) => Self::Client(e),
        }
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

impl Typed for ExtError {
    const TYPE_ID: TypeId = TypeId::new(0xa2a040);
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
