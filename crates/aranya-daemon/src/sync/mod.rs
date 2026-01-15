//! Aranya syncer used to send/receive graph commands to other peers.

mod handle;
#[cfg(feature = "preview")]
mod hello;
mod manager;
mod transport;
mod types;

use aranya_runtime::GraphId;
use aranya_util::Addr;

pub(super) use self::{handle::Callback, types::SyncResponse};
pub(crate) use self::{
    handle::SyncHandle,
    hello::HelloSubscriptions,
    manager::SyncManager,
    transport::{quic, SyncState},
    types::SyncPeer,
};

/// The error type which is returned from syncing with peers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum Error {
    // TODO(nikki): generalize for generic transport support.
    /// Something went wrong inside the QUIC Syncer.
    #[error(transparent)]
    QuicSync(#[from] quic::QuicError),

    /// Something went wrong in the Aranya Runtime.
    #[error(transparent)]
    Runtime(#[from] aranya_runtime::SyncError),

    /// Failed to send sync request.
    #[error("Could not send sync request: {0}")]
    SendSyncRequest(Box<Error>),

    /// Failed to receive sync response.
    #[error("Could not receive sync response: {0}")]
    ReceiveSyncResponse(Box<Error>),

    /// Peer sent an empty response.
    #[error("peer sent empty response")]
    EmptyResponse,

    /// Encountered a bug in the program.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Something has gone wrong.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// Implements this error type to allow it being sent over RPC.
impl From<Error> for aranya_daemon_api::Error {
    fn from(err: Error) -> Self {
        Self::from_err(err)
    }
}

// Allows Infallible types to be desugared properly with ?.
impl From<std::convert::Infallible> for Error {
    fn from(err: std::convert::Infallible) -> Self {
        match err {}
    }
}

impl Error {
    /// Returns whether a `ParallelFinalize` error occurred, which needs to be resolved manually.
    fn is_parallel_finalize(&self) -> bool {
        use aranya_runtime::ClientError;
        match self {
            Self::Other(err) => err
                .downcast_ref::<ClientError>()
                .is_some_and(|err| matches!(err, ClientError::ParallelFinalize)),
            _ => false,
        }
    }
}

/// A specialized Result type for sync operations.
///
/// This type is used broadly across [`aranya_daemon::sync`] for any operation which may produce an
/// error.
///
/// This type alias is generally used to avoid writing out [`sync::Error`] directly and is otherwise
/// a direct mapping to [`Result`].
///
/// [`aranya_daemon::sync`]: crate::sync
/// [`sync::Error`]: Error
/// [`Result`]: std::result::Result
type Result<T> = core::result::Result<T, Error>;
