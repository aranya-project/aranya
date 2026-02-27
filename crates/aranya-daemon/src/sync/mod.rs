//! Aranya syncer used to send/receive graph commands to other peers.

mod handle;
mod manager;
mod server;
mod transport;
mod types;

use aranya_runtime::GraphId;
use aranya_util::Addr;

#[cfg(feature = "preview")]
pub(crate) use self::types::HelloSubscription;
pub(super) use self::types::SyncResponse;
pub(crate) use self::{
    handle::SyncHandle, manager::SyncManager, server::SyncServer, transport::quic, types::SyncPeer,
};

/// The error type which is returned from syncing with peers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum Error {
    // TODO(nikki): decide if we want to add a generic.
    /// Something went wrong with the transport layer.
    #[error(transparent)]
    Transport(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Something went wrong in the Aranya Runtime.
    #[error(transparent)]
    Runtime(#[from] aranya_runtime::SyncError),

    /// Peer sent an empty response.
    #[cfg(feature = "preview")]
    #[error("peer sent empty response")]
    EmptyResponse,

    #[error(transparent)]
    AranyaClient(#[from] aranya_runtime::ClientError),

    #[error("the sync manager has shut down")]
    SyncerShutdown,

    /// Encountered a bug in the program.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Something has gone wrong.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// Implements this error type to allow it being sent over RPC.
impl From<Error> for aranya_daemon_api::Error {
    #[inline]
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
    fn transport(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Transport(Box::new(err))
    }

    /// Returns whether a `ParallelFinalize` error occurred, which needs to be resolved manually.
    fn is_parallel_finalize(&self) -> bool {
        use aranya_runtime::ClientError;
        match self {
            Self::AranyaClient(ClientError::ParallelFinalize) => true,
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
