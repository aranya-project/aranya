//! Aranya syncer for syncing Aranya graph commands.
mod handle;
#[cfg(feature = "preview")]
pub mod hello;
pub mod manager;
pub mod transport;
mod types;

pub(crate) use aranya_runtime::GraphId;
pub(crate) use aranya_util::Addr;
pub(crate) use handle::{Request, SyncHandle};
pub(crate) use manager::SyncManager;
pub(crate) use types::SyncPeer;
pub(super) use types::{Client, EffectSender, SyncResponse};

/// Possible errors that could happen in the Aranya Syncer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// Something went wrong inside the QUIC Syncer.
    #[error(transparent)]
    QuicSync(#[from] transport::quic::QuicError),

    /// Something went wrong in the Aranya Runtime.
    #[error(transparent)]
    Runtime(#[from] aranya_runtime::SyncError),

    /// Failed to send sync request.
    #[error("Could not send sync request: {0}")]
    SendSyncRequest(Box<SyncError>),

    /// Failed to receive sync response.
    #[error("Could not receive sync response: {0}")]
    ReceiveSyncResponse(Box<SyncError>),

    /// Peer sent an empty response
    #[error("peer sent empty response")]
    EmptyResponse,

    /// Encountered a bug in the program.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),

    /// Something has gone wrong.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Possible sync related errors
pub type Result<T> = core::result::Result<T, SyncError>;

impl From<SyncError> for aranya_daemon_api::Error {
    fn from(err: SyncError) -> Self {
        Self::from_err(err)
    }
}

impl From<std::convert::Infallible> for SyncError {
    fn from(err: std::convert::Infallible) -> Self {
        match err {}
    }
}

impl SyncError {
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
