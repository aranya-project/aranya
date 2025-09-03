//! Aranya syncer for syncing Aranya graph commands.
pub mod task;

use error::SyncError;

/// Possible sync related errors
pub type Result<T> = core::result::Result<T, SyncError>;

mod error {
    use std::convert::Infallible;

    use thiserror::Error;

    use super::task::quic::Error as QSError;

    #[derive(Error, Debug)]
    #[non_exhaustive]
    pub enum SyncError {
        #[error(transparent)]
        QuicSync(#[from] QSError),
        #[error(transparent)]
        Runtime(#[from] aranya_runtime::SyncError),
        #[error("Could not send sync request: {0}")]
        SendSyncRequest(#[source] Box<SyncError>),
        #[error("Could not receive sync response: {0}")]
        ReceiveSyncResponse(#[source] Box<SyncError>),
        #[error(transparent)]
        Bug(#[from] buggy::Bug),
        #[error(transparent)]
        Other(#[from] anyhow::Error),
    }

    impl From<SyncError> for aranya_daemon_api::Error {
        fn from(err: SyncError) -> Self {
            if err.is_parallel_finalize() {
                // TODO: keep error source chain
                return Self::ParallelFinalize(None);
            }
            Self::from_err(err)
        }
    }

    impl From<Infallible> for SyncError {
        fn from(err: Infallible) -> Self {
            match err {}
        }
    }

    impl SyncError {
        pub fn is_parallel_finalize(&self) -> bool {
            use aranya_runtime::ClientError;
            match self {
                Self::SendSyncRequest(err) | Self::ReceiveSyncResponse(err) => {
                    err.is_parallel_finalize()
                }
                Self::Other(err) => err
                    .downcast_ref::<ClientError>()
                    .is_some_and(|err| matches!(err, ClientError::ParallelFinalize)),
                _ => false,
            }
        }
    }
}
