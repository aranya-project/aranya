//! Aranya syncer for syncing Aranya graph commands.
pub mod prot;
pub mod task;

use error::SyncError;

/// Possible sync related errors
pub type Result<T> = core::result::Result<T, SyncError>;

mod error {
    use thiserror::Error;

    use super::task::quic::Error as QSError;

    #[derive(Error, Debug)]
    #[non_exhaustive]
    pub enum SyncError {
        #[error("Protocol mismatch error")]
        _Protocol,
        #[error("Version mismatch error")]
        Version,
        #[error("Unknown Version")]
        UnknownVersion,
        #[error(transparent)]
        QuicSyncError(#[from] QSError),
        #[error(transparent)]
        Runtime(#[from] aranya_runtime::SyncError),
        #[error(transparent)]
        Bug(#[from] buggy::Bug),
        #[error(transparent)]
        Other(#[from] anyhow::Error),
    }

    impl From<SyncError> for aranya_daemon_api::Error {
        fn from(value: SyncError) -> Self {
            Self::from_err(value)
        }
    }
}
