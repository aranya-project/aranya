//! Aranya syncer for syncing Aranya graph commands.
pub mod prot;
pub mod task;

use error::SyncError;

mod error {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub(super) enum SyncError {
        #[error("Protocol mismatch error")]
        Protocol,
        #[error(transparent)]
        Bug(#[from] buggy::Bug),
        #[error(transparent)]
        Other(#[from] anyhow::Error),
    }
}
