//! Aranya syncer for syncing Aranya graph commands.
use thiserror::Error;

pub mod prot;
pub mod task;

#[derive(Error, Debug)]
enum SyncError {
    #[error("Protocol mismatch error")]
    Protocol,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
