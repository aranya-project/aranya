use core::{error, fmt};
use std::{collections::HashSet, sync::RwLock};

use aranya_crypto::keystore::fs_keystore;
use aranya_daemon_api::TeamId;

// TODO(eric): Add a blanket impl for `Clone`?
pub trait TryClone: Sized {
    type Error: fmt::Display + fmt::Debug + error::Error + Send + Sync + 'static;

    fn try_clone(&self) -> Result<Self, Self::Error>;
}

impl TryClone for fs_keystore::Store {
    type Error = fs_keystore::Error;

    fn try_clone(&self) -> Result<Self, Self::Error> {
        fs_keystore::Store::try_clone(self)
    }
}

#[derive(Debug)]
pub struct TeamConfigStore {
    set: RwLock<HashSet<TeamId>>,
}

impl TeamConfigStore {
    pub fn new(teams: HashSet<TeamId>) -> Self {
        Self {
            set: RwLock::new(teams),
        }
    }

    #[must_use]
    pub fn add(&self, team: TeamId) -> bool {
        #[expect(clippy::unwrap_used, reason = "propagate poison")]
        self.set.write().unwrap().insert(team)
    }

    #[must_use]
    pub fn contains(&self, team: TeamId) -> bool {
        #[expect(clippy::unwrap_used, reason = "propagate poison")]
        self.set.read().unwrap().contains(&team)
    }

    #[must_use]
    pub fn remove(&self, team: TeamId) -> bool {
        #[expect(clippy::unwrap_used, reason = "propagate poison")]
        self.set.write().unwrap().remove(&team)
    }
}

// TODO: Use upstream from next version.
pub(crate) fn mem_spill() -> Result<impl aranya_runtime::Spill, aranya_runtime::StorageError> {
    use aranya_runtime::{Spill, StorageError};

    /// In-memory spill backed by a growable byte buffer.
    pub struct MemSpill {
        buf: Vec<u8>,
    }

    impl Spill for MemSpill {
        fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError> {
            let end = offset
                .checked_add(data.len())
                .ok_or(StorageError::IoError)?;
            if end > self.buf.len() {
                self.buf.resize(end, 0);
            }
            self.buf[offset..end].copy_from_slice(data);
            Ok(())
        }

        fn read_at(&mut self, offset: usize, data: &mut [u8]) -> Result<(), StorageError> {
            let end = offset
                .checked_add(data.len())
                .ok_or(StorageError::IoError)?;
            let src = self.buf.get(offset..end).ok_or(StorageError::IoError)?;
            data.copy_from_slice(src);
            Ok(())
        }
    }

    Ok(MemSpill { buf: Vec::new() })
}
