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

// TODO(jdygert): Persist?
#[derive(Debug, Default)]
pub struct TeamConfigStore {
    set: RwLock<HashSet<TeamId>>,
}

impl TeamConfigStore {
    pub fn new() -> Self {
        Self::default()
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
