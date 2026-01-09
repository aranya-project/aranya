use core::{error, fmt};

use aranya_crypto::keystore::fs_keystore;

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
