//! General utility functions and types.

use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path};

use tokio::{fs, io};
use tracing::warn;

/// Asynchronously writes `data` to the specified `path`, creating the file if it
/// doesn't exist, and truncating it if it does.
///
/// After writing, it attempts to set the file permissions to `0o600` (read/write
/// for owner only). A warning is logged if setting permissions fails, but the
/// operation is still considered successful.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be written to (e.g., due to permissions
/// or invalid path), but not if setting permissions fails.
pub async fn write_file(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    fs::write(path.as_ref(), data).await?;
    let perms = Permissions::from_mode(0o600);
    if let Err(err) = fs::set_permissions(&path, perms).await {
        warn!(err = ?err, path = %path.as_ref().display(), "unable to set file perms to 0o600");
    }
    Ok(())
}

/// Asynchronously creates a directory and all of its parent components if they
/// are missing.
///
/// After creating the directory (or if it already exists), it attempts to set
/// the directory permissions to `0o700` (read/write/execute for owner only).
/// A warning is logged if setting permissions fails, but the operation is still
/// considered successful.
///
/// # Errors
///
/// Returns `io::Error` if the directory cannot be created (e.g., due to permissions
/// or invalid path), but not if setting permissions fails.
pub async fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(path.as_ref()).await?;
    let perms = Permissions::from_mode(0o700);
    if let Err(err) = fs::set_permissions(&path, perms).await {
        warn!(err = ?err, path = %path.as_ref().display(), "unable to set directory perms to 0o700");
    }
    Ok(())
}

pub mod freeze {
    use std::ops::Deref;

    use serde::{Deserialize, Serialize};

    /// Attempt to mutate a frozen value
    #[derive(Clone, Debug)]
    pub struct FrozenError;

    impl std::fmt::Display for FrozenError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Attempt to mutate a frozen value")
        }
    }

    impl std::error::Error for FrozenError {}

    /// A wrapper type that can toggle between allowing and disallowing mutation.
    ///
    /// When frozen, attempts to mutably borrow the inner value will fail.
    /// The value can always be read immutably regardless of frozen state.
    ///
    /// Note: This type may not be that useful if T is [`std::cell::Cell`] or
    /// [`std::cell::RefCell`]
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Freezeable<T> {
        value: T,
        frozen: bool,
    }

    impl<T> Freezeable<T> {
        /// Creates a new [`Freezeable`] in the unfrozen state.
        pub fn new(value: T) -> Self {
            Self {
                value,
                frozen: false,
            }
        }

        /// Freezes the value, preventing mutation until unfrozen.
        pub fn freeze(&mut self) {
            self.frozen = true;
        }

        /// Unfreezes the value, allowing mutation again.
        pub fn unfreeze(&mut self) {
            self.frozen = false;
        }

        /// Unwraps the value, consuming the Freezeable.
        pub fn into_inner(self) -> T {
            self.value
        }

        /// Attempts to mutably borrow the inner value.
        ///
        /// # Errors
        ///
        /// Returns an error if the value is currently frozen.
        pub fn try_borrow_mut(&mut self) -> Result<&mut T, FrozenError> {
            if self.frozen {
                return Err(FrozenError);
            }

            Ok(&mut self.value)
        }
    }

    impl<T> Deref for Freezeable<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.value
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[derive(Serialize, Deserialize)]
        struct TestConfig {
            value: Freezeable<u32>,
        }

        #[test]
        fn test_roundtrip() {
            let test_config = TestConfig {
                value: Freezeable::new(10),
            };
            let json = serde_json::to_string(&test_config).expect("can convert config to json");
            let mut deserialized_config: TestConfig =
                serde_json::from_str(&json).expect("can convert back to config");

            assert_eq!(*deserialized_config.value, *test_config.value);

            // Can mutate since value hasn't been frozen
            assert!(deserialized_config.value.try_borrow_mut().is_ok());

            let inner = deserialized_config
                .value
                .try_borrow_mut()
                .expect("can mutate");
            *inner = 30;

            assert_eq!(*deserialized_config.value, 30);
        }

        #[test]
        fn test_roundtrip_frozen() {
            let mut test_config = TestConfig {
                value: Freezeable::new(10),
            };
            test_config.value.freeze();
            let json = serde_json::to_string(&test_config).expect("can convert config to json");
            let mut deserialized_config: TestConfig =
                serde_json::from_str(&json).expect("can convert back to config");

            assert_eq!(*deserialized_config.value, *test_config.value);

            // Can't mutate since value hasn't been frozen. Must call Freezeable::unfreeze.
            assert!(deserialized_config.value.try_borrow_mut().is_err());

            deserialized_config.value.unfreeze();
            *(deserialized_config
                .value
                .try_borrow_mut()
                .expect("can mutate")) = 5;

            assert_eq!(*deserialized_config.value, 5);
        }
    }
}
