//! General utility functions and types.

#[cfg(all(feature = "afc", feature = "preview"))]
use std::str::FromStr;
use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path};

#[cfg(all(feature = "afc", feature = "preview"))]
use aranya_fast_channels::shm;
use tokio::{fs, io};
use tracing::warn;

use crate::error::ReportExt as _;

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
        warn!(error = %err.report(), path = %path.as_ref().display(), "unable to set file perms to 0o600");
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
        warn!(error = %err.report(), path = %path.as_ref().display(), "unable to set directory perms to 0o700");
    }
    Ok(())
}

/// An owned, validated buffer representing a shared memory path string.
///
/// Shared memory paths often have specific syntax requirements (e.g., starting
/// with '/' and containing only a single slash). The requirements for
/// shared memory path also depend on the operating system.
/// `ShmPathBuf` wraps a `Vec<u8>` but ensures (upon creation via `FromStr`
/// or `TryFrom`) that the content represents a valid shared memory path
/// according to [`aranya_fast_channels::shm::Path::validate`].
///
/// # Errors
///
/// The `FromStr` and `TryFrom` implementations return `shm::InvalidPathError`
/// if the input string is not a valid shared memory path.
#[cfg(all(feature = "afc", feature = "preview"))]
#[derive(Clone, Debug)]
pub struct ShmPathBuf(Vec<u8>);

impl AsRef<shm::Path> for ShmPathBuf {
    fn as_ref(&self) -> &shm::Path {
        // TODO(eric): I guess `Path` needs a `new_unchecked`
        // method or something.
        #[allow(clippy::expect_used)]
        shm::Path::from_bytes(&self.0[..]).expect("should already be validated")
    }
}

impl FromStr for ShmPathBuf {
    type Err = shm::InvalidPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut path = s.as_bytes().to_vec();
        path.push(0);
        shm::Path::validate(&path[..])?;
        Ok(ShmPathBuf(path))
    }
}

impl TryFrom<&str> for ShmPathBuf {
    type Error = shm::InvalidPathError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse::<Self>()
    }
}

impl TryFrom<String> for ShmPathBuf {
    type Error = shm::InvalidPathError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse::<Self>()
    }
}
