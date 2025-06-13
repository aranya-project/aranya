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
