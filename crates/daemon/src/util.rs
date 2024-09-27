//! Utility routines.

use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path};

use tokio::{fs, io};
use tracing::warn;

/// Writes `data` to `path` using with 600 permissions.
pub(crate) async fn write_file(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    fs::write(path.as_ref(), data).await?;
    let perms = Permissions::from_mode(0o600);
    if let Err(err) = fs::set_permissions(&path, perms).await {
        warn!(err = ?err, path = %path.as_ref().display(), "unable to set file perms");
    }
    Ok(())
}

/// Creates all directories in `path` with 700 permissions.
pub(crate) async fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(path.as_ref()).await?;
    let perms = Permissions::from_mode(0o700);
    if let Err(err) = fs::set_permissions(&path, perms).await {
        warn!(err = ?err, path = %path.as_ref().display(), "unable to set directory perms");
    }
    Ok(())
}
