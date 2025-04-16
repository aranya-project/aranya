//! Utility routines.

use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path, str::FromStr};

use anyhow::Context as _;
use aranya_crypto::{import::Import, keys::SecretKey, Rng};
use aranya_fast_channels::shm;
use tokio::{fs, io};
use tracing::{info_span, warn, Instrument as _};

/// Writes `data` to `path` using with 600 permissions.
pub async fn write_file(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    fs::write(path.as_ref(), data).await?;
    let perms = Permissions::from_mode(0o600);
    if let Err(err) = fs::set_permissions(&path, perms).await {
        warn!(err = ?err, path = %path.as_ref().display(), "unable to set file perms");
    }
    Ok(())
}

/// Creates all directories in `path` with 700 permissions.
pub async fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(path.as_ref()).await?;
    let perms = Permissions::from_mode(0o700);
    if let Err(err) = fs::set_permissions(&path, perms).await {
        warn!(err = ?err, path = %path.as_ref().display(), "unable to set directory perms");
    }
    Ok(())
}

/// An owned shared memory path.
///
/// It's like `Vec<u8>`, but syntactically valid.
#[derive(Clone)]
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

/// Loads a key from a file or generates and writes a new one.
pub async fn load_or_gen_key<K: SecretKey>(path: impl AsRef<Path>) -> anyhow::Result<K> {
    pub async fn inner<K: SecretKey>(path: &Path) -> anyhow::Result<K> {
        match fs::read(&path).await {
            Ok(buf) => {
                tracing::info!("loading key");
                let key =
                    Import::import(buf.as_slice()).context("unable to import key from file")?;
                Ok(key)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::info!("generating key");
                let key = K::new(&mut Rng);
                let bytes = key
                    .try_export_secret()
                    .context("unable to export new key")?;
                write_file(&path, bytes.as_bytes())
                    .await
                    .context("unable to write key")?;
                Ok(key)
            }
            Err(err) => Err(err).context("unable to read key"),
        }
    }
    let path = path.as_ref();
    inner(path)
        .instrument(info_span!("load_or_gen_key", ?path))
        .await
        .with_context(|| format!("load_or_gen_key({path:?})"))
}
