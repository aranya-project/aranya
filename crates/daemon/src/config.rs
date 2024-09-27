//! Daemon configuration.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Options for configuring the daemon.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Human-readable name for the daemon for tracing.
    pub name: String,

    /// The daemon's working directory.
    pub work_dir: PathBuf,

    /// Used to receive API requests from the frontend client.
    pub uds_api_path: PathBuf,

    /// Path where the daemon should write its PID file.
    pub pid_file: PathBuf,
}

// TODO: remove allow dead_code once all methods are used.
#[allow(dead_code)]
impl Config {
    /// Reads the configuration from `path`.
    pub fn load<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let cfg: Self = read_json(path.as_ref())
            .context(format!("unable to parse config: {:?}", path.as_ref()))?;

        Ok(cfg)
    }

    /// Path to `State`.
    pub(crate) fn state_path(&self) -> PathBuf {
        self.work_dir.join("app_state.cbor")
    }

    /// Path to the [`DefaultEngine`]'s key wrapping key.
    pub(crate) fn key_wrap_key_path(&self) -> PathBuf {
        self.work_dir.join("key_wrap_key")
    }

    /// Path to the [`KeyBundle`].
    pub(crate) fn key_bundle_path(&self) -> PathBuf {
        self.work_dir.join("key_bundle")
    }

    /// Path to `Store`.
    pub(crate) fn keystore_path(&self) -> PathBuf {
        self.work_dir.join("keystore")
    }

    /// Path to the runtime's storage.
    pub(crate) fn storage_path(&self) -> PathBuf {
        self.work_dir.join("storage")
    }
}

/// Reads JSON from `path`.
fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let buf = fs::read(path.as_ref())?;
    Ok(deser_hjson::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_config() -> Result<()> {
        const DIR: &str = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(DIR).join("example.json");
        let got = Config::load(path)?;
        let want = Config {
            name: "name".to_string(),
            work_dir: "/var/lib/work_dir".parse()?,
            uds_api_path: "/var/run/uds_api.sock".parse()?,
            pid_file: "/var/run/hub.pid".parse()?,
        };
        assert_eq!(got, want);
        Ok(())
    }
}
