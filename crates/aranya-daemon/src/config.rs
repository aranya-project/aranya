//! Daemon configuration.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use aranya_util::Addr;
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

    /// Network address of Aranya sync server.
    pub sync_addr: Addr,

    /// AFC configuration.
    pub afc: AfcConfig,

    /// AQC configuration.
    pub aqc: AfcConfig,
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

    /// Path to the daemon's public API key.
    pub(crate) fn daemon_api_pk_path(&self) -> PathBuf {
        self.work_dir.join("daemon_api_pk")
    }

    /// The directory where keystore files are written.
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

/// AFC configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfcConfig {
    /// Shared memory path.
    pub shm_path: String,

    /// Unlink `shm_path` before creating the shared memory?
    ///
    /// Ignored if `create` is false.
    pub unlink_on_startup: bool,

    /// Unlink `shm_path` before on exit?
    ///
    /// If false, the shared memory will persist across daemon
    /// restarts.
    pub unlink_at_exit: bool,

    /// Create the shared memory?
    pub create: bool,

    /// Maximum number of channels AFC should support.
    pub max_chans: usize,
}

/// AQC configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AqcConfig {}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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
            uds_api_path: "/var/run/uds.sock".parse()?,
            pid_file: "/var/run/hub.pid".parse()?,
            sync_addr: Addr::new(Ipv4Addr::UNSPECIFIED.to_string(), 4321)?,
            afc: AfcConfig {
                shm_path: "/afc".to_owned(),
                unlink_on_startup: false,
                unlink_at_exit: false,
                create: true,
                max_chans: 100,
            },
            aqc: AqcConfig {},
        };
        assert_eq!(got, want);
        Ok(())
    }
}
