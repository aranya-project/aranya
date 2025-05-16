//! Daemon configuration.

use std::{
    fs,
    ops::Deref,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use aranya_util::Addr;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::sync::prot::SyncProtocol;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct NonEmptyString(String);

impl Deref for NonEmptyString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<String> for NonEmptyString {
    type Error = anyhow::Error;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() {
            anyhow::bail!("Invalid String. NonEmptyString can't be blank")
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<&str> for NonEmptyString {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

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
    pub service_name: NonEmptyString,

    /// Sync Protocol Version
    #[serde(default)]
    pub sync_version: Option<SyncProtocol>,

    /// AFC configuration.
    #[serde(default)]
    pub afc: Option<AfcConfig>,

    /// AQC configuration.
    #[serde(default)]
    pub aqc: Option<AqcConfig>,
}

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

    /// Path to the [`DefaultEngine`]'s key wrapping key.
    pub(crate) fn key_wrap_key_path(&self) -> PathBuf {
        self.work_dir.join("key_wrap_key")
    }

    /// Path to the [`KeyBundle`].
    pub(crate) fn key_bundle_path(&self) -> PathBuf {
        self.work_dir.join("key_bundle")
    }

    /// Path to the daemon's public API key.
    pub fn daemon_api_pk_path(&self) -> PathBuf {
        self.work_dir.join("daemon_api_pk")
    }

    /// The directory where keystore files are written.
    pub(crate) fn keystore_path(&self) -> PathBuf {
        self.work_dir.join("keystore")
    }

    /// The directory where the root keystore exists.
    ///
    /// The Aranaya keystore contains Aranya's key material.
    pub(crate) fn aranya_keystore_path(&self) -> PathBuf {
        self.keystore_path().join("aranya")
    }

    /// The directory where the local keystore exists.
    ///
    /// The local keystore contains key material for the daemon.
    /// E.g., its API key.
    pub(crate) fn local_keystore_path(&self) -> PathBuf {
        self.keystore_path().join("local")
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
    use tracing::warn;

    use super::*;

    pub fn delete_sync_psk(service_name: &NonEmptyString) -> Result<()> {
        let id_string = crate::daemon::TEAM_ID.to_string();
        let entry = keyring::Entry::new(service_name, &id_string)?;
        let _ = entry
            .delete_credential()
            .inspect_err(|e| warn!("Couldn't delete secret for PSK: {}", e));

        Ok(())
    }

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
            sync_version: Some(SyncProtocol::V1),
            service_name: NonEmptyString::try_from("Aranya-QUIC-sync")?,
            afc: None,
            aqc: None,
        };
        assert_eq!(got, want);

        delete_sync_psk(&want.service_name)?;
        Ok(())
    }
}
