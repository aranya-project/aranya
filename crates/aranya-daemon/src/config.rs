//! Daemon configuration.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use aranya_util::Addr;
use serde::{
    de::{self, DeserializeOwned},
    Deserialize, Serialize,
};

mod toggle;
pub use toggle::Toggle;

/// Options for configuring the daemon.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The name of the daemon, used for logging and debugging
    /// purposes.
    pub name: String,

    /// The directory where the daemon stores non-essential
    /// runtime files and other file objects (sockets, etc.).
    ///
    /// # Multiple Daemon Support
    ///
    /// This directory should be unique for each instance of the
    /// daemon.
    ///
    /// # Example
    ///
    /// For example, this could be `/var/run/aranya`.
    ///
    /// See also: systemd `RuntimeDirectory=` and
    /// `$XDG_RUNTIME_DIR`.
    #[serde(deserialize_with = "non_empty_path")]
    pub runtime_dir: PathBuf,
    /// The directory where the daemon stores non-portable data
    /// that should persist between application restarts.
    ///
    /// # Multiple Daemon Support
    ///
    /// This directory should be unique for each instance of the
    /// daemon.
    ///
    /// # Example
    ///
    /// For example, this could be `/var/lib/aranya`.
    ///
    /// See also: systemd `StateDirectory=` and
    /// `$XDG_STATE_HOME`.
    #[serde(deserialize_with = "non_empty_path")]
    pub state_dir: PathBuf,
    /// The directory where the daemon stores non-essential data
    /// files.
    ///
    /// # Multiple Daemon Support
    ///
    /// This directory should be unique for each instance of the
    /// daemon.
    ///
    /// # Example
    ///
    /// For example, this could be `/var/cache/aranya`.
    ///
    /// See also: systemd `CacheDirectory=` and
    /// `$XDG_CACHE_HOME`.
    #[serde(deserialize_with = "non_empty_path")]
    pub cache_dir: PathBuf,
    /// The directory where the daemon writes log files.
    ///
    /// # Multiple Daemon Support
    ///
    /// This directory should be unique for each instance of the
    /// daemon.
    ///
    /// # Example
    ///
    /// For example, this could be `/var/log/aranya`.
    ///
    /// See also: systemd `LogsDirectory=`.
    #[serde(deserialize_with = "non_empty_path")]
    pub logs_dir: PathBuf,
    /// The directory where the daemon can find additional
    /// configuration files.
    ///
    /// # Multiple Daemon Support
    ///
    /// This directory should be unique for each instance of the
    /// daemon.
    ///
    /// # Example
    ///
    /// For example, this could be `/etc/aranya`.
    ///
    /// See also: systemd `ConfigDirectory=` and
    /// `$XDG_CONFIG_HOME`.
    #[serde(deserialize_with = "non_empty_path")]
    pub config_dir: PathBuf,

    /// AQC configuration.
    #[serde(default)]
    pub aqc: Toggle<AqcConfig>,

    /// QUIC syncer config
    #[serde(default)]
    pub sync: SyncConfig,
}

impl Config {
    /// Reads the configuration from `path`.
    pub fn load<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let cfg: Self = read_toml(path.as_ref())
            .with_context(|| format!("unable to parse config: {}", path.as_ref().display()))?;
        Ok(cfg)
    }

    /// Path to the PID file.
    pub fn pid_path(&self) -> PathBuf {
        self.runtime_dir.join("daemon.pid")
    }

    /// Path to the [`DefaultEngine`]'s key wrapping key.
    pub(crate) fn key_wrap_key_path(&self) -> PathBuf {
        self.state_dir.join("key_wrap_key")
    }

    /// Path to the [`KeyBundle`].
    pub(crate) fn key_bundle_path(&self) -> PathBuf {
        self.state_dir.join("key_bundle")
    }

    /// The directory where keystore files are written.
    pub(crate) fn keystore_path(&self) -> PathBuf {
        self.state_dir.join("keystore")
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
        self.state_dir.join("storage")
    }

    /// Path to file containing the seed IDs.
    pub(crate) fn seed_id_path(&self) -> PathBuf {
        self.state_dir.join("seeds")
    }

    /// Path to the daemon's UDS API socket.
    pub fn uds_api_sock(&self) -> PathBuf {
        self.runtime_dir.join("uds.sock")
    }

    /// Path to the daemon's API public key.
    pub fn api_pk_path(&self) -> PathBuf {
        self.runtime_dir.join("api.pk")
    }
}

/// Reads TOML from `path`.
fn read_toml<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let buf = fs::read_to_string(path.as_ref())?;
    Ok(toml::from_str(&buf)?)
}

/// Sync configuration
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    /// QUIC syncer config
    #[serde(default)]
    pub quic: Toggle<QuicSyncConfig>,
}

/// AQC configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AqcConfig {}

/// QUIC syncer configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicSyncConfig {
    /// Network address of Aranya sync server.
    pub addr: Addr,
}

fn non_empty_path<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path = PathBuf::deserialize(deserializer)?;
    if path.components().next().is_none() {
        Err(de::Error::custom("path cannot be empty"))
    } else {
        Ok(path)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;

    use pretty_assertions::assert_eq;
    use toml::toml;

    use super::*;

    #[test]
    fn test_example_config() -> Result<()> {
        const DIR: &str = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(DIR).join("example.toml");
        let got = Config::load(path)?;
        let want = Config {
            name: "my-aranya-daemon".into(),
            runtime_dir: "/var/run/aranya".parse()?,
            state_dir: "/var/lib/aranya".parse()?,
            cache_dir: "/var/cache/aranya".parse()?,
            logs_dir: "/var/log/aranya".parse()?,
            config_dir: "/etc/aranya".parse()?,
            sync: SyncConfig {
                quic: Toggle::Enabled(QuicSyncConfig {
                    addr: Addr::from((Ipv4Addr::UNSPECIFIED, 4321)),
                }),
            },
            aqc: Toggle::Enabled(AqcConfig {}),
        };
        assert_eq!(got, want);

        Ok(())
    }

    #[test]
    fn test_config() {
        #![allow(clippy::disallowed_macros, reason = "toml! uses unreachable!")]

        // Missing a required field.
        let data = toml! {
            name = "aranya"
            runtime_dir = "/var/run/aranya"
            state_dir = "/var/lib/aranya"
            logs_dir = "/var/log/aranya"
            config_dir = "/etc/aranya"
        };
        data.try_into::<Config>()
            .expect_err("missing `cache_dir` should be rejected");

        // A required field is empty.
        let data = toml! {
            name = "aranya"
            runtime_dir = "/var/run/aranya"
            state_dir = "/var/lib/aranya"
            cache_dir = ""
            logs_dir = "/var/log/aranya"
            config_dir = "/etc/aranya"
        };
        data.try_into::<Config>()
            .expect_err("empty `cache_dir` should be rejected");
    }
}
