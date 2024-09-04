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
    /// The daemon's working directory.
    pub work_dir: PathBuf,

    /// Used to receive API requests from the frontend client.
    pub uds_api_path: PathBuf,
}

// TODO: remove allow dead_code once all methods are used.
#[allow(dead_code)]
impl Config {
    /// Reads the configuration from `path`.
    pub fn load<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let cfg: Self = read_json(path.as_ref()).context("unable to parse config")?;

        Ok(cfg)
    }

    /// Path to `State`.
    pub(crate) fn state_path(&self) -> PathBuf {
        self.work_dir.join("app_state.cbor")
    }

    // TODO: key_wrap_key_path

    // TODO: key_bundle_path

    /// Path to `Store`.
    pub(crate) fn keystore_path(&self) -> PathBuf {
        self.work_dir.join("keystore")
    }

    /// Path to the effect queue.
    pub(crate) fn effect_queue_path(&self) -> PathBuf {
        self.work_dir.join("effectq")
    }

    /// Path where TLS certificates are stored.
    pub fn certs_path(&self) -> PathBuf {
        self.work_dir.join("certs")
    }

    /// Path to where the audit log is stored.
    pub fn audit_log_path(&self) -> PathBuf {
        self.work_dir.join("audit.log")
    }

    /// Path to the TLS public cert.
    pub(crate) fn tls_cert_path(&self) -> PathBuf {
        self.certs_path().join("tls_cert.der")
    }

    /// Path to the TLS private key.
    pub(crate) fn tls_key_path(&self) -> PathBuf {
        self.certs_path().join("tls_key.der")
    }

    /// Path to the root certificate used to verify peer TLS
    /// certificates.
    pub(crate) fn tls_root_ca_path(&self) -> PathBuf {
        self.certs_path().join("tls_root_ca_cert.der")
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
            work_dir: "/var/lib/work_dir".parse()?,
            uds_api_path: "/var/run/uds_api.sock".parse()?,
        };
        assert_eq!(got, want);
        Ok(())
    }
}
