//! Utility for generating a daemon config file and mTLS certificates.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aranya_certgen::CaCert;
use aranya_client::Addr;
use tokio::fs;
use tracing::info;

/// Certificate authority for signing certificates.
pub struct CertificateAuthority {
    ca: CaCert,
    root_certs_dir: PathBuf,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("root_certs_dir", &self.root_certs_dir)
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Creates a new certificate authority and writes the CA cert to the root certs directory.
    pub fn new(certs_dir: &Path) -> Result<Self> {
        let root_certs_dir = certs_dir.join("root_certs");
        std::fs::create_dir_all(&root_certs_dir)?;

        // Generate CA certificate
        let ca = CaCert::new("Aranya Example CA", 365).context("failed to generate CA")?;
        let ca_prefix = root_certs_dir.join("ca");
        ca.save(ca_prefix.to_str().expect("valid UTF-8 path"), None)
            .context("failed to write CA cert/key")?;

        Ok(Self { ca, root_certs_dir })
    }

    /// Returns the path to the root certificates directory.
    pub fn root_certs_dir(&self) -> &Path {
        &self.root_certs_dir
    }

    /// Generates a signed certificate.
    pub fn generate_signed_cert(&self, _name: &str, work_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        // Use 127.0.0.1 as CN to create IP SAN (certgen auto-detects IP vs hostname).
        // This ensures TLS verification works with the actual socket address.
        let signed = self
            .ca
            .generate("127.0.0.1", 365)
            .context("failed to generate signed cert")?;

        let device_prefix = work_dir.join("device");
        signed
            .save(device_prefix.to_str().expect("valid UTF-8 path"), None)
            .context("failed to write signed cert/key")?;

        Ok((
            work_dir.join("device.crt.pem"),
            work_dir.join("device.key.pem"),
        ))
    }
}

// Create a daemon config file.
pub async fn create_config(
    device: String,
    sync_addr: Addr,
    dir: &Path,
    ca: &CertificateAuthority,
) -> Result<PathBuf> {
    let device_dir = dir.join(&device);
    let work_dir = device_dir.join("daemon");
    fs::create_dir_all(&work_dir).await?;

    let cfg = work_dir.join("config.toml");

    let shm = format!("/shm_{}", device);
    let _ = rustix::shm::unlink(&shm);
    // TODO: reuse code to derive subdirectories for all examples.
    let runtime_dir = work_dir.join("run");
    let state_dir = work_dir.join("state");
    let cache_dir = work_dir.join("cache");
    let logs_dir = work_dir.join("logs");
    let config_dir = work_dir.join("config");
    let sync_addr = sync_addr.to_string();
    for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
        fs::create_dir_all(dir)
            .await
            .with_context(|| format!("unable to create directory: {}", dir.display()))?;
    }

    // Generate signed certificate
    let (device_cert, device_key) = ca.generate_signed_cert(&device, &work_dir)?;
    let root_certs_dir = ca.root_certs_dir();

    let buf = format!(
        r#"
                name = {device:?}
                runtime_dir = {runtime_dir:?}
                state_dir = {state_dir:?}
                cache_dir = {cache_dir:?}
                logs_dir = {logs_dir:?}
                config_dir = {config_dir:?}

                [afc]
                enable = true
                shm_path = {shm:?}
                max_chans = 100

                [sync.quic]
                enable = true
                addr = {sync_addr:?}
                root_certs_dir = {root_certs_dir:?}
                device_cert = {device_cert:?}
                device_key = {device_key:?}
                "#
    );
    fs::write(&cfg, buf).await?;
    info!("generated config file: {:?}", cfg);

    Ok(cfg)
}
