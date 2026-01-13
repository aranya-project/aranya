//! Utility for generating a daemon config file and mTLS certificates.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aranya_certgen::{CertGen, SubjectAltNames};
use aranya_client::Addr;
use tokio::fs;
use tracing::info;

/// Certificate authority for signing certificates.
pub struct CertificateAuthority {
    ca: CertGen,
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
        let ca = CertGen::ca("Aranya Example CA", 365).context("failed to generate CA")?;
        ca.save(root_certs_dir.join("ca.pem"), root_certs_dir.join("ca.key"))
            .context("failed to write CA cert/key")?;

        Ok(Self { ca, root_certs_dir })
    }

    /// Returns the path to the root certificates directory.
    pub fn root_certs_dir(&self) -> &Path {
        &self.root_certs_dir
    }

    /// Generates a signed certificate.
    pub fn generate_signed_cert(&self, name: &str, work_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let cert_path = work_dir.join("device.pem");
        let key_path = work_dir.join("device.key");

        let sans = SubjectAltNames::new()
            .with_dns(format!("{}.example.local", name))
            .with_ip("127.0.0.1".parse().expect("valid IP address"));

        let signed = self
            .ca
            .generate(&format!("{} Server", name), 365, &sans)
            .context("failed to generate signed cert")?;

        signed
            .save(&cert_path, &key_path)
            .context("failed to write signed cert/key")?;

        Ok((cert_path, key_path))
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
