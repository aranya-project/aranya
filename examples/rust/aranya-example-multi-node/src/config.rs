//! Utility for generating a daemon config file and mTLS certificates.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aranya_certgen::{
    generate_root_ca, generate_signed_cert, write_cert, write_key, Issuer, KeyPair, SubjectAltNames,
};
use aranya_client::Addr;
use tokio::fs;
use tracing::info;

/// Certificate authority for signing device certificates.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
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
        let (ca_cert, ca_key) =
            generate_root_ca("Aranya Example CA", 365).context("failed to generate CA")?;
        write_cert(root_certs_dir.join("ca.pem"), &ca_cert).context("failed to write CA cert")?;

        // Create issuer from CA
        let issuer =
            aranya_certgen::issuer_from_ca(&ca_cert, ca_key).context("failed to create issuer")?;

        Ok(Self {
            issuer,
            root_certs_dir,
        })
    }

    /// Returns the path to the root certificates directory.
    pub fn root_certs_dir(&self) -> &Path {
        &self.root_certs_dir
    }

    /// Generates a device certificate signed by this CA.
    pub fn generate_device_cert(
        &self,
        device_name: &str,
        work_dir: &Path,
    ) -> Result<(PathBuf, PathBuf)> {
        let device_cert_path = work_dir.join("device.pem");
        let device_key_path = work_dir.join("device-key.pem");

        let san = SubjectAltNames {
            dns_names: vec![format!("{}.example.local", device_name)],
            ip_addresses: vec!["127.0.0.1".parse().expect("valid IP address")],
        };

        let (device_cert, device_key) =
            generate_signed_cert(&format!("{} Device", device_name), &self.issuer, 365, &san)
                .context("failed to generate device cert")?;

        write_cert(&device_cert_path, &device_cert)?;
        write_key(&device_key_path, &device_key)?;

        Ok((device_cert_path, device_key_path))
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

    // Generate device certificate
    let (device_cert, device_key) = ca.generate_device_cert(&device, &work_dir)?;
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
