//! Certificate loading and mTLS configuration for QUIC sync.
//!
//! This module provides functions to load root CA certificates and device certificates
//! from PEM files, and build rustls configurations for mutual TLS authentication.

use std::{
    fs::{self, File},
    io::BufReader,
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, warn};

/// Loads root CA certificates from a directory.
///
/// Reads all `.pem` files from the specified directory and parses them as X.509 certificates.
/// Each PEM file can contain one or more certificates.
///
/// # Arguments
/// * `dir` - Path to the directory containing root CA certificate PEM files
///
/// # Returns
/// A `RootCertStore` containing all loaded certificates
///
/// # Errors
/// Returns an error if the directory cannot be read or if any certificate fails to parse.
pub fn load_root_certs(dir: &Path) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();

    let entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read root certs directory: {}", dir.display()))?;

    let mut cert_count = 0;
    for entry in entries {
        let entry = entry.context("failed to read directory entry")?;
        let path = entry.path();

        // Only process .pem files
        if path.extension().is_some_and(|ext| ext == "pem") {
            let file = File::open(&path)
                .with_context(|| format!("failed to open certificate file: {}", path.display()))?;
            let mut reader = BufReader::new(file);

            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>().with_context(
                    || format!("failed to parse certificates from: {}", path.display()),
                )?;

            for cert in certs {
                root_store.add(cert).with_context(|| {
                    format!("failed to add certificate to root store from: {}", path.display())
                })?;
                cert_count += 1;
            }
        }
    }

    if cert_count == 0 {
        warn!(
            "no certificates found in root certs directory: {}",
            dir.display()
        );
    } else {
        debug!("loaded {} root CA certificate(s)", cert_count);
    }

    Ok(root_store)
}

/// Loads a device certificate chain and private key from PEM files.
///
/// # Arguments
/// * `cert_path` - Path to the device certificate PEM file (may contain certificate chain)
/// * `key_path` - Path to the private key PEM file (PKCS#8 or SEC1/EC format)
///
/// # Returns
/// A tuple of (certificate chain, private key)
///
/// # Errors
/// Returns an error if the files cannot be read or parsed.
pub fn load_device_cert(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load certificate chain
    let cert_file = File::open(cert_path)
        .with_context(|| format!("failed to open device certificate: {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed to parse device certificate: {}",
                cert_path.display()
            )
        })?;

    if certs.is_empty() {
        anyhow::bail!(
            "no certificates found in device certificate file: {}",
            cert_path.display()
        );
    }

    debug!("loaded {} certificate(s) from device cert file", certs.len());

    // Load private key
    let key_file = File::open(key_path)
        .with_context(|| format!("failed to open device key: {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("failed to parse device key: {}", key_path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no private key found in device key file: {}",
                key_path.display()
            )
        })?;

    debug!("loaded device private key");

    Ok((certs, key))
}

/// Builds a rustls client configuration for mutual TLS.
///
/// The client will:
/// - Verify server certificates against the provided root CA store
/// - Present its own device certificate for client authentication
///
/// # Arguments
/// * `roots` - Root certificate store for server verification
/// * `certs` - Device certificate chain for client authentication
/// * `key` - Device private key
///
/// # Returns
/// A rustls `ClientConfig` configured for mutual TLS
pub fn build_client_config(
    roots: rustls::RootCertStore,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("failed to build client TLS config with client auth")?;

    debug!("built rustls client config for mTLS");
    Ok(config)
}

/// Builds a rustls server configuration for mutual TLS.
///
/// The server will:
/// - Verify client certificates against the provided root CA store (required)
/// - Present its own device certificate to clients
///
/// # Arguments
/// * `roots` - Root certificate store for client verification
/// * `certs` - Device certificate chain for server identity
/// * `key` - Device private key
///
/// # Returns
/// A rustls `ServerConfig` configured for mutual TLS with required client authentication
pub fn build_server_config(
    roots: rustls::RootCertStore,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    // Build client certificate verifier that requires valid client certs
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to build client certificate verifier")?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .context("failed to build server TLS config")?;

    debug!("built rustls server config for mTLS");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // Helper to create a test PEM file with dummy content
    fn create_pem_file(dir: &Path, name: &str, content: &str) -> std::io::Result<()> {
        let path = dir.join(name);
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    #[test]
    fn test_load_root_certs_empty_dir() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let result = load_root_certs(temp_dir.path());
        assert!(result.is_ok());
        let store = result.expect("expected Ok");
        assert!(store.is_empty());
    }

    #[test]
    fn test_load_root_certs_no_pem_files() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        create_pem_file(temp_dir.path(), "not-a-cert.txt", "hello world")
            .expect("failed to create file");
        let result = load_root_certs(temp_dir.path());
        assert!(result.is_ok());
        let store = result.expect("expected Ok");
        assert!(store.is_empty());
    }

    #[test]
    fn test_load_root_certs_invalid_pem() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        create_pem_file(temp_dir.path(), "invalid.pem", "not a valid certificate")
            .expect("failed to create file");
        let result = load_root_certs(temp_dir.path());
        // Invalid PEM content should result in empty certs (rustls_pemfile returns empty)
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_device_cert_missing_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cert_path = temp_dir.path().join("missing.pem");
        let key_path = temp_dir.path().join("missing.key");
        let result = load_device_cert(&cert_path, &key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_device_cert_empty_cert_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        create_pem_file(temp_dir.path(), "cert.pem", "").expect("failed to create cert file");
        create_pem_file(temp_dir.path(), "key.pem", "").expect("failed to create key file");

        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        let result = load_device_cert(&cert_path, &key_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no certificates found"));
    }
}
