//! Certificate loading and mTLS configuration for QUIC sync.
//!
//! This module provides functions to load root CA certificates and device certificates
//! from PEM files, and build rustls configurations for mutual TLS authentication.

use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tracing::debug;

use super::CertConfig;

/// Errors that can occur during certificate loading and TLS configuration.
#[derive(Error, Debug)]
pub enum CertError {
    /// Failed to read a directory.
    #[error("failed to read directory '{path}': {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to read a directory entry.
    #[error("failed to read directory entry: {0}")]
    ReadDirEntry(#[source] std::io::Error),

    /// Failed to open a file.
    #[error("failed to open '{path}': {source}")]
    OpenFile {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to parse certificates from a PEM file.
    #[error("failed to parse certificates from '{path}': {source}")]
    ParseCert {
        path: PathBuf,
        source: rustls::pki_types::pem::Error,
    },

    /// A .pem file contains no valid certificates.
    #[error("no valid certificates found in '{0}'")]
    NoCertsInFile(PathBuf),

    /// Failed to add a certificate to the root store.
    #[error("failed to add certificate from '{path}' to root store: {source}")]
    AddToRootStore {
        path: PathBuf,
        source: rustls::Error,
    },

    /// No device certificate found in file.
    #[error("no device certificate found in '{0}'")]
    NoDeviceCertFound(PathBuf),

    /// No root CA certificates found in directory.
    #[error("no root CA certificates found in '{0}'")]
    NoRootCertsFound(PathBuf),

    /// Failed to parse a private key from a PEM file.
    #[error("failed to parse private key from '{path}': {source}")]
    ParseKey {
        path: PathBuf,
        source: rustls::pki_types::pem::Error,
    },

    /// Failed to build client TLS configuration.
    #[error("failed to build client TLS config: {0}")]
    BuildClientConfig(#[source] rustls::Error),

    /// Failed to build client certificate verifier.
    #[error("failed to build client certificate verifier: {0}")]
    BuildClientVerifier(#[source] rustls::server::VerifierBuilderError),

    /// Failed to build server TLS configuration.
    #[error("failed to build server TLS config: {0}")]
    BuildServerConfig(#[source] rustls::Error),
}

/// Result type for certificate operations.
pub type Result<T> = std::result::Result<T, CertError>;

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

    let entries = fs::read_dir(dir).map_err(|e| CertError::ReadDir {
        path: dir.to_path_buf(),
        source: e,
    })?;

    let mut cert_count = 0;
    for entry in entries {
        let entry = entry.map_err(CertError::ReadDirEntry)?;
        let path = entry.path();

        // Only process .pem files, skipping .key.pem files (private keys)
        let is_pem = path.extension().is_some_and(|ext| ext == "pem");
        let is_key = path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".key.pem"));
        if is_pem && !is_key {
            let file = File::open(&path).map_err(|e| CertError::OpenFile {
                path: path.clone(),
                source: e,
            })?;

            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(file)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| CertError::ParseCert {
                    path: path.clone(),
                    source: e,
                })?;

            // Error if a .pem file contains no valid certificates
            if certs.is_empty() {
                return Err(CertError::NoCertsInFile(path));
            }

            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| CertError::AddToRootStore {
                        path: path.clone(),
                        source: e,
                    })?;
                cert_count += 1;
            }
        }
    }

    if cert_count == 0 {
        return Err(CertError::NoRootCertsFound(dir.to_path_buf()));
    }

    debug!("loaded {} root CA certificate(s)", cert_count);
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
// TODO: Support loading multiple device certificates for devices that join multiple teams.
// Each team may issue its own device certificate, so a device joining multiple teams
// would need to load multiple cert/key pairs and select the appropriate one based on
// which team is being synced.
pub fn load_device_cert(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load certificate chain
    let cert_file = File::open(cert_path).map_err(|e| CertError::OpenFile {
        path: cert_path.to_path_buf(),
        source: e,
    })?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| CertError::ParseCert {
            path: cert_path.to_path_buf(),
            source: e,
        })?;

    if certs.is_empty() {
        return Err(CertError::NoDeviceCertFound(cert_path.to_path_buf()));
    }

    debug!(
        "loaded {} certificate(s) from device cert file",
        certs.len()
    );

    // Load private key.
    // With the `alloc` feature enabled on rustls-pki-types, PrivateKeyDer uses
    // Zeroizing<Vec<u8>> internally, ensuring key bytes are zeroized on drop.
    let key_file = File::open(key_path).map_err(|e| CertError::OpenFile {
        path: key_path.to_path_buf(),
        source: e,
    })?;

    let key = PrivateKeyDer::from_pem_reader(key_file).map_err(|e| CertError::ParseKey {
        path: key_path.to_path_buf(),
        source: e,
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
        .map_err(CertError::BuildClientConfig)?;

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
        .map_err(CertError::BuildClientVerifier)?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(CertError::BuildServerConfig)?;

    debug!("built rustls server config for mTLS");
    Ok(config)
}

/// Loads all certificates needed for mTLS from a [`CertConfig`].
///
/// This is a convenience function that combines [`load_root_certs`] and [`load_device_cert`].
///
/// # Returns
/// A tuple of (root cert store, device certificate chain, device private key)
pub fn load_certs(
    config: &CertConfig,
) -> Result<(
    rustls::RootCertStore,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
)> {
    let root_store = load_root_certs(&config.root_certs_dir)?;
    let (device_certs, device_key) = load_device_cert(&config.device_cert, &config.device_key)?;
    Ok((root_store, device_certs, device_key))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;

    // Helper to create a file and write string content to it
    fn create_file_from_str(dir: &Path, name: &str, content: &str) -> std::io::Result<()> {
        let path = dir.join(name);
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    #[test]
    fn test_load_root_certs_empty_dir() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let err = load_root_certs(temp_dir.path()).unwrap_err();
        assert!(matches!(err, CertError::NoRootCertsFound(_)));
    }

    #[test]
    fn test_load_root_certs_no_pem_files() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        create_file_from_str(temp_dir.path(), "not-a-cert.txt", "hello world")
            .expect("failed to create file");
        let err = load_root_certs(temp_dir.path()).unwrap_err();
        assert!(matches!(err, CertError::NoRootCertsFound(_)));
    }

    #[test]
    fn test_load_root_certs_invalid_pem() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        create_file_from_str(temp_dir.path(), "invalid.pem", "not a valid certificate")
            .expect("failed to create file");
        let err = load_root_certs(temp_dir.path()).unwrap_err();
        assert!(matches!(err, CertError::NoCertsInFile(_)));
    }

    #[test]
    fn test_load_device_cert_missing_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cert_path = temp_dir.path().join("missing.pem");
        let key_path = temp_dir.path().join("missing.key");
        let err = load_device_cert(&cert_path, &key_path).unwrap_err();
        assert!(matches!(err, CertError::OpenFile { .. }));
    }

    #[test]
    fn test_load_device_cert_empty_cert_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        create_file_from_str(temp_dir.path(), "cert.pem", "").expect("failed to create cert file");
        create_file_from_str(temp_dir.path(), "key.pem", "").expect("failed to create key file");

        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        let err = load_device_cert(&cert_path, &key_path).unwrap_err();
        assert!(matches!(err, CertError::NoDeviceCertFound(_)));
    }

    /// Tests that certificates generated by aranya-certgen can be loaded by this module.
    ///
    /// This test exists here (rather than in aranya-certgen) to ensure compatibility
    /// with the exact rustls version used by this crate. If the test were in
    /// aranya-certgen, it would validate against aranya-certgen's rustls dependency,
    /// which could potentially differ.
    ///
    /// This serves as an integration test to catch any incompatibilities between
    /// the certificate generation tool and the daemon's certificate loading code.
    #[test]
    fn test_load_certs_generated_by_certgen() {
        use aranya_certgen::{CaCert, CertPaths, SaveOptions};

        let temp_dir = TempDir::new().expect("failed to create temp dir");

        // Generate CA and device certificates using aranya-certgen
        let ca = CaCert::new("Test Root CA", 365).expect("failed to create CA");
        // CN is automatically added as DNS SAN by the new certgen API
        let device = ca
            .generate("localhost", 365)
            .expect("failed to generate device cert");

        // Save certificates to temp directory
        let root_certs_dir = temp_dir.path().join("root_certs");
        fs::create_dir(&root_certs_dir).expect("failed to create root_certs dir");

        let ca_paths = CertPaths::new(root_certs_dir.join("ca"));
        ca.save(&ca_paths, SaveOptions::default())
            .expect("failed to save CA");

        let device_paths = CertPaths::new(temp_dir.path().join("device"));
        device
            .save(&device_paths, SaveOptions::default())
            .expect("failed to save device cert");

        let device_cert_path = temp_dir.path().join("device.crt.pem");
        let device_key_path = temp_dir.path().join("device.key.pem");

        // Load root certs
        let root_store = load_root_certs(&root_certs_dir).expect("failed to load root certs");
        assert!(!root_store.is_empty(), "root store should not be empty");

        // Load device cert
        let (device_certs, device_key) = load_device_cert(&device_cert_path, &device_key_path)
            .expect("failed to load device cert");
        assert!(!device_certs.is_empty(), "device certs should not be empty");

        // Build TLS configs to verify everything works together
        let client_config = build_client_config(
            root_store.clone(),
            device_certs.clone(),
            device_key.clone_key(),
        )
        .expect("failed to build client config");
        assert!(client_config.alpn_protocols.is_empty(), "ALPN not set yet");

        let server_config = build_server_config(root_store, device_certs, device_key)
            .expect("failed to build server config");
        assert!(server_config.alpn_protocols.is_empty(), "ALPN not set yet");
    }
}
