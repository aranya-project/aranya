//! Library for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Example
//!
//! ```no_run
//! use aranya_certgen::CertGen;
//!
//! // Create a new CA
//! let ca = CertGen::ca("My Root CA", 365).unwrap();
//!
//! // Generate a signed certificate
//! let signed = ca.generate("my-server", 365).unwrap();
//!
//! // Save CA and signed certificates to files
//! // Creates ./ca.crt.pem and ./ca.key.pem
//! ca.save(".", "ca", None).unwrap();
//! // Creates ./server.crt.pem and ./server.key.pem
//! signed.save(".", "server", None).unwrap();
//! ```
//!
//! # Loading an Existing CA
//!
//! ```no_run
//! use aranya_certgen::CertGen;
//!
//! // Load an existing CA from PEM files
//! // Loads from ./ca.crt.pem and ./ca.key.pem
//! let ca = CertGen::load(".", "ca").unwrap();
//!
//! // Generate certificates signed by the loaded CA
//! let signed = ca.generate("server", 365).unwrap();
//! ```

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Errors that can occur during certificate generation operations.
#[derive(Error, Debug)]
pub enum CertGenError {
    /// An I/O error occurred while reading or writing a file.
    #[error("IO error for '{path}': {source}")]
    Io {
        /// The path to the file that caused the error.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to parse a PEM-encoded certificate.
    #[error("Failed to parse certificate '{path}': {source}")]
    ParseCert {
        /// The path to the certificate file that failed to parse.
        path: String,
        /// The underlying parsing error.
        source: rcgen::Error,
    },

    /// Failed to parse a PEM-encoded private key.
    #[error("Failed to parse private key '{path}': {source}")]
    ParseKey {
        /// The path to the key file that failed to parse.
        path: String,
        /// The underlying parsing error.
        source: rcgen::Error,
    },

    /// Failed to generate a certificate.
    #[error("Failed to generate certificate: {0}")]
    Generate(#[from] rcgen::Error),

    /// Invalid validity period.
    #[error("Invalid validity period: days must be greater than 0")]
    InvalidDays,

    /// Directory does not exist.
    #[error("Directory does not exist: {0}")]
    DirNotFound(String),

    /// File already exists.
    #[error("File already exists: {0}")]
    FileExists(String),
}

impl CertGenError {
    /// Creates a new I/O error with the given path and source error.
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    /// Creates a new certificate parsing error with the given path and source error.
    pub fn parse_cert(path: impl AsRef<Path>, source: rcgen::Error) -> Self {
        Self::ParseCert {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    /// Creates a new key parsing error with the given path and source error.
    pub fn parse_key(path: impl AsRef<Path>, source: rcgen::Error) -> Self {
        Self::ParseKey {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

/// Options for saving certificates to disk.
#[derive(Debug, Clone, Default)]
pub struct SaveOptions {
    /// Create parent directories if they don't exist.
    pub create_parents: bool,
    /// Overwrite existing files.
    pub force: bool,
}

impl SaveOptions {
    /// Enable creating parent directories if they don't exist.
    pub fn create_parents(mut self) -> Self {
        self.create_parents = true;
        self
    }

    /// Enable overwriting existing files.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }
}

/// Certificate generator for creating CA and signed certificates.
///
/// `CertGen` holds a Certificate Authority (CA) and can generate certificates
/// signed by that CA. All generated keys use P-256 ECDSA.
///
/// # Example
///
/// ```no_run
/// use aranya_certgen::CertGen;
///
/// // Create a new CA
/// let ca = CertGen::ca("My CA", 365).unwrap();
///
/// // Generate a signed certificate
/// let signed = ca.generate("my-server", 365).unwrap();
/// ```
pub struct CertGen {
    cert_pem: String,
    key: KeyPair,
    issuer: Issuer<'static, KeyPair>,
}

impl CertGen {
    /// Creates a new Certificate Authority (CA) with a self-signed certificate.
    ///
    /// Generates a new P-256 ECDSA key pair and creates a self-signed CA certificate
    /// that can be used to sign other certificates.
    ///
    /// # Arguments
    ///
    /// * `cn` - The Common Name (CN) for the CA certificate.
    /// * `days` - The validity period in days from now.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `days` is 0 ([`CertGenError::InvalidDays`])
    /// - Key generation or certificate signing fails ([`CertGenError::Generate`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CertGen;
    ///
    /// let ca = CertGen::ca("My Root CA", 365)?;
    /// ca.save(".", "ca", None)?;  // Creates ./ca.crt.pem and ./ca.key.pem
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn ca(cn: &str, days: u32) -> Result<Self, CertGenError> {
        if days == 0 {
            return Err(CertGenError::InvalidDays);
        }
        let (cert, key) = generate_root_ca(cn, days)?;
        let cert_pem = cert.pem();

        let issuer_key = KeyPair::from_pem(&key.serialize_pem())?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, issuer_key)?;

        Ok(Self {
            cert_pem,
            key,
            issuer,
        })
    }

    /// Generates a certificate signed by this CA.
    ///
    /// Creates a new P-256 ECDSA key pair and generates a certificate signed by
    /// this CA.
    ///
    /// # Arguments
    ///
    /// * `cn` - The Common Name (CN) for the certificate.
    /// * `days` - The validity period in days from now. Must be greater than 0.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `days` is 0 ([`CertGenError::InvalidDays`])
    /// - Key generation or certificate signing fails ([`CertGenError::Generate`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CertGen;
    ///
    /// let ca = CertGen::ca("My CA", 365)?;
    /// let signed = ca.generate("server", 365)?;
    /// signed.save(".", "server", None)?;  // Creates ./server.crt.pem and ./server.key.pem
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn generate(&self, cn: &str, days: u32) -> Result<Self, CertGenError> {
        if days == 0 {
            return Err(CertGenError::InvalidDays);
        }
        let (cert, key) = generate_signed_cert(cn, &self.issuer, days)?;
        let cert_pem = cert.pem();

        let issuer_key = KeyPair::from_pem(&key.serialize_pem())?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, issuer_key)?;

        Ok(Self {
            cert_pem,
            key,
            issuer,
        })
    }

    /// Loads a certificate and private key from PEM files.
    ///
    /// Use this to load an existing CA for signing new certificates.
    /// Files are loaded from `{dir}/{name}.crt.pem` and `{dir}/{name}.key.pem`.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory containing the certificate and key files.
    /// * `name` - Base name for the files (without extension).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The files cannot be read ([`CertGenError::Io`])
    /// - The certificate cannot be parsed ([`CertGenError::ParseCert`])
    /// - The private key cannot be parsed ([`CertGenError::ParseKey`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CertGen;
    ///
    /// // Loads from ./ca.crt.pem and ./ca.key.pem
    /// let ca = CertGen::load(".", "ca")?;
    /// let signed = ca.generate("server", 365)?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn load(dir: impl AsRef<Path>, name: &str) -> Result<Self, CertGenError> {
        let dir = dir.as_ref();
        let cert_path = dir.join(format!("{name}.crt.pem"));
        let key_path = dir.join(format!("{name}.key.pem"));

        let cert_pem = fs::read_to_string(&cert_path).map_err(|e| CertGenError::io(&cert_path, e))?;
        let key_pem = fs::read_to_string(&key_path).map_err(|e| CertGenError::io(&key_path, e))?;

        let key = KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(&key_path, e))?;

        let issuer_key =
            KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(&key_path, e))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, issuer_key)
            .map_err(|e| CertGenError::parse_cert(&cert_path, e))?;

        Ok(Self {
            cert_pem,
            key,
            issuer,
        })
    }

    /// Saves the certificate and private key to PEM files.
    ///
    /// Files are saved as `{dir}/{name}.crt.pem` and `{dir}/{name}.key.pem`.
    ///
    /// By default (when `options` is `None`), this function will return an error if:
    /// - The directory does not exist
    /// - The files already exist
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory to save the files in.
    /// * `name` - Base name for the files (without extension).
    /// * `options` - Optional settings for directory creation and file overwriting.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CertGenError::DirNotFound`] if directory doesn't exist and `create_parents` is false
    /// - [`CertGenError::FileExists`] if files exist and `force` is false
    /// - [`CertGenError::Io`] if writing files fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::{CertGen, SaveOptions};
    ///
    /// let ca = CertGen::ca("My CA", 365)?;
    ///
    /// // Save with default options (fails if dir missing or files exist)
    /// ca.save(".", "ca", None)?;
    ///
    /// // Create directory if needed and overwrite existing files
    /// ca.save("certs", "ca", Some(SaveOptions::default().create_parents().force()))?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn save(
        &self,
        dir: impl AsRef<Path>,
        name: &str,
        options: Option<SaveOptions>,
    ) -> Result<(), CertGenError> {
        let options = options.unwrap_or_default();
        let dir = dir.as_ref();
        let cert_path = dir.join(format!("{name}.crt.pem"));
        let key_path = dir.join(format!("{name}.key.pem"));

        // Check/create directory
        if !dir.exists() {
            if options.create_parents {
                fs::create_dir_all(dir).map_err(|e| CertGenError::io(dir, e))?;
            } else {
                return Err(CertGenError::DirNotFound(dir.display().to_string()));
            }
        }

        // Check for existing files
        if !options.force {
            if cert_path.exists() {
                return Err(CertGenError::FileExists(cert_path.display().to_string()));
            }
            if key_path.exists() {
                return Err(CertGenError::FileExists(key_path.display().to_string()));
            }
        }

        fs::write(&cert_path, &self.cert_pem).map_err(|e| CertGenError::io(&cert_path, e))?;

        // Write private key with restrictive permissions set at creation time
        // to prevent race condition where others could read the key before
        // permissions are set.
        let mut key_options = OpenOptions::new();
        key_options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        key_options.mode(0o600);
        let mut key_file = key_options
            .open(&key_path)
            .map_err(|e| CertGenError::io(&key_path, e))?;
        key_file
            .write_all(self.key.serialize_pem().as_bytes())
            .map_err(|e| CertGenError::io(&key_path, e))?;

        Ok(())
    }

    /// Returns the certificate as a PEM-encoded string.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Returns the private key as a PEM-encoded string.
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }
}

impl std::fmt::Debug for CertGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertGen")
            .field("cert_pem", &"<PEM data>")
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Internal helper functions
// ============================================================================

/// Generates a self-signed root CA certificate with a P-256 ECDSA private key.
fn generate_root_ca(cn: &str, days: u32) -> Result<(Certificate, KeyPair), CertGenError> {
    let mut params = CertificateParams::default();

    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));
    params.distinguished_name.push(
        DnType::OrganizationName,
        DnValue::Utf8String("Certificate Authority".to_string()),
    );

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(days));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

/// Generates a certificate signed by a CA with a P-256 ECDSA private key.
fn generate_signed_cert(
    cn: &str,
    issuer: &Issuer<'_, KeyPair>,
    days: u32,
) -> Result<(Certificate, KeyPair), CertGenError> {
    let mut params = CertificateParams::default();

    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));

    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(days));

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;

    Ok((cert, key_pair))
}

#[cfg(test)]
mod tests {
    use x509_parser::prelude::*;

    use super::*;

    #[test]
    fn test_cert_gen_ca_roundtrip() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let dir = tempfile::tempdir().unwrap();

        ca.save(dir.path(), "ca", None).expect("should save");
        let loaded = CertGen::load(dir.path(), "ca").expect("should load");

        assert_eq!(ca.cert_pem(), loaded.cert_pem());

        // Verify the files are named correctly
        assert!(dir.path().join("ca.crt.pem").exists());
        assert!(dir.path().join("ca.key.pem").exists());
    }

    #[test]
    fn test_cert_gen_generate_roundtrip() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let cert = ca
            .generate("test-server", 365)
            .expect("should generate cert");

        let dir = tempfile::tempdir().unwrap();

        cert.save(dir.path(), "server", None).expect("should save");
        let loaded = CertGen::load(dir.path(), "server").expect("should load");

        assert_eq!(cert.cert_pem(), loaded.cert_pem());

        // Verify the files are named correctly
        assert!(dir.path().join("server.crt.pem").exists());
        assert!(dir.path().join("server.key.pem").exists());
    }

    #[test]
    fn test_cert_gen_multiple_certs_are_unique() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let cert1 = ca
            .generate("server-1", 365)
            .expect("should generate cert 1");
        let cert2 = ca
            .generate("server-2", 365)
            .expect("should generate cert 2");

        // Each generated cert should be unique
        assert_ne!(cert1.cert_pem(), cert2.cert_pem());
    }

    #[test]
    fn test_cert_signed_by_ca() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let cert = ca
            .generate("test-server", 365)
            .expect("should generate cert");

        // Parse the CA certificate to get its public key
        let (_, ca_pem) = parse_x509_pem(ca.cert_pem().as_bytes()).expect("should parse CA PEM");
        let ca_cert = ca_pem.parse_x509().expect("should parse CA cert");

        // Parse the signed certificate
        let (_, signed_pem) =
            parse_x509_pem(cert.cert_pem().as_bytes()).expect("should parse signed PEM");
        let signed_cert = signed_pem.parse_x509().expect("should parse signed cert");

        // Verify the signed certificate's signature using the CA's public key
        signed_cert
            .verify_signature(Some(ca_cert.public_key()))
            .expect("certificate should be signed by CA");
    }

    #[test]
    fn test_save_fails_if_dir_not_exists() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("nonexistent");

        let result = ca.save(&nonexistent, "ca", None);

        assert!(
            matches!(result, Err(CertGenError::DirNotFound(_))),
            "expected DirNotFound error, got {:?}",
            result
        );
    }

    #[test]
    fn test_save_fails_if_file_exists() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let dir = tempfile::tempdir().unwrap();

        // Save once successfully
        ca.save(dir.path(), "ca", None).expect("first save should succeed");

        // Second save should fail because files exist
        let result = ca.save(dir.path(), "ca", None);

        assert!(
            matches!(result, Err(CertGenError::FileExists(_))),
            "expected FileExists error, got {:?}",
            result
        );
    }

    #[test]
    fn test_save_with_create_parents() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");

        // Should succeed with create_parents option
        ca.save(&nested, "ca", Some(SaveOptions::default().create_parents()))
            .expect("save with create_parents should succeed");

        assert!(nested.join("ca.crt.pem").exists());
        assert!(nested.join("ca.key.pem").exists());
    }

    #[test]
    fn test_save_with_force() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let dir = tempfile::tempdir().unwrap();

        // Save once
        ca.save(dir.path(), "ca", None).expect("first save should succeed");

        // Second save with force should succeed
        ca.save(dir.path(), "ca", Some(SaveOptions::default().force()))
            .expect("save with force should succeed");
    }
}
