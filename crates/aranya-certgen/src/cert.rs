//! Certificate types for CA and signed certificates.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SigningKey,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::CertGenError;

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

/// Paths for certificate and private key files.
///
/// Provides a single source of truth for path calculation, ensuring consistent
/// naming conventions across save and load operations.
///
/// # Example
///
/// ```
/// use aranya_certgen::CertPaths;
///
/// let paths = CertPaths::new("ca");
/// assert_eq!(paths.cert.to_str().unwrap(), "ca.crt.pem");
/// assert_eq!(paths.key.to_str().unwrap(), "ca.key.pem");
///
/// let paths = CertPaths::new("./certs/server");
/// assert_eq!(paths.cert.to_str().unwrap(), "./certs/server.crt.pem");
/// assert_eq!(paths.key.to_str().unwrap(), "./certs/server.key.pem");
/// ```
#[derive(Debug, Clone)]
pub struct CertPaths {
    /// Path to the certificate file (`.crt.pem`).
    pub cert: PathBuf,
    /// Path to the private key file (`.key.pem`).
    pub key: PathBuf,
}

impl CertPaths {
    /// Creates paths from a prefix.
    ///
    /// The prefix is used as the base path, with `.crt.pem` and `.key.pem`
    /// extensions appended for the certificate and key files respectively.
    pub fn new(prefix: impl AsRef<Path>) -> Self {
        let prefix = prefix.as_ref();
        Self {
            cert: prefix.with_extension("crt.pem"),
            key: prefix.with_extension("key.pem"),
        }
    }
}

/// A Certificate Authority (CA) certificate that can sign other certificates.
///
/// `CaCert` holds a CA certificate and its private key, and can generate
/// signed certificates. All generated keys use P-256 ECDSA.
///
/// # Security
///
/// The private key is wrapped in [`Zeroizing`] and automatically zeroized when dropped
/// to prevent key material from lingering in memory. The key is stored directly (not
/// inside rcgen's `Issuer`). When signing certificates, an `Issuer` is created temporarily
/// with a reference to the key - no copy is made.
///
/// # Example
///
/// ```no_run
/// use aranya_certgen::{CaCert, CertPaths, SaveOptions};
///
/// // Create a new CA and save
/// let ca = CaCert::new("My CA", 365).unwrap();
/// ca.save(&CertPaths::new("ca"), SaveOptions::default()).unwrap();
///
/// // Generate a signed certificate
/// let signed = ca.generate("my-server", 365).unwrap();
/// signed.save(&CertPaths::new("server"), SaveOptions::default()).unwrap();
/// ```
// Debug intentionally not implemented to avoid risk of exposing private keys.
#[allow(missing_debug_implementations)]
pub struct CaCert {
    cert_pem: String,
    key: Zeroizing<KeyPair>,
}

impl CaCert {
    /// Returns a reference to the inner key for use with rcgen APIs.
    fn key_ref(&self) -> &KeyPair {
        &self.key
    }

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
    pub fn new(cn: &str, days: u32) -> Result<Self, CertGenError> {
        if days == 0 {
            return Err(CertGenError::InvalidDays);
        }
        let (cert, key) = generate_root_ca(cn, days)?;
        let cert_pem = cert.pem();

        Ok(Self {
            cert_pem,
            key: Zeroizing::new(key),
        })
    }

    /// Generates a leaf certificate signed by this CA.
    ///
    /// Creates a new P-256 ECDSA key pair and generates a certificate signed by
    /// this CA. The resulting certificate cannot sign other certificates.
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
    pub fn generate(&self, cn: &str, days: u32) -> Result<SignedCert, CertGenError> {
        if days == 0 {
            return Err(CertGenError::InvalidDays);
        }
        // Create issuer on-demand using a reference to our key.
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, self.key_ref())?;
        let (cert, key) = generate_signed_cert(cn, &issuer, days)?;
        let cert_pem = cert.pem();

        Ok(SignedCert {
            cert_pem,
            key: Zeroizing::new(key),
        })
    }

    /// Loads a CA certificate and private key from PEM files.
    ///
    /// # Arguments
    ///
    /// * `paths` - Paths to the certificate and key files.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The files cannot be read ([`CertGenError::Io`])
    /// - The certificate cannot be parsed ([`CertGenError::ParseCert`])
    /// - The private key cannot be parsed ([`CertGenError::ParseKey`])
    pub fn load(paths: &CertPaths) -> Result<Self, CertGenError> {
        let cert_pem =
            fs::read_to_string(&paths.cert).map_err(|e| CertGenError::io(&paths.cert, e))?;

        // Wrap in Zeroizing to ensure the key PEM is zeroized on drop, even if parsing fails
        let key_pem = Zeroizing::new(
            fs::read_to_string(&paths.key).map_err(|e| CertGenError::io(&paths.key, e))?,
        );

        let key = Zeroizing::new(
            KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(&paths.key, e))?,
        );

        // Validate that the cert is a valid CA certificate
        Issuer::from_ca_cert_pem(&cert_pem, &*key)
            .map_err(|e| CertGenError::not_ca_cert(&paths.cert, e))?;

        Ok(Self { cert_pem, key })
    }

    /// Saves the CA certificate and private key to PEM files.
    ///
    /// # Arguments
    ///
    /// * `paths` - Paths to save the certificate and key files.
    /// * `options` - Settings for directory creation and file overwriting.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CertGenError::DirNotFound`] if directory doesn't exist and `create_parents` is false
    /// - [`CertGenError::FileExists`] if files exist and `force` is false
    /// - [`CertGenError::Io`] if writing files fails
    pub fn save(&self, paths: &CertPaths, options: SaveOptions) -> Result<(), CertGenError> {
        save_cert_and_key(paths, &self.cert_pem, &self.key.serialize_pem(), options)
    }

    /// Returns the certificate as a PEM-encoded string.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Returns the private key as a PEM-encoded string.
    ///
    /// Returns [`Zeroizing<String>`] to ensure key material is zeroized when dropped.
    pub fn key_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.key.serialize_pem())
    }
}

/// A signed leaf certificate that cannot sign other certificates.
///
/// `SignedCert` holds a certificate signed by a CA and its private key.
/// Unlike [`CaCert`], this type cannot be used to sign other certificates.
///
/// # Security
///
/// The private key is wrapped in [`Zeroizing`] and automatically zeroized when dropped
/// to prevent key material from lingering in memory.
///
/// # Example
///
/// ```no_run
/// use aranya_certgen::{CaCert, CertPaths, SaveOptions};
///
/// let ca = CaCert::new("My CA", 365).unwrap();
/// let signed = ca.generate("my-server", 365).unwrap();
/// signed.save(&CertPaths::new("server"), SaveOptions::default()).unwrap();
/// ```
// Debug intentionally not implemented to avoid risk of exposing private keys.
#[allow(missing_debug_implementations)]
pub struct SignedCert {
    cert_pem: String,
    key: Zeroizing<KeyPair>,
}

impl SignedCert {
    /// Saves the certificate and private key to PEM files.
    ///
    /// # Arguments
    ///
    /// * `paths` - Paths to save the certificate and key files.
    /// * `options` - Settings for directory creation and file overwriting.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CertGenError::DirNotFound`] if directory doesn't exist and `create_parents` is false
    /// - [`CertGenError::FileExists`] if files exist and `force` is false
    /// - [`CertGenError::Io`] if writing files fails
    pub fn save(&self, paths: &CertPaths, options: SaveOptions) -> Result<(), CertGenError> {
        save_cert_and_key(paths, &self.cert_pem, &self.key.serialize_pem(), options)
    }

    /// Returns the certificate as a PEM-encoded string.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Returns the private key as a PEM-encoded string.
    ///
    /// Returns [`Zeroizing<String>`] to ensure key material is zeroized when dropped.
    pub fn key_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.key.serialize_pem())
    }
}

// ============================================================================
// Internal helper functions
// ============================================================================

/// Saves a certificate and private key to PEM files.
fn save_cert_and_key(
    paths: &CertPaths,
    cert_pem: &str,
    key_pem: &str,
    options: SaveOptions,
) -> Result<(), CertGenError> {

    // Check/create parent directory
    if let Some(dir) = paths.cert.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            if options.create_parents {
                fs::create_dir_all(dir).map_err(|e| CertGenError::io(dir, e))?;
            } else {
                return Err(CertGenError::DirNotFound(dir.display().to_string()));
            }
        }
    }

    // Check for existing files
    if !options.force {
        if paths.cert.exists() {
            return Err(CertGenError::FileExists(paths.cert.display().to_string()));
        }
        if paths.key.exists() {
            return Err(CertGenError::FileExists(paths.key.display().to_string()));
        }
    }

    fs::write(&paths.cert, cert_pem).map_err(|e| CertGenError::io(&paths.cert, e))?;

    // Write private key with restrictive permissions set at creation time
    // to prevent race condition where others could read the key before
    // permissions are set.
    let mut key_options = OpenOptions::new();
    key_options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    key_options.mode(0o600);
    let mut key_file = key_options
        .open(&paths.key)
        .map_err(|e| CertGenError::io(&paths.key, e))?;
    key_file
        .write_all(key_pem.as_bytes())
        .map_err(|e| CertGenError::io(&paths.key, e))?;

    Ok(())
}

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
    issuer: &Issuer<'_, impl SigningKey>,
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

    // Add CN as SAN for rustls compatibility (rustls ignores CN, only checks SAN).
    // Auto-detect whether CN is an IP address or hostname and use the appropriate SAN type.
    params.subject_alt_names = if let Ok(ip) = cn.parse::<std::net::IpAddr>() {
        vec![SanType::IpAddress(ip)]
    } else {
        vec![SanType::DnsName(cn.to_string().try_into()?)]
    };

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(days));

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;

    Ok((cert, key_pair))
}
