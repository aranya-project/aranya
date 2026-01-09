//! Library for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Example
//!
//! ```no_run
//! use aranya_certgen::{CertGen, SubjectAltNames};
//!
//! // Create a new CA
//! let cert_gen = CertGen::ca("My Root CA", 365).unwrap();
//!
//! // Generate a signed certificate
//! let sans = SubjectAltNames::new()
//!     .with_dns("localhost")
//!     .with_ip("127.0.0.1".parse().unwrap());
//! let device = CertGen::generate(&cert_gen, "my-device", 365, &sans).unwrap();
//!
//! // Save CA and device certificates to files
//! cert_gen.save("ca.pem", "ca.key").unwrap();
//! device.save("device.pem", "device.key").unwrap();
//! ```
//!
//! # Loading an Existing CA
//!
//! ```no_run
//! use aranya_certgen::{CertGen, SubjectAltNames};
//!
//! // Load an existing CA from PEM files
//! let cert_gen = CertGen::load("ca.pem", "ca.key").unwrap();
//!
//! // Generate certificates signed by the loaded CA
//! let sans = SubjectAltNames::new().with_dns("myserver.local");
//! let server = CertGen::generate(&cert_gen, "server", 365, &sans).unwrap();
//! ```

use std::{fs, net::IpAddr, path::Path};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
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

/// Subject Alternative Names (SANs) for a certificate.
///
/// SANs specify additional identities (hostnames and IP addresses) that the
/// certificate is valid for, beyond the Common Name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SubjectAltNames {
    /// DNS names for Subject Alternative Names.
    pub dns_names: Vec<String>,
    /// IP addresses for Subject Alternative Names.
    pub ip_addresses: Vec<IpAddr>,
}

impl SubjectAltNames {
    /// Creates an empty SubjectAltNames.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a DNS name.
    pub fn with_dns(mut self, dns: impl Into<String>) -> Self {
        self.dns_names.push(dns.into());
        self
    }

    /// Adds an IP address.
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip_addresses.push(ip);
        self
    }
}

/// A PEM-encoded string.
type PemString = String;

/// Certificate generator for creating CA and signed certificates.
///
/// `CertGen` holds a Certificate Authority (CA) and can generate certificates
/// signed by that CA. All generated keys use P-256 ECDSA.
///
/// # Example
///
/// ```no_run
/// use aranya_certgen::{CertGen, SubjectAltNames};
///
/// // Create a new CA
/// let cert_gen = CertGen::ca("My CA", 365).unwrap();
///
/// // Generate device certificates
/// let sans = SubjectAltNames::new()
///     .with_dns("device.local")
///     .with_ip("192.168.1.100".parse().unwrap());
/// let device = CertGen::generate(&cert_gen, "device-1", 365, &sans).unwrap();
/// ```
pub struct CertGen {
    cert_pem: PemString,
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
    /// Returns [`CertGenError::Generate`] if key generation or certificate signing fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CertGen;
    ///
    /// let ca = CertGen::ca("My Root CA", 365)?;
    /// ca.save("ca.pem", "ca.key")?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn ca(cn: &str, days: u32) -> Result<Self, CertGenError> {
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

    /// Generates a certificate signed by the given CA.
    ///
    /// Creates a new P-256 ECDSA key pair and generates a certificate signed by the
    /// provided CA. The certificate includes the specified Subject Alternative Names.
    ///
    /// # Arguments
    ///
    /// * `signer` - The CA that will sign the certificate.
    /// * `cn` - The Common Name (CN) for the certificate.
    /// * `days` - The validity period in days from now.
    /// * `san` - Subject Alternative Names (DNS hostnames and IP addresses).
    ///
    /// # Errors
    ///
    /// Returns [`CertGenError::Generate`] if key generation or certificate signing fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::{CertGen, SubjectAltNames};
    ///
    /// let ca = CertGen::ca("My CA", 365)?;
    ///
    /// let sans = SubjectAltNames::new()
    ///     .with_dns("server.local")
    ///     .with_ip("192.168.1.10".parse().unwrap());
    /// let cert = CertGen::generate(&ca, "server", 365, &sans)?;
    /// cert.save("server.pem", "server.key")?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn generate(
        signer: &CertGen,
        cn: &str,
        days: u32,
        san: &SubjectAltNames,
    ) -> Result<Self, CertGenError> {
        let (cert, key) = generate_signed_cert(cn, &signer.issuer, days, san)?;
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
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the certificate file (PEM format).
    /// * `key_path` - Path to the private key file (PEM format).
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
    /// use aranya_certgen::{CertGen, SubjectAltNames};
    ///
    /// let ca = CertGen::load("ca.pem", "ca.key")?;
    ///
    /// let sans = SubjectAltNames::new().with_dns("device.local");
    /// let device = CertGen::generate(&ca, "device", 365, &sans)?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn load(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, CertGenError> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        let cert_pem =
            fs::read_to_string(cert_path).map_err(|e| CertGenError::io(cert_path, e))?;
        let key_pem = fs::read_to_string(key_path).map_err(|e| CertGenError::io(key_path, e))?;

        let key = KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(key_path, e))?;

        let issuer_key =
            KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(key_path, e))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, issuer_key)
            .map_err(|e| CertGenError::parse_cert(cert_path, e))?;

        Ok(Self {
            cert_pem,
            key,
            issuer,
        })
    }

    /// Saves the certificate and private key to PEM files.
    ///
    /// Creates parent directories if they don't exist.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path for the certificate file (PEM format).
    /// * `key_path` - Path for the private key file (PEM format).
    ///
    /// # Errors
    ///
    /// Returns [`CertGenError::Io`] if creating directories or writing files fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CertGen;
    ///
    /// let ca = CertGen::ca("My CA", 365)?;
    /// ca.save("certs/ca.pem", "certs/ca.key")?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn save(
        &self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<(), CertGenError> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        if let Some(parent) = cert_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| CertGenError::io(cert_path, e))?;
            }
        }
        fs::write(cert_path, &self.cert_pem).map_err(|e| CertGenError::io(cert_path, e))?;

        if let Some(parent) = key_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| CertGenError::io(key_path, e))?;
            }
        }
        fs::write(key_path, self.key.serialize_pem())
            .map_err(|e| CertGenError::io(key_path, e))?;

        Ok(())
    }
}

impl std::fmt::Debug for CertGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertGen")
            .field("cert_pem", &"<PEM data>")
            .field("key", &"<private key>")
            .finish_non_exhaustive()
    }
}

impl PartialEq for CertGen {
    fn eq(&self, other: &Self) -> bool {
        self.cert_pem == other.cert_pem && self.key.serialize_pem() == other.key.serialize_pem()
    }
}

impl Eq for CertGen {}

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
    san: &SubjectAltNames,
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

    // Build Subject Alternative Names
    let mut sans: Vec<SanType> = Vec::new();
    for dns in &san.dns_names {
        sans.push(SanType::DnsName(dns.clone().try_into()?));
    }
    for ip in &san.ip_addresses {
        sans.push(SanType::IpAddress(*ip));
    }
    // If no SANs provided, use the CN as a default DNS name
    if sans.is_empty() {
        sans.push(SanType::DnsName(cn.to_string().try_into()?));
    }
    params.subject_alt_names = sans;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(days));

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;

    Ok((cert, key_pair))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_gen_ca_roundtrip() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");

        ca.save(&cert_path, &key_path).expect("should save");
        let loaded = CertGen::load(&cert_path, &key_path).expect("should load");

        assert_eq!(ca, loaded);
    }

    #[test]
    fn test_cert_gen_generate_roundtrip() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let sans = SubjectAltNames::new()
            .with_dns("localhost")
            .with_ip("127.0.0.1".parse().unwrap());

        let cert = CertGen::generate(&ca, "test-device", 365, &sans).expect("should generate cert");

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("device.pem");
        let key_path = dir.path().join("device.key");

        cert.save(&cert_path, &key_path).expect("should save");
        let loaded = CertGen::load(&cert_path, &key_path).expect("should load");

        assert_eq!(cert, loaded);
    }

    #[test]
    fn test_cert_gen_multiple_certs_are_unique() {
        let ca = CertGen::ca("Test CA", 365).expect("should create CA");

        let sans1 = SubjectAltNames::new().with_dns("device1.local");
        let sans2 = SubjectAltNames::new().with_dns("device2.local");

        let cert1 = CertGen::generate(&ca, "device-1", 365, &sans1).expect("should generate cert 1");
        let cert2 = CertGen::generate(&ca, "device-2", 365, &sans2).expect("should generate cert 2");

        // Each generated cert should be unique
        assert_ne!(cert1, cert2);
    }
}
