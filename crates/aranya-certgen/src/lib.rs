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
//! let cert_gen = CertGen::new_ca("My Root CA", 365).unwrap();
//!
//! // Generate a signed certificate
//! let san = SubjectAltNames::new()
//!     .with_dns("localhost")
//!     .with_ip("127.0.0.1".parse().unwrap());
//! let (cert, key) = cert_gen.generate_cert("my-device", 365, &san).unwrap();
//!
//! // Write CA and device certificates to files
//! cert_gen.write_ca("ca.pem", "ca-key.pem").unwrap();
//! aranya_certgen::write_cert("device.pem", &cert).unwrap();
//! aranya_certgen::write_key("device-key.pem", &key).unwrap();
//! ```
//!
//! # Loading an Existing CA
//!
//! ```no_run
//! use aranya_certgen::{CertGen, SubjectAltNames};
//!
//! // Load an existing CA from PEM files
//! let cert_gen = CertGen::load_ca("ca.pem", "ca-key.pem").unwrap();
//!
//! // Generate certificates signed by the loaded CA
//! let san = SubjectAltNames::new().with_dns("myserver.local");
//! let (cert, key) = cert_gen.generate_cert("server", 365, &san).unwrap();
//! ```

use std::{fs, net::IpAddr, path::Path};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, SanType,
};
pub use rcgen::{Certificate, Issuer, KeyPair};
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
#[derive(Debug, Clone, Default)]
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
/// let cert_gen = CertGen::new_ca("My CA", 365).unwrap();
///
/// // Generate device certificates
/// let san = SubjectAltNames::new()
///     .with_dns("device.local")
///     .with_ip("192.168.1.100".parse().unwrap());
/// let (cert, key) = cert_gen.generate_cert("device-1", 365, &san).unwrap();
/// ```
pub struct CertGen {
    ca_cert_pem: String,
    ca_key: KeyPair,
    issuer: Issuer<'static, KeyPair>,
}

impl CertGen {
    /// Creates a new Certificate Authority with a self-signed certificate.
    ///
    /// The generated key pair uses the NIST P-256 curve (secp256r1) with ECDSA signatures.
    ///
    /// # Arguments
    /// * `cn` - The Common Name for the CA.
    /// * `validity_days` - The number of days the CA certificate is valid for.
    ///
    /// # Errors
    /// Returns an error if key generation or certificate signing fails.
    pub fn new_ca(cn: &str, validity_days: u32) -> Result<Self, CertGenError> {
        let (cert, key_pair) = generate_root_ca(cn, validity_days)?;
        let ca_cert_pem = cert.pem();

        // Create a new key pair for the issuer (we need to keep the original for writing)
        let issuer_key = KeyPair::from_pem(&key_pair.serialize_pem())?;
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, issuer_key)?;

        Ok(Self {
            ca_cert_pem,
            ca_key: key_pair,
            issuer,
        })
    }

    /// Loads an existing CA from PEM files.
    ///
    /// # Arguments
    /// * `cert_path` - Path to the CA certificate file (PEM format).
    /// * `key_path` - Path to the CA private key file (PEM format).
    ///
    /// # Errors
    /// Returns an error if the files cannot be read or parsed.
    pub fn load_ca(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, CertGenError> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        let ca_cert_pem =
            fs::read_to_string(cert_path).map_err(|e| CertGenError::io(cert_path, e))?;
        let key_pem = fs::read_to_string(key_path).map_err(|e| CertGenError::io(key_path, e))?;

        let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(key_path, e))?;

        // Create a separate key for the issuer
        let issuer_key =
            KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(key_path, e))?;
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, issuer_key)
            .map_err(|e| CertGenError::parse_cert(cert_path, e))?;

        Ok(Self {
            ca_cert_pem,
            ca_key,
            issuer,
        })
    }

    /// Generates a certificate signed by this CA with a P-256 ECDSA private key.
    ///
    /// # Arguments
    /// * `cn` - The Common Name for the certificate.
    /// * `validity_days` - The number of days the certificate is valid for.
    /// * `san` - The Subject Alternative Names (DNS and IP addresses).
    ///
    /// # Returns
    /// A tuple containing the certificate and P-256 ECDSA private key.
    ///
    /// # Errors
    /// Returns an error if key generation or certificate signing fails.
    pub fn generate_cert(
        &self,
        cn: &str,
        validity_days: u32,
        san: &SubjectAltNames,
    ) -> Result<(Certificate, KeyPair), CertGenError> {
        generate_signed_cert(cn, &self.issuer, validity_days, san)
    }

    /// Returns the CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns a reference to the CA private key.
    pub fn ca_key(&self) -> &KeyPair {
        &self.ca_key
    }

    /// Returns a reference to the issuer for advanced use cases.
    pub fn issuer(&self) -> &Issuer<'static, KeyPair> {
        &self.issuer
    }

    /// Writes the CA certificate and private key to PEM files.
    ///
    /// # Arguments
    /// * `cert_path` - Path for the CA certificate file.
    /// * `key_path` - Path for the CA private key file.
    ///
    /// # Errors
    /// Returns an error if writing fails.
    pub fn write_ca(
        &self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<(), CertGenError> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent).map_err(|e| CertGenError::io(cert_path, e))?;
        }
        fs::write(cert_path, &self.ca_cert_pem).map_err(|e| CertGenError::io(cert_path, e))?;

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|e| CertGenError::io(key_path, e))?;
        }
        fs::write(key_path, self.ca_key.serialize_pem())
            .map_err(|e| CertGenError::io(key_path, e))?;

        Ok(())
    }
}

impl std::fmt::Debug for CertGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertGen")
            .field("ca_cert_pem", &"<PEM data>")
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Standalone functions (for backwards compatibility and simple use cases)
// ============================================================================

/// Generates a self-signed root CA certificate with a P-256 ECDSA private key.
///
/// The generated key pair uses the NIST P-256 curve (secp256r1) with ECDSA signatures.
///
/// # Arguments
/// * `cn` - The Common Name for the CA.
/// * `validity_days` - The number of days the certificate is valid for.
///
/// # Returns
/// A tuple containing the certificate and P-256 ECDSA private key.
///
/// # Errors
/// Returns an error if key generation or certificate signing fails.
pub fn generate_root_ca(
    cn: &str,
    validity_days: u32,
) -> Result<(Certificate, KeyPair), CertGenError> {
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
    params.not_after = now + Duration::days(i64::from(validity_days));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

/// Creates an Issuer from a CA certificate and key pair.
///
/// This is used to sign other certificates with the CA.
///
/// # Arguments
/// * `ca_cert` - The CA certificate.
/// * `ca_key` - The CA private key.
///
/// # Returns
/// An Issuer that can be used to sign certificates.
pub fn issuer_from_ca(
    ca_cert: &Certificate,
    ca_key: KeyPair,
) -> Result<Issuer<'static, KeyPair>, CertGenError> {
    let issuer = Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key)?;
    Ok(issuer)
}

/// Generates a certificate signed by a CA with a P-256 ECDSA private key.
///
/// The generated key pair uses the NIST P-256 curve (secp256r1) with ECDSA signatures.
///
/// # Arguments
/// * `cn` - The Common Name for the certificate.
/// * `issuer` - The CA issuer to sign with.
/// * `validity_days` - The number of days the certificate is valid for.
/// * `san` - The Subject Alternative Names (DNS and IP addresses).
///
/// # Returns
/// A tuple containing the certificate and P-256 ECDSA private key.
///
/// # Errors
/// Returns an error if key generation or certificate signing fails.
pub fn generate_signed_cert(
    cn: &str,
    issuer: &Issuer<'_, KeyPair>,
    validity_days: u32,
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
        sans.push(SanType::DnsName(
            dns.clone().try_into().expect("expected DNS name"),
        ));
    }
    for ip in &san.ip_addresses {
        sans.push(SanType::IpAddress(*ip));
    }
    // If no SANs provided, use the CN as a default DNS name
    if sans.is_empty() {
        sans.push(SanType::DnsName(
            cn.to_string().try_into().expect("expected DNS name"),
        ));
    }
    params.subject_alt_names = sans;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(validity_days));

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;

    Ok((cert, key_pair))
}

/// Writes a certificate to a file in PEM format.
///
/// # Arguments
/// * `path` - The file path to write to.
/// * `cert` - The certificate to write.
///
/// # Errors
/// Returns an error if writing fails.
pub fn write_cert(path: impl AsRef<Path>, cert: &Certificate) -> Result<(), CertGenError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CertGenError::io(path, e))?;
    }
    fs::write(path, cert.pem()).map_err(|e| CertGenError::io(path, e))?;
    Ok(())
}

/// Writes a private key to a file in PEM format.
///
/// # Arguments
/// * `path` - The file path to write to.
/// * `key` - The private key to write.
///
/// # Errors
/// Returns an error if writing fails.
pub fn write_key(path: impl AsRef<Path>, key: &KeyPair) -> Result<(), CertGenError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| CertGenError::io(path, e))?;
    }
    fs::write(path, key.serialize_pem()).map_err(|e| CertGenError::io(path, e))?;
    Ok(())
}

/// Loads a CA certificate and private key from PEM files.
///
/// # Arguments
/// * `cert_path` - Path to the CA certificate file.
/// * `key_path` - Path to the CA private key file.
///
/// # Returns
/// An Issuer that can be used to sign certificates.
///
/// # Errors
/// Returns an error if the files cannot be read or parsed.
pub fn load_ca(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<Issuer<'static, KeyPair>, CertGenError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();

    let cert_pem = fs::read_to_string(cert_path).map_err(|e| CertGenError::io(cert_path, e))?;
    let key_pem = fs::read_to_string(key_path).map_err(|e| CertGenError::io(key_path, e))?;

    let key = KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(key_path, e))?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
        .map_err(|e| CertGenError::parse_cert(cert_path, e))?;

    Ok(issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_root_ca() {
        let (cert, _key) = generate_root_ca("Test CA", 365).expect("should generate CA");
        let pem = cert.pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_generate_signed_cert() {
        let (ca_cert, ca_key) = generate_root_ca("Test CA", 365).expect("should generate CA");
        let issuer = issuer_from_ca(&ca_cert, ca_key).expect("should create issuer");

        let san = SubjectAltNames::new()
            .with_dns("localhost")
            .with_ip("127.0.0.1".parse().unwrap());

        let (cert, _key) =
            generate_signed_cert("test-device", &issuer, 365, &san).expect("should generate cert");

        let pem = cert.pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_cert_gen_new_ca() {
        let cert_gen = CertGen::new_ca("Test CA", 365).expect("should create CA");
        assert!(cert_gen.ca_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_cert_gen_generate_cert() {
        let cert_gen = CertGen::new_ca("Test CA", 365).expect("should create CA");

        let san = SubjectAltNames::new()
            .with_dns("localhost")
            .with_ip("127.0.0.1".parse().unwrap());

        let (cert, key) = cert_gen
            .generate_cert("test-device", 365, &san)
            .expect("should generate cert");

        assert!(cert.pem().contains("BEGIN CERTIFICATE"));
        assert!(key.serialize_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_cert_gen_multiple_certs() {
        let cert_gen = CertGen::new_ca("Test CA", 365).expect("should create CA");

        let san1 = SubjectAltNames::new().with_dns("device1.local");
        let san2 = SubjectAltNames::new().with_dns("device2.local");

        let (cert1, _) = cert_gen
            .generate_cert("device-1", 365, &san1)
            .expect("should generate cert 1");
        let (cert2, _) = cert_gen
            .generate_cert("device-2", 365, &san2)
            .expect("should generate cert 2");

        // Both should be valid certificates
        assert!(cert1.pem().contains("BEGIN CERTIFICATE"));
        assert!(cert2.pem().contains("BEGIN CERTIFICATE"));

        // They should be different
        assert_ne!(cert1.pem(), cert2.pem());
    }
}
