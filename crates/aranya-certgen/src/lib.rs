//! Library for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Example
//!
//! ```no_run
//! use aranya_certgen::{generate_root_ca, generate_signed_cert, issuer_from_ca, SubjectAltNames};
//!
//! // Generate a root CA
//! let (ca_cert, ca_key) = generate_root_ca("My Root CA", 365).unwrap();
//!
//! // Generate a signed certificate
//! let issuer = issuer_from_ca(&ca_cert, ca_key).unwrap();
//! let san = SubjectAltNames::new()
//!     .with_dns("localhost")
//!     .with_ip("127.0.0.1".parse().unwrap());
//! let (cert, key) = generate_signed_cert("my-device", &issuer, 365, &san).unwrap();
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
}
