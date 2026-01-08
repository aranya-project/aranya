//! CLI tool for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Usage
//!
//! ```bash
//! # Create a root CA with P-256 ECDSA key
//! aranya-certgen ca --cert ca.pem --key ca.key --ca-name "My CA"
//!
//! # Create a signed certificate with P-256 ECDSA key
//! aranya-certgen signed --ca-cert ca.pem --ca-key ca.key \
//!     --cert server.pem --key server.key \
//!     --cn server --dns example.com --ip 192.168.1.10
//! ```

use std::{fs, net::IpAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Errors that can occur during certificate generation operations.
#[derive(Error, Debug)]
enum CertGenError {
    /// An I/O error occurred while reading or writing a file.
    #[error("IO error for '{}': {source}", path.display())]
    Io {
        /// The path to the file that caused the error.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to parse a PEM-encoded certificate.
    #[error("Failed to parse certificate '{}': {source}", path.display())]
    ParseCert {
        /// The path to the certificate file that failed to parse.
        path: PathBuf,
        /// The underlying parsing error.
        source: rcgen::Error,
    },

    /// Failed to parse a PEM-encoded private key.
    #[error("Failed to parse private key '{}': {source}", path.display())]
    ParseKey {
        /// The path to the key file that failed to parse.
        path: PathBuf,
        /// The underlying parsing error.
        source: rcgen::Error,
    },

    /// Failed to generate a certificate.
    #[error("Failed to generate certificate: {0}")]
    Generate(#[from] rcgen::Error),
}

impl CertGenError {
    /// Creates a new I/O error with the given path and source error.
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Creates a new certificate parsing error with the given path and source error.
    fn parse_cert(path: impl Into<PathBuf>, source: rcgen::Error) -> Self {
        Self::ParseCert {
            path: path.into(),
            source,
        }
    }

    /// Creates a new key parsing error with the given path and source error.
    fn parse_key(path: impl Into<PathBuf>, source: rcgen::Error) -> Self {
        Self::ParseKey {
            path: path.into(),
            source,
        }
    }
}

/// A pair of file paths for a certificate and its corresponding P-256 ECDSA private key.
#[derive(Debug, Clone)]
struct CertKeyPaths {
    /// Path to the certificate file (PEM format).
    cert: PathBuf,
    /// Path to the P-256 ECDSA private key file (PEM format).
    key: PathBuf,
}

/// Subject Alternative Names (SANs) for a certificate.
///
/// SANs specify additional identities (hostnames and IP addresses) that the
/// certificate is valid for, beyond the Common Name.
#[derive(Args, Debug, Clone)]
struct SubjectAltNames {
    /// DNS names for Subject Alternative Names (can be specified multiple times).
    #[arg(long = "dns", value_name = "HOSTNAME")]
    dns_names: Vec<String>,

    /// IP addresses for Subject Alternative Names (can be specified multiple times).
    #[arg(long = "ip", value_name = "ADDRESS")]
    ip_addresses: Vec<IpAddr>,
}

/// Command-line arguments for the certgen tool.
#[derive(Parser, Debug)]
#[command(name = "certgen")]
#[command(about = "Generate a root CA certificate and signed certificates using P-256 ECDSA keys")]
struct CliArgs {
    /// The subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands for certificate generation.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new root Certificate Authority (CA) with a P-256 ECDSA private key.
    ///
    /// Generates a self-signed CA certificate and P-256 ECDSA private key that
    /// can be used to sign other certificates.
    Ca {
        /// Path for the CA certificate file (PEM format).
        #[arg(long)]
        cert: PathBuf,

        /// Path for the CA P-256 ECDSA private key file (PEM format).
        #[arg(long)]
        key: PathBuf,

        /// Common Name (CN) for the root CA.
        #[arg(long, default_value = "My Root CA")]
        ca_name: String,

        /// Validity period in days from today.
        #[arg(long, default_value_t = 365)]
        validity_days: u32,
    },

    /// Create a new certificate signed by an existing root CA with a P-256 ECDSA private key.
    ///
    /// Generates a certificate and P-256 ECDSA private key, signed by the specified CA.
    /// The certificate can include Subject Alternative Names for DNS hostnames
    /// and IP addresses.
    Signed {
        /// Path for the output certificate file (PEM format).
        #[arg(long)]
        cert: PathBuf,

        /// Path for the output P-256 ECDSA private key file (PEM format).
        #[arg(long)]
        key: PathBuf,

        /// Path to the CA certificate file used for signing (PEM format).
        #[arg(long)]
        ca_cert: PathBuf,

        /// Path to the CA P-256 ECDSA private key file used for signing (PEM format).
        #[arg(long)]
        ca_key: PathBuf,

        /// Subject Alternative Names (DNS and IP).
        #[command(flatten)]
        san: SubjectAltNames,

        /// Common Name (CN) for the certificate.
        #[arg(long)]
        cn: String,

        /// Validity period in days from today.
        #[arg(long, default_value_t = 365)]
        validity_days: u32,
    },
}

fn main() -> Result<(), CertGenError> {
    let args = CliArgs::parse();

    match args.command {
        Commands::Ca {
            cert,
            key,
            ca_name,
            validity_days,
        } => {
            let output = CertKeyPaths { cert, key };
            init_ca(&output, &ca_name, validity_days)?;
        }
        Commands::Signed {
            cert,
            key,
            ca_cert,
            ca_key,
            san,
            cn,
            validity_days,
        } => {
            let output = CertKeyPaths { cert, key };
            let ca = CertKeyPaths {
                cert: ca_cert,
                key: ca_key,
            };
            generate_signed_cert_files(&output, &ca, &cn, &san, validity_days)?;
        }
    }

    Ok(())
}

/// Creates parent directories for the certificate and key paths if they don't exist.
///
/// # Arguments
/// * `paths` - The certificate and key paths to create parent directories for.
///
/// # Errors
/// Returns a `CertGenError::Io` if directory creation fails.
fn create_parent_dirs(paths: &CertKeyPaths) -> Result<(), CertGenError> {
    if let Some(parent) = paths.cert.parent() {
        fs::create_dir_all(parent).map_err(|e| CertGenError::io(&paths.cert, e))?;
    }
    if let Some(parent) = paths.key.parent() {
        fs::create_dir_all(parent).map_err(|e| CertGenError::io(&paths.key, e))?;
    }
    Ok(())
}

/// Writes a certificate and private key to the specified paths in PEM format.
///
/// # Arguments
/// * `paths` - The file paths to write the certificate and private key to.
/// * `cert` - The certificate to write.
/// * `key` - The private key to write.
///
/// # Errors
/// Returns a `CertGenError::Io` if writing fails.
fn write_cert_and_key(
    paths: &CertKeyPaths,
    cert: &Certificate,
    key: &KeyPair,
) -> Result<(), CertGenError> {
    fs::write(&paths.cert, cert.pem()).map_err(|e| CertGenError::io(&paths.cert, e))?;
    fs::write(&paths.key, key.serialize_pem()).map_err(|e| CertGenError::io(&paths.key, e))?;
    Ok(())
}

/// Loads a CA certificate and private key from PEM files.
///
/// # Arguments
/// * `ca` - The file paths to the CA certificate and private key.
///
/// # Errors
/// Returns an error if the files cannot be read or parsed.
fn load_ca(ca: &CertKeyPaths) -> Result<Issuer<'_, KeyPair>, CertGenError> {
    let cert_pem = fs::read_to_string(&ca.cert).map_err(|e| CertGenError::io(&ca.cert, e))?;
    let key_pem = fs::read_to_string(&ca.key).map_err(|e| CertGenError::io(&ca.key, e))?;

    let key = KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(&ca.key, e))?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
        .map_err(|e| CertGenError::parse_cert(&ca.cert, e))?;

    Ok(issuer)
}

/// Initializes a new root Certificate Authority.
///
/// Creates a self-signed CA certificate with the following properties:
/// - P-256 ECDSA private key
/// - Key usage: certificate signing, CRL signing, digital signature
/// - Basic constraints: CA=true
///
/// # Arguments
/// * `output` - The file paths to write the CA certificate and private key to.
/// * `ca_name` - The Common Name for the CA.
/// * `validity_days` - The number of days the certificate is valid for.
///
/// # Errors
/// Returns an error if certificate generation or file writing fails.
fn init_ca(output: &CertKeyPaths, ca_name: &str, validity_days: u32) -> Result<(), CertGenError> {
    create_parent_dirs(output)?;

    println!("Generating root CA certificate...");
    let (cert, key) = generate_root_ca(ca_name, validity_days)?;

    write_cert_and_key(output, &cert, &key)?;

    println!("  Root CA certificate: {}", output.cert.display());
    println!("  Root CA private key: {}", output.key.display());

    Ok(())
}

/// Generates a signed certificate and writes it to disk.
///
/// Creates a certificate signed by the specified CA with the following properties:
/// - P-256 ECDSA private key
/// - Key usage: digital signature, key encipherment
/// - Extended key usage: server auth, client auth
/// - Subject Alternative Names as specified (or CN as default)
///
/// # Arguments
/// * `output` - The file paths to write the certificate and private key to.
/// * `ca` - The file paths to the CA certificate and private key for signing.
/// * `cn` - The Common Name for the certificate.
/// * `san` - The Subject Alternative Names (DNS and IP addresses).
/// * `validity_days` - The number of days the certificate is valid for.
///
/// # Errors
/// Returns an error if CA loading, certificate generation, or file writing fails.
fn generate_signed_cert_files(
    output: &CertKeyPaths,
    ca: &CertKeyPaths,
    cn: &str,
    san: &SubjectAltNames,
    validity_days: u32,
) -> Result<(), CertGenError> {
    create_parent_dirs(output)?;

    if san.dns_names.is_empty() && san.ip_addresses.is_empty() {
        eprintln!(
            "Warning: No SANs provided. Using CN '{}' as default DNS SAN.",
            cn
        );
    }

    let issuer = load_ca(ca)?;

    println!("Generating certificate '{}'...", cn);
    let (cert, key) = generate_signed_cert(cn, &issuer, validity_days, san)?;

    write_cert_and_key(output, &cert, &key)?;

    println!("  Certificate: {}", output.cert.display());
    println!("  Private key: {}", output.key.display());

    if !san.dns_names.is_empty() || !san.ip_addresses.is_empty() {
        println!("  SANs:");
        for dns in &san.dns_names {
            println!("    - DNS: {}", dns);
        }
        for ip in &san.ip_addresses {
            println!("    - IP:  {}", ip);
        }
    }

    Ok(())
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
fn generate_root_ca(cn: &str, validity_days: u32) -> Result<(Certificate, KeyPair), rcgen::Error> {
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
fn generate_signed_cert(
    cn: &str,
    issuer: &Issuer<'_, KeyPair>,
    validity_days: u32,
    san: &SubjectAltNames,
) -> Result<(Certificate, KeyPair), rcgen::Error> {
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
