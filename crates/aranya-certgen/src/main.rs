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

use std::{net::IpAddr, path::PathBuf};

use aranya_certgen::{CertGen, CertGenError, SubjectAltNames};
use clap::{Args, Parser, Subcommand};

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
        #[arg(long = "days", default_value_t = 365)]
        days: u32,
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
        sans: CliSubjectAltNames,

        /// Common Name (CN) for the certificate.
        #[arg(long)]
        cn: String,

        /// Validity period in days from today.
        #[arg(long = "days", default_value_t = 365)]
        days: u32,
    },
}

/// CLI-specific Subject Alternative Names with clap derives.
#[derive(Args, Debug, Clone)]
struct CliSubjectAltNames {
    /// DNS names for Subject Alternative Names (can be specified multiple times).
    #[arg(long = "dns", value_name = "HOSTNAME")]
    dns_names: Vec<String>,

    /// IP addresses for Subject Alternative Names (can be specified multiple times).
    #[arg(long = "ip", value_name = "ADDRESS")]
    ip_addresses: Vec<IpAddr>,
}

impl From<CliSubjectAltNames> for SubjectAltNames {
    fn from(cli: CliSubjectAltNames) -> Self {
        SubjectAltNames {
            dns_names: cli.dns_names,
            ip_addresses: cli.ip_addresses,
        }
    }
}

fn main() -> Result<(), CertGenError> {
    let args = CliArgs::parse();

    match args.command {
        Commands::Ca {
            cert,
            key,
            ca_name,
            days,
        } => {
            println!("Generating root CA certificate...");
            let cert_gen = CertGen::ca(&ca_name, days)?;
            cert_gen.save(&cert, &key)?;

            println!("  Root CA certificate: {}", cert.display());
            println!("  Root CA private key: {}", key.display());
        }
        Commands::Signed {
            cert,
            key,
            ca_cert,
            ca_key,
            sans,
            cn,
            days,
        } => {
            if sans.dns_names.is_empty() && sans.ip_addresses.is_empty() {
                eprintln!(
                    "Warning: No SANs provided. Using CN '{}' as default DNS SAN.",
                    cn
                );
            }

            let cert_gen = CertGen::load(&ca_cert, &ca_key)?;

            println!("Generating certificate '{}'...", cn);
            let device = CertGen::generate(&cert_gen, &cn, days, &sans.clone().into())?;
            device.save(&cert, &key)?;

            println!("  Certificate: {}", cert.display());
            println!("  Private key: {}", key.display());

            if !sans.dns_names.is_empty() || !sans.ip_addresses.is_empty() {
                println!("  SANs:");
                for dns in &sans.dns_names {
                    println!("    - DNS: {}", dns);
                }
                for ip in &sans.ip_addresses {
                    println!("    - IP:  {}", ip);
                }
            }
        }
    }

    Ok(())
}
