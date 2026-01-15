//! CLI tool for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Usage
//!
//! ```bash
//! # Create a root CA with P-256 ECDSA key (creates ./ca.crt.pem and ./ca.key.pem)
//! aranya-certgen ca --cn "My CA"
//!
//! # Create a signed certificate with P-256 ECDSA key (creates ./cert.crt.pem and ./cert.key.pem)
//! aranya-certgen signed --cn server --dns example.com --ip 192.168.1.10
//! ```

use std::{net::IpAddr, path::PathBuf};

use aranya_certgen::{CertGen, CertGenError, SaveOptions, SubjectAltNames};
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

/// Common output arguments for certificate generation.
#[derive(Args, Debug)]
struct OutputArgs {
    /// Directory to save the certificate and key files.
    #[arg(long, default_value = ".")]
    dir: PathBuf,

    /// Common Name (CN) for the certificate.
    #[arg(long)]
    cn: String,

    /// Validity period in days from today.
    #[arg(long = "days", default_value_t = 365)]
    days: u32,

    /// Create parent directories if they don't exist.
    #[arg(short = 'p')]
    create_parents: bool,

    /// Overwrite existing files.
    #[arg(long)]
    force: bool,
}

/// Available subcommands for certificate generation.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new root Certificate Authority (CA) with a P-256 ECDSA private key.
    ///
    /// Generates a self-signed CA certificate and P-256 ECDSA private key that
    /// can be used to sign other certificates. Files are saved as
    /// `{dir}/{name}.crt.pem` and `{dir}/{name}.key.pem`.
    Ca {
        /// Output file arguments.
        #[command(flatten)]
        output: OutputArgs,

        /// Base name for the output files (creates {name}.crt.pem and {name}.key.pem).
        #[arg(long, default_value = "ca")]
        name: String,
    },

    /// Create a new certificate signed by an existing root CA with a P-256 ECDSA private key.
    ///
    /// Generates a certificate and P-256 ECDSA private key, signed by the specified CA.
    /// The certificate can include Subject Alternative Names for DNS hostnames
    /// and IP addresses. Files are saved as `{dir}/{name}.crt.pem` and `{dir}/{name}.key.pem`.
    Signed {
        /// Output file arguments.
        #[command(flatten)]
        output: OutputArgs,

        /// Base name for the output files (creates {name}.crt.pem and {name}.key.pem).
        #[arg(long, default_value = "cert")]
        name: String,

        /// Directory containing the CA certificate and key files.
        #[arg(long, default_value = ".")]
        ca_dir: PathBuf,

        /// Base name of the CA files (loads {ca-name}.crt.pem and {ca-name}.key.pem).
        #[arg(long, default_value = "ca")]
        ca_name: String,

        /// Subject Alternative Names (DNS and IP).
        #[command(flatten)]
        sans: CliSubjectAltNames,
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
        Commands::Ca { output, name } => {
            println!("Generating root CA certificate...");
            let cert_gen = CertGen::ca(&output.cn, output.days)?;

            let mut save_opts = SaveOptions::new();
            if output.create_parents {
                save_opts = save_opts.create_parents();
            }
            if output.force {
                save_opts = save_opts.force();
            }
            cert_gen.save(&output.dir, &name, save_opts)?;

            let cert_path = output.dir.join(format!("{name}.crt.pem"));
            println!("  Certificate: {}", cert_path.display());
        }
        Commands::Signed {
            output,
            name,
            ca_dir,
            ca_name,
            sans,
        } => {
            if sans.dns_names.is_empty() && sans.ip_addresses.is_empty() {
                eprintln!(
                    "Warning: No SANs provided. Using CN '{}' as default DNS SAN.",
                    output.cn
                );
            }

            let ca = CertGen::load(&ca_dir, &ca_name)?;

            println!("Generating certificate '{}'...", output.cn);
            let signed = ca.generate(&output.cn, output.days, &sans.clone().into())?;

            let mut save_opts = SaveOptions::new();
            if output.create_parents {
                save_opts = save_opts.create_parents();
            }
            if output.force {
                save_opts = save_opts.force();
            }
            signed.save(&output.dir, &name, save_opts)?;

            let cert_path = output.dir.join(format!("{name}.crt.pem"));
            println!("  Certificate: {}", cert_path.display());

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
