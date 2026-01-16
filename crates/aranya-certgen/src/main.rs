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
//! aranya-certgen signed --cn server
//! ```

use std::path::PathBuf;

use aranya_certgen::{CaCert, CertGenError, SaveOptions};
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
    #[arg(short, long)]
    force: bool,
}

impl OutputArgs {
    fn save_options(&self) -> Option<SaveOptions> {
        if !self.create_parents && !self.force {
            return None;
        }
        let mut opts = SaveOptions::default();
        if self.create_parents {
            opts = opts.create_parents();
        }
        if self.force {
            opts = opts.force();
        }
        Some(opts)
    }
}

/// Available subcommands for certificate generation.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new root Certificate Authority (CA) with a P-256 ECDSA private key.
    ///
    /// Generates a self-signed CA certificate and P-256 ECDSA private key that
    /// can be used to sign other certificates. Files are saved as
    /// `{output}.crt.pem` and `{output}.key.pem`.
    Ca {
        /// Output file arguments.
        #[command(flatten)]
        args: OutputArgs,

        /// Output path prefix (creates {output}.crt.pem and {output}.key.pem).
        #[arg(long, short, default_value = "ca")]
        output: PathBuf,
    },

    /// Create a new certificate signed by an existing root CA with a P-256 ECDSA private key.
    ///
    /// Generates a certificate and P-256 ECDSA private key, signed by the specified CA.
    /// Files are saved as `{output}.crt.pem` and `{output}.key.pem`.
    Signed {
        /// Output file arguments.
        #[command(flatten)]
        args: OutputArgs,

        /// Output path prefix (creates {output}.crt.pem and {output}.key.pem).
        #[arg(long, short, default_value = "cert")]
        output: PathBuf,

        /// Path prefix for the CA files (loads {ca}.crt.pem and {ca}.key.pem).
        #[arg(long, default_value = "ca")]
        ca: PathBuf,
    },
}

fn main() -> Result<(), CertGenError> {
    let cli = CliArgs::parse();

    match cli.command {
        Commands::Ca { args, output } => {
            println!("Generating root CA certificate...");
            let ca = CaCert::new(&args.cn, args.days)?;

            let output_str = output.to_str().expect("invalid path");
            ca.save(output_str, args.save_options())?;

            let cert_path = output.with_extension("crt.pem");
            println!("  Certificate: {}", cert_path.display());
        }
        Commands::Signed { args, output, ca } => {
            let ca_path = ca.to_str().expect("invalid CA path");
            let ca = CaCert::load(ca_path)?;

            println!("Generating certificate '{}'...", args.cn);
            let signed = ca.generate(&args.cn, args.days)?;

            let output_str = output.to_str().expect("invalid path");
            signed.save(output_str, args.save_options())?;

            let cert_path = output.with_extension("crt.pem");
            println!("  Certificate: {}", cert_path.display());
        }
    }

    Ok(())
}
