//! CLI tool for generating root CA certificates and signed certificates.
//!
//! All generated keys currently use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Usage
//!
//! ```bash
//! # Create a root CA with P-256 ECDSA key (creates ./ca.crt.pem and ./ca.key.pem)
//! aranya-certgen ca --cn "My CA"
//!
//! # Create a signed certificate with P-256 ECDSA key (creates ./cert.crt.pem and ./cert.key.pem)
//! aranya-certgen signed ca --cn server
//! ```

use std::path::PathBuf;

use aranya_certgen::{CaCert, CertGenError, CertPaths, SaveOptions};
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
    fn get_save_options(&self) -> SaveOptions {
        let mut opts = SaveOptions::default();
        if self.create_parents {
            opts = opts.create_parents();
        }
        if self.force {
            opts = opts.force();
        }
        opts
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
    ///
    /// The CA path prefix is required to ensure the expected CA certificate is used for signing.
    Signed {
        /// Path prefix for the CA files (loads <CA>.crt.pem and <CA>.key.pem).
        ca: PathBuf,

        /// Output file arguments.
        #[command(flatten)]
        args: OutputArgs,

        /// Output path prefix (creates {output}.crt.pem and {output}.key.pem).
        #[arg(long, short, default_value = "cert")]
        output: PathBuf,
    },
}

fn main() -> Result<(), CertGenError> {
    let cli = CliArgs::parse();

    match cli.command {
        Commands::Ca { args, output } => {
            let paths = CertPaths::new(&output);

            println!("Generating root CA certificate...");
            let ca = CaCert::new(&args.cn, args.days)?;
            ca.save(&paths, args.get_save_options())?;

            println!("  Certificate: {}", paths.cert().display());
        }
        Commands::Signed { args, output, ca } => {
            let ca_paths = CertPaths::new(&ca);
            let paths = CertPaths::new(&output);

            let ca = CaCert::load(&ca_paths)?;

            println!("Generating certificate '{}'...", args.cn);
            let signed = ca.generate(&args.cn, args.days)?;
            signed.save(&paths, args.get_save_options())?;

            println!("  Certificate: {}", paths.cert().display());
        }
    }

    Ok(())
}
