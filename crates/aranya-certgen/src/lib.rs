//! Library for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Future Work
//!
//! The following features may be added in the future:
//!
//! - **DER/BER format support**: Currently only PEM format is supported for saving/loading
//!   certificates. DER (Distinguished Encoding Rules) and BER (Basic Encoding Rules)
//!   binary format support could be added for environments where base64 encoding
//!   overhead is undesirable.
//!
//! - **Additional key types**: Support for other key algorithms such as:
//!   - P-384 ECDSA
//!   - Ed25519
//!   - HPKE (Hybrid Public Key Encryption) keys for use with MLS or other protocols
//!   - Post-quantum algorithms (e.g., ML-KEM, ML-DSA)
//!
//! - **Subject Alternative Names (SANs)**: Currently, only the Common Name (CN) is added
//!   as a DNS SAN. Explicit SAN support could be added via `--dns` and `--ip` flags to
//!   allow multiple DNS names and IP addresses in a single certificate.
//!
//! - **Certificate extensions**: Support for additional X.509 extensions such as
//!   custom OIDs and extension values.
//!
//! - **CSR support**: Certificate Signing Request (CSR) generation and signing.
//!
//! # Example
//!
//! ```no_run
//! use aranya_certgen::{CaCert, CertPaths, SaveOptions};
//!
//! // Create a new CA and save
//! let ca = CaCert::new("My Root CA", 365).unwrap();
//! ca.save(&CertPaths::new("ca"), SaveOptions::default()).unwrap();
//!
//! // Generate a signed certificate and save
//! let signed = ca.generate("my-server", 365).unwrap();
//! signed.save(&CertPaths::new("server"), SaveOptions::default()).unwrap();
//!
//! // Save to a specific path with options
//! ca.save(
//!     &CertPaths::new("./certs/myca"),
//!     SaveOptions::default().create_parents(),
//! )
//! .unwrap();
//! ```
//!
//! # Loading an Existing CA
//!
//! ```no_run
//! use aranya_certgen::{CaCert, CertPaths};
//!
//! let ca = CaCert::load(&CertPaths::new("ca")).unwrap();
//! let ca = CaCert::load(&CertPaths::new("./certs/myca")).unwrap();
//!
//! // Generate certificates signed by the loaded CA
//! let signed = ca.generate("server", 365).unwrap();
//! ```

mod cert;
mod error;

pub use cert::{CaCert, CertPaths, SaveOptions, SignedCert};
pub use error::CertGenError;
