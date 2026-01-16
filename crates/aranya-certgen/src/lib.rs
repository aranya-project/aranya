//! Library for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Future Work
//!
//! The following features may be added in the future:
//!
//! - **DER format support**: Currently only PEM format is supported for saving/loading
//!   certificates. DER (binary) format support could be added for environments where
//!   base64 encoding overhead is undesirable.
//!
//! - **Additional key types**: Support for other key algorithms such as:
//!   - P-384 ECDSA
//!   - Ed25519
//!   - HPKE (Hybrid Public Key Encryption) keys for use with MLS or other protocols
//!   - Post-quantum algorithms (e.g., ML-KEM, ML-DSA)
//!
//! - **Certificate extensions**: Support for additional X.509 extensions such as:
//!   - Subject Alternative Names (SANs) for IP addresses and additional DNS names
//!   - Custom extensions
//!
//! - **CSR support**: Certificate Signing Request (CSR) generation and signing.
//!
//! # Example
//!
//! ```no_run
//! use aranya_certgen::{CaCert, SaveOptions};
//!
//! // Create a new CA and save
//! let ca = CaCert::new("My Root CA", 365).unwrap();
//! ca.save("ca", None).unwrap(); // Creates ./ca.crt.pem and ./ca.key.pem
//!
//! // Generate a signed certificate and save
//! let signed = ca.generate("my-server", 365).unwrap();
//! signed.save("server", None).unwrap(); // Creates ./server.crt.pem
//!
//! // Save to a specific path with options
//! ca.save(
//!     "./certs/myca",
//!     Some(SaveOptions::default().create_parents()),
//! )
//! .unwrap();
//! ```
//!
//! # Loading an Existing CA
//!
//! ```no_run
//! use aranya_certgen::CaCert;
//!
//! let ca = CaCert::load("ca").unwrap();
//! let ca = CaCert::load("./certs/myca").unwrap();
//!
//! // Generate certificates signed by the loaded CA
//! let signed = ca.generate("server", 365).unwrap();
//! ```

mod cert;
mod error;

pub use cert::{CaCert, SaveOptions, SignedCert};
pub use error::CertGenError;
