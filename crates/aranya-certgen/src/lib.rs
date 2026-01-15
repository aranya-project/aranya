//! Library for generating root CA certificates and signed certificates.
//!
//! All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
//!
//! # Example
//!
//! ```no_run
//! use aranya_certgen::CaCert;
//!
//! // Create a new CA
//! let ca = CaCert::new("My Root CA", 365).unwrap();
//!
//! // Generate a signed certificate
//! let signed = ca.generate("my-server", 365).unwrap();
//!
//! // Save CA and signed certificates to files
//! // Creates ./ca.crt.pem and ./ca.key.pem
//! ca.save(".", "ca", None).unwrap();
//! // Creates ./server.crt.pem and ./server.key.pem
//! signed.save(".", "server", None).unwrap();
//! ```
//!
//! # Loading an Existing CA
//!
//! ```no_run
//! use aranya_certgen::CaCert;
//!
//! // Load an existing CA from PEM files
//! // Loads from ./ca.crt.pem and ./ca.key.pem
//! let ca = CaCert::load(".", "ca").unwrap();
//!
//! // Generate certificates signed by the loaded CA
//! let signed = ca.generate("server", 365).unwrap();
//! ```

mod cert;
mod error;

pub use cert::{CaCert, SaveOptions, SignedCert};
pub use error::CertGenError;
