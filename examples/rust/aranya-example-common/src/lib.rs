//! Shared utilities for Aranya examples.

pub mod age_encryption;

pub use age::secrecy::{ExposeSecret, SecretString};
pub use age_encryption::AgeEncryptor;
