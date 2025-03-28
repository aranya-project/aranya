//! # Aranya Keygen
//!
//! Utilities for generating and managing cryptographic key bundles for Aranya applications.
//!
//! This crate provides functionality to:
//! - Generate secure cryptographic key bundles containing identity, encryption, and signing keys
//! - Store generated keys in a keystore
//! - Retrieve public keys from a key bundle
//!
//! ## Key Components
//!
//! - [`KeyBundle`]: The main structure that contains references to identity, encryption, and signing keys
//! - [`PublicKeys`]: A structure that holds the public portions of the keys in a key bundle
//!
//! ## Example
//!
//! ```rust
//! # use anyhow::Result;
//! # use aranya_crypto::{Engine, KeyStore};
//! # use aranya_keygen::KeyBundle;
//! #
//! # fn example<E, S>(engine: &mut E, store: &mut S) -> Result<()>
//! # where
//! #     E: Engine,
//! #     S: KeyStore,
//! # {
//! // Generate a new key bundle
//! let key_bundle = KeyBundle::generate(engine, store)?;
//! 
//! // Load the public keys from the bundle
//! let public_keys = key_bundle.public_keys(engine, store)?;
//! 
//! // Use the public keys for operations like encryption or verification
//! # Ok(())
//! # }
//! ```

#![warn(clippy::wildcard_imports, missing_docs)]

mod keygen;

pub use keygen::*;
