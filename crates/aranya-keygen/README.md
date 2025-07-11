# Aranya Keygen

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![License][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/aranya-keygen.svg
[crates-url]: https://crates.io/crates/aranya-keygen
[docs-badge]: https://docs.rs/aranya-keygen/badge.svg
[docs-url]: https://docs.rs/aranya-keygen/latest/aranya_keygen/
[license-badge]: https://img.shields.io/crates/l/aranya-keygen.svg
[license-url]: https://github.com/aranya-project/aranya/blob/main/LICENSE.md

A utility crate for generating cryptographic key bundles for Aranya. This crate provides:

- Generation of secure cryptographic key bundles
- Management of identity, encryption, and signing keys
- Utilities for loading key bundles from storage

## Overview

The `aranya-keygen` crate simplifies the process of generating and managing cryptographic keys for Aranya applications. It provides a unified interface to create key bundles containing:

- Identity keys (for uniquely identifying devices)
- Encryption keys (for secure data encryption)
- Signing keys (for message authentication)

## Usage

```rust
use anyhow::Result;
use aranya_crypto::{Engine, KeyStore};
use aranya_keygen::KeyBundle;

fn generate_keys<E, S>(engine: &mut E, store: &mut S) -> Result<()>
where
    E: Engine,
    S: KeyStore,
{
    // Generate a new key bundle
    let key_bundle = KeyBundle::generate(engine, store)?;
    
    // Load the public keys from the bundle
    let public_keys = key_bundle.public_keys(engine, store)?;
    
    // Use the public keys as needed
    // ...
    
    Ok(())
}
```
