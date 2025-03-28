# Aranya Keygen

A utility crate for generating cryptographic key bundles for Aranya. This crate provides:

- Generation of secure cryptographic key bundles
- Management of identity, encryption, and signing keys
- Utilities for loading key bundles from storage

## Overview

The `aranya-keygen` crate simplifies the process of generating and managing cryptographic keys for Aranya applications. It provides a unified interface to create key bundles containing:

- Identity keys (for device identification)
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

## License

This crate is licensed under the same terms as the Aranya project. 