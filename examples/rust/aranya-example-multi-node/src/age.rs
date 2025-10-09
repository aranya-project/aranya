//! Utilities for encrypting/decrypting with `age` tool and a passphrase.

use std::{
    io::{Read, Write},
    iter,
};

use age::{scrypt::Identity, secrecy::SecretString, Decryptor, Encryptor};
use anyhow::Result;

/// Encrypt/decrypt data with `age` tool and a passphrase.
#[derive(Debug)]
pub struct AgeEncryptor {
    passphrase: SecretString,
}

impl AgeEncryptor {
    /// Create a new `age` encryptor with a passphrase.
    pub fn new(passphrase: SecretString) -> Self {
        Self { passphrase }
    }

    /// Encrypt data with a passhrase.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        /// Constants copied from age-0.11.1/src/primitives/stream.rs
        const CHUNK_SIZE: usize = 64 * 1024;
        const TAG_SIZE: usize = 16;
        const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

        let encryptor = Encryptor::with_user_passphrase(self.passphrase.clone());

        let mut ciphertext =
            Vec::with_capacity(plaintext.len() * ENCRYPTED_CHUNK_SIZE / CHUNK_SIZE);
        let mut writer = encryptor.wrap_output(&mut ciphertext)?;
        writer.write_all(plaintext)?;
        writer.finish()?;

        Ok(ciphertext)
    }

    /// Decrypt data with a passphrase.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let decryptor = Decryptor::new(ciphertext)?;

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut reader =
            decryptor.decrypt(iter::once(&Identity::new(self.passphrase.clone()) as _))?;
        reader.read_to_end(&mut plaintext)?;

        Ok(plaintext)
    }
}
