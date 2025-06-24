#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use aranya_crypto::{tls::EncryptedPskSeed, Encap, EncryptionPublicKey};
use serde::{Deserialize, Serialize};

use crate::CS;

#[derive(Debug, Serialize, Deserialize)]
pub struct QuicSyncConfig {
    pub seed_mode: SeedMode,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SeedMode {
    /// The default option. Used in the create_team API
    Generate,
    /// Used in the create_team and add_team APIs
    IKM([u8; 32]),
    /// Used in the add_team API
    Wrapped(WrappedSeed),
}

impl Default for SeedMode {
    fn default() -> Self {
        Self::Generate
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedSeed {
    pub sender_pk: EncryptionPublicKey<CS>,
    pub encap_key: Encap<CS>,
    pub encrypted_seed: EncryptedPskSeed<CS>,
}

impl Clone for WrappedSeed {
    fn clone(&self) -> Self {
        Self {
            sender_pk: self.sender_pk.clone(),
            encap_key: Encap::from_bytes(self.encap_key.as_bytes()).expect("can round trip"),
            encrypted_seed: self.encrypted_seed.clone(),
        }
    }
}
