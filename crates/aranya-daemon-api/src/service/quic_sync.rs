#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::hash::Hash;

use aranya_crypto::custom_id;
use serde::{Deserialize, Serialize};

custom_id! {
    /// A QUIC sync PSK ID.
    pub struct QuicSyncPskId;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicSyncConfig {
    seed_mode: GenSeedMode,
}

impl QuicSyncConfig {
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }

    pub fn seed_mode(&self) -> &GenSeedMode {
        &self.seed_mode
    }
}

#[derive(Default)]
pub struct QuicSyncConfigBuilder {
    seed_mode: GenSeedMode,
}

impl QuicSyncConfigBuilder {
    /// Sets the seed type.
    pub fn seed(mut self, seed_mode: GenSeedMode) -> Self {
        self.seed_mode = seed_mode;
        self
    }

    pub fn build(self) -> anyhow::Result<QuicSyncConfig> {
        Ok(QuicSyncConfig {
            seed_mode: self.seed_mode,
        })
    }
}

// Rename this? GenSeedMode is confusing because a seed is being passed in with the `Wrapped` variant
// TODO: Create analogous type in aranya-client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GenSeedMode {
    /// The default option. Used in the create_team API
    Generate,
    /// Used in the create_team and add_team APIs
    IKM([u8; 32]),
    /// Used in the add_team API
    Wrapped {
        sender_pk: Box<[u8]>,
        encap_key: Box<[u8]>,
        encrypted_seed: Box<[u8]>,
    },
}

impl Default for GenSeedMode {
    fn default() -> Self {
        Self::Generate
    }
}
