#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::hash::Hash;

use anyhow::Context as _;
use aranya_crypto::custom_id;
use serde::{Deserialize, Serialize};

custom_id! {
    /// A QUIC sync PSK ID.
    pub struct QuicSyncPskId;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicSyncConfig {
    seed: GenSeedMode,
}

impl QuicSyncConfig {
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }

    pub fn seed(&self) -> &GenSeedMode {
        &self.seed
    }
}

#[derive(Default)]
pub struct QuicSyncConfigBuilder {
    seed: Option<GenSeedMode>,
}

impl QuicSyncConfigBuilder {
    /// Sets the seed type.
    pub fn seed(mut self, seed: GenSeedMode) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn build(self) -> anyhow::Result<QuicSyncConfig> {
        Ok(QuicSyncConfig {
            seed: self.seed.context("Missing `seed` field")?,
        })
    }
}

// TODO: Create analogous type in aranya-client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GenSeedMode {
    /// The default option. Used in the create_team API
    Generate,
    /// Used in the create_team and add_team APIs
    IKM(Box<[u8]>),
    /// Used in the add_team API
    Wrapped { recv_pk: Box<[u8]> },
}

impl Default for GenSeedMode {
    fn default() -> Self {
        Self::Generate
    }
}
