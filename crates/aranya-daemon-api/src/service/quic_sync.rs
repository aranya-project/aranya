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
    pub seed_mode: SeedMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SeedMode {
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

impl Default for SeedMode {
    fn default() -> Self {
        Self::Generate
    }
}
