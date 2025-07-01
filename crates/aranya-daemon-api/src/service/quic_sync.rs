#![allow(clippy::disallowed_macros)] // tarpc uses unreachable

use core::hash::Hash;
use std::{
    fmt,
    hash::{DefaultHasher, Hasher},
};

use aranya_crypto::{tls::EncryptedPskSeed, Encap, EncryptionPublicKey};
use serde::{Deserialize, Serialize};

use crate::{Secret, CS};

pub const SEED_IKM_SIZE: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
pub struct QuicSyncConfig {
    pub seed_mode: SeedMode,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
/// Specifies how PSK seeds are provided when creating or joining teams.
///
/// Teams share a single PSK seed that is used to derive Pre-Shared Keys (PSKs)
/// for QUIC connections between team members.
pub enum SeedMode {
    /// Generates a new random seed.
    ///
    /// Used by team owners in the `create_team` API when establishing a new team.
    Generate,

    /// Provides raw input key material to derive a seed.
    ///
    /// The IKM must be exactly 32 bytes. This mode is available in both:
    /// - `create_team`: Allows team owners to specify deterministic seed material
    /// - `add_team`: Allows non-owners to join using pre-shared key material
    IKM(Secret),

    /// Provides an encrypted seed for secure distribution.
    ///
    /// Used by non-owners in the `add_team` API to join an existing team.
    /// Seeds are wrapped (encrypted) to prevent plaintext exposure during
    /// the join process.
    Wrapped(WrappedSeed),
}

impl Default for SeedMode {
    fn default() -> Self {
        Self::Generate
    }
}

impl fmt::Debug for SeedMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedMode::Generate => f.debug_struct("SeedMode::Generate").finish(),
            SeedMode::IKM(ikm) => {
                let mut hasher = DefaultHasher::new();
                ikm.hash(&mut hasher);
                f.debug_struct("SeedMode::Ikm")
                    .field("ikm", &hasher.finish())
                    .finish_non_exhaustive()
            }
            SeedMode::Wrapped(_) => f.debug_struct("SeedMode::Wrapped").finish(),
        }
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
