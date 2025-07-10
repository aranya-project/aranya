use aranya_daemon_api as api;
pub use aranya_daemon_api::SEED_IKM_SIZE;
use serde::{Deserialize, Serialize};

/// Specifies how PSK seeds are provided when creating or joining teams.
///
/// Teams share a single PSK seed that is used to derive Pre-Shared Keys (PSKs)
/// for QUIC connections between team members.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SeedMode(pub(crate) api::SeedMode);

impl SeedMode {
    #[doc(hidden)]
    pub const fn generate() -> Self {
        Self(api::SeedMode::Generate)
    }

    #[doc(hidden)]
    pub fn from_ikm(ikm: [u8; SEED_IKM_SIZE]) -> Self {
        Self(api::SeedMode::IKM(ikm.into()))
    }

    #[doc(hidden)]
    pub fn from_wrapped(wrapped: WrappedSeed) -> Self {
        Self(api::SeedMode::Wrapped(wrapped.0))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WrappedSeed(pub(crate) api::WrappedSeed);
