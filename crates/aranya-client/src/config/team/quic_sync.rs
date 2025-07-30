//! Configuration for team synchronization over QUIC connections.
//!
//! # Overview
//!
//! There are two main configuration types:
//! - [`CreateTeamQuicSyncConfig`] - For creating new teams
//! - [`AddTeamQuicSyncConfig`] - For adding members to existing teams

use core::fmt;

use aranya_crypto::zeroize::Zeroize as _;
use aranya_daemon_api::{self as api, Secret};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    config::{private::UseDefaultSpread, ConfigResult},
    error::InvalidArg,
};

/// Configuration for creating a new team with QUIC synchronization.
#[skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CreateTeamQuicSyncConfigV1 {
    pub seed_mode: Option<CreateSeedModeV1>,
    #[doc(hidden)]
    #[serde(skip)]
    pub __use_default_spread: UseDefaultSpread,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub enum CreateSeedModeV1 {
    #[default]
    Generate,
    Ikm(SeedIkm),
}

/// Configuration for adding members to an existing team with QUIC synchronization.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddTeamQuicSyncConfigV1 {
    pub seed_mode: Option<AddSeedModeV1>,
    #[doc(hidden)]
    #[serde(skip)]
    pub __use_default_spread: UseDefaultSpread,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AddSeedModeV1 {
    Ikm(SeedIkm),
    Wrapped(Secret),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SeedIkm([u8; 32]);

impl CreateTeamQuicSyncConfigV1 {
    pub(crate) fn into_api(self) -> ConfigResult<aranya_daemon_api::CreateTeamQuicSyncConfig> {
        Ok(aranya_daemon_api::CreateTeamQuicSyncConfig {
            seed_mode: self
                .seed_mode
                .map_or(api::CreateSeedMode::Generate, |m| m.into_api()),
        })
    }
}

impl From<SeedIkm> for CreateSeedModeV1 {
    fn from(value: SeedIkm) -> Self {
        Self::Ikm(value)
    }
}

impl CreateSeedModeV1 {
    fn into_api(self) -> api::CreateSeedMode {
        match self {
            Self::Generate => api::CreateSeedMode::Generate,
            Self::Ikm(seed_ikm) => api::CreateSeedMode::IKM(seed_ikm.into_api()),
        }
    }
}

impl AddTeamQuicSyncConfigV1 {
    pub(crate) fn into_api(self) -> ConfigResult<api::AddTeamQuicSyncConfig> {
        Ok(api::AddTeamQuicSyncConfig {
            seed_mode: self
                .seed_mode
                .ok_or(InvalidArg::new("seed_mode", "missing"))?
                .into_api()?,
        })
    }
}

impl From<SeedIkm> for AddSeedModeV1 {
    fn from(value: SeedIkm) -> Self {
        Self::Ikm(value)
    }
}

impl AddSeedModeV1 {
    fn into_api(self) -> ConfigResult<api::AddSeedMode> {
        Ok(match self {
            AddSeedModeV1::Ikm(seed_ikm) => api::AddSeedMode::IKM(seed_ikm.into_api()),
            AddSeedModeV1::Wrapped(secret) => api::AddSeedMode::Wrapped(
                postcard::from_bytes(secret.raw_secret_bytes())
                    .map_err(|_| InvalidArg::new("wrapped seed", "invalid"))?,
            ),
        })
    }
}

impl Drop for SeedIkm {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl fmt::Debug for SeedIkm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedIkm").finish_non_exhaustive()
    }
}

impl From<[u8; 32]> for SeedIkm {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl SeedIkm {
    fn into_api(self) -> aranya_daemon_api::Ikm {
        aranya_daemon_api::Ikm::from(self.0)
    }
}
