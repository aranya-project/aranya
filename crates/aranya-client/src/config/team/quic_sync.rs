//! Configuration for team synchronization over QUIC connections.
//!
//! # Overview
//!
//! There are two main configuration types:
//! - [`CreateTeamQuicSyncConfig`] - For creating new teams
//! - [`AddTeamQuicSyncConfig`] - For adding members to existing teams

use aranya_daemon_api::{AddSeedMode, CreateSeedMode, SEED_IKM_SIZE};
use tracing::error;

use crate::{error::InvalidArg, ConfigError, Result};

/// Configuration for creating a new team with QUIC synchronization.
#[derive(Clone, Debug)]
pub struct CreateTeamQuicSyncConfig {
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfig {
    /// Creates a new builder for team creation configuration.
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }
}

/// Configuration for adding members to an existing team with QUIC synchronization.
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {
    mode: AddSeedMode,
}

impl AddTeamQuicSyncConfig {
    /// Creates a new builder for team member addition configuration.
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for [`CreateTeamQuicSyncConfig`]
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: CreateSeedMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn gen_seed(mut self) -> Self {
        self.mode = CreateSeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = CreateSeedMode::IKM(ikm.into());
        self
    }

    /// Builds the config.
    pub fn build(self) -> Result<CreateTeamQuicSyncConfig> {
        Ok(CreateTeamQuicSyncConfig { mode: self.mode })
    }
}

/// Builder for [`AddTeamQuicSyncConfig`]
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<AddSeedMode>,
}

impl AddTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: AddSeedMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = Some(AddSeedMode::IKM(ikm.into()));
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn wrapped_seed(mut self, wrapped_seed: &[u8]) -> Result<Self> {
        let wrapped = postcard::from_bytes(wrapped_seed).map_err(|err| {
            error!(?err);
            ConfigError::InvalidArg(InvalidArg::new("wrapped_seed", "could not deserialize"))
        })?;
        self.mode = Some(AddSeedMode::Wrapped(wrapped));
        Ok(self)
    }

    /// Builds the config.
    pub fn build(self) -> Result<AddTeamQuicSyncConfig> {
        let Some(mode) = self.mode else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "mode",
                "`mode` must be set in order to build an `AddQuicSyncConfig`",
            ))
            .into());
        };

        Ok(AddTeamQuicSyncConfig { mode })
    }
}

impl From<CreateTeamQuicSyncConfig> for aranya_daemon_api::CreateTeamQuicSyncConfig {
    fn from(value: CreateTeamQuicSyncConfig) -> Self {
        aranya_daemon_api::CreateTeamQuicSyncConfig {
            seed_mode: value.mode,
        }
    }
}

impl From<AddTeamQuicSyncConfig> for aranya_daemon_api::AddTeamQuicSyncConfig {
    fn from(value: AddTeamQuicSyncConfig) -> Self {
        aranya_daemon_api::AddTeamQuicSyncConfig {
            seed_mode: value.mode,
        }
    }
}

pub(crate) mod versioned {
    use serde::{Deserialize, Serialize};

    use super::AddSeedMode;

    #[obake::versioned]
    #[obake(version("0.1.0"))]
    #[obake(derive(Clone, Debug, Serialize, Deserialize))]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AddTeamQuicSyncConfig {
        mode: AddSeedMode,
    }

    #[obake::versioned]
    #[obake(version("0.1.0"))]
    #[obake(derive(Clone, Debug, Serialize, Deserialize))]
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub(crate) enum MaybeAddTeamQuicSyncConfig {
        Some {
            #[obake(inherit)]
            inner: AddTeamQuicSyncConfig,
        },
        #[default]
        None,
    }

    impl From<super::AddTeamQuicSyncConfig> for AddTeamQuicSyncConfig {
        fn from(value: super::AddTeamQuicSyncConfig) -> Self {
            Self { mode: value.mode }
        }
    }

    impl From<AddTeamQuicSyncConfig> for super::AddTeamQuicSyncConfig {
        fn from(value: AddTeamQuicSyncConfig) -> Self {
            Self { mode: value.mode }
        }
    }

    impl From<Option<super::AddTeamQuicSyncConfig>> for MaybeAddTeamQuicSyncConfig {
        fn from(value: Option<super::AddTeamQuicSyncConfig>) -> Self {
            match value {
                Some(cfg) => Self::Some { inner: cfg.into() },
                None => Self::None,
            }
        }
    }

    impl From<MaybeAddTeamQuicSyncConfig> for Option<super::AddTeamQuicSyncConfig> {
        fn from(value: MaybeAddTeamQuicSyncConfig) -> Self {
            match value {
                MaybeAddTeamQuicSyncConfig::Some { inner } => Self::Some(inner.into()),
                MaybeAddTeamQuicSyncConfig::None => Self::None,
            }
        }
    }
}
