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

// Values added here should be set
// in AddTeamQuicSyncConfigBuilder::set_from_cfg
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
#[derive(Clone, Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<AddSeedMode>,
}

impl AddTeamQuicSyncConfigBuilder {
    /// gets the PSK seed mode.
    #[doc(hidden)]
    pub fn get_mode(&self) -> Option<&AddSeedMode> {
        self.mode.as_ref()
    }

    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(&mut self, mode: AddSeedMode) -> &mut Self {
        self.mode = Some(mode);
        self
    }

    /// set values from a [`AddTeamQuicSyncConfig`].
    #[doc(hidden)]
    pub fn set_from_cfg(&mut self, cfg: AddTeamQuicSyncConfig) -> &mut Self {
        self.mode = Some(cfg.mode);
        self
    }

    /// set values from a [`versioned::QuicSyncTeamInfo`].
    pub(crate) fn set_from_team_info(&mut self, info: versioned::QuicSyncTeamInfo) -> &mut Self {
        self.mode = info.mode;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    pub fn seed_ikm(&mut self, ikm: [u8; SEED_IKM_SIZE]) -> &mut Self {
        self.mode = Some(AddSeedMode::IKM(ikm.into()));
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn wrapped_seed(&mut self, wrapped_seed: &[u8]) -> Result<&mut Self> {
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
    #![allow(unused_macros)]
    //! Versioned types for use in [`super::super::TeamInfo`]

    use serde::{Deserialize, Serialize};

    use super::AddSeedMode;

    // Values added here should be set
    // in super::AddTeamQuicSyncConfigBuilder::set_from_team_info
    #[obake::versioned]
    #[obake(version("0.1.0"))]
    #[obake(derive(Clone, Debug, Serialize, Deserialize))]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct QuicSyncTeamInfo {
        #[obake(cfg("0.1.0"))]
        pub(crate) mode: Option<AddSeedMode>,
    }

    impl QuicSyncTeamInfo {
        pub(crate) fn from_builder(builder: super::AddTeamQuicSyncConfigBuilder) -> Self {
            Self { mode: builder.mode }
        }
    }

    #[obake::versioned]
    #[obake(version("0.1.0"))]
    #[obake(derive(Clone, Debug, Serialize, Deserialize))]
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub(crate) enum MaybeQuicSyncTeamInfo {
        Some {
            #[obake(inherit)]
            inner: QuicSyncTeamInfo,
        },
        #[default]
        None,
    }

    impl From<super::AddTeamQuicSyncConfig> for QuicSyncTeamInfo {
        fn from(value: super::AddTeamQuicSyncConfig) -> Self {
            Self {
                mode: Some(value.mode),
            }
        }
    }

    impl From<Option<QuicSyncTeamInfo>> for MaybeQuicSyncTeamInfo {
        fn from(value: Option<QuicSyncTeamInfo>) -> Self {
            match value {
                Some(cfg) => Self::Some { inner: cfg },
                None => Self::None,
            }
        }
    }
}
