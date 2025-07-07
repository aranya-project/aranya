//! Configuration for team synchronization over QUIC connections.
//!
//! # Overview
//!
//! There are two main configuration types:
//! - [`CreateQuicSyncConfig`] - For creating new teams
//! - [`AddQuicSyncConfig`] - For adding members to existing teams

use aranya_daemon_api::{AddSeedMode, CreateSeedMode, SEED_IKM_SIZE};
use tracing::error;

use crate::{error::InvalidArg, ConfigError, Result};

/// Configuration data for adding members to an existing team.
/// See [`QuicSyncConfig`].
#[derive(Clone)]
pub struct AddMemberData {
    pub(super) mode: AddSeedMode,
}

/// Configuration data for creating a new team.
/// See [`QuicSyncConfig`].
#[derive(Clone)]
pub struct CreateTeamData {
    pub(super) mode: CreateSeedMode,
}

impl CreateTeamData {
    pub(super) fn new(mode: CreateSeedMode) -> Self {
        Self { mode }
    }
}

impl AddMemberData {
    pub(super) fn new(mode: AddSeedMode) -> Self {
        Self { mode }
    }
}

/// Configuration data for adding members to an existing team.
/// See [`QuicSyncConfigBuilder`].
#[derive(Clone, Default)]
pub struct AddBuild {
    pub(super) mode: Option<AddSeedMode>,
}

/// Configuration data for creating a new team.
/// See [`QuicSyncConfigBuilder`].
#[derive(Clone, Default)]
pub struct CreateBuild {
    pub(super) mode: CreateSeedMode,
}

/// Configuration for QUIC-based team synchronization.
///
/// This wraps either [`CreateTeamData`] or [`AddMemberData`] configuration data.
#[derive(Clone)]
pub struct QuicSyncConfig<T> {
    pub(super) data: T,
}

/// Configuration for creating a new team with QUIC synchronization.
pub type CreateQuicSyncConfig = QuicSyncConfig<CreateTeamData>;

/// Configuration for adding members to an existing team with QUIC synchronization.
pub type AddQuicSyncConfig = QuicSyncConfig<AddMemberData>;

impl CreateQuicSyncConfig {
    /// Creates a new builder for team creation configuration.
    pub fn builder() -> CreateQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

impl AddQuicSyncConfig {
    /// Creates a new builder for team member addition configuration.
    pub fn builder() -> AddQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

/// Configuration for syncing over QUIC.
///
/// This wraps either [`CreateBuild`] or [`AddBuild`] configuration data.
#[derive(Clone, Default)]
pub struct QuicSyncConfigBuilder<T> {
    data: T,
}

type CreateQuicSyncConfigBuilder = QuicSyncConfigBuilder<CreateBuild>;
type AddQuicSyncConfigBuilder = QuicSyncConfigBuilder<AddBuild>;

impl CreateQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: CreateSeedMode) -> Self {
        self.data.mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn gen_seed(mut self) -> Self {
        self.data.mode = CreateSeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.data.mode = CreateSeedMode::IKM(ikm.into());
        self
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig<CreateTeamData>> {
        Ok(QuicSyncConfig {
            data: CreateTeamData::new(self.data.mode),
        })
    }
}

impl AddQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: AddSeedMode) -> Self {
        self.data.mode = Some(mode);
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.data.mode = Some(AddSeedMode::IKM(ikm.into()));
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
        self.data.mode = Some(AddSeedMode::Wrapped(wrapped));
        Ok(self)
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig<AddMemberData>> {
        let Some(mode) = self.data.mode else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "mode",
                "`mode` must be set in order to build an `AddQuicSyncConfig`",
            ))
            .into());
        };

        Ok(QuicSyncConfig {
            data: AddMemberData::new(mode),
        })
    }
}

impl From<CreateQuicSyncConfig> for aranya_daemon_api::CreateQuicSyncConfig {
    fn from(value: CreateQuicSyncConfig) -> Self {
        aranya_daemon_api::CreateQuicSyncConfig {
            seed_mode: value.data.mode,
        }
    }
}

impl From<AddQuicSyncConfig> for aranya_daemon_api::AddQuicSyncConfig {
    fn from(value: AddQuicSyncConfig) -> Self {
        aranya_daemon_api::AddQuicSyncConfig {
            seed_mode: value.data.mode,
        }
    }
}
