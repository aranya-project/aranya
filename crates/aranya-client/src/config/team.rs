//! Team configuration for creating new teams or adding existing ones.
//!
//! This module provides builders for configuring team operations with support
//! for multiple transport mechanisms.
//!
//! # Overview
//!
//! There are two primary operations:
//! - **Create Team**: Establish a new team with [`CreateTeamConfig`]
//! - **Add Team**: Add an existing team with [`AddTeamConfig`]
//!
//! Both operations support optional transport configuration.

use crate::{client::TeamId, error::InvalidArg, util::ApiConv as _, ConfigError, Result};

pub mod quic_sync;
#[expect(deprecated)]
pub use quic_sync::{
    AddTeamQuicSyncConfig, AddTeamQuicSyncConfigBuilder, CreateTeamQuicSyncConfig,
    CreateTeamQuicSyncConfigBuilder,
};

/// Builder for [`CreateTeamConfig`].
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {}

impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    #[expect(deprecated)]
    pub fn quic_sync(self, _cfg: CreateTeamQuicSyncConfig) -> Self {
        self
    }

    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {})
    }
}

/// Builder for [`AddTeamConfig`].
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct AddTeamConfigBuilder {
    id: Option<TeamId>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn team_id(mut self, id: TeamId) -> Self {
        self.id = Some(id);
        self
    }

    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    #[expect(deprecated)]
    pub fn quic_sync(self, _cfg: AddTeamQuicSyncConfig) -> Self {
        self
    }

    /// Attempts to build an [`AddTeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<AddTeamConfig> {
        let id = self.id.ok_or_else(|| {
            ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
        })?;

        Ok(AddTeamConfig { id })
    }
}

/// Configuration for creating a new team.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct CreateTeamConfig {}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

impl From<CreateTeamConfig> for aranya_daemon_api::CreateTeamConfig {
    fn from(_value: CreateTeamConfig) -> Self {
        Self {}
    }
}

/// Configuration for joining an existing team.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    pub(crate) id: TeamId,
}

impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

impl From<AddTeamConfig> for aranya_daemon_api::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        Self {
            team_id: value.id.into_api(),
        }
    }
}
