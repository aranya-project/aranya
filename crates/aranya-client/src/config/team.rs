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
pub use quic_sync::{
    AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig, CreateTeamQuicSyncConfigBuilder,
};

/// Builder for [`CreateTeamConfig`].
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic_sync(mut self, cfg: CreateTeamQuicSyncConfig) -> Self {
        self.quic_sync = Some(cfg);
        self
    }

    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {
            quic_sync: self.quic_sync,
        })
    }
}

/// Builder for [`AddTeamConfig`].
#[derive(Debug, Default)]
pub struct AddTeamConfigBuilder {
    id: Option<TeamId>,
    quic_sync: Option<AddTeamQuicSyncConfig>,
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
    pub fn quic_sync(mut self, cfg: AddTeamQuicSyncConfig) -> Self {
        self.quic_sync = Some(cfg);
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

        Ok(AddTeamConfig {
            id,
            quic_sync: self.quic_sync,
        })
    }
}

/// Configuration for creating a new team.
#[derive(Clone, Debug)]
pub struct CreateTeamConfig {
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

impl From<CreateTeamConfig> for aranya_daemon_api::CreateTeamConfig {
    fn from(value: CreateTeamConfig) -> Self {
        Self {
            quic_sync: value.quic_sync.map(Into::into),
        }
    }
}

/// Configuration for joining an existing team.
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    id: TeamId,
    quic_sync: Option<AddTeamQuicSyncConfig>,
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
            quic_sync: value.quic_sync.map(Into::into),
        }
    }
}
