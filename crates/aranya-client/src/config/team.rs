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

use crate::{client::TeamId, error::InvalidArg, ConfigError, Result};

pub mod quic_sync;
pub use quic_sync::{
    AddSeedMode, AddTeamQuicSyncConfig, AddTeamQuicSyncConfigBuilder, CreateSeedMode,
    CreateTeamQuicSyncConfig, CreateTeamQuicSyncConfigBuilder, SEED_IKM_SIZE,
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
#[derive(Clone, Debug, Default)]
pub struct CreateTeamConfig {
    #[allow(dead_code)]
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

/// Configuration for joining an existing team.
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    pub(crate) id: TeamId,
    #[allow(dead_code)]
    quic_sync: Option<AddTeamQuicSyncConfig>,
}

impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}
