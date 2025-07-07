//! Team configuration for creating new teams or joining existing ones.
//!
//! This module provides builders for configuring team operations with support
//! for multiple transport mechanisms.
//!
//! # Overview
//!
//! There are two primary operations:
//! - **Create Team**: Establish a new team with [`CreateTeamConfig`]
//! - **Join Team**: Join an existing team with [`AddTeamConfig`]
//!
//! Both operations support optional transport configuration.

use aranya_daemon_api::TeamId;

use crate::{error::InvalidArg, ConfigError, Result};

pub mod quic_sync;
pub use quic_sync::{
    AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig, QuicSyncConfig, QuicSyncConfigBuilder,
};

/// Data required to join an existing team.
#[derive(Clone)]
struct AddMemberData {
    pub(super) id: TeamId,
}

/// Marker type for creating a new team.
#[derive(Clone, Default)]
pub struct CreateTeamData;

impl AddMemberData {
    pub(super) fn new(id: TeamId) -> Self {
        Self { id }
    }
}

/// Configuration for joining an existing team.
/// See [`TeamConfigBuilder`]
#[derive(Default)]
struct AddMemberDataBuild {
    pub(super) id: Option<TeamId>,
}

/// Generic builder for team configuration.
///
/// This builder supports both team creation and joining operations,
/// with optional transport configuration.
/// See [`TeamConfig`].
#[derive(Clone)]
struct TeamConfigBuilder<T, U> {
    data: T,
    quic_sync: Option<QuicSyncConfig<U>>,
}

impl<T: Default, U> Default for TeamConfigBuilder<T, U> {
    fn default() -> Self {
        Self {
            data: T::default(),
            quic_sync: None,
        }
    }
}

/// Builder for creating a new team configuration.
#[derive(Default)]
pub struct CreateTeamConfigBuilder(TeamConfigBuilder<CreateTeamData, quic_sync::CreateTeamData>);

/// Builder for joining an existing team configuration.
#[derive(Default)]
pub struct AddTeamConfigBuilder(TeamConfigBuilder<AddMemberDataBuild, quic_sync::AddMemberData>);

/// Generic team configuration.
#[derive(Clone)]
struct TeamConfig<T, U> {
    data: T,
    quic_sync: Option<QuicSyncConfig<U>>,
}

/// Configuration for creating a new team.
#[derive(Clone)]
pub struct CreateTeamConfig(TeamConfig<CreateTeamData, quic_sync::CreateTeamData>);

/// Configuration for joining an existing team.
#[derive(Clone)]
pub struct AddTeamConfig(TeamConfig<AddMemberData, quic_sync::AddMemberData>);

impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn team_id(mut self, id: TeamId) -> Self {
        self.0.data.id = Some(id);
        self
    }

    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic_sync(mut self, cfg: AddTeamQuicSyncConfig) -> Self {
        self.0.quic_sync = Some(cfg);
        self
    }

    /// Attempts to build an [`AddTeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<AddTeamConfig> {
        let id = self.0.data.id.ok_or_else(|| {
            ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
        })?;

        Ok(AddTeamConfig(TeamConfig {
            data: AddMemberData::new(id),
            quic_sync: self.0.quic_sync,
        }))
    }
}

impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic_sync(mut self, cfg: CreateTeamQuicSyncConfig) -> Self {
        self.0.quic_sync = Some(cfg);
        self
    }

    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig(TeamConfig {
            data: CreateTeamData,
            quic_sync: self.0.quic_sync,
        }))
    }
}

impl From<AddTeamConfig> for aranya_daemon_api::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        Self {
            id: value.0.data.id,
            quic_sync: value.0.quic_sync.map(Into::into),
        }
    }
}

impl From<CreateTeamConfig> for aranya_daemon_api::CreateTeamConfig {
    fn from(value: CreateTeamConfig) -> Self {
        Self {
            quic_sync: value.0.quic_sync.map(Into::into),
        }
    }
}
