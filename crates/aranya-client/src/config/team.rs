//! Team configuration for creating new teams or adding existing ones.
//!
//! This module provides builders for configuring team operations.
//!
//! # Overview
//!
//! There are two primary operations:
//! - **Create Team**: Establish a new team with [`CreateTeamConfig`]
//! - **Add Team**: Add an existing team with [`AddTeamConfig`]

use crate::{client::TeamId, error::InvalidArg, ConfigError, Result};

/// Builder for [`CreateTeamConfig`].
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {}

impl CreateTeamConfigBuilder {
    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {})
    }
}

/// Builder for [`AddTeamConfig`].
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    id: TeamId,
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
