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
#[expect(deprecated)]
pub use quic_sync::{
    AddTeamQuicSyncConfig, AddTeamQuicSyncConfigBuilder, CreateTeamQuicSyncConfig,
    CreateTeamQuicSyncConfigBuilder,
};

/// Builder for [`CreateTeamConfig`].
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, config types are no longer needed.
#[deprecated(note = "Config types are no longer needed with mTLS authentication")]
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {}

#[expect(deprecated)]
impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn quic_sync(self, _cfg: CreateTeamQuicSyncConfig) -> Self {
        self
    }

    /// Builds the configuration for creating a new team.
    #[deprecated(note = "Config types are no longer needed with mTLS authentication")]
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {})
    }
}

/// Builder for [`AddTeamConfig`].
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, use the team ID directly
/// instead of this config type.
#[deprecated(note = "Use `Client::team` instead - config types are no longer needed with mTLS")]
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct AddTeamConfigBuilder {
    id: Option<TeamId>,
}

#[expect(deprecated)]
impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    #[deprecated(note = "Use `Client::team` instead - config types are no longer needed with mTLS")]
    pub fn team_id(mut self, id: TeamId) -> Self {
        self.id = Some(id);
        self
    }

    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn quic_sync(self, _cfg: AddTeamQuicSyncConfig) -> Self {
        self
    }

    /// Attempts to build an [`AddTeamConfig`] using the provided parameters.
    #[deprecated(note = "Use `Client::team` instead - config types are no longer needed with mTLS")]
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
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, config types are no longer needed.
#[deprecated(note = "Config types are no longer needed with mTLS authentication")]
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct CreateTeamConfig {}

#[expect(deprecated)]
impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    #[deprecated(note = "Config types are no longer needed with mTLS authentication")]
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

/// Configuration for joining an existing team.
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, use the team ID directly
/// instead of this config type.
#[deprecated(note = "Use `Client::team` instead - config types are no longer needed with mTLS")]
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    pub(crate) id: TeamId,
}

#[expect(deprecated)]
impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    #[deprecated(note = "Use `Client::team` instead - config types are no longer needed with mTLS")]
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}
