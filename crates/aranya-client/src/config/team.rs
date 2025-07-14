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

use aranya_daemon_api::TeamId;
use serde::{Deserialize, Serialize};

use crate::{error::InvalidArg, ConfigError, Result};

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

/// Configuration for joining an existing team.
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    team_id: TeamId,
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
        let quic_sync: Option<AddTeamQuicSyncConfig> = value.quic_sync;
        Self {
            team_id: value.team_id,
            quic_sync: quic_sync.map(Into::into),
        }
    }
}

/// Team data for initializing an [`AddTeamConfigBuilder`].
#[obake::versioned]
#[obake(version("0.1.0"))]
#[obake(derive(Clone, Debug, Serialize, Deserialize,))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamInfo {
    team_id: Option<TeamId>,
    #[obake(inherit)]
    quic_sync: quic_sync::versioned::MaybeAddTeamQuicSyncConfig,
}

/// Builder for joining an existing team configuration.
#[derive(Clone, Debug, Default)]
pub struct AddTeamConfigBuilder {
    team_id: Option<TeamId>,
    quic_sync: Option<AddTeamQuicSyncConfig>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn team_id(mut self, id: TeamId) -> Self {
        self.team_id = Some(id);
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
        let Some(id) = self.team_id else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
            .into());
        };

        Ok(AddTeamConfig {
            team_id: id,
            quic_sync: self.quic_sync,
        })
    }

    /// Build the latest [`VersionedTeamInfo`] using the provided parameters.
    pub fn to_team_info(self) -> obake::AnyVersion<TeamInfo> {
        let team_info = TeamInfo {
            team_id: self.team_id,
            quic_sync: self.quic_sync.into(),
        };
        VersionedTeamInfo::from(team_info)
    }

    /// Initializes a builder from any version of a [`TeamInfo`]
    pub fn from_team_info(team_info: obake::AnyVersion<TeamInfo>) -> Result<Self> {
        // Convert any version of `TeamInfo` into the latest version
        let TeamInfo { team_id, quic_sync } = team_info.into();

        let builder = {
            let mut builder = Self::default();

            if let Some(quic_sync) = quic_sync.into() {
                builder = builder.quic_sync(quic_sync);
            }

            if let Some(id) = team_id {
                builder = builder.team_id(id);
            }

            builder
        };

        Ok(builder)
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

#[cfg(test)]
mod test {
    use aranya_daemon_api::SEED_IKM_SIZE;

    use super::*;

    #[test]
    fn test_team_info_roundtrip() {
        let quic_sync_config = {
            let builder = AddTeamQuicSyncConfig::builder();
            builder
                .seed_ikm([0; SEED_IKM_SIZE])
                .build()
                .expect("can build")
        };

        let team_info = {
            let builder = AddTeamConfig::builder()
                .team_id(TeamId::default())
                .quic_sync(quic_sync_config);
            builder.to_team_info()
        };

        let json = serde_json::to_string(&team_info).expect("can serialize to json");
        let deserialized: VersionedTeamInfo = serde_json::from_str(&json).expect("can deserialize");

        let builder = AddTeamConfigBuilder::from_team_info(deserialized).expect("can initialize");
        // assert_eq!(team_info, builder.build_team_info().expect("can build"));
        assert!(builder.build().is_ok());
    }
}
