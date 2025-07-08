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
use serde::{Deserialize, Serialize};

use crate::{error::InvalidArg, ConfigError, Result};

pub mod quic_sync;
pub use quic_sync::{
    AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig, CreateTeamQuicSyncConfigBuilder,
};

/// Configuration for creating a new team.
#[derive(Clone)]
pub struct CreateTeamConfig {
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

/// Configuration for joining an existing team.
#[obake::versioned]
#[obake(version("0.1.0"))]
#[obake(derive(Clone, Debug, Serialize, Deserialize))]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AddTeamConfigInternal {
    id: TeamId,
    #[obake(inherit)]
    quic_sync: quic_sync::MaybeAddTeamQuicSyncConfig,
}

impl From<AddTeamConfigInternal> for AddTeamConfig {
    fn from(value: AddTeamConfigInternal) -> Self {
        Self(value)
    }
}

impl From<AddTeamConfigInternal> for TeamInfo {
    fn from(value: AddTeamConfigInternal) -> Self {
        Self { inner: value }
    }
}

/// Configuration for joining an existing team.
#[derive(Clone)]
pub struct AddTeamConfig(AddTeamConfigInternal);

impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

/// Team data for initializing and [`AddTeamConfigBuilder`].
#[obake::versioned]
#[obake(version("0.1.0"))]
#[obake(derive(Clone, Debug, Serialize, Deserialize,))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamInfo {
    #[obake(inherit)]
    inner: AddTeamConfigInternal,
}

/// Builder for joining an existing team configuration.
#[derive(Clone, Default)]
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

    fn _build(self) -> Result<AddTeamConfigInternal> {
        let id = self.id.ok_or_else(|| {
            ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
        })?;

        Ok(AddTeamConfigInternal {
            id,
            quic_sync: self.quic_sync.into(),
        })
    }

    /// Attempts to build an [`AddTeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<AddTeamConfig> {
        self._build().map(Into::into)
    }

    /// Attempts to build the latest [`VersionedTeamInfo`] using the provided parameters.
    pub fn to_team_info(self) -> Result<obake::AnyVersion<TeamInfo>> {
        self._build()
            .map(TeamInfo::from)
            .map(VersionedTeamInfo::from)
    }

    /// Initializes a builder from any version of a [`TeamInfo`]
    pub fn from_team_info(team_info: obake::AnyVersion<TeamInfo>) -> Result<Self> {
        // Convert any version of `TeamInfo` into the latest version
        let TeamInfo { inner: latest } = team_info.into();

        let builder = {
            let mut builder = Self::default();

            if let Some(quic_sync) = latest.quic_sync.into() {
                builder = builder.quic_sync(quic_sync);
            }

            builder.team_id(latest.id)
        };

        Ok(builder)
    }
}

/// Builder for creating a new team configuration.
#[derive(Default)]
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

impl From<AddTeamConfig> for aranya_daemon_api::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        let quic_sync: Option<AddTeamQuicSyncConfig> = value.0.quic_sync.into();
        Self {
            id: value.0.id,
            quic_sync: quic_sync.map(Into::into),
        }
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
            builder.to_team_info().expect("can build")
        };

        let json = serde_json::to_string(&team_info).expect("can serialize to json");
        let deserialized: VersionedTeamInfo = serde_json::from_str(&json).expect("can deserialize");

        let builder = AddTeamConfigBuilder::from_team_info(deserialized).expect("can initialize");
        // assert_eq!(team_info, builder.build_team_info().expect("can build"));
        assert!(builder.build().is_ok());
    }
}
