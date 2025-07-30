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

use aranya_daemon_api as api;
use aranya_daemon_api::TeamId;

pub mod quic_sync;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    config::{
        private::{ConfigFor, UseDefaultSpread},
        ConfigResult,
    },
    error::InvalidArg,
};

#[skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CreateTeamConfigV1 {
    pub quic_sync: Option<quic_sync::CreateTeamQuicSyncConfigV1>,
    #[doc(hidden)]
    #[serde(skip)]
    pub __use_default_spread: UseDefaultSpread,
}

impl ConfigFor<api::CreateTeamConfig> for CreateTeamConfigV1 {
    fn resolve(self) -> ConfigResult<api::CreateTeamConfig> {
        Ok(api::CreateTeamConfig {
            quic_sync: self.quic_sync.map(|x| x.into_api()).transpose()?,
        })
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddTeamConfigV1 {
    pub team_id: Option<TeamId>,
    pub quic_sync: Option<quic_sync::AddTeamQuicSyncConfigV1>,
    #[doc(hidden)]
    #[serde(skip)]
    pub __use_default_spread: UseDefaultSpread,
}

impl ConfigFor<api::AddTeamConfig> for AddTeamConfigV1 {
    fn resolve(self) -> ConfigResult<api::AddTeamConfig> {
        Ok(api::AddTeamConfig {
            team_id: self.team_id.ok_or(InvalidArg::new("team_id", "missing"))?,
            quic_sync: self.quic_sync.map(|x| x.into_api()).transpose()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod cbor {
        use anyhow::Result;

        pub fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
            let mut buf = Vec::new();
            ciborium::into_writer(value, &mut buf)?;
            Ok(buf)
        }

        pub fn from_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
            Ok(ciborium::from_reader(bytes)?)
        }
    }

    #[test]
    fn test_full_config() {
        let config1 = AddTeamConfigV1 {
            team_id: Some(std::array::from_fn(|i| i as u8).into()),
            quic_sync: Some(quic_sync::AddTeamQuicSyncConfigV1 {
                seed_mode: Some(quic_sync::AddSeedModeV1::Ikm(quic_sync::SeedIkm::from(
                    [0u8; 32],
                ))),
                ..Default::default()
            }),
            ..Default::default()
        };
        let bytes = cbor::to_vec(&config1).unwrap();
        println!("{bytes:?}");
        println!("{:?}", cbor::from_bytes::<ciborium::Value>(&bytes).unwrap());
        let config2: AddTeamConfigV1 = cbor::from_bytes(&bytes).unwrap();
        assert_eq!(format!("{config1:?}"), format!("{config2:?}"));
    }

    #[test]
    fn test_empty_config() {
        let config1 = AddTeamConfigV1::default();
        let bytes = cbor::to_vec(&config1).unwrap();
        println!("{bytes:?}");
        assert_eq!(bytes.len(), 1);
        println!("{:?}", cbor::from_bytes::<ciborium::Value>(&bytes).unwrap());
        let config2: AddTeamConfigV1 = cbor::from_bytes(&bytes).unwrap();
        assert_eq!(format!("{config1:?}"), format!("{config2:?}"));
    }
}
