// Allow deprecated types in this module - it provides backward compatibility
// for the deprecated team config types during the mTLS migration.

use core::mem::MaybeUninit;

use aranya_capi_core::{Builder, InvalidArg};

use super::Error;
use crate::api::defs::{self, TeamId};

pub(crate) mod quic_sync;
pub(crate) use quic_sync::{
    AddTeamQuicSyncConfig, AddTeamQuicSyncConfigBuilder, CreateTeamQuicSyncConfig,
    CreateTeamQuicSyncConfigBuilder,
};

/// A team config required to create a new Aranya team.
#[derive(Clone, Debug)]
pub struct CreateTeamConfig {}

impl CreateTeamConfig {
    fn new() -> Self {
        Self {}
    }

    /// Creates a new [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

/// Builder for constructing a [`CreateTeamConfig`].
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {}

impl Builder for CreateTeamConfigBuilder {
    type Output = defs::CreateTeamConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, CreateTeamConfig::new());
        Ok(())
    }
}

/// Configuration for adding an existing Aranya team to a device.
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    team_id: TeamId,
}

impl AddTeamConfig {
    fn new(team_id: TeamId) -> Self {
        Self { team_id }
    }

    /// Creates a new [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

/// Builder for constructing an [`AddTeamConfig`].
#[derive(Debug, Default)]
pub struct AddTeamConfigBuilder {
    team_id: Option<TeamId>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(&mut self, id: TeamId) {
        self.team_id = Some(id);
    }
}

impl Builder for AddTeamConfigBuilder {
    type Output = defs::AddTeamConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let Some(id) = self.team_id else {
            return Err(InvalidArg::new("id", "field not set").into());
        };

        Self::Output::init(out, AddTeamConfig::new(id));
        Ok(())
    }
}

impl From<AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        let builder = Self::builder().team_id((&value.team_id).into());
        builder.build().expect("All fields set")
    }
}

impl From<&AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: &AddTeamConfig) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<CreateTeamConfig> for aranya_client::CreateTeamConfig {
    fn from(_value: CreateTeamConfig) -> Self {
        let builder = Self::builder();
        builder.build().expect("All fields set")
    }
}

impl From<&CreateTeamConfig> for aranya_client::CreateTeamConfig {
    fn from(value: &CreateTeamConfig) -> Self {
        Self::from(value.to_owned())
    }
}
