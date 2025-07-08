use core::mem::MaybeUninit;

use aranya_capi_core::{
    safe::{TypeId, Typed},
    Builder, InvalidArg,
};

use super::Error;
use crate::api::defs::{self, TeamId};

pub(crate) mod quic_sync;
pub(crate) use quic_sync::{
    AddTeamQuicSyncConfig, AddTeamQuicSyncConfigBuilder, CreateTeamQuicSyncConfig,
    CreateTeamQuicSyncConfigBuilder,
};

/// A team config required to create a new Aranya team.
#[derive(Clone)]
pub struct CreateTeamConfig {
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfig {
    fn new(quic_sync: Option<CreateTeamQuicSyncConfig>) -> Self {
        Self { quic_sync }
    }

    /// Creates a new [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

impl Typed for CreateTeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7518);
}

/// Builder for constructing a [`CreateTeamConfig`].
#[derive(Default)]
pub struct CreateTeamConfigBuilder {
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic(&mut self, cfg: CreateTeamQuicSyncConfig) {
        self.quic_sync = Some(cfg);
    }
}

impl Typed for CreateTeamConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x69F54A43);
}

impl Builder for CreateTeamConfigBuilder {
    type Output = defs::CreateTeamConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, CreateTeamConfig::new(self.quic_sync));
        Ok(())
    }
}

/// Configuration for adding an existing Aranya team to a device.
#[derive(Clone)]
pub struct AddTeamConfig {
    team_id: TeamId,
    quic_sync: Option<AddTeamQuicSyncConfig>,
}

impl AddTeamConfig {
    fn new(team_id: TeamId, quic_sync: Option<AddTeamQuicSyncConfig>) -> Self {
        Self { team_id, quic_sync }
    }

    /// Creates a new [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

impl Typed for AddTeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7519);
}

/// Builder for constructing an [`AddTeamConfig`].
#[derive(Default)]
pub struct AddTeamConfigBuilder {
    team_id: Option<TeamId>,
    quic_sync: Option<AddTeamQuicSyncConfig>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(&mut self, id: TeamId) {
        self.team_id = Some(id);
    }

    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic(&mut self, cfg: AddTeamQuicSyncConfig) {
        self.quic_sync = Some(cfg);
    }
}

impl Typed for AddTeamConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x112905E7);
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

        Self::Output::init(out, AddTeamConfig::new(id, self.quic_sync));
        Ok(())
    }
}

impl From<AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(cfg) = value.quic_sync {
            builder = builder
                .quic_sync(cfg.into())
                .team_id((&value.team_id).into());
        }

        builder.build().expect("All fields set")
    }
}

impl From<&AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: &AddTeamConfig) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<CreateTeamConfig> for aranya_client::CreateTeamConfig {
    fn from(value: CreateTeamConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(cfg) = value.quic_sync {
            builder = builder.quic_sync(cfg.into());
        }

        builder.build().expect("All fields set")
    }
}

impl From<&CreateTeamConfig> for aranya_client::CreateTeamConfig {
    fn from(value: &CreateTeamConfig) -> Self {
        Self::from(value.to_owned())
    }
}
