use core::mem::MaybeUninit;

use aranya_capi_core::{
    safe::{TypeId, Typed},
    Builder, InvalidArg,
};

use super::Error;
use crate::api::defs::{self, TeamId};

pub(crate) mod quic_sync;
pub(crate) use quic_sync::{
    AddQuicSyncConfig, AddQuicSyncConfigBuilder, CreateQuicSyncConfig, CreateQuicSyncConfigBuilder,
    QuicSyncConfig,
};

#[derive(Clone)]
pub struct Add {
    pub(super) id: TeamId,
}

#[derive(Clone)]
pub struct Create;

impl Add {
    pub(super) fn new(id: TeamId) -> Self {
        Self { id }
    }
}

#[derive(Default)]
pub struct AddBuild {
    pub(super) id: Option<TeamId>,
}

#[derive(Default)]
pub struct CreateBuild;

#[derive(Clone)]
/// Builder for a [`TeamConfig`].
pub struct TeamConfigBuilder<T, U> {
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

pub type CreateTeamConfigBuilder = TeamConfigBuilder<CreateBuild, quic_sync::Create>;
pub type AddTeamConfigBuilder = TeamConfigBuilder<AddBuild, quic_sync::Add>;

#[derive(Clone)]
/// Configuration info for creating or adding teams.
pub struct TeamConfig<T, U> {
    data: T,
    quic_sync: Option<QuicSyncConfig<U>>,
}

pub type CreateTeamConfig = TeamConfig<Create, quic_sync::Create>;
pub type AddTeamConfig = TeamConfig<Add, quic_sync::Add>;

impl AddTeamConfig {
    fn new(id: TeamId, quic_sync: Option<AddQuicSyncConfig>) -> Self {
        Self {
            data: Add::new(id),
            quic_sync,
        }
    }

    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        TeamConfigBuilder::default()
    }
}

impl CreateTeamConfig {
    fn new(quic_sync: Option<CreateQuicSyncConfig>) -> Self {
        Self {
            data: Create,
            quic_sync,
        }
    }

    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        TeamConfigBuilder::default()
    }
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(&mut self, id: TeamId) {
        self.data.id = Some(id);
    }

    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic(&mut self, cfg: AddQuicSyncConfig) {
        self.quic_sync = Some(cfg);
    }
}

impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic(&mut self, cfg: CreateQuicSyncConfig) {
        self.quic_sync = Some(cfg);
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

impl Typed for CreateTeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7518);
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

impl From<AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(cfg) = value.quic_sync {
            builder = builder.quic_sync(cfg.into()).id((&value.data.id).into());
        }

        builder.build().expect("All fields set")
    }
}

impl From<&AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: &AddTeamConfig) -> Self {
        Self::from(value.to_owned())
    }
}

impl Typed for AddTeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7519);
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
        let Some(id) = self.data.id else {
            return Err(InvalidArg::new("id", "field not set").into());
        };

        Self::Output::init(out, AddTeamConfig::new(id, self.quic_sync));
        Ok(())
    }
}
