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
#[derive(Clone, Debug)]
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
#[derive(Debug, Default)]
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
#[derive(Clone, Debug)]
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
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct AddTeamConfigBuilder {
    team_id: Option<TeamId>,
    quic_sync: Option<defs::AddTeamQuicSyncConfigBuilder>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(&mut self, id: TeamId) {
        self.team_id = Some(id);
    }

    /// Returns a mutable reference to a builder for an [`AddTeamQuicSyncConfig`].
    ///
    /// This function must be called in order to initialize an [`AddTeamQuicSyncConfigBuilder`]
    /// with default values.
    pub fn quic_sync(&mut self) -> &mut defs::AddTeamQuicSyncConfigBuilder {
        self.quic_sync.get_or_insert_with(|| {
            let mut ret = MaybeUninit::uninit();
            defs::AddTeamQuicSyncConfigBuilder::init(
                &mut ret,
                AddTeamQuicSyncConfigBuilder::default(),
            );

            // SAFETY: Initialized in the call above.
            unsafe { ret.assume_init() }
        })
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

        let maybe_qs_cfg = if let Some(quic_sync_builder) = self.quic_sync {
            let mut out_qs_cfg = MaybeUninit::uninit();

            // SAFETY: No special considerations.
            unsafe {
                quic_sync_builder.build(&mut out_qs_cfg)?;
            }

            // SAFETY: Initialized in the call above.
            unsafe { Some(out_qs_cfg.assume_init().into_inner().into_inner()) }
        } else {
            None
        };

        Self::Output::init(out, AddTeamConfig::new(id, maybe_qs_cfg));
        Ok(())
    }
}

impl From<AddTeamConfig> for aranya_client::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(cfg) = value.quic_sync {
            builder.quic_sync().set_from_cfg(cfg.into());
        }

        builder = builder.team_id((&value.team_id).into());

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

impl From<AddTeamConfigBuilder> for aranya_client::AddTeamConfigBuilder {
    fn from(value: AddTeamConfigBuilder) -> Self {
        let mut builder = Self::default();

        if let Some(team_id) = value.team_id {
            builder = builder.team_id(team_id.into());
        }

        if let Some(qs_cfg_builder) = value.quic_sync {
            let qs_cfg_builder = qs_cfg_builder.into_inner().into_inner();

            if let Some(mode) = qs_cfg_builder.mode {
                builder.quic_sync().mode(mode);
            }
        }

        builder
    }
}

impl From<aranya_client::AddTeamConfigBuilder> for AddTeamConfigBuilder {
    fn from(mut value: aranya_client::AddTeamConfigBuilder) -> Self {
        let mut builder = Self::default();

        if let Some(team_id) = value.get_team_id() {
            builder.id((*team_id).into());
        }

        if value.has_quic_sync() {
            let qs_cfg_builder = value.quic_sync();

            if let Some(mode) = qs_cfg_builder.get_mode() {
                builder.quic_sync().mode(mode.clone());
            }
        }

        builder
    }
}
