use core::mem::MaybeUninit;

use aranya_capi_core::{
    safe::{TypeId, Typed},
    Builder, InvalidArg,
};
use aranya_daemon_api::{AddSeedMode, CreateSeedMode, SEED_IKM_SIZE};
use tracing::error;

use super::Error;
use crate::api::defs::{self};

#[derive(Clone)]
pub struct Add {
    pub(super) mode: AddSeedMode,
}

#[derive(Clone)]
pub struct Create {
    pub(super) mode: CreateSeedMode,
}

impl Create {
    pub(super) fn new(mode: CreateSeedMode) -> Self {
        Self { mode }
    }
}

impl Add {
    pub(super) fn new(mode: AddSeedMode) -> Self {
        Self { mode }
    }
}

#[derive(Clone, Default)]
pub struct AddBuild {
    pub(super) mode: Option<AddSeedMode>,
}

#[derive(Clone, Default)]
pub struct CreateBuild {
    pub(super) mode: CreateSeedMode,
}
#[derive(Clone)]
pub struct QuicSyncConfig<T> {
    data: T,
}

impl<T: Clone> QuicSyncConfig<T> {
    /// Useful for deref coercion.
    pub(crate) fn imp(&self) -> Self {
        self.clone()
    }
}

pub type CreateQuicSyncConfig = QuicSyncConfig<Create>;
pub type AddQuicSyncConfig = QuicSyncConfig<Add>;

impl CreateQuicSyncConfig {
    fn new(mode: CreateSeedMode) -> Self {
        Self {
            data: Create::new(mode),
        }
    }

    pub fn builder() -> CreateQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

impl AddQuicSyncConfig {
    fn new(mode: AddSeedMode) -> Self {
        Self {
            data: Add::new(mode),
        }
    }

    pub fn builder() -> AddQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

#[derive(Clone, Default)]
pub struct QuicSyncConfigBuilder<T> {
    data: T,
}

pub(crate) type CreateQuicSyncConfigBuilder = QuicSyncConfigBuilder<CreateBuild>;
pub(crate) type AddQuicSyncConfigBuilder = QuicSyncConfigBuilder<AddBuild>;

impl CreateQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(&mut self, mode: CreateSeedMode) {
        self.data.mode = mode;
    }

    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn generate(&mut self) {
        self.data.mode = CreateSeedMode::Generate;
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    pub fn raw_seed_ikm(&mut self, ikm: [u8; SEED_IKM_SIZE]) {
        self.data.mode = CreateSeedMode::IKM(ikm.into());
    }
}

impl AddQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(&mut self, mode: AddSeedMode) {
        self.data.mode = Some(mode);
    }

    /// Sets raw PSK seed IKM.
    pub fn raw_seed_ikm(&mut self, ikm: [u8; SEED_IKM_SIZE]) {
        self.data.mode = Some(AddSeedMode::IKM(ikm.into()));
    }

    /// Sets wrapped PSK seed.
    pub fn wrapped_seed(&mut self, encap_seed: &[u8]) -> Result<(), Error> {
        let wrapped = postcard::from_bytes(encap_seed).map_err(|err| {
            error!(?err);
            InvalidArg::new("wrapped_seed", "could not deserialize")
        })?;
        self.data.mode = Some(AddSeedMode::Wrapped(wrapped));

        Ok(())
    }
}

impl Typed for AddQuicSyncConfig {
    const TYPE_ID: TypeId = TypeId::new(0xADF0F970);
}

impl Typed for CreateQuicSyncConfig {
    const TYPE_ID: TypeId = TypeId::new(0xADF0F971);
}

impl From<AddQuicSyncConfig> for aranya_client::AddQuicSyncConfig {
    fn from(value: AddQuicSyncConfig) -> Self {
        Self::builder()
            .mode(value.data.mode)
            .build()
            .expect("All fields are set")
    }
}

impl From<CreateQuicSyncConfig> for aranya_client::CreateQuicSyncConfig {
    fn from(value: CreateQuicSyncConfig) -> Self {
        Self::builder()
            .mode(value.data.mode)
            .build()
            .expect("All fields are set")
    }
}

impl Typed for CreateQuicSyncConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xEEC2FA47);
}

impl Typed for AddQuicSyncConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xEEC2FA48);
}

impl Builder for CreateQuicSyncConfigBuilder {
    type Output = defs::CreateQuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, CreateQuicSyncConfig::new(self.data.mode));
        Ok(())
    }
}

impl Builder for AddQuicSyncConfigBuilder {
    type Output = defs::AddQuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let Some(mode) = self.data.mode else {
            return Err(InvalidArg::new("mode", "field not set").into());
        };

        Self::Output::init(out, AddQuicSyncConfig::new(mode));
        Ok(())
    }
}
