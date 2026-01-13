use core::mem::MaybeUninit;

use aranya_capi_core::{Builder, InvalidArg};
use aranya_client::config::SEED_IKM_SIZE;
use tracing::error;

use super::Error;
use crate::api::defs::{self};

/// Mode for creating a PSK seed when creating a team.
#[derive(Clone, Debug, Default)]
pub(crate) enum CreateSeedMode {
    /// Generate a random seed.
    #[default]
    Generate,
    /// Use the provided IKM (Input Keying Material).
    IKM(Box<[u8; SEED_IKM_SIZE]>),
}

/// Mode for providing a PSK seed when adding a team.
#[derive(Clone, Debug)]
pub(crate) enum AddSeedMode {
    /// Use the provided IKM (Input Keying Material).
    IKM(Box<[u8; SEED_IKM_SIZE]>),
    /// Use a wrapped (encrypted) seed.
    Wrapped(Vec<u8>),
}

/// QUIC syncer configuration for CreateTeam() operation.
#[derive(Clone, Debug, Default)]
pub struct CreateTeamQuicSyncConfig {
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfig {
    fn new(mode: CreateSeedMode) -> Self {
        Self { mode }
    }

    /// Creates a new [`CreateTeamQuicSyncConfigBuilder`].
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }

    /// Useful for deref coercion.
    pub(crate) fn imp(&self) -> Self {
        self.clone()
    }
}

impl From<CreateTeamQuicSyncConfig> for aranya_client::CreateTeamQuicSyncConfig {
    fn from(value: CreateTeamQuicSyncConfig) -> Self {
        let builder = match value.mode {
            CreateSeedMode::Generate => Self::builder().gen_seed(),
            CreateSeedMode::IKM(ikm) => Self::builder().seed_ikm(*ikm),
        };
        builder.build().expect("All fields are set")
    }
}

/// QUIC syncer configuration for AddTeam() operation.
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {
    mode: AddSeedMode,
}

impl AddTeamQuicSyncConfig {
    fn new(mode: AddSeedMode) -> Self {
        Self { mode }
    }

    /// Creates a new [`AddTeamQuicSyncConfigBuilder`].
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }

    /// Useful for deref coercion.
    pub(crate) fn imp(&self) -> Self {
        self.clone()
    }
}

impl From<AddTeamQuicSyncConfig> for aranya_client::AddTeamQuicSyncConfig {
    fn from(value: AddTeamQuicSyncConfig) -> Self {
        let builder = match value.mode {
            AddSeedMode::IKM(ikm) => Self::builder().seed_ikm(*ikm),
            AddSeedMode::Wrapped(wrapped) => Self::builder()
                .wrapped_seed(&wrapped)
                .expect("wrapped_seed should not fail"),
        };
        builder.build().expect("All fields are set")
    }
}

/// Builder for constructing a [`CreateTeamQuicSyncConfig`].
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    #[doc(hidden)]
    pub(crate) fn mode(&mut self, mode: CreateSeedMode) {
        self.mode = mode;
    }

    /// Sets the seed to be generated.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn generate(&mut self) {
        self.mode = CreateSeedMode::Generate;
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    ///
    /// Overwrites [`Self::gen_seed`].
    pub fn raw_seed_ikm(&mut self, ikm: [u8; SEED_IKM_SIZE]) {
        self.mode = CreateSeedMode::IKM(ikm.into());
    }
}

impl Builder for CreateTeamQuicSyncConfigBuilder {
    type Output = defs::CreateTeamQuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, CreateTeamQuicSyncConfig::new(self.mode));
        Ok(())
    }
}

/// Builder for constructing an [`AddTeamQuicSyncConfig`].
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<AddSeedMode>,
}

impl AddTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    #[doc(hidden)]
    pub(crate) fn mode(&mut self, mode: AddSeedMode) {
        self.mode = Some(mode);
    }

    /// Sets raw PSK seed IKM.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    pub fn raw_seed_ikm(&mut self, ikm: [u8; SEED_IKM_SIZE]) {
        self.mode = Some(AddSeedMode::IKM(ikm.into()));
    }

    /// Sets wrapped PSK seed.
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    pub fn wrapped_seed(&mut self, encap_seed: &[u8]) -> Result<(), Error> {
        let wrapped = postcard::from_bytes(encap_seed).map_err(|err| {
            error!(error = %err, "could not deserialize wrapped_seed");
            InvalidArg::new("wrapped_seed", "could not deserialize")
        })?;
        self.mode = Some(AddSeedMode::Wrapped(wrapped));

        Ok(())
    }
}

impl Builder for AddTeamQuicSyncConfigBuilder {
    type Output = defs::AddTeamQuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let Some(mode) = self.mode else {
            return Err(InvalidArg::new("mode", "field not set").into());
        };

        Self::Output::init(out, AddTeamQuicSyncConfig::new(mode));
        Ok(())
    }
}
