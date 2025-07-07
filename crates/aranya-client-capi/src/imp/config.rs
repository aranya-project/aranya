use core::{ffi::c_char, mem::MaybeUninit, ptr};

use aranya_capi_core::{
    safe::{TypeId, Typed},
    Builder, InvalidArg,
};
use aranya_daemon_api::{AddSeedMode, CreateSeedMode, SEED_IKM_SIZE};
use tracing::error;

use super::Error;
use crate::api::defs::{self, Duration, TeamId};

/// Configuration info for Aranya
#[derive(Clone, Debug)]
pub struct ClientConfig {
    daemon_addr: *const c_char,
    aqc: AqcConfig,
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }

    pub(crate) fn aqc_addr(&self) -> *const c_char {
        self.aqc.addr
    }
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

/// Builder for a [`ClientConfig`]
#[derive(Clone, Debug)]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
    aqc: Option<AqcConfig>,
}

impl ClientConfigBuilder {
    /// Set the address for the daemon
    pub fn daemon_addr(&mut self, addr: *const c_char) {
        self.daemon_addr = addr;
    }

    /// Set the config to be used for AQC
    pub fn aqc(&mut self, cfg: AqcConfig) {
        self.aqc = Some(cfg);
    }
}

impl Typed for ClientConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xAAAA611B);
}

impl Builder for ClientConfigBuilder {
    type Output = defs::ClientConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        if self.daemon_addr.is_null() {
            return Err(InvalidArg::new("daemon_addr", "field not set").into());
        }

        let Some(aqc) = self.aqc else {
            return Err(InvalidArg::new("aqc", "field not set").into());
        };

        let cfg = ClientConfig {
            daemon_addr: self.daemon_addr,
            aqc,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: ptr::null(),
            aqc: None,
        }
    }
}

/// AQC configuration.
#[derive(Clone, Debug)]
pub struct AqcConfig {
    /// Address to bind AQC server to.
    pub addr: *const c_char,
}

impl Typed for AqcConfig {
    const TYPE_ID: TypeId = TypeId::new(0x64CEB3F4);
}

/// Builder for an [`AqcConfig`]
#[derive(Clone, Debug)]
pub struct AqcConfigBuilder {
    /// Address to bind AQC server to.
    addr: *const c_char,
}

impl AqcConfigBuilder {
    /// Sets the network address that the AQC server should
    /// listen on.
    pub fn addr(&mut self, addr: *const c_char) {
        self.addr = addr;
    }
}

impl Builder for AqcConfigBuilder {
    type Output = defs::AqcConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        if self.addr.is_null() {
            return Err(InvalidArg::new("addr", "field not set").into());
        }

        let cfg = AqcConfig { addr: self.addr };

        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Typed for AqcConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x153AE387);
}

impl Default for AqcConfigBuilder {
    fn default() -> Self {
        Self { addr: ptr::null() }
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug)]
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
}

impl Typed for SyncPeerConfig {
    const TYPE_ID: TypeId = TypeId::new(0x44BE85E7);
}

impl From<SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self::builder()
            .interval(value.interval.into())
            .sync_now(value.sync_now)
            .build()
            .expect("All values are set")
    }
}

impl From<&SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: &SyncPeerConfig) -> Self {
        value.clone().into()
    }
}

/// Builder for a [`SyncPeerConfig`]
#[derive(Clone, Debug)]
pub struct SyncPeerConfigBuilder {
    interval: Option<Duration>,
    sync_now: bool,
}

impl SyncPeerConfigBuilder {
    /// Set the interval at which syncing occurs
    pub fn interval(&mut self, duration: Duration) {
        self.interval = Some(duration);
    }

    /// Configures whether the peer will be immediately synced with after being added.
    ///
    /// By default, the peer is immediately synced with.
    pub fn sync_now(&mut self, sync_now: bool) {
        self.sync_now = sync_now;
    }
}

impl Builder for SyncPeerConfigBuilder {
    type Output = defs::SyncPeerConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let Some(interval) = self.interval else {
            return Err(InvalidArg::new("interval", "field not set").into());
        };

        let cfg = SyncPeerConfig {
            interval,
            sync_now: self.sync_now,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Typed for SyncPeerConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xFE81AF7E);
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: None,
            sync_now: true,
        }
    }
}

mod quic_sync {
    use aranya_daemon_api::{AddSeedMode, CreateSeedMode};

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

pub type CreateQuicSyncConfig = QuicSyncConfig<quic_sync::Create>;
pub type AddQuicSyncConfig = QuicSyncConfig<quic_sync::Add>;

impl CreateQuicSyncConfig {
    fn new(mode: CreateSeedMode) -> Self {
        Self {
            data: quic_sync::Create::new(mode),
        }
    }

    pub fn builder() -> CreateQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

impl AddQuicSyncConfig {
    fn new(mode: AddSeedMode) -> Self {
        Self {
            data: quic_sync::Add::new(mode),
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

pub(crate) type CreateQuicSyncConfigBuilder = QuicSyncConfigBuilder<quic_sync::CreateBuild>;
pub(crate) type AddQuicSyncConfigBuilder = QuicSyncConfigBuilder<quic_sync::AddBuild>;

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

mod team {
    use super::TeamId;

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
}

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

pub type CreateTeamConfigBuilder = TeamConfigBuilder<team::CreateBuild, quic_sync::Create>;
pub type AddTeamConfigBuilder = TeamConfigBuilder<team::AddBuild, quic_sync::Add>;

#[derive(Clone)]
/// Configuration info for creating or adding teams.
pub struct TeamConfig<T, U> {
    data: T,
    quic_sync: Option<QuicSyncConfig<U>>,
}

pub type CreateTeamConfig = TeamConfig<team::Create, quic_sync::Create>;
pub type AddTeamConfig = TeamConfig<team::Add, quic_sync::Add>;

impl AddTeamConfig {
    fn new(id: TeamId, quic_sync: Option<AddQuicSyncConfig>) -> Self {
        Self {
            data: team::Add::new(id),
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
            data: team::Create,
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
