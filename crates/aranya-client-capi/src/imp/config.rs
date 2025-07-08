use core::{ffi::c_char, mem::MaybeUninit, ptr};

use aranya_capi_core::{
    safe::{TypeId, Typed},
    Builder, InvalidArg,
};
use aranya_daemon_api::{Ikm, SeedMode, SEED_IKM_SIZE};
use tracing::error;

use super::Error;
use crate::api::defs::{self, Duration};

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
    ///
    /// This method is unstable because [`AqcConfig`] is unstable.
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
///
/// This config is unstable.
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

/// QUIC syncer configuation.
#[derive(Clone, Debug)]
pub struct QuicSyncConfig {
    mode: SeedMode,
}

impl QuicSyncConfig {
    /// Useful for deref coercion.
    pub(crate) fn imp(&self) -> Self {
        self.clone()
    }

    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

impl Typed for QuicSyncConfig {
    const TYPE_ID: TypeId = TypeId::new(0xADF0F970);
}

impl From<QuicSyncConfig> for aranya_client::QuicSyncConfig {
    fn from(value: QuicSyncConfig) -> Self {
        Self::builder()
            .mode(value.mode)
            .build()
            .expect("All fields are set")
    }
}

/// Builder for a [`QuicSyncConfig`].
#[derive(Default)]
pub struct QuicSyncConfigBuilder {
    mode: SeedMode,
}

impl QuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    ///
    /// This method will be deprecated soon since certificates will be used instead of PSKs in the future.
    pub fn mode(&mut self, mode: SeedMode) {
        self.mode = mode;
    }

    /// Sets mode to generate PSK seed.
    ///
    /// This method will be deprecated soon since certificates will be used instead of PSKs in the future.
    pub fn generate(&mut self) {
        self.mode = SeedMode::Generate;
    }

    /// Sets wrapped PSK seed.
    ///
    /// This method will be deprecated soon since certificates will be used instead of PSKs in the future.
    pub fn wrapped_seed(&mut self, encap_seed: &[u8]) -> Result<(), Error> {
        let wrapped = postcard::from_bytes(encap_seed).map_err(|err| {
            error!(?err);
            InvalidArg::new("wrapped_seed", "could not deserialize")
        })?;
        self.mode = SeedMode::Wrapped(wrapped);

        Ok(())
    }

    /// Sets raw PSK seed IKM.
    ///
    /// This method will be deprecated soon since certificates will be used instead of PSKs in the future.
    pub fn raw_seed_ikm(&mut self, ikm: &[u8; SEED_IKM_SIZE]) -> Result<(), Error> {
        self.mode = SeedMode::IKM(Ikm::from(*ikm));

        Ok(())
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig, Error> {
        Ok(QuicSyncConfig { mode: self.mode })
    }
}

impl Typed for QuicSyncConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xEEC2FA47);
}

impl Builder for QuicSyncConfigBuilder {
    type Output = defs::QuicSyncConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(out, QuicSyncConfig { mode: self.mode });
        Ok(())
    }
}

/// Configuration info when creating or adding a team in Aranya
#[derive(Clone, Debug)]
pub struct TeamConfig {
    quic_sync: Option<QuicSyncConfig>,
}

impl From<TeamConfig> for aranya_client::TeamConfig {
    fn from(value: TeamConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(cfg) = value.quic_sync {
            builder = builder.quic_sync(cfg.into());
        }

        builder.build().expect("All fields set")
    }
}

impl From<&TeamConfig> for aranya_client::TeamConfig {
    fn from(value: &TeamConfig) -> Self {
        Self::from(value.to_owned())
    }
}

impl Typed for TeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7518);
}

/// Builder for a [`TeamConfig`]
#[derive(Clone, Debug, Default)]
pub struct TeamConfigBuilder {
    quic_sync: Option<QuicSyncConfig>,
}

impl Typed for TeamConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x112905E7);
}

impl TeamConfigBuilder {
    /// Sets the QUIC syncer config.
    pub fn quic(&mut self, quic: QuicSyncConfig) {
        self.quic_sync = Some(quic.clone());
    }
}

impl Builder for TeamConfigBuilder {
    type Output = defs::TeamConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Self::Output::init(
            out,
            TeamConfig {
                quic_sync: self.quic_sync,
            },
        );
        Ok(())
    }
}
