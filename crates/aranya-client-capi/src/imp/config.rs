use core::{ffi::c_char, mem::MaybeUninit, ptr};

use aranya_capi_core::{
    safe::{Safe, TypeId, Typed},
    Builder, InvalidArg,
};

use super::Error;
use crate::api::defs::Duration;

/// Configuration values for syncing with a peer
#[repr(C)]
#[derive(Clone, Debug)]
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
}

impl Typed for SyncPeerConfig {
    const TYPE_ID: TypeId = TypeId::new(0x2049e682);
}

impl From<SyncPeerConfig> for aranya_client::config::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self::builder()
            .interval(value.interval.into())
            .sync_now(value.sync_now)
            .build()
            .expect("All values are set")
    }
}

impl From<&SyncPeerConfig> for aranya_client::config::SyncPeerConfig {
    fn from(value: &SyncPeerConfig) -> Self {
        value.clone().into()
    }
}

/// Configuration info for Aranya
#[repr(C)]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
pub struct ClientConfig {
    daemon_addr: *const c_char,
    // The daemon's public API key.
    pk: Vec<u8>,
    aqc: AqcConfig,
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }

    pub(crate) fn daemon_api_pk(&self) -> &[u8] {
        &self.pk
    }
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

/// Builder for a [`ClientConfig`]
#[repr(C)]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 56, align = 8)]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
    pk: Option<Vec<u8>>,
    aqc: Option<AqcConfig>,
}

impl ClientConfigBuilder {
    /// Set the address for the daemon
    pub fn set_daemon_addr(&mut self, addr: *const c_char) {
        self.daemon_addr = addr;
    }

    /// Sets the daemon's public API key.
    pub fn set_daemon_pk(&mut self, pk: &[u8]) {
        self.pk = Some(pk.to_vec());
    }

    /// Set the config to be used for AQC
    pub fn set_aqc(&mut self, cfg: AqcConfig) {
        self.aqc = Some(cfg);
    }
}

impl Typed for ClientConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xAAAA611B);
}

impl Builder for ClientConfigBuilder {
    type Output = Safe<ClientConfig>;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        if self.daemon_addr.is_null() {
            return Err(InvalidArg::new("daemon_addr", "field not set").into());
        }

        let Some(pk) = self.pk else {
            return Err(InvalidArg::new("pk", "field not set").into());
        };

        let Some(aqc) = self.aqc else {
            return Err(InvalidArg::new("aqc", "field not set").into());
        };

        let cfg = ClientConfig {
            daemon_addr: self.daemon_addr,
            pk,
            aqc,
        };
        Safe::init(out, cfg);
        Ok(())
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: ptr::null(),
            pk: None,
            aqc: None,
        }
    }
}

/// Builder for a [`SyncPeerConfig`]
#[repr(C)]
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
    type Output = Safe<SyncPeerConfig>;
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
        Safe::init(out, cfg);
        Ok(())
    }
}

impl Typed for SyncPeerConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x2049e683);
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: None,
            sync_now: true,
        }
    }
}

/// Configuration info for Aranya Fast Channels
#[repr(C)]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
#[cfg(feature = "afc")]
pub struct AfcConfig {
    /// Shared memory path.
    pub shm_path: *const c_char,
    /// Maximum number of channels to store in shared-memory.
    pub max_channels: usize,
    /// Address to bind AFC server to.
    pub addr: *const c_char,
}

#[cfg(feature = "afc")]
impl Typed for AfcConfig {
    const TYPE_ID: TypeId = TypeId::new(0x1C3BE29F);
}

/// Builder for an [`AfcConfig`]
#[derive(Clone, Debug)]
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub struct AfcConfigBuilder {
    /// Shared memory path.
    pub shm_path: *const c_char,
    /// Maximum number of channels to store in shared-memory.
    pub max_channels: usize,
    /// Address to bind AFC server to.
    pub addr: *const c_char,
}

#[cfg(feature = "afc")]
impl Typed for AfcConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xB4E69EF0);
}

#[cfg(feature = "afc")]
impl AfcConfigBuilder {
    /// Attempts to construct an [`AfcConfig`], returning an [`Error::Bug`](Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<AfcConfig, Error> {
        if self.shm_path.is_null() {
            return Err(InvalidArg::new("shm_path", "field not set").into());
        }

        if self.addr.is_null() {
            return Err(InvalidArg::new("addr", "field not set").into());
        }

        Ok(AfcConfig {
            shm_path: self.shm_path,
            max_channels: self.max_channels,
            addr: self.addr,
        })
    }
}

/// Configuration info for Aranya Fast Channels
#[repr(C)]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub struct AqcConfig {
    /// Address to bind AQC server to.
    addr: *const c_char,
}

impl Typed for AqcConfig {
    const TYPE_ID: TypeId = TypeId::new(0x64CEB3F4);
}

/// Builder for an [`AqcConfig`]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
pub struct AqcConfigBuilder {
    /// Address to bind AQC server to.
    addr: *const c_char,
}

impl AqcConfigBuilder {
    /// Set the Address to bind AQC server to
    pub fn set_addr(&mut self, addr: *const c_char) {
        self.addr = addr;
    }
}

impl Builder for AqcConfigBuilder {
    type Output = Safe<AqcConfig>;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        if self.addr.is_null() {
            return Err(InvalidArg::new("addr", "field not set").into());
        }

        let cfg = AqcConfig { addr: self.addr };

        Safe::init(out, cfg);
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

/// Configuration info when creating or adding a team in Aranya
#[repr(C)]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 0, align = 1)]
pub struct TeamConfig {}

impl Typed for TeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7518);
}

/// Builder for a [`TeamConfig`]
#[repr(C)]
#[derive(Clone, Debug)]
#[aranya_capi_core::opaque(size = 0, align = 1)]
pub struct TeamConfigBuilder {}

impl Typed for TeamConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x112905E7);
}

impl Builder for TeamConfigBuilder {
    type Output = Safe<TeamConfig>;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        Safe::init(out, TeamConfig {});
        Ok(())
    }
}
