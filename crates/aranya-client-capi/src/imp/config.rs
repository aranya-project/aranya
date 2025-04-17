use std::ffi::c_char;

use aranya_capi_core::{
    safe::{TypeId, Typed},
    InvalidArg,
};
use buggy::bug;

use crate::api::defs::Duration;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// Configuration values for syncing with a peer
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
}

impl Typed for SyncPeerConfig {
    const TYPE_ID: TypeId = TypeId::new(0x2049e682);
}

impl From<SyncPeerConfig> for aranya_client::client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self::builder()
            .interval(value.interval.into())
            .sync_now(value.sync_now)
            .build()
            .expect("All values are set")
    }
}

impl From<&SyncPeerConfig> for aranya_client::client::SyncPeerConfig {
    fn from(value: &SyncPeerConfig) -> Self {
        (*value).into()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
/// Configuration info for Aranya
pub struct ClientConfig {
    daemon_addr: *const c_char,
    #[cfg(feature = "afc")]
    afc: AfcConfig,
    aqc: AqcConfig,
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }

    #[cfg(feature = "afc")]
    pub(crate) fn afc(&self) -> &AfcConfig {
        &self.afc
    }
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 56, align = 8)]
/// Builder for a [`ClientConfig`]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
    #[cfg(feature = "afc")]
    afc: Option<AfcConfig>,
    aqc: Option<AqcConfig>,
}

impl Typed for ClientConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9F);
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

    #[cfg(feature = "afc")]
    /// Set the config to be used for AFC
    pub fn afc(&mut self, cfg: AfcConfig) {
        self.afc = Some(cfg);
    }

    /// Attempts to construct a [`ClientConfig`], returning an [`Error::Bug`](super::Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<ClientConfig, super::Error> {
        if self.daemon_addr.is_null() {
            bug!("Tried to create a ClientConfig without a valid address!");
        }

        #[cfg(feature = "afc")]
        let Some(afc) = self.afc
        else {
            bug!("Tried to create a ClientConfig without a valid AfcConfig!");
        };

        let Some(aqc) = self.aqc else {
            bug!("Tried to create a ClientConfig without a valid AqcConfig!");
        };

        Ok(ClientConfig {
            daemon_addr: self.daemon_addr,
            #[cfg(feature = "afc")]
            afc,
            aqc,
        })
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: std::ptr::null(),
            aqc: None,
            #[cfg(feature = "afc")]
            afc: None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// Builder for a [`SyncPeerConfig`]
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

    /// Build a [`SyncPeerConfig`]
    pub fn build(&self) -> Result<SyncPeerConfig, super::Error> {
        let Some(interval) = self.interval else {
            let e = Into::into(InvalidArg::new(
                "interval",
                "Tried to create a `SyncPeerConfig` without setting the interval!",
            ));
            return Err(e);
        };

        Ok(SyncPeerConfig {
            interval,
            sync_now: self.sync_now,
        })
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

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Configuration info for Aranya Fast Channels
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
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9F);
}

#[derive(Copy, Clone, Debug)]
#[cfg(feature = "afc")]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Builder for an [`AfcConfig`]
pub struct AfcConfigBuilder {
    /// Shared memory path.
    pub shm_path: *const c_char,
    /// Maximum number of channels to store in shared-memory.
    pub max_channels: usize,
    /// Address to bind AFC server to.
    pub addr: *const c_char,
}

#[cfg(feature = "afc")]
impl AfcConfigBuilder {
    /// Attempts to construct an [`AfcConfig`], returning an [`Error::Bug`](super::Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<AfcConfig, super::Error> {
        if self.shm_path.is_null() {
            bug!("Tried to create an AfcConfig without a valid shm_path!");
        }

        if self.addr.is_null() {
            bug!("Tried to create an AfcConfig without a valid address!");
        }

        Ok(AfcConfig {
            shm_path: self.shm_path,
            max_channels: self.max_channels,
            addr: self.addr,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Configuration info for Aranya Fast Channels
pub struct AqcConfig {
    /// Address to bind AQC server to.
    addr: *const c_char,
}

impl Typed for AqcConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9F);
}

#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Builder for an [`AqcConfig`]
pub struct AqcConfigBuilder {
    /// Address to bind AQC server to.
    addr: *const c_char,
}

impl Typed for AqcConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x227DFCA0);
}

impl AqcConfigBuilder {
    /// Set the Address to bind AQC server to
    pub fn addr(&mut self, addr: *const c_char) {
        self.addr = addr;
    }

    /// Attempts to construct an [`AqcConfig`], returning an [`Error::Bug`](super::Error::Bug) if
    /// there are invalid parameters.
    pub fn build(self) -> Result<AqcConfig, super::Error> {
        if self.addr.is_null() {
            bug!("Tried to create an AqcConfig without a valid address!");
        }

        Ok(AqcConfig { addr: self.addr })
    }
}

impl Default for AqcConfigBuilder {
    fn default() -> Self {
        Self {
            addr: std::ptr::null(),
        }
    }
}
