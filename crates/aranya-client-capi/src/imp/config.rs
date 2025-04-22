use std::ffi::c_char;

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::ConfigError;

use crate::api::defs::Duration;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
/// Configuration info for Aranya
pub struct ClientConfig {
    daemon_addr: *const c_char,
    aqc: AqcConfig,
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 56, align = 8)]
/// Builder for a [`ClientConfig`]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
    aqc: Option<AqcConfig>,
}

impl Typed for ClientConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xAAAA611B);
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

    /// Attempts to construct a [`ClientConfig`], returning an
    /// [`Error::Config`](super::error::Error::Config) if invalid.
    pub fn build(self) -> Result<ClientConfig, super::Error> {
        if self.daemon_addr.is_null() {
            let e = ConfigError::InvalidArg {
                arg: "daemon_addr",
                reason: "Tried to create a `ClientConfig` without setting the daemon address!",
            };
            return Err(e.into());
        }

        let Some(aqc) = self.aqc else {
            let e = ConfigError::InvalidArg {
                arg: "aqc_config",
                reason: "Tried to create a `ClientConfig` without setting a valid `AqcConfig`!",
            };
            return Err(e.into());
        };

        Ok(ClientConfig {
            daemon_addr: self.daemon_addr,
            aqc,
        })
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: std::ptr::null(),
            aqc: None,
        }
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
    const TYPE_ID: TypeId = TypeId::new(0x64CEB3F4);
}

#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 24, align = 8)]
/// Builder for an [`AqcConfig`]
pub struct AqcConfigBuilder {
    /// Address to bind AQC server to.
    addr: *const c_char,
}

impl Typed for AqcConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x153AE387);
}

impl AqcConfigBuilder {
    /// Set the Address to bind AQC server to
    pub fn addr(&mut self, addr: *const c_char) {
        self.addr = addr;
    }

    /// Attempts to construct an [`AqcConfig`], returning an
    /// [`Error::Config`](super::error::Error::Config) if invalid.
    pub fn build(self) -> Result<AqcConfig, super::Error> {
        if self.addr.is_null() {
            let e = ConfigError::InvalidArg {
                arg: "address",
                reason: "Tried to create an `AqcConfig` without setting a valid address!",
            };
            return Err(e.into());
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

#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// Configuration info for syncing with a peer
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
        (*value).into()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// Builder for a [`SyncPeerConfig`]
pub struct SyncPeerConfigBuilder {
    interval: Option<Duration>,
    sync_now: bool,
}

impl Typed for SyncPeerConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0xFE81AF7E);
}

impl SyncPeerConfigBuilder {
    /// Sets the interval at which syncing occurs.
    pub fn interval(&mut self, duration: Duration) {
        self.interval = Some(duration);
    }

    /// Configures whether the peer will be immediately synced with after being added.
    ///
    /// By default, the peer is immediately synced with.
    pub fn sync_now(&mut self, sync_now: bool) {
        self.sync_now = sync_now;
    }

    /// Attempts to construct a [`SyncPeerConfig`], returning an
    /// [`Error::Config`](super::error::Error::Config) if invalid.
    pub fn build(&self) -> Result<SyncPeerConfig, super::Error> {
        let Some(interval) = self.interval else {
            let e = ConfigError::InvalidArg {
                arg: "interval",
                reason: "Tried to create a `SyncPeerConfig` without setting the interval!",
            };
            return Err(e.into());
        };

        Ok(SyncPeerConfig {
            interval,
            sync_now: self.sync_now,
        })
    }
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
#[aranya_capi_core::opaque(size = 0, align = 1)]
/// Configuration info when creating or adding a team in Aranya
pub struct TeamConfig {}

impl Typed for TeamConfig {
    const TYPE_ID: TypeId = TypeId::new(0xA05F7518);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 0, align = 1)]
/// Builder for a [`TeamConfig`]
pub struct TeamConfigBuilder {}

impl Typed for TeamConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x112905E7);
}

impl TeamConfigBuilder {
    /// Attempts to construct a [`TeamConfig`], returning an
    /// [`Error::Config`](super::error::Error::Config) if invalid.
    pub fn build(self) -> Result<TeamConfig, super::Error> {
        Ok(TeamConfig {})
    }
}
