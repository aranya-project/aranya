use std::ffi::c_char;

use aranya_capi_core::safe::{TypeId, Typed};
use aranya_client::ConfigError;

use crate::api::defs::Duration;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 32, align = 8)]
/// Configuration info when creating a client in Aranya
pub struct ClientConfig {
    pub daemon_addr: *const c_char,
    #[cfg(feature = "afc")]
    pub afc: AfcConfig,
}

impl Typed for ClientConfig {
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 40, align = 8)]
/// Builder for a [`ClientConfig`]
pub struct ClientConfigBuilder {
    pub daemon_addr: *const c_char,
    #[cfg(feature = "afc")]
    pub afc: Option<AfcConfig>,
}

impl ClientConfigBuilder {
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

        #[cfg(feature = "afc")]
        let Some(afc) = self.afc
        else {
            let e = ConfigError::InvalidArg {
                arg: "afc_config",
                reason: "Tried to create a `ClientConfig` without setting a valid `AfcConfig`!",
            };
            return Err(e.into());
        };

        Ok(ClientConfig {
            daemon_addr: self.daemon_addr,
            #[cfg(feature = "afc")]
            afc,
        })
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
    /// Attempts to construct an [`AfcConfig`], returning an
    /// [`Error::Config`](super::error::Error::Config) if invalid.
    pub fn build(self) -> Result<AfcConfig, super::Error> {
        if self.shm_path.is_null() {
            let e = ConfigError::InvalidArg {
                arg: "shm_path",
                reason: "Tried to create a `AfcConfig` without setting a valid shared memory path!",
            };
            return Err(e.into());
        }

        if self.addr.is_null() {
            let e = ConfigError::InvalidArg {
                arg: "address",
                reason: "Tried to create a `AfcConfig` without setting a valid address!",
            };
            return Err(e.into());
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
/// Configuration info for syncing with a peer
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
}

impl Typed for SyncPeerConfig {
    const TYPE_ID: TypeId = TypeId::new(0x2049E682);
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

impl Typed for SyncPeerConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x2049E683);
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
    const TYPE_ID: TypeId = TypeId::new(0x227DFC9E);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[aranya_capi_core::opaque(size = 0, align = 1)]
/// Builder for a [`TeamConfig`]
pub struct TeamConfigBuilder {}

impl TeamConfigBuilder {
    /// Attempts to construct a [`TeamConfig`], returning an
    /// [`Error::Config`](super::error::Error::Config) if invalid.
    pub fn build(self) -> Result<TeamConfig, super::Error> {
        Ok(TeamConfig {})
    }
}
