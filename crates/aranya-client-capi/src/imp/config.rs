use std::ffi::c_char;

use aranya_capi_core::safe::{TypeId, Typed};
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
#[aranya_capi_core::opaque(size = 32, align = 8)]
/// Configuration info for Aranya
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

        Ok(ClientConfig {
            daemon_addr: self.daemon_addr,
            #[cfg(feature = "afc")]
            afc,
        })
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// Builder for a [`SyncPeerConfig`]
pub struct SyncPeerConfigBuilder {
    interval: *const Duration,
    sync_now: bool,
}

impl SyncPeerConfigBuilder {
    /// Set the interval at which syncing occurs
    pub fn interval(&mut self, duration: &Duration) {
        self.interval = duration;
    }

    /// Configures whether the peer will be immediately synced with after being added.
    ///
    /// By default, the peer is immediately synced with.
    pub fn sync_now(&mut self, sync_now: bool) {
        self.sync_now = sync_now;
    }

    /// Build a [`SyncPeerConfig`]
    pub fn build(&self) -> Result<SyncPeerConfig, super::Error> {
        // SAFETY: Trusts that the caller invoked [`Self::interval`] and provided a pointer to a valid `Duration`.
        unsafe {
            let Some(interval) = self.interval.as_ref() else {
                bug!("Tried to create a `SyncPeerConfig` without setting the interval!");
            };

            Ok(SyncPeerConfig {
                interval: *interval,
                sync_now: self.sync_now,
            })
        }
    }
}

impl Typed for SyncPeerConfigBuilder {
    const TYPE_ID: TypeId = TypeId::new(0x2049e683);
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: std::ptr::null(),
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
