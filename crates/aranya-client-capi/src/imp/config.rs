//! Client configuration for C API.

use core::{ffi::c_char, mem::MaybeUninit, ptr};

use aranya_capi_core::{
    safe::{TypeId, Typed},
    Builder, InvalidArg,
};
use aranya_client::config::MAX_SYNC_INTERVAL;

use super::Error;
use crate::api::defs::{self, Duration};

pub(crate) mod team;
pub(crate) use team::*;

/// Configuration info for Aranya
#[derive(Clone, Debug)]
pub struct ClientConfig {
    daemon_addr: *const c_char,
    #[cfg(feature = "aqc")]
    aqc: AqcConfig,
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }

    #[cfg(feature = "aqc")]
    pub(crate) fn aqc_addr(&self) -> *const c_char {
        self.aqc.addr
    }
}

/// Builder for a [`ClientConfig`]
#[derive(Clone, Debug)]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
    #[cfg(feature = "aqc")]
    aqc: Option<AqcConfig>,
}

impl ClientConfigBuilder {
    /// Set the address for the daemon
    pub fn daemon_addr(&mut self, addr: *const c_char) {
        self.daemon_addr = addr;
    }

    /// Set the config to be used for AQC
    #[cfg(feature = "aqc")]
    pub fn aqc(&mut self, cfg: AqcConfig) {
        self.aqc = Some(cfg);
    }
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

        #[cfg(feature = "aqc")]
        let Some(aqc) = self.aqc
        else {
            return Err(InvalidArg::new("aqc", "field not set").into());
        };

        let cfg = ClientConfig {
            daemon_addr: self.daemon_addr,
            #[cfg(feature = "aqc")]
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
            #[cfg(feature = "aqc")]
            aqc: None,
        }
    }
}

#[cfg(feature = "aqc")]
pub use aqc::*;
#[cfg(feature = "aqc")]
mod aqc {
    use std::ffi::c_char;

    use aranya_capi_core::{prelude::*, InvalidArg};

    use crate::{api::defs, imp::Error};

    /// AQC configuration.
    #[derive(Clone, Debug)]
    pub struct AqcConfig {
        /// Address to bind AQC server to.
        pub addr: *const c_char,
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

    impl Default for AqcConfigBuilder {
        fn default() -> Self {
            Self {
                addr: core::ptr::null(),
            }
        }
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug)]
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
    sync_on_hello: bool,
}

impl From<SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self::builder()
            .interval(value.interval.into())
            .sync_now(value.sync_now)
            .sync_on_hello(value.sync_on_hello)
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
    interval: Duration,
    sync_now: bool,
    sync_on_hello: bool,
}

impl SyncPeerConfigBuilder {
    /// Set the interval at which syncing occurs
    pub fn interval(&mut self, duration: Duration) {
        self.interval = duration;
    }

    /// Configures whether the peer will be immediately synced with after being added.
    ///
    /// By default, the peer is immediately synced with.
    pub fn sync_now(&mut self, sync_now: bool) {
        self.sync_now = sync_now;
    }

    /// Configures whether to automatically sync when a hello message is received from this peer
    /// indicating they have a head that we don't have.
    ///
    /// By default, sync on hello is disabled.
    pub fn sync_on_hello(&mut self, sync_on_hello: bool) {
        self.sync_on_hello = sync_on_hello;
    }
}

impl Builder for SyncPeerConfigBuilder {
    type Output = defs::SyncPeerConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let cfg = SyncPeerConfig {
            interval: self.interval,
            sync_now: self.sync_now,
            sync_on_hello: self.sync_on_hello,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: Duration {
                nanos: MAX_SYNC_INTERVAL.as_nanos() as u64,
            },
            sync_now: true,
            sync_on_hello: false,
        }
    }
}
