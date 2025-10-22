//! Client configuration for C API.

use core::{ffi::c_char, mem::MaybeUninit, ptr};

use aranya_capi_core::{Builder, InvalidArg};

use super::Error;
use crate::api::defs::{self, Duration};

pub(crate) mod team;
pub(crate) use team::*;

/// Configuration info for Aranya
#[derive(Clone, Debug)]
pub struct ClientConfig {
    daemon_addr: *const c_char,
}

impl ClientConfig {
    pub(crate) fn daemon_addr(&self) -> *const c_char {
        self.daemon_addr
    }
}

/// Builder for a [`ClientConfig`]
#[derive(Clone, Debug)]
pub struct ClientConfigBuilder {
    daemon_addr: *const c_char,
}

impl ClientConfigBuilder {
    /// Set the address for the daemon
    pub fn daemon_addr(&mut self, addr: *const c_char) {
        self.daemon_addr = addr;
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

        let cfg = ClientConfig {
            daemon_addr: self.daemon_addr,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            daemon_addr: ptr::null(),
        }
    }
}

/// Configuration values for syncing with a peer
#[derive(Clone, Debug)]
pub struct SyncPeerConfig {
    interval: Option<Duration>,
    sync_now: bool,
    sync_on_hello: bool,
}

impl From<SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self::builder()
            .interval(value.interval.map(|d| d.into()))
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
    interval: Option<Duration>,
    sync_now: bool,
    sync_on_hello: bool,
}

impl SyncPeerConfigBuilder {
    /// Set the interval at which syncing occurs
    pub fn interval(&mut self, duration: Option<Duration>) {
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
            interval: None,
            sync_now: true,
            sync_on_hello: false,
        }
    }
}
