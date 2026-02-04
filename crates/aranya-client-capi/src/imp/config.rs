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
    #[cfg(feature = "preview")]
    sync_on_hello: bool,
}

impl From<SyncPeerConfig> for aranya_client::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        let mut builder = Self::builder();
        if let Some(interval) = value.interval {
            builder = builder.interval(interval.into());
        }
        builder = builder.sync_now(value.sync_now);
        #[cfg(feature = "preview")]
        {
            builder = builder.sync_on_hello(value.sync_on_hello);
        }
        builder.build().expect("All values are set")
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
    #[cfg(feature = "preview")]
    sync_on_hello: bool,
}

impl SyncPeerConfigBuilder {
    /// Set the interval at which syncing occurs
    pub fn interval(&mut self, duration: Duration) {
        self.interval = Some(duration);
    }

    /// Configures whether the peer will be scheduled for an immediate sync when added.
    ///
    /// By default, the peer is scheduled for an immediate sync.
    pub fn sync_now(&mut self, sync_now: bool) {
        self.sync_now = sync_now;
    }

    /// Configures whether to automatically sync when a hello message is received from this peer
    /// indicating they have a head that we don't have.
    ///
    /// By default, sync on hello is disabled.
    #[cfg(feature = "preview")]
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
            #[cfg(feature = "preview")]
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
            #[cfg(feature = "preview")]
            sync_on_hello: false,
        }
    }
}

/// Configuration for hello subscription.
#[cfg(feature = "preview")]
#[derive(Clone, Debug)]
pub struct HelloSubscriptionConfig {
    /// Debounce interval for hello notifications after sending one.
    pub graph_change_debounce: Duration,
    /// How long the subscription remains active before expiring.
    pub expiration: Duration,
    /// Interval between periodic hello messages.
    pub periodic_interval: Duration,
}

#[cfg(feature = "preview")]
impl From<aranya_client::HelloSubscriptionConfig> for HelloSubscriptionConfig {
    fn from(value: aranya_client::HelloSubscriptionConfig) -> Self {
        Self {
            graph_change_debounce: value.graph_change_debounce().into(),
            expiration: value.expiration().into(),
            periodic_interval: value.periodic_interval().into(),
        }
    }
}

#[cfg(feature = "preview")]
impl From<HelloSubscriptionConfig> for aranya_client::HelloSubscriptionConfig {
    fn from(value: HelloSubscriptionConfig) -> Self {
        aranya_client::HelloSubscriptionConfig::builder()
            .graph_change_debounce(value.graph_change_debounce.into())
            .expiration(value.expiration.into())
            .periodic_interval(value.periodic_interval.into())
            .build()
            .expect("All values are set")
    }
}

#[cfg(feature = "preview")]
impl From<&HelloSubscriptionConfig> for aranya_client::HelloSubscriptionConfig {
    fn from(value: &HelloSubscriptionConfig) -> Self {
        value.clone().into()
    }
}

#[cfg(feature = "preview")]
impl Default for HelloSubscriptionConfig {
    fn default() -> Self {
        aranya_client::HelloSubscriptionConfig::default().into()
    }
}

/// Builder for a [`HelloSubscriptionConfig`].
#[cfg(feature = "preview")]
#[derive(Clone, Debug)]
pub struct HelloSubscriptionConfigBuilder {
    graph_change_debounce: Duration,
    expiration: Duration,
    periodic_interval: Duration,
}

#[cfg(feature = "preview")]
impl HelloSubscriptionConfigBuilder {
    /// Sets the graph_change_debounce interval for hello notifications.
    pub fn graph_change_debounce(&mut self, duration: Duration) {
        self.graph_change_debounce = duration;
    }

    /// Sets how long the subscription remains active before expiring.
    pub fn expiration(&mut self, duration: Duration) {
        self.expiration = duration;
    }

    /// Sets the interval between periodic hello messages.
    pub fn periodic_interval(&mut self, interval: Duration) {
        self.periodic_interval = interval;
    }
}

#[cfg(feature = "preview")]
impl Builder for HelloSubscriptionConfigBuilder {
    type Output = defs::HelloSubscriptionConfig;
    type Error = Error;

    /// # Safety
    ///
    /// No special considerations.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let cfg = HelloSubscriptionConfig {
            graph_change_debounce: self.graph_change_debounce,
            expiration: self.expiration,
            periodic_interval: self.periodic_interval,
        };
        Self::Output::init(out, cfg);
        Ok(())
    }
}

#[cfg(feature = "preview")]
impl Default for HelloSubscriptionConfigBuilder {
    fn default() -> Self {
        let config = HelloSubscriptionConfig::default();
        Self {
            graph_change_debounce: config.graph_change_debounce,
            expiration: config.expiration,
            periodic_interval: config.periodic_interval,
        }
    }
}
