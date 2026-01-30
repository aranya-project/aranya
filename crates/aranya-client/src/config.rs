#![warn(missing_docs)]

//! Client configurations.

use core::time::Duration;

use crate::{error::InvalidArg, ConfigError, Result};

pub mod team;
pub use team::*;

/// Maximum sync interval of 1 year (365 days).
///
/// This limit prevents overflow when calculating deadlines in DelayQueue::insert(),
/// which adds the interval to Instant::now().
pub const MAX_SYNC_INTERVAL: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Configuration info for syncing with a peer.
#[derive(Clone, Debug)]
pub struct SyncPeerConfig {
    interval: Option<Duration>,
    sync_now: bool,
    #[cfg(feature = "preview")]
    sync_on_hello: bool,
}

impl SyncPeerConfig {
    /// Creates a default [`SyncPeerConfigBuilder`].
    pub fn builder() -> SyncPeerConfigBuilder {
        Default::default()
    }
}

impl From<SyncPeerConfig> for aranya_daemon_api::SyncPeerConfig {
    fn from(value: SyncPeerConfig) -> Self {
        Self {
            interval: value.interval,
            sync_now: value.sync_now,
            #[cfg(feature = "preview")]
            sync_on_hello: value.sync_on_hello,
        }
    }
}

/// Builder for a [`SyncPeerConfig`]
#[derive(Debug)]
pub struct SyncPeerConfigBuilder {
    interval: Option<Duration>,
    sync_now: bool,
    #[cfg(feature = "preview")]
    sync_on_hello: bool,
}

impl SyncPeerConfigBuilder {
    /// Creates a new builder for [`SyncPeerConfig`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Attempts to build a [`SyncPeerConfig`] using the provided parameters.
    pub fn build(self) -> Result<SyncPeerConfig> {
        // Check that interval doesn't exceed 1 year to prevent overflow when adding to Instant::now()
        // in DelayQueue::insert() (which calculates deadline as current_time + interval)
        if let Some(interval) = self.interval {
            if interval > MAX_SYNC_INTERVAL {
                return Err(ConfigError::InvalidArg(InvalidArg::new(
                    "duration",
                    "must not exceed 1 year to prevent overflow",
                ))
                .into());
            }
        }

        Ok(SyncPeerConfig {
            interval: self.interval,
            sync_now: self.sync_now,
            #[cfg(feature = "preview")]
            sync_on_hello: self.sync_on_hello,
        })
    }

    /// Sets the interval at which syncing occurs.
    ///
    /// The interval must be less than 1 year to prevent overflow when calculating deadlines.
    ///
    /// By default, the interval is not set (None), which means the peer will not be periodically synced.
    pub fn interval(mut self, duration: Duration) -> Self {
        self.interval = Some(duration);
        self
    }

    /// Configures whether the peer will be scheduled for an immediate sync when added.
    ///
    /// By default, the peer is scheduled for an immediate sync.
    pub fn sync_now(mut self, sync_now: bool) -> Self {
        self.sync_now = sync_now;
        self
    }

    /// Configures whether to automatically sync when a hello message is received from this peer
    /// indicating they have a head that we don't have.
    ///
    /// By default, sync on hello is disabled.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    pub fn sync_on_hello(mut self, sync_on_hello: bool) -> Self {
        self.sync_on_hello = sync_on_hello;
        self
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
///
/// This configures how a device subscribes to hello notifications from a sync peer.
/// Hello notifications inform subscribers when the peer's graph has changed,
/// enabling reactive syncing.
#[cfg(feature = "preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
#[derive(Clone, Debug)]
pub struct HelloSubscriptionConfig {
    graph_change_delay: Duration,
    expiration: Duration,
    periodic_interval: Duration,
}

#[cfg(feature = "preview")]
impl HelloSubscriptionConfig {
    /// Creates a default [`HelloSubscriptionConfigBuilder`].
    pub fn builder() -> HelloSubscriptionConfigBuilder {
        Default::default()
    }

    /// Minimum delay after a graph change before sending a hello notification.
    pub fn graph_change_delay(&self) -> Duration {
        self.graph_change_delay
    }

    /// How long the subscription remains active.
    pub fn expiration(&self) -> Duration {
        self.expiration
    }

    /// Interval between periodic hello messages.
    pub fn periodic_interval(&self) -> Duration {
        self.periodic_interval
    }
}

#[cfg(feature = "preview")]
impl Default for HelloSubscriptionConfig {
    fn default() -> Self {
        Self {
            graph_change_delay: Duration::from_millis(100),
            expiration: MAX_SYNC_INTERVAL,
            periodic_interval: Duration::from_secs(10),
        }
    }
}

/// Builder for a [`HelloSubscriptionConfig`].
#[cfg(feature = "preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
#[derive(Debug)]
pub struct HelloSubscriptionConfigBuilder {
    graph_change_delay: Duration,
    expiration: Duration,
    periodic_interval: Duration,
}

#[cfg(feature = "preview")]
impl HelloSubscriptionConfigBuilder {
    /// Creates a new builder for [`HelloSubscriptionConfig`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Attempts to build a [`HelloSubscriptionConfig`] using the provided parameters.
    pub fn build(self) -> Result<HelloSubscriptionConfig> {
        Ok(HelloSubscriptionConfig {
            graph_change_delay: self.graph_change_delay,
            expiration: self.expiration,
            periodic_interval: self.periodic_interval,
        })
    }

    /// Sets the minimum delay after a graph change before sending a hello notification.
    ///
    /// This helps batch rapid changes into fewer notifications. Default is 100ms.
    pub fn graph_change_delay(mut self, delay: Duration) -> Self {
        self.graph_change_delay = delay;
        self
    }

    /// Sets how long the subscription remains active before expiring.
    ///
    /// After this duration, the subscription will automatically end and no more
    /// hello notifications will be sent. Default is `MAX_SYNC_INTERVAL` (1 year).
    pub fn expiration(mut self, duration: Duration) -> Self {
        self.expiration = duration;
        self
    }

    /// Sets the interval between periodic hello messages.
    ///
    /// Periodic hello messages are sent at this interval regardless of graph changes. Default is 10 seconds.
    pub fn periodic_interval(mut self, interval: Duration) -> Self {
        self.periodic_interval = interval;
        self
    }
}

#[cfg(feature = "preview")]
impl Default for HelloSubscriptionConfigBuilder {
    fn default() -> Self {
        let config = HelloSubscriptionConfig::default();
        Self {
            graph_change_delay: config.graph_change_delay,
            expiration: config.expiration,
            periodic_interval: config.periodic_interval,
        }
    }
}
