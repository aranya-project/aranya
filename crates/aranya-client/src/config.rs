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

    /// Configures whether the peer will be immediately synced with after being added.
    ///
    /// By default, the peer is immediately synced with.
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
