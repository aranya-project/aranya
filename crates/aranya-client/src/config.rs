#![warn(missing_docs)]

//! Client configurations.

use core::time::Duration;

use crate::{error::InvalidArg, ConfigError, Result};

pub mod team;
pub use team::*;

/// Configuration info for syncing with a peer.
#[derive(Debug, Clone)]
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
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
            sync_on_hello: value.sync_on_hello,
        }
    }
}

/// Builder for a [`SyncPeerConfig`]
#[derive(Debug)]
pub struct SyncPeerConfigBuilder {
    interval: Option<Duration>,
    sync_now: bool,
    sync_on_hello: bool,
}

impl SyncPeerConfigBuilder {
    /// Creates a new builder for [`SyncPeerConfig`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Attempts to build a [`SyncPeerConfig`] using the provided parameters.
    pub fn build(self) -> Result<SyncPeerConfig> {
        let Some(interval) = self.interval else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "interval",
                "must call `SyncPeerConfigBuilder::interval`",
            ))
            .into());
        };

        Ok(SyncPeerConfig {
            interval,
            sync_now: self.sync_now,
            sync_on_hello: self.sync_on_hello,
        })
    }

    /// Sets the interval at which syncing occurs.
    ///
    /// By default, the interval is not set. It is an error to call [`build`][Self::build] before
    /// setting the interval with this method
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
            sync_on_hello: false,
        }
    }
}
