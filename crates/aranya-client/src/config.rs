use std::time::Duration;

use crate::{Error, Result};

/// Configuration info for syncing with a peer.
#[derive(Debug, Clone)]
pub struct SyncPeerConfig {
    interval: Duration,
    sync_now: bool,
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
        }
    }
}

/// Builder for a [`SyncPeerConfig`]
pub struct SyncPeerConfigBuilder {
    interval: Option<Duration>,
    sync_now: bool,
}

impl SyncPeerConfigBuilder {
    /// Creates a new builder for [`SyncPeerConfig`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Attempts to build a [`SyncPeerConfig`] using the provided parameters.
    pub fn build(self) -> Result<SyncPeerConfig> {
        let Some(interval) = self.interval else {
            let e = Error::InvalidArg {
                arg: "interval",
                reason: "Tried to create a `SyncPeerConfig` without setting the interval!",
            };
            return Err(e);
        };

        Ok(SyncPeerConfig {
            interval,
            sync_now: self.sync_now,
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
}

impl Default for SyncPeerConfigBuilder {
    fn default() -> Self {
        Self {
            interval: None,
            sync_now: true,
        }
    }
}

/// Configuration info for adding and creating teams.
pub struct TeamConfig {}

impl TeamConfig {
    /// Creates a default [`TeamConfigBuilder`].
    pub fn builder() -> TeamConfigBuilder {
        Default::default()
    }
}

impl From<TeamConfig> for aranya_daemon_api::TeamConfig {
    fn from(_value: TeamConfig) -> Self {
        Self {}
    }
}

/// Builder for a [`TeamConfig`]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TeamConfigBuilder {}

impl TeamConfigBuilder {
    /// Creates a new builder for [`TeamConfig`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to build a [`TeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<TeamConfig> {
        Ok(TeamConfig {})
    }
}
