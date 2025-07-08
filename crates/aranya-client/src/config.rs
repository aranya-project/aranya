#![warn(missing_docs)]

//! Client configurations.

use core::time::Duration;

use aranya_daemon_api::{SeedMode, SEED_IKM_SIZE};
use tracing::error;

use crate::{error::InvalidArg, ConfigError, Result};

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
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "interval",
                "must call `SyncPeerConfigBuilder::interval`",
            ))
            .into());
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

/// QUIC syncer configuration.
#[derive(Clone)]
pub struct QuicSyncConfig {
    seed_mode: SeedMode,
}

impl QuicSyncConfig {
    /// Creates a default [`QuicSyncConfigBuilder`].
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

/// QUIC syncer configuration builder.
#[derive(Clone, Default)]
pub struct QuicSyncConfigBuilder {
    seed_mode: SeedMode,
}

impl QuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: SeedMode) -> Self {
        self.seed_mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// This option is only valid when used in [`super::Client::create_team`].
    /// Overwrites [`Self::wrapped_seed`] and [`Self::seed_ikm`].
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    pub fn gen_seed(mut self) -> Self {
        self.seed_mode = SeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// This option is valid in both [`super::Client::create_team`] and [`super::Client::add_team`].
    /// Overwrites [`Self::wrapped_seed`] and [`Self::gen_seed`]
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.seed_mode = SeedMode::IKM(ikm.into());
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// This option is only valid in [`super::Client::add_team`].
    /// Overwrites [`Self::seed_ikm`] and [`Self::gen_seed`]
    ///
    /// This method will be removed soon since certificates will be used instead of PSKs in the future.
    pub fn wrapped_seed(mut self, wrapped_seed: &[u8]) -> Result<Self> {
        let wrapped = postcard::from_bytes(wrapped_seed).map_err(|err| {
            error!(?err);
            ConfigError::InvalidArg(InvalidArg::new("wrapped_seed", "could not deserialize"))
        })?;
        self.seed_mode = SeedMode::Wrapped(wrapped);
        Ok(self)
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig> {
        Ok(QuicSyncConfig {
            seed_mode: self.seed_mode,
        })
    }
}

/// Configuration info for adding and creating teams.
#[derive(Clone)]
pub struct TeamConfig {
    quic_sync: Option<QuicSyncConfig>,
}

impl TeamConfig {
    /// Creates a default [`TeamConfigBuilder`].
    pub fn builder() -> TeamConfigBuilder {
        Default::default()
    }
}

impl From<QuicSyncConfig> for aranya_daemon_api::QuicSyncConfig {
    fn from(value: QuicSyncConfig) -> Self {
        aranya_daemon_api::QuicSyncConfig {
            seed_mode: value.seed_mode,
        }
    }
}

impl From<TeamConfig> for aranya_daemon_api::TeamConfig {
    fn from(value: TeamConfig) -> Self {
        Self {
            quic_sync: value.quic_sync.map(Into::into),
        }
    }
}

/// Builder for a [`TeamConfig`].
#[derive(Clone, Default)]
pub struct TeamConfigBuilder {
    quic_sync: Option<QuicSyncConfig>,
}

impl TeamConfigBuilder {
    /// Creates a new builder for [`TeamConfig`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the quic_sync config.
    pub fn quic_sync(mut self, cfg: QuicSyncConfig) -> Self {
        self.quic_sync = Some(cfg);

        self
    }

    /// Attempts to build a [`TeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<TeamConfig> {
        Ok(TeamConfig {
            quic_sync: self.quic_sync,
        })
    }
}
