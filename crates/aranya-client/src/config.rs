use core::time::Duration;

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

#[derive(Clone)]
pub enum SeedType {
    Raw(Box<[u8]>),
    Wrapped {
        encrypted_seed: Box<[u8]>,
        encap_key: Box<[u8]>,
        sender_pk: Box<[u8]>,
    },
}

impl From<SeedType> for aranya_daemon_api::SeedType {
    fn from(value: SeedType) -> Self {
        match value {
            SeedType::Raw(seed) => Self::Raw(seed),
            SeedType::Wrapped {
                encrypted_seed,
                encap_key,
                sender_pk,
            } => Self::Wrapped {
                encrypted_seed,
                encap_key,
                sender_pk,
            },
        }
    }
}

#[derive(Clone)]
pub struct QuicSyncConfig {
    seed: SeedType,
}

impl QuicSyncConfig {
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct QuicSyncConfigBuilder {
    seed: Option<SeedType>,
}

impl QuicSyncConfigBuilder {
    /// Sets the raw seed.
    /// Overwrites [`Self::wrapped_seed`]
    pub fn raw_seed(mut self, seed: Box<[u8]>) -> Self {
        self.seed = Some(SeedType::Raw(seed));
        self
    }

    /// Sets the wrapped seed.
    /// Overwrites [`Self::raw_seed`]
    pub fn wrapped_seed(
        mut self,
        encrypted_seed: Box<[u8]>,
        encap_key: Box<[u8]>,
        sender_pk: Box<[u8]>,
    ) -> Self {
        self.seed = Some(SeedType::Wrapped {
            encrypted_seed,
            encap_key,
            sender_pk,
        });
        self
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig> {
        let Some(seed) = self.seed else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "seed",
                "must call `QuicSyncConfigBuilder::raw_seed or QuicSyncConfigBuilder::wrapped_seed`",
            ))
            .into());
        };

        Ok(QuicSyncConfig { seed })
    }
}

#[derive(Clone)]
/// Configuration info for adding and creating teams.
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
        Self::builder()
            .seed(value.seed.into())
            .build()
            .expect("All fields are set")
    }
}

impl From<TeamConfig> for aranya_daemon_api::TeamConfig {
    fn from(value: TeamConfig) -> Self {
        Self {
            quic_sync: value.quic_sync.map(Into::into),
        }
    }
}

/// Builder for a [`TeamConfig`]
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
