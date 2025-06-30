use core::time::Duration;

use aranya_daemon_api::{SeedMode, TeamId, SEED_IKM_SIZE};
use serde::{Deserialize, Serialize};
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

// Fields added here should be set in QuicSyncConfigBuilder::from_cfg
#[derive(Clone)]
pub struct QuicSyncConfig {
    seed_mode: SeedMode,
}

impl QuicSyncConfig {
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

/// The builder for a [`QuicSyncConfig`].
///
/// The default seed mode is 'Generated'.
/// This can be overwritten by calling [`Self::wrapped_seed`] or [`Self::seed_ikm`]
#[derive(Clone, Default)]
pub struct QuicSyncConfigBuilder {
    seed_mode: SeedMode,
}

impl QuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(&mut self, mode: SeedMode) -> &mut Self {
        self.seed_mode = mode;
        self
    }

    /// Sets values using a QuicSyncConfig
    #[doc(hidden)]
    pub fn set_from_cfg(&mut self, cfg: QuicSyncConfig) -> &mut Self {
        self.seed_mode = cfg.seed_mode;
        self
    }

    /// Set the seed mode to 'Generated'.
    ///
    /// This option is only valid when used in [`super::Client::create_team`].
    /// Overwrites [`Self::wrapped_seed`] and [`Self::seed_ikm`].
    pub fn gen_seed(&mut self) -> &mut Self {
        self.seed_mode = SeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// This option is valid in both [`super::Client::create_team`] and [`super::Team::add_team`].
    /// Overwrites [`Self::wrapped_seed`] and [`Self::gen_seed`]
    pub fn seed_ikm(&mut self, ikm: [u8; SEED_IKM_SIZE]) -> &mut Self {
        self.seed_mode = SeedMode::IKM(ikm);
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// This option is only valid in [`super::Team::add_team`].
    /// Overwrites [`Self::seed_ikm`] and [`Self::gen_seed`]
    pub fn wrapped_seed(&mut self, wrapped_seed: &[u8]) -> Result<&mut Self> {
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

/// Represents team configuration information in various versions.
///
/// This enum contains versioned team data that can be serialized and used to
/// reconstruct team configs on different devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
#[non_exhaustive]
pub enum TeamInfo {
    V1 {
        /// Unique identifier for the team
        id: TeamId,
        /// Serialized representation of [`aranya_daemon_api::WrappedSeed`]
        wrapped_seed: Vec<u8>,
    },
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

/// Builder for a [`TeamConfig`]
#[derive(Clone, Default)]
pub struct TeamConfigBuilder {
    quic_sync: Option<QuicSyncConfigBuilder>,
}

impl TeamConfigBuilder {
    /// Creates a new builder for [`TeamConfig`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a mutable reference to the inner [`QuicSyncConfigBuilder`].
    /// This method must be called to initialize a QUIC sync config builder with default values.
    pub fn quic_sync(&mut self) -> &mut QuicSyncConfigBuilder {
        self.quic_sync.get_or_insert_default()
    }

    /// Creates a [`TeamConfigBuilder`] from persisted team information.
    ///
    /// Extracts the team ID and encrypted seed data from the provided team info
    /// and initializes a builder with the appropriate QUIC sync configuration.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// * The initialized [`TeamConfigBuilder`]
    /// * The [`TeamId`] extracted from the team info
    ///
    /// # Errors
    ///
    /// This method will return an error if:
    /// * The wrapped seed data cannot be deserialized to a [`aranya_daemon_api::WrappedSeed`]
    pub fn from_team_info_v1(team_info: TeamInfo) -> Result<(Self, TeamId)> {
        let TeamInfo::V1 { id, wrapped_seed } = team_info;

        let builder = {
            let mut team_cfg_builder = Self::new();
            let qs_builder = team_cfg_builder.quic_sync();
            qs_builder.wrapped_seed(&wrapped_seed)?;

            team_cfg_builder
        };

        Ok((builder, id))
    }

    /// Attempts to build a [`TeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<TeamConfig> {
        let quic_sync = match self.quic_sync {
            Some(qs_cfg_builder) => Some(qs_cfg_builder.build()?),
            None => None,
        };

        Ok(TeamConfig { quic_sync })
    }
}
