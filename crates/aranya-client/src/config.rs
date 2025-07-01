use core::time::Duration;

use aranya_daemon_api::{SeedMode, TeamId, SEED_IKM_SIZE};
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

#[derive(Clone)]
pub struct QuicSyncConfig {
    seed_mode: SeedMode,
}

impl QuicSyncConfig {
    pub fn builder() -> QuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

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
    pub fn gen_seed(mut self) -> Self {
        self.seed_mode = SeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// This option is valid in both [`super::Client::create_team`] and [`super::Client::add_team`].
    /// Overwrites [`Self::wrapped_seed`] and [`Self::gen_seed`]
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.seed_mode = SeedMode::IKM(ikm);
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// This option is only valid in [`super::Client::add_team`].
    /// Overwrites [`Self::seed_ikm`] and [`Self::gen_seed`]
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

#[derive(Clone)]
/// Configuration info for adding teams.
pub struct AddTeamConfig {
    id: TeamId,
    quic_sync: Option<QuicSyncConfig>,
}

impl AddTeamConfig {
    /// Creates a default [`TeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        Default::default()
    }
}

#[derive(Clone)]
/// Configuration info for adding teams.
pub struct CreateTeamConfig {
    quic_sync: Option<QuicSyncConfig>,
}

impl CreateTeamConfig {
    /// Creates a default [`TeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
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

impl From<AddTeamConfig> for aranya_daemon_api::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        Self {
            id: value.id,
            quic_sync: value.quic_sync.map(Into::into),
        }
    }
}

impl From<CreateTeamConfig> for aranya_daemon_api::CreateTeamConfig {
    fn from(value: CreateTeamConfig) -> Self {
        Self {
            quic_sync: value.quic_sync.map(Into::into),
        }
    }
}

/// Common fields shared between team config builders.
///
/// This struct contains config options that are available
/// for both adding existing teams and creating new teams.
#[derive(Clone, Default)]
struct CommonBuilderFields {
    quic_sync: Option<QuicSyncConfig>,
}

/// Builder for [`AddTeamConfig`].
#[derive(Clone, Default)]
pub struct AddTeamConfigBuilder {
    id: Option<TeamId>,
    common: CommonBuilderFields,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(mut self, id: TeamId) -> Self {
        self.id = Some(id);
        self
    }

    /// Attempts to build a [`AddTeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<AddTeamConfig> {
        let id = self.id.ok_or_else(|| {
            ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
        })?;

        Ok(AddTeamConfig {
            id,
            quic_sync: self.common.quic_sync,
        })
    }
}

/// Builder for a [`CreateTeamConfig`]
#[derive(Clone, Default)]
pub struct CreateTeamConfigBuilder {
    common: CommonBuilderFields,
}

impl CreateTeamConfigBuilder {
    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {
            quic_sync: self.common.quic_sync,
        })
    }
}

/// Implements common methods shared between team config builders.
macro_rules! team_config_builder_common_impl {
    ($( $name:ident ),*) => {
        $(
            impl $name {
                #[doc = concat!("Creates a new builder for [`", stringify!($name), "`].")]
                pub fn new() -> Self {
                    Self::default()
                }

                /// Configures the quic_sync config..
                ///
                /// This is an optional field that configures how the team
                /// synchronizes data over QUIC connections.
                pub fn quic_sync(mut self, cfg: QuicSyncConfig) -> Self {
                    self.common.quic_sync = Some(cfg);
                    self
                }
            }
        )*
    };
}

team_config_builder_common_impl!(CreateTeamConfigBuilder, AddTeamConfigBuilder);
