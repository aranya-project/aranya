use core::time::Duration;

use aranya_daemon_api::{AddSeedMode, CreateSeedMode, TeamId, SEED_IKM_SIZE};
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

mod quic_sync {
    use aranya_daemon_api::{AddSeedMode, CreateSeedMode};

    #[derive(Clone)]
    pub struct Add {
        pub(super) mode: AddSeedMode,
    }

    #[derive(Clone)]
    pub struct Create {
        pub(super) mode: CreateSeedMode,
    }

    impl Create {
        pub(super) fn new(mode: CreateSeedMode) -> Self {
            Self { mode }
        }
    }

    impl Add {
        pub(super) fn new(mode: AddSeedMode) -> Self {
            Self { mode }
        }
    }

    #[derive(Clone, Default)]
    pub struct AddBuild {
        pub(super) mode: Option<AddSeedMode>,
    }

    #[derive(Clone, Default)]
    pub struct CreateBuild {
        pub(super) mode: CreateSeedMode,
    }
}

#[derive(Clone)]
pub struct QuicSyncConfig<T> {
    data: T,
}

pub type CreateQuicSyncConfig = QuicSyncConfig<quic_sync::Create>;
pub type AddQuicSyncConfig = QuicSyncConfig<quic_sync::Add>;

impl CreateQuicSyncConfig {
    pub fn builder() -> CreateQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

impl AddQuicSyncConfig {
    pub fn builder() -> AddQuicSyncConfigBuilder {
        QuicSyncConfigBuilder::default()
    }
}

#[derive(Clone, Default)]
pub struct QuicSyncConfigBuilder<T> {
    data: T,
}

type CreateQuicSyncConfigBuilder = QuicSyncConfigBuilder<quic_sync::CreateBuild>;
type AddQuicSyncConfigBuilder = QuicSyncConfigBuilder<quic_sync::AddBuild>;

impl CreateQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: CreateSeedMode) -> Self {
        self.data.mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn gen_seed(mut self) -> Self {
        self.data.mode = CreateSeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.data.mode = CreateSeedMode::IKM(ikm.into());
        self
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig<quic_sync::Create>> {
        Ok(QuicSyncConfig {
            data: quic_sync::Create::new(self.data.mode),
        })
    }
}

impl AddQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: AddSeedMode) -> Self {
        self.data.mode = Some(mode);
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.data.mode = Some(AddSeedMode::IKM(ikm.into()));
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn wrapped_seed(mut self, wrapped_seed: &[u8]) -> Result<Self> {
        let wrapped = postcard::from_bytes(wrapped_seed).map_err(|err| {
            error!(?err);
            ConfigError::InvalidArg(InvalidArg::new("wrapped_seed", "could not deserialize"))
        })?;
        self.data.mode = Some(AddSeedMode::Wrapped(wrapped));
        Ok(self)
    }

    /// Builds the config.
    pub fn build(self) -> Result<QuicSyncConfig<quic_sync::Add>> {
        let Some(mode) = self.data.mode else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "mode",
                "`mode` must be set in order to build an `AddTeamConfig`",
            ))
            .into());
        };

        Ok(QuicSyncConfig {
            data: quic_sync::Add::new(mode),
        })
    }
}

mod team {
    use aranya_daemon_api::TeamId;

    #[derive(Clone)]
    pub struct Add {
        pub(super) id: TeamId,
    }

    #[derive(Clone)]
    pub struct Create;

    impl Add {
        pub(super) fn new(id: TeamId) -> Self {
            Self { id }
        }
    }

    #[derive(Default)]
    pub struct AddBuild {
        pub(super) id: Option<TeamId>,
    }

    #[derive(Default)]
    pub struct CreateBuild;
}

#[derive(Clone)]
/// Builder for a [`TeamConfig`].
pub struct TeamConfigBuilder<T, U> {
    data: T,
    quic_sync: Option<QuicSyncConfig<U>>,
}

impl<T: Default, U> Default for TeamConfigBuilder<T, U> {
    fn default() -> Self {
        Self {
            data: T::default(),
            quic_sync: None,
        }
    }
}

pub type CreateTeamConfigBuilder = TeamConfigBuilder<team::CreateBuild, quic_sync::Create>;
pub type AddTeamConfigBuilder = TeamConfigBuilder<team::AddBuild, quic_sync::Add>;

#[derive(Clone)]
/// Configuration info for creating or adding teams.
pub struct TeamConfig<T, U> {
    data: T,
    quic_sync: Option<QuicSyncConfig<U>>,
}

pub type CreateTeamConfig = TeamConfig<team::Create, quic_sync::Create>;
pub type AddTeamConfig = TeamConfig<team::Add, quic_sync::Add>;

impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        TeamConfigBuilder::default()
    }
}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        TeamConfigBuilder::default()
    }
}

impl From<CreateQuicSyncConfig> for aranya_daemon_api::CreateQuicSyncConfig {
    fn from(value: CreateQuicSyncConfig) -> Self {
        aranya_daemon_api::CreateQuicSyncConfig {
            seed_mode: value.data.mode,
        }
    }
}

impl From<AddQuicSyncConfig> for aranya_daemon_api::AddQuicSyncConfig {
    fn from(value: AddQuicSyncConfig) -> Self {
        aranya_daemon_api::AddQuicSyncConfig {
            seed_mode: value.data.mode,
        }
    }
}

impl From<AddTeamConfig> for aranya_daemon_api::AddTeamConfig {
    fn from(value: AddTeamConfig) -> Self {
        Self {
            id: value.data.id,
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

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn id(mut self, id: TeamId) -> Self {
        self.data.id = Some(id);
        self
    }

    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic_sync(mut self, cfg: AddQuicSyncConfig) -> Self {
        self.quic_sync = Some(cfg);
        self
    }

    /// Attempts to build a [`AddTeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<AddTeamConfig> {
        let id = self.data.id.ok_or_else(|| {
            ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
        })?;

        Ok(AddTeamConfig {
            data: team::Add::new(id),
            quic_sync: self.quic_sync,
        })
    }
}

impl CreateTeamConfigBuilder {
    /// Configures the quic_sync config..
    ///
    /// This is an optional field that configures how the team
    /// synchronizes data over QUIC connections.
    pub fn quic_sync(mut self, cfg: CreateQuicSyncConfig) -> Self {
        self.quic_sync = Some(cfg);
        self
    }

    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {
            data: team::Create,
            quic_sync: self.quic_sync,
        })
    }
}
