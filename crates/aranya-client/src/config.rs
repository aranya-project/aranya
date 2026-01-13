#![warn(missing_docs)]

//! Client configurations.

use core::time::Duration;

use crate::{client::TeamId, error::InvalidArg, ConfigError, Result};

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

/// Builder for [`CreateTeamConfig`].
///
/// This type exists for backward compatibility. With mTLS authentication,
/// team configuration is no longer required.
#[derive(Debug, Default)]
pub struct CreateTeamConfigBuilder {
    #[allow(dead_code)]
    quic_sync: Option<CreateTeamQuicSyncConfig>,
}

impl CreateTeamConfigBuilder {
    /// Sets the QUIC sync configuration.
    ///
    /// This method exists for backward compatibility and is ignored.
    /// With mTLS authentication, PSK seeds are no longer used.
    pub fn quic_sync(mut self, config: CreateTeamQuicSyncConfig) -> Self {
        self.quic_sync = Some(config);
        self
    }

    /// Builds the configuration for creating a new team.
    pub fn build(self) -> Result<CreateTeamConfig> {
        Ok(CreateTeamConfig {})
    }
}

/// Configuration for creating a new team.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// team configuration is no longer required. The configuration is accepted
/// but ignored.
#[derive(Clone, Debug, Default)]
pub struct CreateTeamConfig {}

impl CreateTeamConfig {
    /// Creates a default [`CreateTeamConfigBuilder`].
    pub fn builder() -> CreateTeamConfigBuilder {
        CreateTeamConfigBuilder::default()
    }
}

/// Builder for [`AddTeamConfig`].
///
/// This type exists for backward compatibility. With mTLS authentication,
/// the add_team operation is no longer required.
#[derive(Debug, Default)]
pub struct AddTeamConfigBuilder {
    id: Option<TeamId>,
    #[allow(dead_code)]
    quic_sync: Option<AddTeamQuicSyncConfig>,
}

impl AddTeamConfigBuilder {
    /// Sets the ID of the team to add.
    pub fn team_id(mut self, id: TeamId) -> Self {
        self.id = Some(id);
        self
    }

    /// Sets the QUIC sync configuration.
    ///
    /// This method exists for backward compatibility and is ignored.
    /// With mTLS authentication, PSK seeds are no longer used.
    pub fn quic_sync(mut self, config: AddTeamQuicSyncConfig) -> Self {
        self.quic_sync = Some(config);
        self
    }

    /// Attempts to build an [`AddTeamConfig`] using the provided parameters.
    pub fn build(self) -> Result<AddTeamConfig> {
        let id = self.id.ok_or_else(|| {
            ConfigError::InvalidArg(InvalidArg::new(
                "id",
                "Missing `id` field when calling `AddTeamConfigBuilder::build`",
            ))
        })?;

        Ok(AddTeamConfig { id })
    }
}

/// Configuration for joining an existing team.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// devices authenticate via certificates at the connection level, not
/// per-team PSKs. The configuration is accepted but the operation is a no-op.
#[derive(Clone, Debug)]
pub struct AddTeamConfig {
    pub(crate) id: TeamId,
}

impl AddTeamConfig {
    /// Creates a default [`AddTeamConfigBuilder`].
    pub fn builder() -> AddTeamConfigBuilder {
        AddTeamConfigBuilder::default()
    }
}

// ============================================================================
// QuicSyncConfig types (backward compatibility - these are no-ops with mTLS)
// ============================================================================

/// Size of the seed IKM (Input Keying Material) in bytes.
///
/// This constant exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used.
pub const SEED_IKM_SIZE: usize = 32;

/// Mode for creating a PSK seed when creating a team.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Clone, Debug, Default)]
pub enum CreateSeedMode {
    /// Generate a random seed.
    #[default]
    Generate,
    /// Use the provided IKM (Input Keying Material).
    IKM([u8; SEED_IKM_SIZE]),
}

/// Mode for providing a PSK seed when adding a team.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Clone, Debug)]
pub enum AddSeedMode {
    /// Use the provided IKM (Input Keying Material).
    IKM([u8; SEED_IKM_SIZE]),
    /// Use a wrapped seed (serialized format).
    Wrapped(Vec<u8>),
}

/// Configuration for creating a new team with QUIC synchronization.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Clone, Debug)]
pub struct CreateTeamQuicSyncConfig {
    #[allow(dead_code)]
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfig {
    /// Creates a new builder for team creation configuration.
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }
}

/// Configuration for adding members to an existing team with QUIC synchronization.
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {
    #[allow(dead_code)]
    mode: AddSeedMode,
}

impl AddTeamQuicSyncConfig {
    /// Creates a new builder for team member addition configuration.
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for [`CreateTeamQuicSyncConfig`].
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    ///
    /// This method exists for backward compatibility and is ignored.
    #[doc(hidden)]
    pub fn mode(mut self, mode: CreateSeedMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// This method exists for backward compatibility and is ignored.
    /// Overwrites [`Self::seed_ikm`].
    pub fn gen_seed(mut self) -> Self {
        self.mode = CreateSeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// This method exists for backward compatibility and is ignored.
    /// Overwrites [`Self::gen_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = CreateSeedMode::IKM(ikm);
        self
    }

    /// Builds the config.
    pub fn build(self) -> Result<CreateTeamQuicSyncConfig> {
        Ok(CreateTeamQuicSyncConfig { mode: self.mode })
    }
}

/// Builder for [`AddTeamQuicSyncConfig`].
///
/// This type exists for backward compatibility. With mTLS authentication,
/// PSK seeds are no longer used and this configuration is ignored.
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<AddSeedMode>,
}

impl AddTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    ///
    /// This method exists for backward compatibility and is ignored.
    #[doc(hidden)]
    pub fn mode(mut self, mode: AddSeedMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// This method exists for backward compatibility and is ignored.
    /// Overwrites [`Self::wrapped_seed`].
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = Some(AddSeedMode::IKM(ikm));
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// This method exists for backward compatibility and is ignored.
    /// Overwrites [`Self::seed_ikm`].
    pub fn wrapped_seed(mut self, wrapped_seed: &[u8]) -> Result<Self> {
        // For backward compatibility, we accept the wrapped seed but don't validate it
        // since it's ignored anyway with mTLS.
        self.mode = Some(AddSeedMode::Wrapped(wrapped_seed.to_vec()));
        Ok(self)
    }

    /// Builds the config.
    pub fn build(self) -> Result<AddTeamQuicSyncConfig> {
        let Some(mode) = self.mode else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "mode",
                "`mode` must be set in order to build an `AddTeamQuicSyncConfig`",
            ))
            .into());
        };

        Ok(AddTeamQuicSyncConfig { mode })
    }
}
