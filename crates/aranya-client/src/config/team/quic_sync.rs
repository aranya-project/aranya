//! Configuration for team synchronization over QUIC connections.
//!
//! # Overview
//!
//! There are two main configuration types:
//! - [`CreateTeamQuicSyncConfig`] - For creating new teams
//! - [`AddTeamQuicSyncConfig`] - For adding members to existing teams
//!
//! Note: With mTLS authentication, PSK seeds are no longer used.
//! These types exist for backward compatibility but are ignored internally.

// Allow deprecated usage within this module since we're implementing the deprecated API
#![allow(deprecated)]

use crate::{error::InvalidArg, ConfigError, Result};

/// Size of the seed IKM (Input Keying Material) in bytes.
///
/// # Deprecation Notice
///
/// With mTLS authentication, PSK seeds are no longer used for QUIC sync.
/// This constant exists for backward compatibility.
#[deprecated(note = "PSK-based sync replaced by mTLS. Seed IKM is no longer used.")]
pub const SEED_IKM_SIZE: usize = 32;

/// Mode for creating a PSK seed when creating a team.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub(crate) enum CreateSeedMode {
    /// Generate a random seed.
    #[default]
    Generate,
    /// Use the provided IKM (Input Keying Material).
    Ikm(Box<[u8; SEED_IKM_SIZE]>),
}

/// Mode for providing a PSK seed when adding a team.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum AddSeedMode {
    /// Use the provided IKM (Input Keying Material).
    Ikm(Box<[u8; SEED_IKM_SIZE]>),
    /// Use a wrapped (encrypted) seed.
    Wrapped(Vec<u8>),
}

/// Configuration for creating a new team with QUIC synchronization.
///
/// # Deprecation Notice
///
/// With mTLS authentication, PSK seeds are no longer used for QUIC sync.
/// This type exists for backward compatibility but is ignored internally.
#[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
#[derive(Clone, Debug)]
pub struct CreateTeamQuicSyncConfig {
    #[allow(dead_code)]
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfig {
    /// Creates a new builder for team creation configuration.
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }
}

/// Configuration for adding members to an existing team with QUIC synchronization.
///
/// # Deprecation Notice
///
/// With mTLS authentication, PSK seeds are no longer used for QUIC sync.
/// This type exists for backward compatibility but is ignored internally.
#[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {
    #[allow(dead_code)]
    mode: AddSeedMode,
}

impl AddTeamQuicSyncConfig {
    /// Creates a new builder for team member addition configuration.
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for [`CreateTeamQuicSyncConfig`]
///
/// # Deprecation Notice
///
/// With mTLS authentication, PSK seeds are no longer used for QUIC sync.
/// This builder exists for backward compatibility but the resulting config is ignored.
#[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {
    mode: CreateSeedMode,
}

impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn mode(mut self, mode: CreateSeedMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn gen_seed(mut self) -> Self {
        self.mode = CreateSeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = CreateSeedMode::Ikm(ikm.into());
        self
    }

    /// Builds the config.
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn build(self) -> Result<CreateTeamQuicSyncConfig> {
        Ok(CreateTeamQuicSyncConfig { mode: self.mode })
    }
}

/// Builder for [`AddTeamQuicSyncConfig`]
///
/// # Deprecation Notice
///
/// With mTLS authentication, PSK seeds are no longer used for QUIC sync.
/// This builder exists for backward compatibility but the resulting config is ignored.
#[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<AddSeedMode>,
}

impl AddTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn mode(mut self, mode: AddSeedMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = Some(AddSeedMode::Ikm(ikm.into()));
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// Overwrites [`Self::seed_ikm`].
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn wrapped_seed(mut self, wrapped_seed: &[u8]) -> Result<Self> {
        self.mode = Some(AddSeedMode::Wrapped(wrapped_seed.to_vec()));
        Ok(self)
    }

    /// Builds the config.
    #[deprecated(note = "PSK-based sync replaced by mTLS. This config is ignored.")]
    pub fn build(self) -> Result<AddTeamQuicSyncConfig> {
        let Some(mode) = self.mode else {
            return Err(ConfigError::InvalidArg(InvalidArg::new(
                "mode",
                "`mode` must be set in order to build an `AddQuicSyncConfig`",
            ))
            .into());
        };

        Ok(AddTeamQuicSyncConfig { mode })
    }
}
