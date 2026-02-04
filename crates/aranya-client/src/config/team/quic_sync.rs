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

use crate::{error::InvalidArg, ConfigError, Result};

/// Size of the seed IKM (Input Keying Material) in bytes.
#[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
pub const SEED_IKM_SIZE: usize = 32;

/// Mode for creating a PSK seed when creating a team.
#[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
#[allow(deprecated)]
#[derive(Clone, Debug, Default)]
pub enum CreateSeedMode {
    /// Generate a random seed.
    #[default]
    Generate,
    /// Use the provided IKM (Input Keying Material).
    IKM(Box<[u8; SEED_IKM_SIZE]>),
}

/// Mode for providing a PSK seed when adding a team.
#[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
#[allow(deprecated)]
#[derive(Clone, Debug)]
pub enum AddSeedMode {
    /// Use the provided IKM (Input Keying Material).
    IKM(Box<[u8; SEED_IKM_SIZE]>),
    /// Use a wrapped (encrypted) seed.
    Wrapped(Vec<u8>),
}

/// Configuration for creating a new team with QUIC synchronization.
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, QUIC sync config is no longer needed.
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[allow(deprecated)]
#[derive(Clone, Debug)]
pub struct CreateTeamQuicSyncConfig {
    // Field is unused because PSK seeds are deprecated with mTLS authentication.
    // Kept for backward compatibility with existing API consumers.
    #[allow(dead_code)]
    mode: CreateSeedMode,
}

#[allow(deprecated)]
impl CreateTeamQuicSyncConfig {
    /// Creates a new builder for team creation configuration.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }
}

/// Configuration for adding members to an existing team with QUIC synchronization.
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, QUIC sync config is no longer needed.
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[allow(deprecated)]
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {
    // Field is unused because PSK seeds are deprecated with mTLS authentication.
    // Kept for backward compatibility with existing API consumers.
    #[allow(dead_code)]
    mode: AddSeedMode,
}

#[allow(deprecated)]
impl AddTeamQuicSyncConfig {
    /// Creates a new builder for team member addition configuration.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for [`CreateTeamQuicSyncConfig`]
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, QUIC sync config is no longer needed.
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[allow(deprecated)]
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {
    mode: CreateSeedMode,
}

#[allow(deprecated)]
impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: CreateSeedMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    pub fn gen_seed(mut self) -> Self {
        self.mode = CreateSeedMode::Generate;
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    #[allow(deprecated)]
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = CreateSeedMode::IKM(ikm.into());
        self
    }

    /// Builds the config.
    #[allow(deprecated)]
    pub fn build(self) -> Result<CreateTeamQuicSyncConfig> {
        Ok(CreateTeamQuicSyncConfig { mode: self.mode })
    }
}

/// Builder for [`AddTeamQuicSyncConfig`]
///
/// # Deprecated
///
/// This type is deprecated. With mTLS authentication, QUIC sync config is no longer needed.
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[allow(deprecated)]
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {
    mode: Option<AddSeedMode>,
}

#[allow(deprecated)]
impl AddTeamQuicSyncConfigBuilder {
    /// Sets the PSK seed mode.
    #[doc(hidden)]
    pub fn mode(mut self, mode: AddSeedMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    #[allow(deprecated)]
    pub fn seed_ikm(mut self, ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self.mode = Some(AddSeedMode::IKM(ikm.into()));
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// Overwrites [`Self::seed_ikm`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    #[allow(deprecated)]
    pub fn wrapped_seed(mut self, wrapped_seed: &[u8]) -> Result<Self> {
        self.mode = Some(AddSeedMode::Wrapped(wrapped_seed.to_vec()));
        Ok(self)
    }

    /// Builds the config.
    #[allow(deprecated)]
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
