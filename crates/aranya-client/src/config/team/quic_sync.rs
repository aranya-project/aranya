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

#![expect(deprecated)]

use crate::Result;

/// Size of the seed IKM (Input Keying Material) in bytes.
const SEED_IKM_SIZE: usize = 32;

/// Configuration for creating a new team with QUIC synchronization.
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CreateTeamQuicSyncConfig {}

impl CreateTeamQuicSyncConfig {
    /// Creates a new builder for team creation configuration.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn builder() -> CreateTeamQuicSyncConfigBuilder {
        CreateTeamQuicSyncConfigBuilder::default()
    }
}

/// Configuration for adding members to an existing team with QUIC synchronization.
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct AddTeamQuicSyncConfig {}

#[expect(deprecated)]
impl AddTeamQuicSyncConfig {
    /// Creates a new builder for team member addition configuration.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn builder() -> AddTeamQuicSyncConfigBuilder {
        AddTeamQuicSyncConfigBuilder::default()
    }
}

/// Builder for [`CreateTeamQuicSyncConfig`]
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct CreateTeamQuicSyncConfigBuilder {}

impl CreateTeamQuicSyncConfigBuilder {
    /// Sets the seed to be generated.
    ///
    /// Overwrites [`Self::seed_ikm`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    pub fn gen_seed(self) -> Self {
        self
    }

    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::gen_seed`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    pub fn seed_ikm(self, _ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self
    }

    /// Builds the config.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn build(self) -> Result<CreateTeamQuicSyncConfig> {
        Ok(CreateTeamQuicSyncConfig {})
    }
}

/// Builder for [`AddTeamQuicSyncConfig`]
#[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct AddTeamQuicSyncConfigBuilder {}

#[expect(deprecated)]
impl AddTeamQuicSyncConfigBuilder {
    /// Sets the seed mode to 'IKM'.
    ///
    /// Overwrites [`Self::wrapped_seed`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    pub fn seed_ikm(self, _ikm: [u8; SEED_IKM_SIZE]) -> Self {
        self
    }

    /// Sets the seed mode to 'Wrapped'.
    ///
    /// Overwrites [`Self::seed_ikm`].
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    pub fn wrapped_seed(self, _wrapped_seed: &[u8]) -> Result<Self> {
        Ok(self)
    }

    /// Builds the config.
    #[deprecated(note = "QUIC sync config is no longer needed with mTLS authentication")]
    pub fn build(self) -> Result<AddTeamQuicSyncConfig> {
        Ok(AddTeamQuicSyncConfig {})
    }
}
