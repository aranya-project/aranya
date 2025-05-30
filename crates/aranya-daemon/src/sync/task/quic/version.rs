//! QUIC Syncer supported versions.
//! New versions must be added to the end of this list since versions can never change.

use crate::sync::{Result as SyncResult, SyncError};

/// 0 indicates an error.
pub const VERSION_ERR: u8 = 0;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
/// Protocols supported by the syncer.
pub enum Version {
    /// Version 1.
    V1 = 1,
}

impl TryFrom<u8> for Version {
    type Error = SyncError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::V1),
            _ => Err(SyncError::UnknownVersion),
        }
    }
}

// Always default to latest version?
impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

pub(super) fn check_version(version_byte: u8, expected: Version) -> SyncResult<()> {
    let got = match version_byte {
        VERSION_ERR => return Err(SyncError::Version),
        v => Version::try_from(v)?,
    };

    if got != expected {
        return Err(SyncError::Version);
    }

    Ok(())
}
