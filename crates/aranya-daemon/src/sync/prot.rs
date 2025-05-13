//! Aranya syncer supported protocols.
//! New protocols must be added to the end of this list since protocol types can never change.

/// 0 indicates an error.
pub const PROTOCOL_ERR: u8 = 0;

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
/// Protocols supported by the syncer.
pub enum SyncProtocol {
    /// Version 1.
    V1 = 1,
}

impl TryFrom<u8> for SyncProtocol {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SyncProtocol::V1),
            _ => anyhow::bail!("Unknown protocol"),
        }
    }
}
