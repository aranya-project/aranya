//! Aranya syncer supported protocols.
//! New protocols must be added to the end of this list since protocol types can never change.

/// 0 indicates an error.
pub const PROTOCOL_ERR: u8 = 0; // When to use this?

#[derive(Copy, Clone)]
#[repr(u8)]
/// Protocols supported by the syncer.
pub enum SyncProtocol {
    /// Version 1.
    V1 = 1,
}
