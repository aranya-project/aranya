//! Aranya syncer supported protocols.
//! New protocols must be added to the end of this list since protocol types can never change.

/// Protocols supported by the syncer.
pub enum SyncProtocols {
    /// QUIC syncer protocol.
    QUIC,
}
