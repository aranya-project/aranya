//! Aranya QUIC Channels (AQC).

mod api;
mod crypto;
mod net;

pub use api::AqcChannels;
pub(super) use net::AqcClient;
pub use net::{
    channels::{
        AqcBidiChannel, AqcBidiStream, AqcPeerChannel, AqcPeerStream, AqcReceiveChannel,
        AqcReceiveStream, AqcSendChannel, AqcSendStream,
    },
    TryReceiveError,
};
