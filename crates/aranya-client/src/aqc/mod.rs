#![cfg(feature = "aqc")]
#![cfg_attr(docsrs, doc(cfg(feature = "aqc")))]

//! Aranya QUIC Channels (AQC).

mod api;
mod crypto;
mod net;

pub use api::{AqcChannels, BidiChannelId, UniChannelId};
pub(super) use net::AqcClient;
pub use net::{
    channels::{
        AqcBidiChannel, AqcBidiStream, AqcPeerChannel, AqcPeerStream, AqcReceiveChannel,
        AqcReceiveStream, AqcSendChannel, AqcSendStream,
    },
    TryReceiveError,
};
