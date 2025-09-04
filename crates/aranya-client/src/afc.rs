//! AFC support.
use aranya_daemon_api::{AfcChannelId, LabelId};

use crate::{error::AfcError, Client};

/// AFC control message sent to a peer when creating a channel.
pub type Ctrl = Vec<u8>;

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
#[derive(Debug)]
pub struct AfcChannels<'a> {
    _client: &'a Client,
    // TODO: shm.
}

impl<'a> AfcChannels<'a> {
    pub(crate) fn new(_client: &'a Client) -> Self {
        Self { _client }
    }

    /// Create a bidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub fn create_bidi_channel(
        &self,
        _label_id: LabelId,
    ) -> Result<(AfcBidiChannel, Ctrl), AfcError> {
        todo!()
    }

    /// Create a unidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub fn create_uni_channel(
        &self,
        _label_id: LabelId,
    ) -> Result<(AfcUniChannel, Ctrl), AfcError> {
        todo!()
    }

    /// Receive a `ctrl` message from a peer to create an AFC channel.
    pub fn receive_channel(&self, _ctrl: Ctrl) -> Result<AfcChannel, AfcError> {
        todo!()
    }

    /// Create an AFC channel by removing channel key entry from shared memory.
    pub fn delete_channel(&self, _chan: AfcChannel) {
        todo!()
    }
}

/// An AFC channel.
#[derive(Debug)]
pub enum AfcChannel {
    /// A bidirectional channel.
    Bidi(AfcBidiChannel),
    /// A unidirectional channel.
    Uni(AfcUniChannel),
}

/// An unidirectional AFC channel.
#[derive(Debug)]
pub enum AfcUniChannel {
    /// A send channel.
    Send(AfcSendChannel),
    /// A receive channel.
    Receive(AfcReceiveChannel),
}

/// A bidirectional AFC channel.
#[derive(Debug)]
pub struct AfcBidiChannel {
    _channel_id: AfcChannelId,
    _label_id: LabelId,
}

impl Open for AfcBidiChannel {
    fn open(&self, _ciphertext: &[u8], _plaintext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

impl Seal for AfcBidiChannel {
    fn seal(&self, _plaintext: &[u8], _ciphertext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel {
    _channel_id: AfcChannelId,
    _label_id: LabelId,
}

impl Seal for AfcSendChannel {
    fn seal(&self, _plaintext: &[u8], _ciphertext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Debug)]
pub struct AfcReceiveChannel {
    _channel_id: AfcChannelId,
    _label_id: LabelId,
}

impl Open for AfcReceiveChannel {
    fn open(&self, _ciphertext: &[u8], _plaintext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

/// AFC channels that can seal datagrams should implement this trait.
pub trait Seal {
    /// Seal a plaintext datagram into ciphertext.
    fn seal(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError>;
}

/// AFC channels that can open datagrams should implement this trait.
pub trait Open {
    /// Open a ciphertext datagram and return the plaintext.
    fn open(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError>;
}
