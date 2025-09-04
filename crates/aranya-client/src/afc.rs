//! AFC support.
use std::{fmt::Debug, str::FromStr, sync::Arc};

use anyhow::Context;
use aranya_crypto::{default::DefaultCipherSuite, CipherSuite, Rng};
use aranya_daemon_api::{AfcChannelId, LabelId, CS};
use aranya_fast_channels::shm::{Flag, Mode, WriteState};
use tokio::sync::Mutex;
use tracing::debug;

use crate::{error::AfcError, Client};

/// AFC control message sent to a peer when creating a channel.
pub type Ctrl = Vec<u8>;

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
#[derive(Debug)]
pub struct AfcChannels<'a> {
    _client: &'a Client,
}

impl<'a> AfcChannels<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { _client: client }
    }

    /// Create a bidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub fn create_bidi_channel(
        &self,
        _label_id: LabelId,
    ) -> Result<(AfcBidiChannel<'_>, Ctrl), AfcError> {
        todo!()
    }

    /// Create a unidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub fn create_uni_channel(
        &self,
        _label_id: LabelId,
    ) -> Result<(AfcUniChannel<'_>, Ctrl), AfcError> {
        todo!()
    }

    /// Receive a `ctrl` message from a peer to create an AFC channel.
    pub fn receive_channel(&self, _ctrl: Ctrl) -> Result<AfcChannel<'_>, AfcError> {
        todo!()
    }

    /// Create an AFC channel by removing channel key entry from shared memory.
    pub fn delete_channel(&self, _chan: AfcChannel<'_>) {
        todo!()
    }
}

/// An AFC channel.
#[derive(Debug)]
pub enum AfcChannel<'a> {
    /// A bidirectional channel.
    Bidi(AfcBidiChannel<'a>),
    /// A unidirectional channel.
    Uni(AfcUniChannel<'a>),
}

/// An unidirectional AFC channel.
#[derive(Debug)]
pub enum AfcUniChannel<'a> {
    /// A send channel.
    Send(AfcSendChannel<'a>),
    /// A receive channel.
    Receive(AfcReceiveChannel<'a>),
}

/// A bidirectional AFC channel.
#[derive(Debug)]
pub struct AfcBidiChannel<'a> {
    _client: &'a Client,
    _channel_id: AfcChannelId,
    _label_id: LabelId,
    _shm: Arc<Mutex<AfcShm>>,
}

impl Open for AfcBidiChannel<'_> {
    fn open(&self, _ciphertext: &[u8], _plaintext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

impl Seal for AfcBidiChannel<'_> {
    fn seal(&self, _plaintext: &[u8], _ciphertext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel<'a> {
    _client: &'a Client,
    _channel_id: AfcChannelId,
    _label_id: LabelId,
}

impl Seal for AfcSendChannel<'_> {
    fn seal(&self, _plaintext: &[u8], _ciphertext: &mut [u8]) -> Result<(), AfcError> {
        todo!()
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Debug)]
pub struct AfcReceiveChannel<'a> {
    _client: &'a Client,
    _channel_id: AfcChannelId,
    _label_id: LabelId,
}

impl Open for AfcReceiveChannel<'_> {
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

/// AFC shared memory.
pub struct AfcShm {
    /// Handle to shared-memory with RW permissions.
    pub write: WriteState<DefaultCipherSuite, Rng>,
}

impl AfcShm
where
    CS: CipherSuite,
{
    /// Open shared-memory to daemon's channel key list.
    pub fn new(shm_path: String, max_chans: usize) -> Result<Self, AfcError> {
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(?shm_path, "setting up afc shm write side");
        let write = {
            let path = aranya_util::ShmPathBuf::from_str(&shm_path)
                .context("unable to parse AFC shared memory path")
                .map_err(AfcError::Shm)?;
            WriteState::open(&path, Flag::Create, Mode::ReadWrite, max_chans, Rng)
                .context(format!("unable to open `WriteState`: {:?}", shm_path))
                .map_err(AfcError::Shm)?
        };

        Ok(Self { write })
    }
}

impl Debug for AfcShm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcShm").finish()
    }
}
