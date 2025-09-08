//! AFC support.
use std::{fmt::Debug, str::FromStr, sync::Arc};

use anyhow::Context;
use aranya_crypto::{default::DefaultCipherSuite, CipherSuite};
use aranya_daemon_api::{AfcChannelId, ChanOp, DeviceId, LabelId, TeamId, CS};
use aranya_fast_channels::{
    shm::{Flag, Mode, ReadState},
    Client as AfcClient,
};
use tarpc::context;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    error::{aranya_error, AfcError, IpcError},
    Client,
};

/// AFC control message sent to a peer when creating a channel.
pub type Ctrl = Vec<Box<[u8]>>;

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
pub struct AfcChannels<'a> {
    client: &'a Client,
    shm: Arc<Mutex<AfcShm>>,
}

// TODO: derive Debug on [`shm`] when [`AfcClient`] implements it.
impl Debug for AfcChannels<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcChannels")
            .field("client", &self.client)
            .finish()
    }
}

impl<'a> AfcChannels<'a> {
    pub(crate) fn new(client: &'a Client, shm: AfcShm) -> Self {
        Self {
            client,
            shm: Arc::new(Mutex::new(shm)),
        }
    }

    /// Create a bidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcBidiChannel, Ctrl)> {
        let (ctrl, channel_id) = self
            .client
            .daemon
            .create_afc_bidi_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcBidiChannel {
                shm: self.shm.clone(),
                channel_id,
                label_id,
            },
            ctrl,
        ))
    }

    /// Create a unidirectional AFC channel.
    ///
    /// Returns the channel object and a `ctrl` message to send to the peer.
    pub async fn create_uni_channel(
        &mut self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcSendChannel, Ctrl)> {
        let (ctrl, channel_id) = self
            .client
            .daemon
            .create_afc_uni_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcSendChannel {
                shm: self.shm.clone(),
                channel_id,
                label_id,
            },
            ctrl,
        ))
    }

    /// Receive a `ctrl` message from a peer to create an AFC channel.
    pub async fn receive_channel(
        &mut self,
        team_id: TeamId,
        ctrl: Ctrl,
    ) -> crate::Result<AfcChannel> {
        let (label_id, channel_id, op) = self
            .client
            .daemon
            .receive_afc_ctrl(context::current(), team_id, ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        match op {
            ChanOp::RecvOnly => Ok(AfcChannel::Uni(AfcUniChannel::Receive(AfcReceiveChannel {
                shm: self.shm.clone(),
                channel_id,
                label_id,
            }))),
            ChanOp::SendOnly => Ok(AfcChannel::Uni(AfcUniChannel::Send(AfcSendChannel {
                shm: self.shm.clone(),
                channel_id,
                label_id,
            }))),
            ChanOp::SendRecv => Ok(AfcChannel::Bidi(AfcBidiChannel {
                shm: self.shm.clone(),
                channel_id,
                label_id,
            })),
        }
    }

    /// Create an AFC channel by removing channel key entry from shared memory.
    pub async fn delete_channel(&self, channel_id: AfcChannelId) -> crate::Result<()> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Return ciphertext overhead.
    /// The ciphertext buffer should allocate plaintext.len() + overhead bytes.
    pub fn overhead() -> usize {
        AfcClient::<ReadState<DefaultCipherSuite>>::OVERHEAD
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
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Channel for AfcBidiChannel {
    fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    fn label_id(&self) -> LabelId {
        self.label_id
    }
}

impl Seal for AfcBidiChannel {
    async fn seal(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
        debug!(?self.channel_id, ?self.label_id, "seal");
        self.shm
            .lock()
            .await
            .0
            .seal(
                self.channel_id,
                self.label_id.into_id().into(),
                ciphertext,
                plaintext,
            )
            .map_err(AfcError::Seal)?;
        Ok(())
    }
}

impl Open for AfcBidiChannel {
    async fn open(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError> {
        debug!(?self.channel_id, ?self.label_id, "open");
        self.shm
            .lock()
            .await
            .0
            .open(
                self.channel_id,
                self.label_id.into_id().into(),
                plaintext,
                ciphertext,
            )
            .map_err(AfcError::Open)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel {
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Channel for AfcSendChannel {
    fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    fn label_id(&self) -> LabelId {
        self.label_id
    }
}

impl Seal for AfcSendChannel {
    async fn seal(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
        self.shm
            .lock()
            .await
            .0
            .seal(
                self.channel_id,
                self.label_id.into_id().into(),
                ciphertext,
                plaintext,
            )
            .map_err(AfcError::Seal)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Debug)]
pub struct AfcReceiveChannel {
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Channel for AfcReceiveChannel {
    fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    fn label_id(&self) -> LabelId {
        self.label_id
    }
}

impl Open for AfcReceiveChannel {
    async fn open(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError> {
        self.shm
            .lock()
            .await
            .0
            .open(
                self.channel_id,
                self.label_id.into_id().into(),
                plaintext,
                ciphertext,
            )
            .map_err(AfcError::Open)?;
        Ok(())
    }
}

/// AFC channels should all implement this trait.
pub trait Channel {
    /// AFC channel ID.
    fn channel_id(&self) -> AfcChannelId;

    /// AFC label ID.
    fn label_id(&self) -> LabelId;
}

/// AFC channels that can seal datagrams should implement this trait.
pub trait Seal {
    /// Seal a plaintext datagram into a ciphertext buffer.
    ///
    /// The ciphertext buffer must have `AfcChannels::overhead()` more bytes allocated to it than the plaintext buffer:
    /// ciphertext.len() = plaintext.len() + AfcChannels::overhead()
    async fn seal(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError>;
}

/// AFC channels that can open datagrams should implement this trait.
pub trait Open {
    /// Open a ciphertext datagram and return the plaintext buffer.
    ///
    /// The plaintext buffer must have `AfcChannels::overhead()` fewer bytes allocated to it than the ciphertext buffer:
    /// plaintext.len() = plaintext.len() - AfcChannels::overhead()
    async fn open(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), AfcError>;
}

/// AFC shared memory.
pub struct AfcShm(AfcClient<ReadState<DefaultCipherSuite>>);

impl AfcShm
where
    CS: CipherSuite,
{
    /// Open shared-memory to daemon's channel key list.
    pub fn new(shm_path: String, max_chans: usize) -> Result<Self, AfcError> {
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(?shm_path, "setting up afc shm read side");
        let read = {
            let path = aranya_util::ShmPathBuf::from_str(&shm_path)
                .context("unable to parse AFC shared memory path")
                .map_err(AfcError::Shm)?;
            ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
                .context(format!("unable to open `WriteState`: {:?}", shm_path))
                .map_err(AfcError::Shm)?
        };

        Ok(Self(AfcClient::new(read)))
    }
}

impl Debug for AfcShm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfcShm").finish()
    }
}
