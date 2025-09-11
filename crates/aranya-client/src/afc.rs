//! AFC support.
use std::{fmt::Debug, sync::Arc};

use anyhow::Context;
use aranya_crypto::CipherSuite;
use aranya_daemon_api::{AfcChannelId, AfcShmInfo, ChanOp, DeviceId, LabelId, TeamId, CS};
use aranya_fast_channels::{
    shm::{Flag, Mode, ReadState},
    Client as AfcClient, Seq,
};
use tarpc::context;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    error::{aranya_error, IpcError},
    Client,
};

/// Possible errors that could happen when using Aranya Fast Channels.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AfcError {
    /// Unable to seal datagram.
    #[error("unable to seal datagram")]
    Seal(aranya_fast_channels::Error),

    /// Unable to open datagram.
    #[error("unable to open datagram")]
    Open(aranya_fast_channels::Error),

    /// Unable to parse shared-memory path.
    #[error("unable initialize shm")]
    Shm(anyhow::Error),

    /// No channel info found.
    #[error("no channel info found")]
    NoChannelInfoFound,

    /// Error parsing control message.
    #[error("failed to parse control message")]
    InvalidCtrlMessage(postcard::Error),

    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] buggy::Bug),
}

/// AFC control message sent to a peer when creating a channel.
pub type Ctrl = Vec<Box<[u8]>>;

/// Aranya Fast Channels handler for managing channels which allow encrypting/decrypting application data buffers.
pub struct AfcChannels<'a> {
    client: &'a Client,
    // TODO: don't use mutex for shm reader aranya-core#399
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
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcBidiChannel<'_>, Ctrl)> {
        let (ctrl, channel_id) = self
            .client
            .daemon
            .create_afc_bidi_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcBidiChannel {
                client: self.client,
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
        &self,
        team_id: TeamId,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> crate::Result<(AfcSendChannel<'_>, Ctrl)> {
        let (ctrl, channel_id) = self
            .client
            .daemon
            .create_afc_uni_channel(context::current(), team_id, peer_id, label_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok((
            AfcSendChannel {
                client: self.client,
                shm: self.shm.clone(),
                channel_id,
                label_id,
            },
            ctrl,
        ))
    }

    /// Receive a `ctrl` message from a peer to create an AFC channel.
    pub async fn recv_ctrl(&self, team_id: TeamId, ctrl: Ctrl) -> crate::Result<AfcChannel<'_>> {
        let (label_id, channel_id, op) = self
            .client
            .daemon
            .receive_afc_ctrl(context::current(), team_id, ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        match op {
            ChanOp::RecvOnly => Ok(AfcChannel::Uni(AfcUniChannel::Receive(AfcReceiveChannel {
                client: self.client,
                shm: self.shm.clone(),
                channel_id,
                label_id,
            }))),
            ChanOp::SendOnly => Ok(AfcChannel::Uni(AfcUniChannel::Send(AfcSendChannel {
                client: self.client,
                shm: self.shm.clone(),
                channel_id,
                label_id,
            }))),
            ChanOp::SendRecv => Ok(AfcChannel::Bidi(AfcBidiChannel {
                client: self.client,
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
    pub const fn overhead() -> usize {
        AfcClient::<ReadState<CS>>::OVERHEAD
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
    client: &'a Client,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl AfcBidiChannel<'_> {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Seal a plaintext datagram into a ciphertext buffer.
    ///
    /// The ciphertext buffer must have `AfcChannels::overhead()` more bytes allocated to it than the plaintext buffer:
    /// ciphertext.len() = plaintext.len() + AfcChannels::overhead()
    pub async fn seal(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
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

    /// Open a ciphertext datagram and return the plaintext buffer.
    ///
    /// The plaintext buffer must have `AfcChannels::overhead()` fewer bytes allocated to it than the ciphertext buffer:
    /// plaintext.len() = plaintext.len() - AfcChannels::overhead()
    pub async fn open(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<Seq, AfcError> {
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
            .map_err(AfcError::Open)
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel<'a> {
    client: &'a Client,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl AfcSendChannel<'_> {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Seal a plaintext datagram into a ciphertext buffer.
    ///
    /// The ciphertext buffer must have `AfcChannels::overhead()` more bytes allocated to it than the plaintext buffer:
    /// ciphertext.len() = plaintext.len() + AfcChannels::overhead()
    pub async fn seal(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
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

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// A unidirectional AFC channel that can only receive.
#[derive(Debug)]
pub struct AfcReceiveChannel<'a> {
    client: &'a Client,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl AfcReceiveChannel<'_> {
    /// The AFC channel ID.
    pub fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    /// The AFC channel's label ID.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Open a ciphertext datagram and return the plaintext buffer.
    ///
    /// The plaintext buffer must have `AfcChannels::overhead()` fewer bytes allocated to it than the ciphertext buffer:
    /// plaintext.len() = plaintext.len() - AfcChannels::overhead()
    pub async fn open(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<Seq, AfcError> {
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
            .map_err(AfcError::Open)
    }

    /// Delete the AFC channel.
    pub async fn delete(&self) -> Result<(), crate::Error> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }
}

/// AFC shared memory.
pub(crate) struct AfcShm(AfcClient<ReadState<CS>>);

impl AfcShm
where
    CS: CipherSuite,
{
    /// Open shared-memory to daemon's channel key list.
    pub fn new(afc_shm_info: &AfcShmInfo) -> Result<Self, AfcError> {
        // TODO: issue stellar-tapestry#34
        // afc::shm{ReadState, WriteState} doesn't work on linux/arm64
        debug!(
            "setting up afc shm read side: {:?}",
            afc_shm_info.path.clone()
        );
        let read = {
            ReadState::open(
                afc_shm_info.path.clone(),
                Flag::OpenOnly,
                Mode::ReadWrite,
                afc_shm_info.max_chans,
            )
            .context(format!(
                "unable to open `WriteState`: {:?}",
                afc_shm_info.path
            ))
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
