//! AFC support.
use std::{fmt::Debug, sync::Arc};

use anyhow::Context;
use aranya_crypto::{default::DefaultCipherSuite, CipherSuite};
use aranya_daemon_api::{AfcChannelId, AfcShmInfo, ChanOp, DeviceId, LabelId, TeamId, CS};
use aranya_fast_channels::{
    shm::{Flag, Mode, ReadState},
    Client as AfcClient, Seq,
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
    pub async fn receive_channel(
        &self,
        team_id: TeamId,
        ctrl: Ctrl,
    ) -> crate::Result<AfcChannel<'_>> {
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
        AfcClient::<ReadState<DefaultCipherSuite>>::OVERHEAD
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

impl Channel for AfcBidiChannel<'_> {
    async fn delete(&self) -> Result<(), crate::Error> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    fn label_id(&self) -> LabelId {
        self.label_id
    }
}

impl Seal for AfcBidiChannel<'_> {
    async fn seal(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
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

impl Open for AfcBidiChannel<'_> {
    async fn open(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<Seq, AfcError> {
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
}

/// A unidirectional AFC channel that can only send.
#[derive(Debug)]
pub struct AfcSendChannel<'a> {
    client: &'a Client,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Channel for AfcSendChannel<'_> {
    async fn delete(&self) -> Result<(), crate::Error> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    fn label_id(&self) -> LabelId {
        self.label_id
    }
}

impl Seal for AfcSendChannel<'_> {
    async fn seal(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), AfcError> {
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
pub struct AfcReceiveChannel<'a> {
    client: &'a Client,
    shm: Arc<Mutex<AfcShm>>,
    channel_id: AfcChannelId,
    label_id: LabelId,
}

impl Channel for AfcReceiveChannel<'_> {
    async fn delete(&self) -> Result<(), crate::Error> {
        self.client
            .daemon
            .delete_afc_channel(context::current(), self.channel_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    fn channel_id(&self) -> AfcChannelId {
        self.channel_id
    }

    fn label_id(&self) -> LabelId {
        self.label_id
    }
}

impl Open for AfcReceiveChannel<'_> {
    async fn open(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<Seq, AfcError> {
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
}

/// AFC channels should all implement this trait.
pub trait Channel {
    /// Delete the channel.
    // TODO: return AfcError
    fn delete(&self) -> impl std::future::Future<Output = Result<(), crate::Error>> + Send;

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
    fn seal(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> impl std::future::Future<Output = Result<(), AfcError>> + Send;
}

/// AFC channels that can open datagrams should implement this trait.
pub trait Open {
    /// Open a ciphertext datagram and return the plaintext buffer.
    ///
    /// The plaintext buffer must have `AfcChannels::overhead()` fewer bytes allocated to it than the ciphertext buffer:
    /// plaintext.len() = plaintext.len() - AfcChannels::overhead()
    fn open(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> impl std::future::Future<Output = Result<Seq, AfcError>> + Send;
}

/// AFC shared memory.
pub struct AfcShm(AfcClient<ReadState<DefaultCipherSuite>>);

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
