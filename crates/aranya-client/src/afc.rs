//! AFC support.
//!
//! # Wire Format
//!
//! ```text
//! magic || len || msg
//! ```
//!
//! - `magic` is a 32-bit little-endian integer with the magic value `"AFC\0"`.
//! - `len` is a 32-bit little endian integer that contains the size in bytes of
//!   `msg`.
//! - `msg`: A postcard-encoded `StreamMsg`.

use std::{
    collections::{btree_map, BTreeMap, VecDeque},
    ffi::c_int,
    fmt,
    future::Future,
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::AsRawFd as _,
    path::Path,
    pin::Pin,
    str::FromStr as _,
    task::{Context, Poll},
};

use anyhow::anyhow;
use aranya_crypto::{Random as _, Rng};
pub use aranya_daemon_api::AfcId;
use aranya_daemon_api::{AfcCtrl, NetIdentifier, TeamId, CS};
pub use aranya_fast_channels::Label;
use aranya_fast_channels::{
    shm::{Flag, Mode, ReadState},
    AfcState, ChannelId, Client, Header, Message as InnerMsg, NodeId, Payload, Seq, Version,
};
use aranya_util::ShmPathBuf;
use buggy::{bug, Bug, BugExt as _};
use indexmap::{map, IndexMap};
use serde::{Deserialize, Serialize};
use tarpc::context;
use tokio::{
    io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};
use tracing::{debug, error, instrument, warn};

/// An AFC error.
#[derive(Debug, thiserror::Error)]
pub enum AfcError {
    /// Unable to bind a network addresss.
    #[error("unable to bind address: {0}")]
    Bind(io::Error),

    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

    /// The channel was not found.
    #[error("channel not found: {0}")]
    ChannelNotFound(AfcId),

    /// AFC message decryption failure.
    #[error("decryption failure: {0}")]
    Decryption(aranya_fast_channels::Error),

    /// DNS lookup failed.
    #[error("DNS lookup failed: {0}")]
    DnsLookup(io::Error),

    /// AFC message encryption failure.
    #[error("encryption failure: {0}")]
    Encryption(aranya_fast_channels::Error),

    /// The 64-bit sequence number overflowed and the end of the channel was
    /// reached. A new channel must be created.
    ///
    /// # Note
    ///
    /// This likely indicates that the peer manually set a very high sequence
    /// number.
    #[error("end of channel reached")]
    EndOfChannel,

    /// Invalid AFC header.
    #[error("invalid AFC header: {0}")]
    InvalidHeader(#[from] aranya_fast_channels::HeaderError),

    /// Invalid AFC magic.
    #[error("invalid magic: {0}")]
    InvalidMagic(u32),

    /// Invalid AFC message.
    #[error("invalid message: {0}")]
    InvalidMsg(#[from] aranya_fast_channels::ParseError),

    /// AFC message was replayed.
    #[error("AFC message was replayed: {0}")]
    MsgReplayed(String),

    /// The message length prefix was larger than the maximum
    /// allowed size.
    #[error("message too large: {got} > {max}")]
    MsgTooLarge { got: usize, max: usize },

    /// Payload is too small to be ciphertext.
    #[error("payload is too small to be ciphertext")]
    PayloadTooSmall,

    /// Local address failure.
    #[error("unable to get local address: {0}")]
    RouterAddr(io::Error),

    /// Serde serialization/deserialization error.
    #[error("serialization/deserialization error: {0}")]
    Serde(postcard::Error),

    /// Unable to parse shm path.
    #[error("unable to parse shared memory path: {0}")]
    ShmPathParse(aranya_fast_channels::shm::InvalidPathError),

    /// Unable to open the shm read state.
    #[error("unable to open shared memory `ReadState`: {0}")]
    ShmReadState(anyhow::Error),

    /// Unable to accept a TCP stream.
    #[error("unable to accept to TCP stream: {0}")]
    StreamAccept(io::Error),

    /// Unable to create a TCP stream.
    #[error("unable to connect to TCP stream: {0}")]
    StreamConnect(io::Error),

    /// Unable to read from TCP stream.
    #[error("unable to read from TCP stream: {0}")]
    StreamRead(io::Error),

    /// Unable to write to TCP stream.
    #[error("unable to write to TCP stream: {0}")]
    StreamWrite(io::Error),

    /// Unable to shutdown TCP stream.
    #[error("unable to shutdown TCP stream: {0}")]
    StreamShutdown(io::Error),

    /// Unable to get the remote peer's address.
    #[error("unable to get remote peer's address: {0}")]
    StreamPeerAddr(io::Error),

    /// The stream was not found.
    #[error("stream not found: {0}")]
    StreamNotFound(SocketAddr),

    /// AFC version mismatch.
    #[error("AFC version mismatch: got {actual:?}, expected {expected:?}")]
    VersionMismatch { expected: Version, actual: Version },

    /// Daemon reported error.
    #[error("daemon reported error: {0}")]
    Daemon(#[from] aranya_daemon_api::Error),

    /// Could not send request to daemon.
    #[error("could not send request to daemon: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    /// Some other error.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// The most recent state from [`poll`][FastChannel::poll].
#[derive(Clone, Debug)]
enum State {
    /// A peer opened a connection with us.
    Accept(SocketAddr),
    /// We recieved an incoming message.
    Msg(SocketAddr),
}

/// AFC messages.
///
/// These messages are sent/received between AFC peers via the TCP transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum StreamMsg {
    Ctrl(Ctrl),
    Data(Data),
}

/// An AFC control message.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Ctrl {
    version: Version,
    team_id: TeamId,
    /// Ephemeral command for AFC channel creation.
    cmd: AfcCtrl,
}

/// An AFC data (ciphertext) message.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Data {
    version: Version,
    afc_id: AfcId,
    ciphertext: Vec<u8>,
}

/// The size in bytes of `magic || len`.
///
/// See the wire format description.
const WIRE_HEADER_SIZE: usize = 4 + 4;

/// See the wire format description.
const WIRE_MAGIC: &[u8; 4] = b"AFC\0";

/// The maximum allowed size of a `StreamMsg`.
///
/// Helps prevent DoS attacks.
// TODO(eric): make this configurable.
const MAX_MSG_SIZE: u32 = 10 * 1024 * 1024;

/// Data that can be polled by the AFC router.
#[must_use]
#[derive(Debug)]
pub struct PollData(State);

/// An Aranya Fast Channel message.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// The plaintext data.
    pub data: Vec<u8>,
    /// The address from which the message was received.
    pub addr: SocketAddr,
    /// The channel from which the message was received.
    pub channel: AfcId,
    /// The Aranya Fast Channel label associated with the message.
    pub label: Label,
    /// The order of the message in the channel.
    pub seq: Seq,
}

/// Sends and receives AFC messages.
pub struct FastChannelsImpl<S> {
    /// The underlying AFC client.
    afc: Client<S>,
    /// Listens for incoming connections from peers.
    listener: TcpListener,
    /// Open TCP connections.
    // TODO(eric): prune unused/idle streams.
    // TODO(eric): use different maps for streams we opened vs streams that
    // peers opened.
    streams: TcpStreams,
    /// All open channels.
    chans: BTreeMap<AfcId, Channel>,
    /// Incrementing counter for unique [`NodeId`]s.
    // TODO: move this counter into the daemon.
    next_node_id: u32,
    /// Messages from `handle_data`.
    msgs: VecDeque<Message>,
    #[cfg(feature = "debug")]
    name: String,
}

impl<S: AfcState> FastChannelsImpl<S> {
    /// Creates a new `FastChannel` listening for connections on `addr`.
    pub(crate) async fn new<A>(afc: Client<S>, addr: A) -> Result<Self, AfcError>
    where
        A: ToSocketAddrs,
    {
        let listener = TcpListener::bind(addr).await.map_err(AfcError::Bind)?;
        Ok(Self {
            afc,
            listener,
            streams: TcpStreams::new(),
            chans: BTreeMap::new(),
            next_node_id: 0,
            msgs: VecDeque::new(),
            #[cfg(feature = "debug")]
            name: String::new(),
        })
    }

    /// Verifies that the router version is expected.
    fn check_version(&self, version: Version) -> Result<(), AfcError> {
        if version != Version::V1 {
            error!(got = ?version, want = ?Version::V1, "AFC version mismatch");
            Err(AfcError::VersionMismatch {
                expected: Version::V1,
                actual: version,
            })
        } else {
            Ok(())
        }
    }

    /// Polls the current AFC state.
    #[instrument(skip_all)]
    async fn inner_poll(&mut self) -> Result<State, AfcError> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;

            // An existing stream has a message.
            result = self.streams.next() => {
                result.map(State::Msg).map_err(Into::into)
            }

            // We have an incoming connection.
            result = self.listener.accept() => {
                result
                    .map(|(stream, addr)| {
                        debug!(%addr, "accepted incoming TCP stream");
                        self.streams.insert(stream)?;
                        Ok::<_, AfcError>(addr)
                    })
                    .map_err(AfcError::StreamAccept)?
                    .map(State::Accept)
            }
        }
    }

    /// Sends a control message to the peer at `net_id`.
    // NB: Eliding `net_id` and `team_id` since `create_bidi_channel` also adds
    // those.
    #[instrument(skip_all, fields(
        %afc_id,
        %chan_id,
    ))]
    async fn send_ctrl(
        &mut self,
        net_id: NetIdentifier,
        cmd: AfcCtrl,
        team_id: TeamId,
        afc_id: AfcId,
        chan_id: ChannelId,
    ) -> Result<(), AfcError> {
        debug!("sending control message");

        // TODO(eric): Don't allocate here.
        let data = postcard::to_allocvec(&StreamMsg::Ctrl(Ctrl {
            version: Version::V1,
            team_id,
            cmd,
        }))
        .map_err(AfcError::Serde)?;
        debug!(len = data.len(), "encoded ctrl message");

        let len = u32::try_from(data.len())
            .assume("`data` should be < 2^32-1")?
            .to_le_bytes();

        let stream = {
            // Try to find an open stream with this peer.
            let addr = tokio::net::lookup_host(net_id.as_ref())
                .await
                .map_err(AfcError::DnsLookup)?
                .find(|addr| {
                    debug!(%addr, "resolved potential address");
                    self.streams.contains(addr)
                });
            self.streams
                .try_get_or_open((addr, net_id.as_ref()))
                .await?
        };
        let addr = stream.peer_addr().map_err(AfcError::StreamPeerAddr)?;
        debug!(%addr, "connected to peer");

        stream
            .write_all_vectored(&mut [
                IoSlice::new(WIRE_MAGIC),
                IoSlice::new(&len),
                IoSlice::new(&data),
            ])
            .await
            .map_err(AfcError::StreamWrite)?;
        stream.flush().await.map_err(AfcError::StreamWrite)?;
        debug!("sent control message");

        // TODO(eric): This throws away `stream` if we already have a stream
        // with this address.
        self.add_channel(afc_id, net_id, team_id, chan_id, addr)
            .await?;

        Ok(())
    }

    /// Encrypts `plaintext` and sends it over the AFC channel.
    // NB: Eliding `id` since `FastChannels::send_data` also adds it.
    #[instrument(skip_all)]
    async fn send_data(&mut self, id: AfcId, plaintext: &[u8]) -> Result<(), AfcError> {
        debug!(pt_len = plaintext.len(), "sending data");

        let Channel {
            net_id,
            chan_id,
            addr,
            ..
        } = self
            .chans
            .get(&id)
            .ok_or_else(|| AfcError::ChannelNotFound(id))?;
        debug!(%chan_id, %addr, "found channel");

        // TODO(eric): Don't allocate here. Use `IoSlice` instead.
        let datagram = {
            // We need enough space to write [header || ciphertext]
            let mut buf = vec![0u8; Header::PACKED_SIZE + plaintext.len() + Client::<S>::OVERHEAD];
            let (header, ciphertext) = buf
                .split_first_chunk_mut()
                .assume("`buf.len()` >= `Header::PACKED_SIZE`")?;
            debug!(%chan_id, "sealing message");
            let hdr = self
                .afc
                .seal(*chan_id, ciphertext, plaintext)
                .map_err(AfcError::Encryption)?;
            debug!(%chan_id, "sealed message");
            hdr.encode(header)?;
            buf
        };
        debug!(len = datagram.len(), "created datagram");

        // TODO(eric): Don't allocate here.
        let data = postcard::to_allocvec(&StreamMsg::Data(Data {
            version: Version::V1,
            afc_id: id,
            ciphertext: datagram,
        }))
        .map_err(AfcError::Serde)?;
        debug!(len = data.len(), "encoded data message");

        let len = u32::try_from(data.len())
            .assume("`data` should be < 2^32-1")?
            .to_le_bytes();

        let stream = self.streams.get_or_open((*addr, net_id.as_ref())).await?;
        stream
            .write_all_vectored(&mut [
                IoSlice::new(WIRE_MAGIC),
                IoSlice::new(&len),
                IoSlice::new(&data),
            ])
            .await
            .map_err(AfcError::StreamWrite)?;
        stream.flush().await.map_err(AfcError::StreamWrite)?;
        debug!(data_len = data.len(), "wrote msg to stream");

        Ok(())
    }

    /// Reads a `StreamMsg` from the stream.
    #[instrument(skip_all, fields(%addr))]
    async fn read_msg(&mut self, addr: SocketAddr) -> Result<StreamMsg, AfcError> {
        debug!("reading message from stream");

        let stream = self
            .streams
            .get_mut(&addr)
            .ok_or_else(|| AfcError::StreamNotFound(addr))?;

        stream.readable().await.map_err(AfcError::StreamRead)?;

        let mut buf = [[0u8; 4]; 2];
        stream
            .read_exact(buf.as_flattened_mut())
            .await
            .map_err(AfcError::StreamRead)?;

        let magic = buf[0];
        if magic != *WIRE_MAGIC {
            error!(got = ?magic, expected = ?WIRE_MAGIC, "invalid magic");
            return Err(AfcError::InvalidMagic(u32::from_le_bytes(magic)));
        }

        let len = u32::from_le_bytes(buf[1]);
        if len > MAX_MSG_SIZE {
            error!(got = %len, expected = %MAX_MSG_SIZE, "msg size too large");
            return Err(AfcError::MsgTooLarge {
                got: len.try_into().unwrap_or(usize::MAX),
                max: MAX_MSG_SIZE.try_into().unwrap_or(usize::MAX),
            });
        }
        debug!(%len, "read message length");

        // TODO(eric): Use a cached buffer.
        let mut buf = vec![0; len as usize];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(AfcError::StreamRead)?;
        debug!(%len, "read message bytes");

        postcard::from_bytes(&buf).map_err(AfcError::Serde)
    }

    /// Decrypts `data`.
    #[instrument(skip_all, fields(afc_id = %data.afc_id))]
    fn open_data(&mut self, data: Data) -> Result<(Vec<u8>, AfcId, Label, Seq), AfcError> {
        debug!(n = data.ciphertext.len(), "decrypting data");

        self.check_version(data.version)?;

        let chan = self
            .chans
            .get_mut(&data.afc_id)
            .ok_or_else(|| AfcError::ChannelNotFound(data.afc_id))?;
        let chan_id = chan.chan_id;
        debug!(%chan_id, "found channel");

        // Might as well check this first to limit how much work we do for
        // expired channels.
        let next_min_seq = chan.next_min_seq()?;

        let InnerMsg { payload, .. } = InnerMsg::try_parse(&data.ciphertext)?;
        let ciphertext = match payload {
            Payload::Data(v) => v,
            Payload::Control(_) => bug!("`Data` should not contain control messages"),
        };

        // TODO(eric): Update `Message` to handle both shared and exclusive refs
        // so that we can reuse the `data.ciphertext` allocation.
        let plaintext_len = ciphertext
            .len()
            .checked_sub(Client::<S>::OVERHEAD)
            .ok_or(AfcError::PayloadTooSmall)?;
        let mut plaintext = vec![0; plaintext_len];
        let (label, seq) = self
            .afc
            .open(chan_id.node_id(), &mut plaintext, ciphertext)
            .map_err(AfcError::Decryption)?;
        debug!(%label, %seq, "decrypted data");

        if chan_id.label() != label {
            error!(got = %label, expected = %chan_id.label(), "mismatched labels");
            bug!("decrypted data with mismatched labels");
        }

        if seq < next_min_seq {
            // TODO(eric): zeroize `plaintext`.
            return Err(AfcError::MsgReplayed(format!("{seq}")));
        }
        chan.next_min_seq = seq.to_u64().checked_add(1).map(Seq::new);
        debug!(next = %FmtOr(chan.next_min_seq, "expired"), "min next seq number");

        Ok((plaintext, data.afc_id, label, seq))
    }

    /// Returns the address that AFC is bound to.
    pub(crate) fn local_addr(&self) -> Result<SocketAddr, AfcError> {
        self.listener.local_addr().map_err(AfcError::RouterAddr)
    }

    /// Get the next Node ID in the sequence.
    async fn get_next_node_id(&mut self) -> Result<NodeId, AfcError> {
        let node_id = NodeId::new(self.next_node_id);
        self.next_node_id += 1;
        Ok(node_id)
    }

    /// Adds a new channel.
    ///
    /// It is an error if the channel already exists.
    #[instrument(skip_all, fields(
        afc_id = %id,
        %net_id,
        %team_id,
        %chan_id,
        %addr,
    ))]
    async fn add_channel(
        &mut self,
        id: AfcId,
        net_id: NetIdentifier,
        team_id: TeamId,
        chan_id: ChannelId,
        addr: SocketAddr,
    ) -> Result<(), AfcError> {
        debug!("adding channel");

        match self.chans.entry(id) {
            // Reject duplicates because
            // 1. Channel IDs are globally unique (a cryptographically
            //    negligible probability of collisions). This probably means
            //    we're processing the same `ctrl` again. It might mean that the
            //    graph/daemon/whatever is buggy?
            // 2. It would reset the sequence number, which would allow replay
            //    attacks.
            btree_map::Entry::Occupied(_) => {
                warn!(%id, "duplicate channel ID");

                // Don't return an error, though, since the most likely cause is
                // that we're processing a duplicate control message.
            }
            btree_map::Entry::Vacant(v) => {
                v.insert(Channel {
                    net_id,
                    chan_id,
                    // `addr` comes from either `Status::Accept` or `send_ctrl`,
                    // so use it instead of performing a DNS lookup. In both
                    // cases we likely already have an open TCP stream. If we
                    // don't, the next operation on the channel will perform the
                    // DNS lookup anyway.
                    addr,
                    next_min_seq: Some(Seq::ZERO),
                });
            }
        }
        debug!("added channel");

        Ok(())
    }

    /// Deletes a channel.
    #[instrument(skip_all, fields(afc_id = %id))]
    async fn remove_channel(&mut self, id: AfcId) {
        debug!("removing channel");

        self.chans.remove(&id);
    }
}

impl<S: AfcState> FastChannelsImpl<S> {
    #[doc(hidden)]
    fn set_name(&mut self, _name: String) {
        #[cfg(feature = "debug")]
        {
            self.name = _name;
        }
    }

    #[cfg(feature = "debug")]
    fn debug(&self) -> &str {
        &self.name
    }

    #[cfg(not(feature = "debug"))]
    fn debug(&self) -> tracing::field::Empty {
        tracing::field::Empty
    }
}

impl<S> fmt::Debug for FastChannelsImpl<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("listener", &self.listener)
            .field("streams", &self.streams)
            .field("chans", &self.chans)
            .field("next_node_id", &self.next_node_id)
            .finish_non_exhaustive()
    }
}

pub struct FastChannels<'a> {
    client: &'a mut crate::Client,
}

impl<'a> FastChannels<'a> {
    pub(crate) fn new(client: &'a mut crate::Client) -> Self {
        Self { client }
    }

    #[doc(hidden)]
    pub fn set_name(&mut self, name: String) {
        self.client.afc.set_name(name)
    }

    /// Returns the address that AFC is bound to.
    pub async fn local_addr(&self) -> crate::Result<SocketAddr> {
        self.client.afc.local_addr().map_err(Into::into)
    }

    /// Creates a bidirectional AFC channel with a peer.
    ///
    /// `label` associates the channel with a set of policy rules that govern
    /// the channel. Both peers must already have permission to use the label.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(self = self.client.afc.debug(), %team_id, %peer, %label))]
    pub async fn create_bidi_channel(
        &mut self,
        team_id: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> crate::Result<AfcId> {
        debug!("creating bidi channel");

        let node_id = self.client.afc.get_next_node_id().await?;
        debug!(%node_id, "selected node ID");

        let (afc_id, ctrl) = self
            .client
            .daemon
            .create_afc_bidi_channel(context::current(), team_id, peer.clone(), node_id, label)
            .await??;
        debug!(%afc_id, %node_id, %label, "created bidi channel");

        let chan_id = ChannelId::new(node_id, label);
        self.client
            .afc
            .send_ctrl(peer, ctrl, team_id, afc_id, chan_id)
            .await?;
        debug!("sent control message");

        Ok(afc_id)
    }

    /// Deletes an AFC channel.
    // TODO(eric): Is it an error if the channel does not exist?
    #[instrument(skip_all, fields(self = self.client.afc.debug(), afc_id = %id))]
    pub async fn delete_channel(&mut self, id: AfcId) -> crate::Result<()> {
        let _ctrl = self
            .client
            .daemon
            .delete_afc_channel(context::current(), id)
            .await??;
        self.client.afc.remove_channel(id).await;
        // TODO(eric): Send control message.
        // self.afc.send_ctrl(peer, ctrl, team_id, id, chan_id);
        Ok(())
    }

    /// Send AFC data over a specific fast channel.
    ///
    /// # Cancellation Safety
    ///
    /// It is safe to cancel the resulting future. However, a partial message
    /// may be written to the channel.
    // TODO(eric): Return a sequence number?
    #[instrument(skip_all, fields(self = self.client.afc.debug(), afc_id = %id))]
    pub async fn send_data(&mut self, id: AfcId, plaintext: &[u8]) -> crate::Result<()> {
        self.client
            .afc
            .send_data(id, plaintext)
            .await
            .map_err(Into::into)
    }

    /// Retrieves the next AFC message, if any.
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    // TODO: return [`NetIdentifier`] instead of [`SocketAddr`].
    // TODO: read into buffer instead of returning `Vec<u8>`.
    #[instrument(skip_all, fields(self = self.client.afc.debug()))]
    pub fn try_recv_data(&mut self) -> Option<Message> {
        // TODO(eric): This method should block until a message
        // has been received.
        let msg = self.client.afc.msgs.pop_front()?;
        debug!(label = %msg.label, seq = %msg.seq, "received AFC data message");
        Some(msg)
    }

    /// Polls the client to check for new data, then retrieves any new data.
    ///
    /// This is shorthand for [`poll_data`][Self::poll_data] and
    /// [`handle_data`][Self::handle_data].
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all)]
    pub async fn poll(&mut self) -> crate::Result<()> {
        let data = self.poll_data().await?;
        self.handle_data(data).await
    }

    /// Polls the client to check for new data.
    ///
    /// # Cancellation Safety
    ///
    /// It is safe to cancel the resulting future.
    #[instrument(skip_all)]
    pub async fn poll_data(&mut self) -> crate::Result<PollData> {
        let data = self.client.afc.inner_poll().await?;
        Ok(PollData(data))
    }

    /// Retrieves data from [`poll_data`][Self::poll_data].
    ///
    /// # Cancellation Safety
    ///
    /// It is NOT safe to cancel the resulting future. Doing so might lose data.
    #[instrument(skip_all, fields(self = self.client.afc.debug(), ?data))]
    pub async fn handle_data(&mut self, data: PollData) -> crate::Result<()> {
        let afc = &mut self.client.afc;
        match data.0 {
            State::Accept(addr) | State::Msg(addr) => match afc.read_msg(addr).await? {
                StreamMsg::Data(data) => {
                    debug!(%addr, "read data message");

                    let (data, channel, label, seq) = afc.open_data(data)?;
                    afc.msgs.push_back(Message {
                        data,
                        addr,
                        channel,
                        label,
                        seq,
                    });
                    debug!(n = afc.msgs.len(), "stored msg");
                }
                StreamMsg::Ctrl(ctrl) => {
                    debug!(%addr, "read control message");

                    let node_id = afc.get_next_node_id().await?;
                    debug!(%node_id, "selected node ID");

                    let (afc_id, peer, label) = self
                        .client
                        .daemon
                        .receive_afc_ctrl(context::current(), ctrl.team_id, node_id, ctrl.cmd)
                        .await??;
                    debug!(%node_id, %label, "applied AFC control msg");

                    let channel_id = ChannelId::new(node_id, label);
                    afc.add_channel(afc_id, peer, ctrl.team_id, channel_id, addr)
                        .await?;
                }
            },
        }
        Ok(())
    }
}

/// Setup the Aranya Client's read side of the AFC channel keys shared memory.
pub(crate) fn setup_afc_shm(shm_path: &Path, max_chans: usize) -> Result<ReadState<CS>, AfcError> {
    debug!(?shm_path, "setting up afc shm read side");

    let Some(path) = shm_path.to_str() else {
        return Err(anyhow!("unable to convert shm path to string").into());
    };
    let path = ShmPathBuf::from_str(path).map_err(AfcError::ShmPathParse)?;
    let read = ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
        .map_err(Into::into)
        .map_err(AfcError::ShmReadState)?;
    Ok(read)
}

/// A set of TCP streams, keyed by the remote peer's address.
#[derive(Debug)]
struct TcpStreams {
    streams: IndexMap<SocketAddr, TcpStream>,
}

impl TcpStreams {
    fn new() -> Self {
        Self {
            streams: IndexMap::new(),
        }
    }

    /// Gets or opens a stream with `peer`.
    async fn get_or_open(
        &mut self,
        peer: (SocketAddr, impl ToSocketAddrs),
    ) -> Result<&mut TcpStream, AfcError> {
        let (addr, host) = peer;
        let prev_len = self.streams.len();
        match self.streams.entry(addr) {
            map::Entry::Occupied(v) => Ok(v.into_mut()),
            map::Entry::Vacant(v) => {
                debug!("opening new stream");

                let stream = TcpStream::connect(host)
                    .await
                    .map_err(AfcError::StreamConnect)?;
                debug!(addr = %TryFmt(stream.peer_addr()), "connected to peer");

                let stream = v.insert(stream);
                debug!(len = prev_len + 1, "inserted stream");
                Ok(stream)
            }
        }
    }

    /// Gets or opens a stream with `peer`.
    async fn try_get_or_open(
        &mut self,
        peer: (Option<SocketAddr>, impl ToSocketAddrs),
    ) -> Result<&mut TcpStream, AfcError> {
        let (addr, host) = peer;
        if let Some(addr) = addr {
            self.get_or_open((addr, host)).await
        } else {
            self.connect(host).await
        }
    }

    /// Opens a new stream with `peer`.
    async fn connect(&mut self, peer: impl ToSocketAddrs) -> Result<&mut TcpStream, AfcError> {
        debug!("opening new stream");

        let stream = TcpStream::connect(peer)
            .await
            .map_err(AfcError::StreamConnect)?;
        debug!(addr = %TryFmt(stream.peer_addr()), "connected to peer");

        let (old, new) = self.insert(stream)?;
        if let Some(mut stream) = new {
            // Reuse the existing TCP stream.
            if let Err(err) = stream.shutdown().await {
                warn!(?err, "shutdown");
            }
        }
        Ok(old)
    }

    /// Adds a stream, returning an exclusive reference to it.
    ///
    /// It refuses to clobber an existing stream. If a stream already exists, it
    /// returns the existing stream and `Some(stream)`.
    fn insert(
        &mut self,
        stream: TcpStream,
    ) -> Result<(&mut TcpStream, Option<TcpStream>), AfcError> {
        let addr = stream.peer_addr().map_err(AfcError::StreamPeerAddr)?;
        let prev_len = self.streams.len();
        let (stream, dupe) = match self.streams.entry(addr) {
            map::Entry::Occupied(v) => {
                warn!(%addr, "duplicate stream");
                (v.into_mut(), Some(stream))
            }
            map::Entry::Vacant(v) => {
                let stream = v.insert(stream);
                debug!(len = prev_len + 1, "inserted stream");
                (stream, None)
            }
        };
        Ok((stream, dupe))
    }

    /// Reports whether the stream exists.
    fn contains(&mut self, addr: &SocketAddr) -> bool {
        self.streams.contains_key(addr)
    }

    /// Retrieves an exclusive reference to a stream.
    fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut TcpStream> {
        self.streams.get_mut(addr)
    }

    /// Identifies the next readable stream.
    // The implementation is partially borrowed from Tokio's `StreamMap`.
    #[instrument(skip_all)]
    fn next_ready(&mut self, cx: &mut Context<'_>) -> Result<Poll<SocketAddr>, Bug> {
        if self.streams.is_empty() {
            debug!("no streams to check");
            return Ok(Poll::Pending);
        }
        // Distribution via % isn't uniform, but it doesn't matter here.
        let start = usize::random(&mut Rng) % self.streams.len();
        let mut idx = start;
        for _ in 0..self.streams.len() {
            match stream_is_ready(cx, &self.streams[idx]) {
                Ok(true) => {
                    let id = *self.streams.get_index(idx).assume("index should exist")?.0;
                    debug!(%id, "stream is ready");
                    return Ok(Poll::Ready(id));
                }
                Err(err) => {
                    error!(?err, idx, "`stream_is_ready` returned an error");

                    // streams[idx] = streams[streams.len()-1];
                    self.streams.swap_remove_index(idx);
                    if idx == self.streams.len() {
                        idx = 0;
                    } else if idx < start && start <= self.streams.len() {
                        // Already polled the stream being swapped, so ignore
                        // it.
                        idx = idx.wrapping_add(1) % self.streams.len();
                    }
                }
                Ok(false) => {
                    idx = idx.wrapping_add(1) % self.streams.len();
                }
            }
        }

        debug!(total = self.streams.len(), "no streams ready");

        Ok(Poll::Pending)
    }

    /// Returns a future that identifies the next readable stream.
    fn next(&mut self) -> NextStream<'_> {
        NextStream { streams: self }
    }
}

/// A future that identifies the next readable stream.
#[derive(Debug)]
struct NextStream<'a> {
    streams: &'a mut TcpStreams,
}

impl Future for NextStream<'_> {
    type Output = Result<SocketAddr, Bug>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.streams.next_ready(cx) {
            Ok(v) => v.map(Ok),
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

/// Is the stream ready to be read from?
///
/// A stream is "ready" if we've received at least the wire format header.
fn stream_is_ready(cx: &mut Context<'_>, stream: &TcpStream) -> io::Result<bool> {
    match stream.poll_read_ready(cx) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(err)) => return Err(err),
        Poll::Pending => {
            debug!("`poll_read_ready` is pending");
            return Ok(false);
        }
    }

    #[cfg(target_family = "unix")]
    if ioctl_fionread(stream)
        .inspect(|n| debug!(n, "fionread"))
        .is_ok_and(|n| n >= WIRE_HEADER_SIZE)
    {
        return Ok(true);
    }

    let mut buf = [0; WIRE_HEADER_SIZE];
    match stream.poll_peek(cx, &mut ReadBuf::new(&mut buf)) {
        Poll::Ready(Ok(n)) => {
            debug!(n, "peeked");
            Ok(n == WIRE_HEADER_SIZE)
        }
        Poll::Ready(Err(err)) => Err(err),
        Poll::Pending => Ok(false),
    }
}

#[cfg(target_family = "unix")]
fn ioctl_fionread(stream: &TcpStream) -> io::Result<usize> {
    let mut n: c_int = 0;
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &mut n) };
    if ret < 0 {
        debug!(%ret, "FIONREAD");
        // TODO(eric): update `aranya_libc`
        // if errno() == Errno::EINTR {
        //     continue;
        // }
        return Err(io::Error::other("ioctl returned -1"));
    }
    usize::try_from(n).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "n < 0"))
}

trait AsyncWriteVectored: AsyncWrite {
    async fn write_all_vectored<'a, 'b>(
        &'a mut self,
        mut bufs: &mut [IoSlice<'b>],
    ) -> Result<(), io::Error>
    where
        'a: 'b,
        Self: Unpin,
    {
        let mut remain = bufs.iter().fold(0, |acc, s| acc + s.len());
        while !bufs.is_empty() {
            let n = self.write_vectored(bufs).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "wrote 0 bytes, but `bufs` is not empty",
                ));
            }
            // Sanity check since `advance_slices` panics of `n` is out of
            // range.
            if n > remain {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bogus response from `write_vectored`",
                ));
            }
            remain -= n;
            IoSlice::advance_slices(&mut bufs, n);
        }
        Ok(())
    }
}

impl<W: AsyncWrite + ?Sized> AsyncWriteVectored for W {}

/// An open channel.
#[derive(Debug)]
struct Channel {
    net_id: NetIdentifier,
    chan_id: ChannelId,
    /// Used to look up the TCP stream.
    addr: SocketAddr,
    /// The minimum allowed next sequence number for a channel, used to prevent
    /// replay attacks.
    ///
    /// `None` indicates that the sequence number would've overflowed and
    /// [`AfcError::EndOfChannel`] should be returned.
    ///
    /// It's `Option<Seq>` instead of `Result<Seq, AfcError>` for size purposes.
    next_min_seq: Option<Seq>,
}

impl Channel {
    fn next_min_seq(&self) -> Result<Seq, AfcError> {
        match self.next_min_seq {
            Some(v) => Ok(v),
            None => Err(AfcError::EndOfChannel),
        }
    }
}

#[derive(Debug)]
struct FmtOr<T>(T, &'static str);

impl<T: fmt::Display> fmt::Display for FmtOr<Option<T>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => v.fmt(f),
            None => self.1.fmt(f),
        }
    }
}

#[derive(Debug)]
struct TryFmt<T>(T);

impl<T, E> fmt::Display for TryFmt<Result<T, E>>
where
    T: fmt::Display,
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(v) => v.fmt(f),
            Err(err) => err.fmt(f),
        }
    }
}
