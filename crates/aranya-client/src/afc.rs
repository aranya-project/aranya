//! Aranya Fast Channels (AFC) Data Router.
//!
//! Routes AFC ctrl/data messages between AFC peers.
//! Encrypts outgoing plaintext from application with AFC `seal` operation before sending it over the network.
//! Decrypts incoming ciphertext with AFC `open` operation from peers before forwarding to the application.

use std::{collections::BTreeMap, net::SocketAddr, path::Path, str::FromStr};

use anyhow::anyhow;
use aranya_buggy::{Bug, BugExt};
use aranya_daemon_api::{AfcCtrl, AfcId, TeamId, CS};
use aranya_fast_channels::{
    shm::{Flag, Mode, ReadState},
    AfcState, ChannelId, Client, Header, Label, NodeId, Version,
};
use aranya_util::{addr::Addr, util};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{debug, error};

/// An error that can occur in the Aranya Fast Channels (AFC) data router.
// TODO: split this into separate errors for app and router.
#[derive(thiserror::Error, Debug)]
pub enum AfcRouterError {
    /// An internal bug was discovered.
    #[error("internal bug")]
    Bug(#[from] Bug),
    /// Router version mismatch.
    #[error("router version mismatch")]
    VersionMismatch { expected: Version, actual: Version },
    /// Router initialization failure.
    #[error("router initialization failure")]
    Init(anyhow::Error),
    /// Router unable to parse shm path.
    #[error("router unable to parse shm path")]
    ShmPathParse,
    /// Router unable to open the shm read state.
    #[error("router unable to open shm `ReadState`")]
    ShmReadState,
    /// Router read failure.
    #[error("router failed to read from transport")]
    RouterRead,
    /// Router write failure.
    #[error("router failed to write to transport")]
    RouterWrite,
    /// Router encryption failure.
    #[error("router encryption failure")]
    RouterEncryption(anyhow::Error),
    /// Router decryption failure.
    #[error("router decryption failure")]
    RouterDecryption(anyhow::Error),
    /// Router unable to encode header.
    #[error("router unable to encode header")]
    HeaderEncoding(anyhow::Error),
    /// Failed to connect to TCP stream.
    #[error("failed to connect to TCP stream")]
    StreamConnect(anyhow::Error),
    /// Failed to read from TCP stream.
    #[error("failed to read from TCP stream")]
    StreamRead(anyhow::Error),
    /// Failed to write to TCP stream.
    #[error("failed to write to TCP stream")]
    StreamWrite(anyhow::Error),
    /// Failed to shutdown TCP stream.
    #[error("failed to shutdown TCP stream")]
    StreamShutdown(anyhow::Error),
    /// Payload is too small to be ciphertext.
    #[error("payload is too small to be ciphertext")]
    PayloadTooSmall,
    /// Data missing header.
    #[error("data missing header")]
    MissingHeader,
    /// Router failed to send data to application.
    #[error("router failed to send data to application")]
    AppSend,
    /// Router local address failure.
    #[error("router failed to get local address")]
    RouterAddr,
    /// Application read failure.
    #[error("application failed to read from buffer")]
    AppRead,
    /// Application write failure.
    #[error("application failed to write to buffer")]
    AppWrite,
    /// Serde serialization/deserialization error.
    #[error("serde serialization/deserialization error")]
    Serde(anyhow::Error),
    /// Failed to poll data.
    #[error("failed to poll data")]
    Poll(anyhow::Error),
    /// Unexpected data type.
    #[error("unexpected data type")]
    UnexpectedType,
}

/// Data types that can be polled by the AFC router.
pub enum DataType {
    /// Data message received by the router from the application.
    Data(AppMsg),
    /// Ctrl message received by the application from the router.
    Ctrl(AppCtrl),
    /// Incoming connection from the transport.
    Txp((TcpStream, SocketAddr)),
}

/// AFC ctrl/data messages.
///
/// These messages are sent/received between AFC peers via the TCP transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxpMsg {
    Ctrl(Ctrl),
    Data(Data),
}

/// AFC Ctrl message.
///
/// The current peer creates an AFC channel locally including populating the AFC shared-memory with channel keys.
/// The peer then sends the encrypted Ctrl message effects to the peer on the other side of the channel.
/// The recipient peer can then process the effects in order to setup corresponding channel keys in its AFC shared-memory.
/// Once both peers have corresponding copies of the AFC channel keys, they can both perform encryption/decryption for the AFC channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ctrl {
    /// AFC protocol version.
    version: Version,
    /// Team ID.
    team_id: TeamId,
    /// Ephemeral command for AFC channel creation.
    cmd: AfcCtrl,
}

/// AFC Data message.
///
/// Data messages contain ciphertext encrypted with the AFC `seal` operation using the appropriate channel keys for the channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Data {
    /// AFC protocol version.
    version: Version,
    /// Truncated channel ID.
    afc_id: AfcId,
    /// Data encrypted with AFC `seal`.
    datagram: Vec<u8>,
}

/// Ctrl message received by application from AFC router.
pub struct AppCtrl {
    /// AFC ctrl message.
    pub afc_ctrl: AfcCtrl,
    /// Team ID.
    pub team_id: TeamId,
    /// Node ID.
    pub node_id: NodeId,
}

/// AFC ctrl/data router.
pub struct Router<S> {
    /// The underlying AFC client.
    afc: Client<S>,
    /// Listens for incoming connections from AFC peers.
    listener: TcpListener,
    /// Forwards an incoming AFC message from router to application.
    send: Sender<AppMsg>,
    /// Receives an outgoing AFC message from application to send over transport.
    recv: Receiver<AppMsg>,
    /// Map of [`AfcId`] to [`ChannelId`] for existing channels.
    chans: BTreeMap<AfcId, ChannelId>,
    /// Sends [`AfcCtrl`] data from AFC router to user library to be forwarded to daemon.
    ctrl_send: Sender<AppCtrl>,
    /// Incrementing counter for unique AFC node_id.
    // TODO: move this counter into the daemon.
    counter: u32,
    /// Buffer for receiving bytes from a peer over the network.
    buf: Vec<u8>,
}

impl<S: AfcState> Router<S> {
    /// Create new AFC Router.
    pub async fn new(afc: Client<S>, afc_addr: Addr) -> Result<(Self, App), AfcRouterError> {
        let afc_addr = afc_addr.lookup().await.map_err(AfcRouterError::Init)?;
        let listener = TcpListener::bind(afc_addr)
            .await
            .map_err(|e| AfcRouterError::Init(e.into()))?;
        let (in_send, in_recv) = mpsc::channel(256);
        let (out_send, out_recv) = mpsc::channel(256);
        let (ctrl_send, ctrl_recv) = mpsc::channel(256);
        let app = App::new(out_send, in_recv, ctrl_recv);
        Ok((
            Self {
                afc,
                listener,
                recv: out_recv,
                send: in_send,
                chans: BTreeMap::new(),
                ctrl_send,
                counter: 0,
                buf: Vec::new(),
            },
            app,
        ))
    }

    /// Verifies that the router version is expected.
    fn check_version(&self, version: Version) -> Result<(), AfcRouterError> {
        if version != Version::V1 {
            error!("afc version mismatch: {:?} != {:?}", version, Version::V1);
            return Err(AfcRouterError::VersionMismatch {
                expected: Version::V1,
                actual: version,
            });
        }
        Ok(())
    }

    /// Create new ctrl/data message to send over transport.
    async fn new_txp_msg(&mut self, msg: AppMsg) -> Result<(TxpMsg, SocketAddr), AfcRouterError> {
        match msg {
            AppMsg::Ctrl { addr, team_id, cmd } => Ok((
                TxpMsg::Ctrl(Ctrl {
                    version: Version::V1,
                    team_id,
                    cmd,
                }),
                addr,
            )),
            AppMsg::Data {
                addr,
                label,
                afc_id,
                plaintext,
            } => {
                let Some(channel_id) = self.chans.get(&afc_id) else {
                    error!(?addr, ?label, "unable to lookup afc channel");
                    return Err(AfcRouterError::RouterRead);
                };

                let datagram = {
                    // We need enough space to write
                    //   header || ciphertext
                    let mut buf =
                        vec![0u8; Header::PACKED_SIZE + plaintext.len() + Client::<S>::OVERHEAD];
                    let (header, ciphertext) = buf
                        .split_first_chunk_mut()
                        .assume("`buf.len()` >= `Header::PACKED_SIZE`")?;
                    debug!(%channel_id, "sealing message");
                    let hdr = self
                        .afc
                        .seal(*channel_id, ciphertext, &plaintext)
                        .map_err(|e| AfcRouterError::RouterEncryption(e.into()))?;
                    debug!(%channel_id, "sealed message");
                    hdr.encode(header)
                        .map_err(|e| AfcRouterError::HeaderEncoding(e.into()))?;
                    buf
                };
                debug!(n = datagram.len(), "created datagram");
                Ok((
                    TxpMsg::Data(Data {
                        version: Version::V1,
                        afc_id,
                        datagram,
                    }),
                    addr,
                ))
            }
        }
    }

    /// Polls the AFC router for data.
    ///
    /// Checks for incoming client connections.
    /// Receives ctrl/data messages from peers.
    pub async fn poll(&mut self) -> Result<DataType, AfcRouterError> {
        #![allow(clippy::disallowed_macros)]
        tokio::select! {
            biased;
            // Check for new messages from the application.
            result = self.recv.recv() => {
                match result {
                    Some(msg) => Ok(DataType::Data(msg)),
                    None => Err(AfcRouterError::Poll(anyhow!("channel closed"))),
                }
            }
            // Check for incoming messages from the transport.
            result = self.listener.accept() => {
                match result {
                    Ok((stream, addr)) => Ok(DataType::Txp((stream, addr))),
                    Err(e) => Err(AfcRouterError::Poll(e.into())),
                }
            }
        }
    }

    /// Handles polled data.
    pub async fn handle_data(&mut self, data: DataType) -> Result<(), AfcRouterError> {
        match data {
            DataType::Data(msg) => self.recv_app_msg(msg).await,
            DataType::Txp((mut stream, addr)) => {
                self.recv_incoming_connection(&mut stream, addr).await
            }
            _ => Err(AfcRouterError::UnexpectedType),
        }
    }

    /// Receive message from application.
    async fn recv_app_msg(&mut self, msg: AppMsg) -> Result<(), AfcRouterError> {
        debug!("router received msg from app");
        // Send message via transport.
        let (txpmsg, addr) = self.new_txp_msg(msg).await?;
        match &txpmsg {
            TxpMsg::Ctrl(_) => debug!(?addr, "router received ctrl from app"),
            TxpMsg::Data(_) => debug!(?addr, "router received data from app"),
        }
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| AfcRouterError::StreamConnect(e.into()))?;
        let buf = postcard::to_allocvec(&txpmsg).map_err(|e| AfcRouterError::Serde(e.into()))?;
        stream
            .write_all(&buf)
            .await
            .map_err(|e| AfcRouterError::StreamWrite(e.into()))?;
        stream
            .shutdown()
            .await
            .map_err(|e| AfcRouterError::StreamShutdown(e.into()))?;
        match txpmsg {
            TxpMsg::Ctrl(_) => debug!(n = buf.len(), "router sent ctrl to peer"),
            TxpMsg::Data(_) => debug!(?addr, n = buf.len(), "router sent data to peer"),
        };
        Ok(())
    }

    /// Receive incoming TCP connection from peer.
    async fn recv_incoming_connection(
        &mut self,
        stream: &mut TcpStream,
        addr: SocketAddr,
    ) -> Result<(), AfcRouterError> {
        debug!(?addr, "received incoming connection");
        self.buf.clear();
        let n = stream
            .read_to_end(&mut self.buf)
            .await
            .map_err(|e| AfcRouterError::StreamRead(e.into()))?;
        debug!(?n, "read incoming bytes");
        let txpmsg =
            postcard::from_bytes(&self.buf).map_err(|e| AfcRouterError::Serde(e.into()))?;
        match txpmsg {
            TxpMsg::Ctrl(ctrl) => self.ctrl_recv(addr, ctrl).await?,
            TxpMsg::Data(data) => self.recv_data(addr, data).await?,
        };
        Ok(())
    }

    /// Receive incoming `TxpMsg::Ctrl` from peer.
    async fn ctrl_recv(&mut self, addr: SocketAddr, ctrl: Ctrl) -> Result<(), AfcRouterError> {
        self.check_version(ctrl.version)?;

        debug!(?addr, "router received ctrl from peer");
        let node_id = self.get_next_node_id().await?;
        let recv = AppCtrl {
            afc_ctrl: ctrl.cmd,
            team_id: ctrl.team_id,
            node_id,
        };
        self.ctrl_send
            .send(recv)
            .await
            .map_err(|_| AfcRouterError::RouterRead)?;
        Ok(())
    }

    /// Receive incoming `TxpMsg::Data` from peer.
    async fn recv_data(&self, addr: SocketAddr, mut data: Data) -> Result<(), AfcRouterError> {
        self.check_version(data.version)?;

        let n = data.datagram.len();
        debug!(n, ?addr, "router received data from peer");
        let Some(channel_id) = self.chans.get(&data.afc_id) else {
            error!(afc_id = ?data.afc_id, ?addr, "unable to lookup channel");
            return Err(AfcRouterError::RouterRead);
        };

        let datagram_len = data
            .datagram
            .len()
            .checked_sub(Client::<S>::OVERHEAD)
            .ok_or(AfcRouterError::PayloadTooSmall)?;
        let (header_len, plaintext_len, label) = {
            let (header, payload) = data
                .datagram
                .split_first_chunk_mut()
                .ok_or(AfcRouterError::MissingHeader)?;
            // TODO: rm unused header from messages.
            let _hdr = Header::try_parse(header).map_err(|_| AfcRouterError::RouterRead)?;

            debug!(?channel_id, "decrypting data");
            let mut buf = aranya_fast_channels::FixedBuf::from_slice_mut(payload, payload.len())
                .assume("length is correct")?;
            let label = self
                .afc
                .open_in_place(channel_id.node_id(), &mut buf)
                .map_err(|e| AfcRouterError::RouterDecryption(e.into()))?;
            (header.len(), buf.len(), label)
        };
        let plaintext = &mut data.datagram;
        plaintext.drain(..header_len);
        plaintext.truncate(plaintext_len);
        debug!(n, ?channel_id, "decrypted data");
        let msg = AppMsg::Data {
            label,
            addr,
            afc_id: data.afc_id,
            // TODO: subtracting header size here seems sloppy.
            plaintext: plaintext[0..(datagram_len - Header::PACKED_SIZE)].to_vec(),
        };
        self.send
            .send(msg)
            .await
            .map_err(|_| AfcRouterError::AppSend)?;
        Ok(())
    }

    /// Get the local address the AFC server bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, AfcRouterError> {
        if let Ok(addr) = self.listener.local_addr() {
            return Ok(addr);
        }
        Err(AfcRouterError::RouterAddr)
    }

    /// Get the next Node ID in the sequence.
    pub async fn get_next_node_id(&mut self) -> Result<NodeId, AfcRouterError> {
        let node_id = NodeId::new(self.counter);
        self.counter += 1;
        Ok(node_id)
    }

    /// Insert a new channel into the AfcId -> ChannelId mapping.
    pub async fn insert_channel_id(
        &mut self,
        afc_id: AfcId,
        channel_id: ChannelId,
    ) -> Result<(), AfcRouterError> {
        debug!(?afc_id, ?channel_id, "inserting channel ID");
        self.chans.insert(afc_id, channel_id);
        Ok(())
    }
}

/// Setup the Aranya Client's read side of the AFC channel keys shared memory.
pub fn setup_afc_shm(shm_path: &Path, max_chans: usize) -> Result<ReadState<CS>, AfcRouterError> {
    debug!(?shm_path, "setting up afc shm read side");
    let Some(path) = shm_path.to_str() else {
        return Err(AfcRouterError::Init(anyhow!(
            "unable to convert shm path to string {:?}",
            shm_path
        )));
    };
    let path = util::ShmPathBuf::from_str(path).map_err(|_| AfcRouterError::ShmPathParse)?;
    let read = ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
        .map_err(|_| AfcRouterError::ShmReadState)?;
    Ok(read)
}

/// AFC message coming from or going to the application.
#[derive(Clone, Debug)]
pub enum AppMsg {
    /// Ctrl message.
    Ctrl {
        /// Peer's socket address.
        addr: SocketAddr,
        /// Team ID.
        team_id: TeamId,
        /// Ephemeral command for creating AFC channel.
        cmd: AfcCtrl,
    },
    /// Data message.
    Data {
        /// Peer's socket address.
        addr: SocketAddr,
        /// AFC label plaintext corresponds to.
        label: Label,
        /// AFC key ID.
        afc_id: AfcId,
        /// Plaintext to be encrypted with AFC `seal` operation.
        plaintext: Vec<u8>,
    },
}

/// The application sends/receives plaintext AFC messages.
pub struct App {
    /// Sends an outgoing AFC message from application to AFC router.
    send: Sender<AppMsg>,
    /// Receives an incoming AFC message from AFC router to application.
    recv: Receiver<AppMsg>,
    /// Receives AFC control message from AFC router.
    ctrl_recv: Receiver<AppCtrl>,
}

impl App {
    /// Creates a new application instance.
    pub fn new(send: Sender<AppMsg>, recv: Receiver<AppMsg>, ctrl_recv: Receiver<AppCtrl>) -> Self {
        Self {
            send,
            recv,
            ctrl_recv,
        }
    }

    /// Reads the next AFC message received by the router.
    pub async fn recv(&mut self) -> Result<(Vec<u8>, SocketAddr, AfcId, Label), AfcRouterError> {
        if let Some(AppMsg::Data {
            label,
            addr,
            afc_id,
            plaintext,
        }) = self.recv.recv().await
        {
            return Ok((plaintext, addr, afc_id, label));
        }
        Err(AfcRouterError::AppRead)
    }

    /// Sends AFC ctrl message to router.
    pub async fn send_ctrl(
        &mut self,
        addr: SocketAddr,
        team_id: TeamId,
        cmd: AfcCtrl,
    ) -> Result<(), AfcRouterError> {
        debug!(?addr, "application sending ctrl msg to AFC router");
        self.send
            .send(AppMsg::Ctrl { addr, team_id, cmd })
            .await
            .map_err(|_| AfcRouterError::AppWrite)
    }

    /// Receives AFC ctrl message from router.
    pub async fn recv_ctrl(&mut self) -> Result<DataType, AfcRouterError> {
        if let Some(ctrl) = self.ctrl_recv.recv().await {
            return Ok(DataType::Ctrl(ctrl));
        }
        Err(AfcRouterError::AppRead)
    }

    /// Sends AFC data message to router.
    pub async fn send_data(
        &mut self,
        addr: SocketAddr,
        label: Label,
        afc_id: AfcId,
        plaintext: Vec<u8>,
    ) -> Result<(), AfcRouterError> {
        debug!("application sending data msg to AFC router");
        self.send
            .send(AppMsg::Data {
                addr,
                label,
                afc_id,
                plaintext,
            })
            .await
            .map_err(|_| AfcRouterError::AppWrite)
    }
}
