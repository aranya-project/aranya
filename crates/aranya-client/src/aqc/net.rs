#![warn(missing_docs)]

//! The AQC network implementation.

use core::task::{Context as CoreContext, Poll};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::{
    AqcBidiPsks, AqcCtrl, AqcPsks, AqcUniPsks, DaemonApiClient, LabelId, TeamId,
};
use buggy::{Bug, BugExt as _};
use bytes::Bytes;
use futures_util::task::noop_waker;
use s2n_quic::{
    client::Connect,
    connection::Handle,
    provider,
    stream::{PeerStream, ReceiveStream, SendStream},
    Client, Connection, Server,
};
use tarpc::context;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use super::api::CTRL_KEY;
use crate::{
    aqc::api::{AqcChannel, ClientPresharedKeys, ServerPresharedKeys, PSK_IDENTITY_CTRL},
    error::{aranya_error, AqcError, IpcError},
};

/// An AQC control message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AqcCtrlMessage {
    /// The team id.
    pub team_id: TeamId,
    /// The control message.
    pub ctrl: AqcCtrl,
}

/// An AQC control message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AqcAckMessage {
    /// The success message.
    Success,
    /// The failure message.
    Failure(String),
}

/// Receives an AQC ctrl message.
async fn receive_aqc_ctrl(
    daemon: Arc<DaemonApiClient>,
    team: TeamId,
    ctrl: AqcCtrl,
    server_keys: &ServerPresharedKeys,
    channel_map: &mut HashMap<Vec<u8>, AqcChannel>,
) -> crate::Result<()> {
    let (_peer, psks) = daemon
        .receive_aqc_ctrl(context::current(), team, ctrl)
        .await
        .map_err(IpcError::new)?
        .map_err(aranya_error)?;

    server_keys.load_psks(psks.clone());

    match psks {
        AqcPsks::Bidi(psks) => {
            for (_suite, psk) in psks {
                channel_map.insert(
                    psk.identity.as_bytes().to_vec(),
                    AqcChannel::Bidirectional {
                        id: *psk.identity.channel_id(),
                    },
                );
            }
        }
        AqcPsks::Uni(psks) => {
            for (_suite, psk) in psks {
                channel_map.insert(
                    psk.identity.as_bytes().to_vec(),
                    AqcChannel::Unidirectional {
                        id: *psk.identity.channel_id(),
                    },
                );
            }
        }
    }

    Ok(())
}

fn create_channel_type(conn: Connection, channel_info: &AqcChannel) -> AqcReceiveChannelType {
    match channel_info {
        AqcChannel::Bidirectional { id } => {
            // Once we accept a valid connection, let's turn it into an AQC Channel that we can
            // then open an arbitrary number of streams on.
            let channel = AqcBidirectionalChannel::new(LabelId::default(), *id, conn);
            AqcReceiveChannelType::Bidirectional { channel }
        }
        AqcChannel::Unidirectional { id } => {
            // Once we accept a valid connection, let's turn it into an AQC Channel that we can
            // then open an arbitrary number of streams on.
            let receiver = AqcReceiverChannel::new(LabelId::default(), *id, conn);
            AqcReceiveChannelType::Receiver { receiver }
        }
    }
}

async fn receive_ctrl_message(
    daemon: &Arc<DaemonApiClient>,
    server_keys: &ServerPresharedKeys,
    channel_map: &mut HashMap<Vec<u8>, AqcChannel>,
    conn: &mut Connection,
) -> crate::Result<()> {
    let stream = conn
        .accept_bidirectional_stream()
        .await
        .map_err(AqcError::ConnectionError)?
        .ok_or(AqcError::ConnectionClosed)?;
    let (mut recv, mut send) = stream.split();
    let Ok(Some(ctrl_bytes)) = recv.receive().await else {
        error!("Failed to receive control message or stream closed");
        return Err(AqcError::ConnectionClosed.into());
    };
    match postcard::from_bytes::<AqcCtrlMessage>(&ctrl_bytes) {
        Ok(ctrl) => {
            receive_aqc_ctrl(
                daemon.clone(),
                ctrl.team_id,
                ctrl.ctrl,
                server_keys,
                channel_map,
            )
            .await?;
            // Send an ACK back
            let ack_msg = AqcAckMessage::Success;
            let ack_bytes = postcard::to_stdvec(&ack_msg).assume("can serialize")?;
            send.send(Bytes::from(ack_bytes))
                .await
                .map_err(AqcError::from)?;
            send.close().await.map_err(AqcError::from)?;
        }
        Err(e) => {
            error!("Failed to deserialize AqcCtrlMessage: {}", e);
            let ack_msg =
                AqcAckMessage::Failure(format!("Failed to deserialize AqcCtrlMessage: {}", e));
            let ack_bytes = postcard::to_stdvec(&ack_msg).assume("can serialize")?;
            let _ = send.send(Bytes::from(ack_bytes)).await;
            let _ = send.close().await;
            return Err(AqcError::Serde(e).into());
        }
    }
    Ok(())
}

/// Indicates the type of channel. This will be a channel that can be used to receive data from a peer.
#[derive(Debug)]
pub enum AqcReceiveChannelType {
    /// Used to receive data from a peer.
    Receiver {
        /// The receiving end of a unidirectional channel.
        receiver: AqcReceiverChannel,
    },
    /// Used to send and receive data from a peer.
    Bidirectional {
        /// The sending and receiving end of a bidirectional channel.
        channel: AqcBidirectionalChannel,
    },
}

/// The sending end of a unidirectional channel.
/// Allows sending data streams over a channel.
#[derive(Debug)]
pub struct AqcSenderChannel {
    label_id: LabelId,
    handle: Handle,
    id: UniChannelId,
}

impl AqcSenderChannel {
    /// Create a new channel with the given id and conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub fn new(label_id: LabelId, id: UniChannelId, handle: Handle) -> Self {
        Self {
            label_id,
            id,
            handle,
        }
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the channel id.
    pub fn aqc_id(&self) -> UniChannelId {
        self.id
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream, AqcError> {
        let send = self.handle.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) {
        const ERROR_CODE: u32 = 0;
        self.handle.close(ERROR_CODE.into());
    }
}

impl Drop for AqcSenderChannel {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Display for AqcSenderChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AqcSenderChannel(label_id: {}, id: {})",
            self.label_id, self.id
        )
    }
}

/// The receive end of a unidirectional channel.
/// Allows receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcReceiverChannel {
    label_id: LabelId,
    aqc_id: UniChannelId,
    conn: Connection,
}

impl AqcReceiverChannel {
    /// Create a new channel with the given conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub fn new(label_id: LabelId, aqc_id: UniChannelId, conn: Connection) -> Self {
        Self {
            label_id,
            aqc_id,
            conn,
        }
    }

    /// Get the channel id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> UniChannelId {
        self.aqc_id
    }

    /// Returns the next unidirectional stream.
    pub async fn receive_uni_stream(&mut self) -> Result<AqcReceiveStream, AqcError> {
        match self.conn.accept_receive_stream().await {
            Ok(Some(stream)) => Ok(AqcReceiveStream { receive: stream }),
            Ok(None) => Err(AqcError::ConnectionClosed),
            Err(e) => Err(AqcError::ConnectionError(e)),
        }
    }

    /// Receive a unidirectional stream if one is available. If there is no stream available,
    /// return Empty. If the stream is disconnected, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_uni_stream(&mut self) -> Result<AqcReceiveStream, TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        match self.conn.poll_accept_receive_stream(&mut cx) {
            Poll::Ready(Ok(Some(stream))) => Ok(AqcReceiveStream { receive: stream }),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Empty),
            Poll::Ready(Err(e)) => Err(TryReceiveError::Error(AqcError::ConnectionError(e))),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }
}

/// A unique channel between two peers.
/// Allows sending and receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcBidirectionalChannel {
    label_id: LabelId,
    aqc_id: BidiChannelId,
    conn: Connection,
}

impl AqcBidirectionalChannel {
    /// Create a new bidirectional channel with the given id and conection handle.
    pub fn new(label_id: LabelId, aqc_id: BidiChannelId, conn: Connection) -> Self {
        Self {
            label_id,
            aqc_id,
            conn,
        }
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> BidiChannelId {
        self.aqc_id
    }

    /// Returns the next available stream.
    /// If the stream is bidirectional, return a tuple of the send and receive streams.
    /// If the stream is unidirectional, return a tuple of None and the receive stream.
    pub async fn receive_stream(
        &mut self,
    ) -> Result<(Option<AqcSendStream>, AqcReceiveStream), AqcError> {
        match self.conn.accept().await {
            Ok(Some(stream)) => match stream {
                PeerStream::Bidirectional(stream) => {
                    let (recv, send) = stream.split();
                    Ok((
                        Some(AqcSendStream { send }),
                        AqcReceiveStream { receive: recv },
                    ))
                }
                PeerStream::Receive(recv) => Ok((None, AqcReceiveStream { receive: recv })),
            },
            Ok(None) => Err(AqcError::ConnectionClosed),
            Err(e) => Err(AqcError::ConnectionError(e)),
        }
    }

    /// Receive a stream if one is available. If there is no stream available,
    /// return Empty. If the channel is closed, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_stream(
        &mut self,
    ) -> Result<(Option<AqcSendStream>, AqcReceiveStream), TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);

        match self.conn.poll_accept(&mut cx) {
            Poll::Ready(Ok(Some(peer_stream))) => match peer_stream {
                PeerStream::Bidirectional(stream) => {
                    let (recv, send) = stream.split();
                    Ok((
                        Some(AqcSendStream { send }),
                        AqcReceiveStream { receive: recv },
                    ))
                }
                PeerStream::Receive(recv) => Ok((None, AqcReceiveStream { receive: recv })),
            },
            Poll::Ready(Ok(None)) => {
                // Connection closed by peer, no more streams will be accepted.
                Err(TryReceiveError::Error(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                Err(TryReceiveError::Error(AqcError::ConnectionError(e)))
            }
            Poll::Pending => {
                // No stream is immediately available.
                Err(TryReceiveError::Empty)
            }
        }
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream, AqcError> {
        let send = self.conn.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidi_stream(
        &mut self,
    ) -> Result<(AqcSendStream, AqcReceiveStream), AqcError> {
        let (receive, send) = self.conn.open_bidirectional_stream().await?.split();
        Ok((AqcSendStream { send }, AqcReceiveStream { receive }))
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) {
        const ERROR_CODE: u32 = 0;
        self.conn.close(ERROR_CODE.into());
    }
}

impl Drop for AqcBidirectionalChannel {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Display for AqcBidirectionalChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AqcBidirectionalChannel(label_id: {}, aqc_id: {})",
            self.label_id, self.aqc_id
        )
    }
}

/// Used to receive data from a peer.
pub struct AqcReceiveStream {
    receive: ReceiveStream,
}

impl AqcReceiveStream {
    /// Receive the next available data from a stream. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self) -> Result<Option<Bytes>, AqcError> {
        match self.receive.receive().await {
            Ok(Some(chunk)) => Ok(Some(chunk)),
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Receive the next available data from a stream.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub fn try_receive(&mut self) -> Result<Bytes, TryReceiveError> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        match self.receive.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => Ok(chunk),
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Closed),
            Poll::Ready(Err(_e)) => Err(TryReceiveError::Closed),
            Poll::Pending => Err(TryReceiveError::Empty),
        }
    }
}

/// Used to send data to a peer.
pub struct AqcSendStream {
    send: SendStream,
}

impl AqcSendStream {
    /// Send data to the given stream.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), AqcError> {
        self.send.send(Bytes::copy_from_slice(data)).await?;
        Ok(())
    }

    /// Close the stream.
    pub async fn close(&mut self) -> Result<(), AqcError> {
        self.send.close().await?;
        Ok(())
    }
}

/// An error that occurs when trying to receive a channel or stream.
#[derive(Debug, thiserror::Error)]
pub enum TryReceiveError<E = AqcError> {
    /// The channel or stream is empty.
    #[error("channel or stream is empty")]
    Empty,
    /// An error occurred.
    #[error("an error occurred")]
    Error(E),
    /// The channel or stream is closed.
    #[error("channel or stream is closed")]
    Closed,
}

/// An AQC client. Used to create and receive channels.
#[derive(Debug)]
pub(crate) struct AqcClient {
    quic_client: Client,
    client_keys: Arc<ClientPresharedKeys>,
    server_keys: Arc<ServerPresharedKeys>,
    /// Map of PSK identity to channel type
    channels: HashMap<Vec<u8>, AqcChannel>,
    server: Server,
    daemon: Arc<DaemonApiClient>,
    identity_rx: mpsc::Receiver<Vec<u8>>,
}

impl AqcClient {
    /// Create an Aqc client with the given certificate chain.
    pub fn new<T: provider::tls::Provider>(
        provider: T,
        client_keys: Arc<ClientPresharedKeys>,
        server_keys: Arc<ServerPresharedKeys>,
        identity_rx: mpsc::Receiver<Vec<u8>>,
        server: Server,
        daemon: Arc<DaemonApiClient>,
    ) -> Result<AqcClient, AqcError> {
        let quic_client = Client::builder()
            .with_tls(provider)?
            .with_io((Ipv4Addr::UNSPECIFIED, 0))
            .assume("can set aqc client addr")?
            .start()?;
        Ok(AqcClient {
            quic_client,
            client_keys,
            server_keys,
            channels: HashMap::new(),
            server,
            daemon,
            identity_rx,
        })
    }

    /// Get the client address.
    pub fn client_addr(&self) -> Result<SocketAddr, Bug> {
        self.quic_client.local_addr().assume("can get local addr")
    }

    /// Get the server address.
    pub fn server_addr(&self) -> Result<SocketAddr, Bug> {
        self.server.local_addr().assume("can get local addr")
    }

    /// Receive the next available channel. If the channel is closed, return None.
    /// This method will return a channel created by a peer that hasn't been received yet.
    pub async fn receive_channel(&mut self) -> crate::Result<AqcReceiveChannelType> {
        loop {
            // Accept a new connection
            let mut conn = self
                .server
                .accept()
                .await
                .ok_or(AqcError::ServerConnectionTerminated)?;
            // Receive a PSK identity hint.
            // TODO: Instead of receiving the PSK identity hint here, we should
            // pull it directly from the connection.
            let identity = self
                .identity_rx
                .try_recv()
                .assume("identity received after accepting connection")?;
            debug!(
                "Processing connection accepted after seeing PSK identity hint: {:02x?}",
                identity
            );
            // If the PSK identity hint is the control PSK, receive a control message.
            // This will update the channel map with the PSK and associate it with an
            // AqcChannel.
            if identity == PSK_IDENTITY_CTRL {
                receive_ctrl_message(
                    &self.daemon,
                    &self.server_keys,
                    &mut self.channels,
                    &mut conn,
                )
                .await?;
                continue;
            }
            // If the PSK identity hint is not the control PSK, check if it's in the channel map.
            // If it is, create a channel of the appropriate type. We should have already received
            // the control message for this PSK, if we don't we can't create a channel.
            let channel_info = self.channels.get(&identity).ok_or_else(|| {
                debug!(
                    "No channel info found in map for identity hint {:02x?}",
                    identity
                );
                AqcError::NoChannelInfoFound
            })?;
            return Ok(create_channel_type(conn, channel_info));
        }
    }

    /// Receive the next available channel. If there is no channel available,
    /// return Empty. If the channel is disconnected, return Disconnected. If disconnected
    /// is returned no channels will be available until the application is restarted.
    pub fn try_receive_channel(
        &mut self,
    ) -> Result<AqcReceiveChannelType, TryReceiveError<crate::Error>> {
        let waker = noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        loop {
            // Accept a new connection
            let mut conn = match self.server.poll_accept(&mut cx) {
                Poll::Ready(Some(conn)) => conn,
                Poll::Ready(None) => {
                    return Err(TryReceiveError::Error(
                        AqcError::ServerConnectionTerminated.into(),
                    ));
                }
                Poll::Pending => {
                    return Err(TryReceiveError::Empty);
                }
            };
            // Receive a PSK identity hint.
            // TODO: Instead of receiving the PSK identity hint here, we should
            // pull it directly from the connection.
            let identity = self
                .identity_rx
                .try_recv()
                .assume("identity received after accepting connection")
                .map_err(|e| TryReceiveError::Error(e.into()))?;
            debug!(
                "Processing connection accepted after seeing PSK identity hint: {:02x?}",
                identity
            );
            // If the PSK identity hint is the control PSK, receive a control message.
            // This will update the channel map with the PSK and associate it with an
            // AqcChannel.
            if identity == PSK_IDENTITY_CTRL {
                // Block on the async function
                let result = futures_lite::future::block_on(receive_ctrl_message(
                    &self.daemon,
                    &self.server_keys,
                    &mut self.channels,
                    &mut conn,
                ));

                if let Err(e) = result {
                    // The original function logged an error and returned ControlFlow::Break
                    // which implies the loop should terminate or an error state.
                    // For try_receive_channel, this might mean the connection is unusable for ctrl messages.
                    warn!(
                        "Receiving control message failed: {}, potential issue with connection.",
                        e
                    );
                    // Depending on desired behavior, you might return an error or continue.
                    // For now, let's assume it's an error if control message processing fails critically.
                    return Err(TryReceiveError::Error(e));
                }

                continue;
            }
            // If the PSK identity hint is not the control PSK, check if it's in the channel map.
            // If it is, create a channel of the appropriate type. We should have already received
            // the control message for this PSK, if we don't we can't create a channel.
            let channel_info = self.channels.get(&identity).ok_or_else(|| {
                debug!(
                    "No channel info found in map for identity hint {:02x?}",
                    identity
                );
                TryReceiveError::Error(AqcError::NoChannelInfoFound.into())
            })?;
            return Ok(create_channel_type(conn, channel_info));
        }
    }

    /// Creates a new unidirectional channel to the given address.
    pub async fn create_uni_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        psks: AqcUniPsks,
    ) -> Result<AqcSenderChannel, AqcError> {
        let channel_id = UniChannelId::from(*psks.channel_id());
        self.client_keys.load_psks(AqcPsks::Uni(psks));
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name(addr.to_string()))
            .await?;
        conn.keep_alive(true)?;
        Ok(AqcSenderChannel::new(label_id, channel_id, conn.handle()))
    }

    /// Creates a new bidirectional channel to the given address.
    pub async fn create_bidi_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        psks: AqcBidiPsks,
    ) -> Result<AqcBidirectionalChannel, AqcError> {
        let channel_id = BidiChannelId::from(*psks.channel_id());
        self.client_keys.load_psks(AqcPsks::Bidi(psks));
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name(addr.to_string()))
            .await?;
        conn.keep_alive(true)?;
        Ok(AqcBidirectionalChannel::new(label_id, channel_id, conn))
    }

    /// Send a control message to the given address.
    pub async fn send_ctrl(
        &mut self,
        addr: SocketAddr,
        ctrl: AqcCtrl,
        team_id: TeamId,
    ) -> Result<(), AqcError> {
        self.client_keys.set_key(CTRL_KEY.clone());
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name(addr.to_string()))
            .await?;
        conn.keep_alive(true)?;
        let (mut recv, mut send) = conn.open_bidirectional_stream().await?.split();
        let msg = AqcCtrlMessage { team_id, ctrl };
        let msg_bytes = postcard::to_stdvec(&msg).assume("can serialize")?;
        send.send(Bytes::from_owner(msg_bytes)).await?;
        if let Some(msg_bytes) = recv.receive().await? {
            let msg = postcard::from_bytes::<AqcAckMessage>(&msg_bytes).map_err(AqcError::Serde)?;
            match msg {
                AqcAckMessage::Success => (),
                AqcAckMessage::Failure(e) => return Err(AqcError::CtrlFailure(e)),
            }
        }
        Ok(())
    }
}
