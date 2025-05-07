#![warn(missing_docs)]

//! The AQC network implementation.

use core::task::{Context as CoreContext, Poll};
use std::{collections::HashMap, net::SocketAddr, ops::ControlFlow, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::{AqcCtrl, AqcPsk, DaemonApiClient, LabelId, TeamId};
use aranya_fast_channels::NodeId;
use buggy::BugExt;
use bytes::Bytes;
use s2n_quic::{
    client::Connect,
    connection::Handle,
    provider::{self, tls::rustls::rustls::crypto::PresharedKey},
    stream::{PeerStream, ReceiveStream, SendStream},
    Client, Connection, Server,
};
use tarpc::context;
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::{
    aqc::api::{AqcChannel, ClientPresharedKeys, PSK_BYTES_CTRL, PSK_IDENTITY_CTRL},
    error::{self, IpcError},
};

/// The maximum number of channels that haven't been received.
const MAXIMUM_UNRECEIVED_CHANNELS: usize = 20;

/// An AQC control message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AqcCtrlMessage {
    /// The team id.
    pub team_id: TeamId,
    /// The control message.
    pub ctrl: AqcCtrl,
}

/// Receives an AQC ctrl message.
async fn receive_aqc_ctrl(
    daemon: Arc<DaemonApiClient>,
    team: TeamId,
    ctrl: AqcCtrl,
    channel_map: &mut HashMap<Vec<u8>, AqcChannel>,
) -> crate::Result<()> {
    // TODO: use correct node ID
    let _node_id: NodeId = 0.into();

    let (_peer, psk) = daemon
        .receive_aqc_ctrl(context::current(), team, ctrl)
        .await
        .map_err(IpcError::new)?
        .context("unable to receive aqc ctrl")
        .map_err(error::other)?;

    match psk {
        AqcPsk::Bidi(b) => {
            channel_map.insert(
                b.identity.as_bytes().to_vec(),
                AqcChannel::Bidirectional {
                    id: b.identity.into(),
                },
            );
        }
        AqcPsk::Uni(u) => {
            channel_map.insert(
                u.identity.as_bytes().to_vec(),
                AqcChannel::Unidirectional {
                    id: u.identity.into(),
                },
            );
        }
    }

    Ok(())
}

/// Runs a server listening for quic channel requests from other peers.
pub async fn run_channels_server(
    mut server: Server,
    sender: mpsc::Sender<AqcChannelType>,
    mut identity_rx: mpsc::Receiver<Vec<u8>>,
    daemon: Arc<DaemonApiClient>,
) {
    // Map of PSK identity to channel type
    let mut channel_map = HashMap::new();
    loop {
        // Accept a new connection
        match server.accept().await {
            Some(mut conn) => {
                // Receive a PSK identity hint if one is available
                // TODO: Instead of receiving the PSK identity hint here, we should
                // pull it directly from the connection. Eric is working on this.
                let identity = match identity_rx.try_recv() {
                    Ok(identity) => {
                        tracing::debug!("Received new PSK identity hint: {:02x?}", identity);
                        Some(identity)
                    }
                    Err(mpsc::error::TryRecvError::Empty) => None,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // Sender was dropped, likely AqcChannelsImpl was dropped.
                        error!("PSK Identity channel disconnected.");
                        break; // Exit the loop if the sender is gone
                    }
                };
                // If we have a PSK identity hint, process the connection
                if let Some(ref identity) = identity {
                    tracing::debug!(
                        "Processing connection accepted after seeing PSK identity hint: {:02x?}",
                        identity
                    );
                    // If the PSK identity hint is the control PSK, receive a control message.
                    // This will update the channel map with the PSK and associate it with an
                    // AqcChannel.
                    if identity == PSK_IDENTITY_CTRL {
                        if let ControlFlow::Break(_) =
                            receive_ctrl_message(&daemon, &mut channel_map, &mut conn).await
                        {
                            continue;
                        }
                    // If the PSK identity hint is not the control PSK, check if it's in the channel map.
                    // If it is, create a channel of the appropriate type. We should have already received
                    // the control message for this PSK, if we don't we can't create a channel.
                    } else if let Some(channel_info) = channel_map.get(identity) {
                        tracing::debug!(
                            "Found channel info in map for identity hint {:02x?}: {:?}",
                            identity,
                            channel_info
                        );
                        if let ControlFlow::Break(_) =
                            create_channel_type(&sender, conn, channel_info).await
                        {
                            return;
                        }
                    } else {
                        tracing::debug!(
                            "No channel info found in map for identity hint {:02x?}",
                            identity
                        );
                        continue;
                    }
                } else {
                    tracing::warn!("No identity hint received. Unable to create channel.");
                }
            }
            None => {
                debug!("Server connection terminated");
                break;
            }
        }
    }
}

async fn create_channel_type(
    sender: &mpsc::Sender<AqcChannelType>,
    conn: Connection,
    channel_info: &AqcChannel,
) -> ControlFlow<()> {
    match channel_info {
        AqcChannel::Bidirectional { id } => {
            // Once we accept a valid connection, let's turn it into an AQC Channel that we can
            // then open an arbitrary number of streams on.
            let (channel, bi_sender) =
                AqcBidirectionalChannel::new(LabelId::default(), *id, conn.handle());

            // Notify the AfcClient that we've accepted a new connection, which the user will
            // have to call receive_channel() on in order to use.
            if sender
                .send(AqcChannelType::Bidirectional { channel })
                .await
                .is_ok()
            {
                // Spawn a new task so that we can receive any future streams that are opened
                // over the connection.
                tokio::spawn(handle_bidi_streams(conn, bi_sender));
            } else {
                error!("Sender closed. Unable to send channel");
                return ControlFlow::Break(());
            }
        }
        AqcChannel::Unidirectional { id } => {
            // Once we accept a valid connection, let's turn it into an AQC Channel that we can
            // then open an arbitrary number of streams on.
            let (receiver, uni_sender) = AqcReceiverChannel::new(LabelId::default(), *id);

            // Notify the AfcClient that we've accepted a new connection, which the user will
            // have to call receive_channel() on in order to use.
            if sender
                .send(AqcChannelType::Receiver { receiver })
                .await
                .is_ok()
            {
                // Spawn a new task so that we can receive any future streams that are opened
                tokio::spawn(handle_uni_streams(conn, uni_sender));
            } else {
                error!("Sender closed. Unable to send channel");
                return ControlFlow::Break(());
            }
        }
    }
    ControlFlow::Continue(())
}

async fn receive_ctrl_message(
    daemon: &Arc<DaemonApiClient>,
    channel_map: &mut HashMap<Vec<u8>, AqcChannel>,
    conn: &mut Connection,
) -> ControlFlow<()> {
    match conn.accept_receive_stream().await {
        Ok(Some(mut receive)) => {
            if let Ok(Some(ctrl_bytes)) = receive.receive().await {
                match postcard::from_bytes::<AqcCtrlMessage>(&ctrl_bytes) {
                    Ok(ctrl) => {
                        if let Err(e) =
                            receive_aqc_ctrl(daemon.clone(), ctrl.team_id, ctrl.ctrl, channel_map)
                                .await
                        {
                            error!("Failed to receive AQC ctrl: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to deserialize AqcCtrlMessage: {}", e);
                    }
                }
            } else {
                // Handle the error or None case from receive.receive() if necessary
                // For example, log an error or break the loop
                error!("Failed to receive control message or stream closed");
            }
        }
        Ok(None) => {
            error!("Receive stream closed unexpectedly");
            return ControlFlow::Break(());
        }
        Err(e) => {
            error!("Failed to accept receive stream: {}", e);
            return ControlFlow::Break(());
        }
    }
    ControlFlow::Continue(())
}

async fn handle_uni_streams(mut conn: Connection, sender: mpsc::Sender<ReceiveStream>) {
    loop {
        match conn.accept_receive_stream().await {
            Ok(Some(stream)) => {
                if sender.send(stream).await.is_err() {
                    error!("error sending uni stream");
                }
            }
            Ok(None) => {
                break;
            }
            Err(e) => {
                error!(cause = ?e, "error accepting uni stream");
                break;
            }
        }
    }
}

async fn handle_bidi_streams(
    mut conn: Connection,
    sender: mpsc::Sender<(Option<SendStream>, ReceiveStream)>,
) {
    loop {
        match conn.accept().await {
            Ok(Some(stream)) => match stream {
                PeerStream::Bidirectional(stream) => {
                    let (recv, send) = stream.split();
                    if sender.send((Some(send), recv)).await.is_err() {
                        error!("error sending bidi stream");
                    }
                }
                PeerStream::Receive(recv) => {
                    if sender.send((None, recv)).await.is_err() {
                        error!("error sending uni stream");
                    }
                }
            },
            Ok(None) => {
                break;
            }
            Err(e) => {
                error!(cause = ?e, "error accepting stream");
                break;
            }
        }
    }
}

/// Indicates the type of channel
#[derive(Debug)]
pub enum AqcChannelType {
    /// Used to send data to a peer.
    Sender {
        /// The sending end of a unidirectional channel.
        sender: AqcSenderChannel,
    },
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
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream> {
        let send = self.handle.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) -> Result<()> {
        const ERROR_CODE: u32 = 0;
        self.handle.close(ERROR_CODE.into());
        Ok(())
    }
}

impl Drop for AqcSenderChannel {
    fn drop(&mut self) {
        // Attempt to close the channel when the sender is dropped.
        // Log if there's an error, but don't panic as drop should not panic.
        if let Err(e) = self.close() {
            tracing::error!("Failed to close AqcChannelSender handle: {}", e);
        }
    }
}

/// The receive end of a unidirectional channel.
/// Allows receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcReceiverChannel {
    label_id: LabelId,
    uni_receiver: mpsc::Receiver<ReceiveStream>,
    aqc_id: UniChannelId,
}

impl AqcReceiverChannel {
    /// Create a new channel with the given conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub fn new(label_id: LabelId, aqc_id: UniChannelId) -> (Self, mpsc::Sender<ReceiveStream>) {
        let (uni_sender, uni_receiver) = mpsc::channel(10);
        (
            Self {
                label_id,
                uni_receiver,
                aqc_id,
            },
            uni_sender,
        )
    }

    /// Get the channel id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> UniChannelId {
        self.aqc_id
    }

    /// Returns the next unidirectional stream. If the channel is closed, return None.
    pub async fn receive_uni_stream(&mut self) -> Result<Option<AqcReceiveStream>> {
        match self.uni_receiver.recv().await {
            Some(stream) => Ok(Some(AqcReceiveStream { receive: stream })),
            None => Ok(None),
        }
    }

    /// Receive the next available unidirectional stream. If there is no stream available,
    /// return Empty. If the stream is disconnected, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_uni_stream(&mut self) -> Result<AqcReceiveStream, TryReceiveError> {
        match self.uni_receiver.try_recv() {
            Ok(stream) => Ok(AqcReceiveStream { receive: stream }),
            Err(mpsc::error::TryRecvError::Empty) => Err(TryReceiveError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TryReceiveError::Disconnected),
        }
    }
}

/// A unique channel between two peers.
/// Allows sending and receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcBidirectionalChannel {
    label_id: LabelId,
    aqc_id: BidiChannelId,
    handle: Handle,
    receiver: mpsc::Receiver<(Option<SendStream>, ReceiveStream)>,
}

impl AqcBidirectionalChannel {
    /// Create a new bidirectional channel with the given id and conection handle.
    pub fn new(
        label_id: LabelId,
        aqc_id: BidiChannelId,
        handle: Handle,
    ) -> (Self, mpsc::Sender<(Option<SendStream>, ReceiveStream)>) {
        let (sender, receiver) = mpsc::channel(10);
        (
            Self {
                label_id,
                aqc_id,
                handle,
                receiver,
            },
            sender,
        )
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> BidiChannelId {
        self.aqc_id
    }

    /// Returns a stream if one has been received.
    /// If the stream is bidirectional, return a tuple of the send and receive streams.
    /// If the stream is unidirectional, return a tuple of None and the receive stream.
    /// If no stream has been received return None.
    pub async fn receive_stream(&mut self) -> Option<(Option<AqcSendStream>, AqcReceiveStream)> {
        match self.receiver.recv().await {
            Some((Some(send), receive)) => {
                Some((Some(AqcSendStream { send }), AqcReceiveStream { receive }))
            }
            Some((None, receive)) => Some((None, AqcReceiveStream { receive })),
            None => None,
        }
    }

    /// Receive the next available stream. If there is no stream available,
    /// return Empty. If the channel is closed, return Disconnected. If disconnected
    /// is returned no streams will be available until a new channel is created.
    pub fn try_receive_stream(
        &mut self,
    ) -> Result<(Option<AqcSendStream>, AqcReceiveStream), TryReceiveError> {
        match self.receiver.try_recv() {
            Ok((Some(send), receive)) => {
                Ok((Some(AqcSendStream { send }), AqcReceiveStream { receive }))
            }
            Ok((None, receive)) => Ok((None, AqcReceiveStream { receive })),
            Err(mpsc::error::TryRecvError::Empty) => Err(TryReceiveError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TryReceiveError::Disconnected),
        }
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream> {
        let send = self.handle.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidi_stream(&mut self) -> Result<(AqcSendStream, AqcReceiveStream)> {
        let (receive, send) = self.handle.open_bidirectional_stream().await?.split();
        Ok((AqcSendStream { send }, AqcReceiveStream { receive }))
    }

    /// Close the channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) -> Result<()> {
        const ERROR_CODE: u32 = 0;
        self.handle.close(ERROR_CODE.into());
        Ok(())
    }
}

impl Drop for AqcBidirectionalChannel {
    fn drop(&mut self) {
        // Attempt to close the channel when the bidirectional channel is dropped.
        // Log if there's an error, but don't panic as drop should not panic.
        if let Err(e) = self.close() {
            tracing::error!("Failed to close AqcBidirectionalChannel handle: {}", e);
        }
    }
}

/// Used to receive data from a peer.
pub struct AqcReceiveStream {
    receive: ReceiveStream,
}

impl AqcReceiveStream {
    /// Receive the next available data from a stream. Writes the data to the
    /// target buffer and returns the number of bytes written. If the stream has
    /// been closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn receive(&mut self, target: &mut [u8]) -> Result<Option<usize>> {
        match self.receive.receive().await {
            Ok(Some(chunk)) => {
                let len = chunk.len();
                target[..len].copy_from_slice(&chunk);
                Ok(Some(len))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Receive the next available data from a stream. Writes the data to the
    /// target buffer and returns the number of bytes written.
    ///
    /// This method will return immediately with an error if there is no data available.
    /// The errors are:
    /// - Empty: No data available.
    /// - Closed: The stream is closed.
    pub async fn try_receive(&mut self, target: &mut [u8]) -> Result<usize, TryReceiveError> {
        let waker = futures_util::task::noop_waker();
        let mut cx = CoreContext::from_waker(&waker);
        match self.receive.poll_receive(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => {
                let len = chunk.len();
                target[..len].copy_from_slice(&chunk);
                Ok(len)
            }
            Poll::Ready(Ok(None)) => Err(TryReceiveError::Closed),
            Poll::Ready(Err(_e)) => Err(TryReceiveError::Empty),
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
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.send.send(Bytes::copy_from_slice(data)).await?;
        Ok(())
    }

    /// Close the stream.
    pub async fn close(&mut self) -> Result<()> {
        self.send.close().await?;
        Ok(())
    }
}

/// An error that occurs when trying to receive a channel or stream.
#[derive(Debug)]
pub enum TryReceiveError {
    /// The channel or stream is empty.
    Empty,
    /// The channel or stream is disconnected.
    Disconnected,
    /// The channel or stream is closed.
    Closed,
}

/// An AQC client. Used to create and receive channels.
#[derive(Debug)]
pub(crate) struct AqcClient {
    quic_client: Client,
    /// Holds channels that have created, but not yet been received.
    receiver: mpsc::Receiver<AqcChannelType>,
    client_keys: Arc<ClientPresharedKeys>,
}

impl AqcClient {
    /// Create an Aqc client with the given certificate chain.
    pub fn new<T: provider::tls::Provider>(
        provider: T,
        client_keys: Arc<ClientPresharedKeys>,
    ) -> Result<(AqcClient, mpsc::Sender<AqcChannelType>)> {
        let (sender, receiver) = mpsc::channel(MAXIMUM_UNRECEIVED_CHANNELS);
        let quic_client = Client::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;
        Ok((
            AqcClient {
                quic_client,
                receiver,
                client_keys,
            },
            sender,
        ))
    }

    /// Get the local address of the client.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.quic_client.local_addr()?)
    }

    /// Receive the next available channel. If the channel is closed, return None.
    /// This method will return a channel created by a peer that hasn't been received yet.
    pub async fn receive_channel(&mut self) -> Option<AqcChannelType> {
        self.receiver.recv().await
    }

    /// Receive the next available channel. If there is no channel available,
    /// return Empty. If the channel is disconnected, return Disconnected. If disconnected
    /// is returned no channels will be available until the application is restarted.
    pub fn try_receive_channel(&mut self) -> Result<AqcChannelType, TryReceiveError> {
        match self.receiver.try_recv() {
            Ok(channel) => Ok(channel),
            Err(mpsc::error::TryRecvError::Empty) => Err(TryReceiveError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TryReceiveError::Disconnected),
        }
    }

    /// Create a new channel to the given address.
    async fn create_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        channel: AqcChannel,
        psk: PresharedKey,
    ) -> Result<AqcChannelType> {
        self.client_keys.set_key(psk);
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let channel = match channel {
            AqcChannel::Unidirectional { id } => AqcChannelType::Sender {
                sender: AqcSenderChannel::new(label_id, id, conn.handle()),
            },
            AqcChannel::Bidirectional { id } => {
                let (channel, sender) = AqcBidirectionalChannel::new(label_id, id, conn.handle());
                tokio::spawn(handle_bidi_streams(conn, sender));
                AqcChannelType::Bidirectional { channel }
            }
        };
        Ok(channel)
    }

    /// Creates a new unidirectional channel to the given address.
    pub async fn create_uni_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        id: UniChannelId,
        psk: PresharedKey,
    ) -> Result<AqcSenderChannel> {
        match self
            .create_channel(addr, label_id, AqcChannel::Unidirectional { id }, psk)
            .await?
        {
            AqcChannelType::Sender { sender } => Ok(sender),
            _ => buggy::bug!("Invalid channel type: expected Sender for unidirectional channel"),
        }
    }

    /// Creates a new bidirectional channel to the given address.
    pub async fn create_bidi_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        id: BidiChannelId,
        psk: PresharedKey,
    ) -> Result<AqcBidirectionalChannel> {
        match self
            .create_channel(addr, label_id, AqcChannel::Bidirectional { id }, psk)
            .await?
        {
            AqcChannelType::Bidirectional { channel } => Ok(channel),
            _ => buggy::bug!(
                "Invalid channel type: expected Bidirectional for bidirectional channel"
            ),
        }
    }

    /// Send a control message to the given address.
    pub async fn send_ctrl(
        &mut self,
        addr: SocketAddr,
        ctrl: AqcCtrl,
        team_id: TeamId,
    ) -> Result<()> {
        let psk = PresharedKey::external(PSK_IDENTITY_CTRL, PSK_BYTES_CTRL)
            .assume("unable to create psk")?;
        self.client_keys.set_key(psk);
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let mut send = conn.open_send_stream().await?;
        let msg = AqcCtrlMessage { team_id, ctrl };
        let msg_bytes = postcard::to_stdvec(&msg)?;
        send.send(Bytes::from_owner(msg_bytes)).await?;
        Ok(())
    }
}
