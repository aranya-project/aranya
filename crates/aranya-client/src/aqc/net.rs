#![warn(missing_docs)]

//! The AQC network implementation.

use core::task::{Context as CoreContext, Poll};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::{AqcCtrl, AqcPsk, DaemonApiClient, LabelId, TeamId};
use buggy::BugExt;
use bytes::Bytes;
use futures_util::task::noop_waker;
use s2n_quic::{
    client::Connect,
    connection::Handle,
    provider::{self, tls::rustls::rustls::crypto::PresharedKey},
    stream::{PeerStream, ReceiveStream, SendStream},
    Client, Connection, Server,
};
use tarpc::context;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::{
    aqc::api::{AqcChannel, ClientPresharedKeys, PSK_BYTES_CTRL, PSK_IDENTITY_CTRL},
    error::{self, AqcError, IpcError},
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
    channel_map: &mut HashMap<Vec<u8>, AqcChannel>,
) -> crate::Result<()> {
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

fn create_channel_type(conn: Connection, channel_info: &AqcChannel) -> AqcChannelType {
    match channel_info {
        AqcChannel::Bidirectional { id } => {
            // Once we accept a valid connection, let's turn it into an AQC Channel that we can
            // then open an arbitrary number of streams on.
            let channel = AqcBidirectionalChannel::new(LabelId::default(), *id, conn);
            AqcChannelType::Bidirectional { channel }
        }
        AqcChannel::Unidirectional { id } => {
            // Once we accept a valid connection, let's turn it into an AQC Channel that we can
            // then open an arbitrary number of streams on.
            let receiver = AqcReceiverChannel::new(LabelId::default(), *id, conn);
            AqcChannelType::Receiver { receiver }
        }
    }
}

async fn receive_ctrl_message(
    daemon: &Arc<DaemonApiClient>,
    channel_map: &mut HashMap<Vec<u8>, AqcChannel>,
    conn: &mut Connection,
) -> Result<(), AqcError> {
    match conn.accept_bidirectional_stream().await {
        Ok(Some(stream)) => {
            let (mut recv, mut send) = stream.split();
            let Ok(Some(ctrl_bytes)) = recv.receive().await else {
                error!("Failed to receive control message or stream closed");
                return Err(AqcError::ConnectionClosed);
            };
            match postcard::from_bytes::<AqcCtrlMessage>(&ctrl_bytes) {
                Ok(ctrl) => {
                    receive_aqc_ctrl(daemon.clone(), ctrl.team_id, ctrl.ctrl, channel_map)
                        .await
                        .map_err(anyhow::Error::new)?;
                    // Send an ACK back
                    let ack_msg = AqcAckMessage::Success;
                    let ack_bytes = postcard::to_stdvec(&ack_msg)
                        .map_err(|e_postcard| AqcError::Other(anyhow::Error::new(e_postcard)))?;
                    send.send(Bytes::from(ack_bytes))
                        .await
                        .map_err(|e| AqcError::ConnectionError(e.to_string()))?;
                    send.close()
                        .await
                        .map_err(|e| AqcError::ConnectionError(e.to_string()))?;
                }
                Err(e) => {
                    error!("Failed to deserialize AqcCtrlMessage: {}", e);
                    let ack_msg = AqcAckMessage::Failure(format!(
                        "Failed to deserialize AqcCtrlMessage: {}",
                        e
                    ));
                    let ack_bytes = postcard::to_stdvec(&ack_msg)
                        .map_err(|e_postcard| AqcError::Other(anyhow::Error::new(e_postcard)))?;
                    let _ = send.send(Bytes::from(ack_bytes)).await;
                    let _ = send.close().await;
                    return Err(AqcError::Other(anyhow::anyhow!(
                        "Failed to deserialize AqcCtrlMessage: {}",
                        e
                    )));
                }
            }
        }
        Ok(None) => {
            return Err(AqcError::ConnectionClosed);
        }
        Err(e) => {
            return Err(AqcError::ConnectionError(e.to_string()));
        }
    }
    Ok(())
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
    pub fn close(&mut self) {
        const ERROR_CODE: u32 = 0;
        self.handle.close(ERROR_CODE.into());
    }
}

impl Drop for AqcSenderChannel {
    fn drop(&mut self) {
        debug!("dropped uni channel");
        // Attempt to close the channel when the sender is dropped.
        // Log if there's an error, but don't panic as drop should not panic.
        self.close()
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
            Err(e) => Err(AqcError::ConnectionError(e.to_string())),
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
            Poll::Ready(Err(e)) => Err(TryReceiveError::AqcError(AqcError::ConnectionError(
                e.to_string(),
            ))),
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
            Err(e) => Err(AqcError::ConnectionError(e.to_string())),
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
                Err(TryReceiveError::AqcError(AqcError::ConnectionClosed))
            }
            Poll::Ready(Err(e)) => {
                // An error occurred on the connection while trying to accept a stream.
                // This likely means the connection is unusable for new streams.
                Err(TryReceiveError::AqcError(AqcError::ConnectionError(
                    e.to_string(),
                )))
            }
            Poll::Pending => {
                // No stream is immediately available.
                Err(TryReceiveError::Empty)
            }
        }
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_uni_stream(&mut self) -> Result<AqcSendStream> {
        let send = self.conn.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidi_stream(&mut self) -> Result<(AqcSendStream, AqcReceiveStream)> {
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
        debug!("dropped bidi channel");
        // Attempt to close the channel when the bidirectional channel is dropped.
        // Log if there's an error, but don't panic as drop should not panic.
        self.close()
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
    pub fn try_receive(&mut self, target: &mut [u8]) -> Result<usize, TryReceiveError> {
        let waker = noop_waker();
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
#[derive(Debug, thiserror::Error)]
pub enum TryReceiveError {
    /// The channel or stream is empty.
    #[error("channel or stream is empty")]
    Empty,
    /// An AQC error occurred.
    #[error("an AQC error occurred")]
    AqcError(AqcError),
    /// The channel or stream is closed.
    #[error("channel or stream is closed")]
    Closed,
}

/// An AQC client. Used to create and receive channels.
#[derive(Debug)]
pub(crate) struct AqcClient {
    quic_client: Client,
    client_keys: Arc<ClientPresharedKeys>,
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
        identity_rx: mpsc::Receiver<Vec<u8>>,
        server: Server,
        daemon: Arc<DaemonApiClient>,
    ) -> Result<AqcClient> {
        let quic_client = Client::builder()
            .with_tls(provider)?
            .with_io("0.0.0.0:0")?
            .start()?;
        Ok(AqcClient {
            quic_client,
            client_keys,
            channels: HashMap::new(),
            server,
            daemon,
            identity_rx,
        })
    }

    /// Get the local address of the client.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.quic_client.local_addr()?)
    }

    /// Receive the next available channel. If the channel is closed, return None.
    /// This method will return a channel created by a peer that hasn't been received yet.
    pub async fn receive_channel(&mut self) -> Result<AqcChannelType, AqcError> {
        loop {
            // Accept a new connection
            match self.server.accept().await {
                Some(mut conn) => {
                    // Receive a PSK identity hint.
                    // TODO: Instead of receiving the PSK identity hint here, we should
                    // pull it directly from the connection.
                    let Some(identity) = self.identity_rx.recv().await else {
                        error!("Identity hint channel closed. Unable to create channel.");
                        return Err(AqcError::NoIdentityHint);
                    };
                    debug!(
                        "Processing connection accepted after seeing PSK identity hint: {:02x?}",
                        identity
                    );
                    // If the PSK identity hint is the control PSK, receive a control message.
                    // This will update the channel map with the PSK and associate it with an
                    // AqcChannel.
                    if identity == PSK_IDENTITY_CTRL {
                        receive_ctrl_message(&self.daemon, &mut self.channels, &mut conn).await?;
                    // If the PSK identity hint is not the control PSK, check if it's in the channel map.
                    // If it is, create a channel of the appropriate type. We should have already received
                    // the control message for this PSK, if we don't we can't create a channel.
                    } else {
                        match self.channels.get(&identity) {
                            Some(channel_info) => {
                                return Ok(create_channel_type(conn, channel_info));
                            }
                            None => {
                                debug!(
                                    "No channel info found in map for identity hint {:02x?}",
                                    identity
                                );
                                return Err(AqcError::NoChannelInfoFound);
                            }
                        }
                    }
                }
                None => {
                    return Err(AqcError::ServerConnectionTerminated);
                }
            }
        }
    }

    /// Receive the next available channel. If there is no channel available,
    /// return Empty. If the channel is disconnected, return Disconnected. If disconnected
    /// is returned no channels will be available until the application is restarted.
    pub fn try_receive_channel(&mut self) -> Result<AqcChannelType, TryReceiveError> {
        loop {
            let waker = noop_waker();
            let mut cx = CoreContext::from_waker(&waker);
            // Accept a new connection
            match self.server.poll_accept(&mut cx) {
                Poll::Ready(Some(mut conn)) => {
                    // Receive a PSK identity hint.
                    // TODO: Instead of receiving the PSK identity hint here, we should
                    // pull it directly from the connection.
                    let Ok(identity) = self.identity_rx.try_recv() else {
                        error!("Identity hint channel closed. Unable to create channel.");
                        return Err(TryReceiveError::AqcError(AqcError::NoIdentityHint));
                    };
                    debug!(
                        "Processing connection accepted after seeing PSK identity hint: {:02x?}",
                        identity
                    );
                    // If the PSK identity hint is the control PSK, receive a control message.
                    // This will update the channel map with the PSK and associate it with an
                    // AqcChannel.
                    if identity == PSK_IDENTITY_CTRL {
                        // Block on the async function
                        let result = futures_lite::future::block_on(async {
                            receive_ctrl_message(&self.daemon, &mut self.channels, &mut conn).await
                        });

                        if let Err(e) = result {
                            // The original function logged an error and returned ControlFlow::Break
                            // which implies the loop should terminate or an error state.
                            // For try_receive_channel, this might mean the connection is unusable for ctrl messages.
                            warn!("Receiving control message failed: {}, potential issue with connection.", e);
                            // Depending on desired behavior, you might return an error or continue.
                            // For now, let's assume it's an error if control message processing fails critically.
                            return Err(TryReceiveError::AqcError(AqcError::Other(
                                anyhow::anyhow!("Control message processing failed: {}", e),
                            )));
                        }
                    // If the PSK identity hint is not the control PSK, check if it's in the channel map.
                    // If it is, create a channel of the appropriate type. We should have already received
                    // the control message for this PSK, if we don't we can't create a channel.
                    } else if let Some(channel_info) = self.channels.get(&identity) {
                        return Ok(create_channel_type(conn, channel_info));
                    } else {
                        debug!(
                            "No channel info found in map for identity hint {:02x?}",
                            identity
                        );
                        return Err(TryReceiveError::AqcError(AqcError::NoChannelInfoFound));
                    }
                }
                Poll::Ready(None) => {
                    return Err(TryReceiveError::AqcError(
                        AqcError::ServerConnectionTerminated,
                    ));
                }
                Poll::Pending => {
                    return Err(TryReceiveError::Empty);
                }
            }
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
                let channel = AqcBidirectionalChannel::new(label_id, id, conn);
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
        let (mut recv, mut send) = conn.open_bidirectional_stream().await?.split();
        let msg = AqcCtrlMessage { team_id, ctrl };
        let msg_bytes = postcard::to_stdvec(&msg)?;
        send.send(Bytes::from_owner(msg_bytes)).await?;
        if let Some(msg_bytes) = recv.receive().await? {
            let msg = postcard::from_bytes::<AqcAckMessage>(&msg_bytes)?;
            match msg {
                AqcAckMessage::Success => (),
                AqcAckMessage::Failure(e) => return Err(anyhow::anyhow!(e)),
            }
        }
        Ok(())
    }
}
