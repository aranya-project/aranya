#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::net::SocketAddr;

use anyhow::Result;
use aranya_crypto::Id;
use aranya_daemon_api::{AqcBidiChannelId, LabelId};
use bytes::Bytes;
use s2n_quic::{
    client::Connect,
    connection::{self, Handle},
    provider::{self, StartError},
    stream::{self, BidirectionalStream, PeerStream, ReceiveStream, SendStream},
    Client, Connection, Server,
};
use tokio::sync::mpsc::{self};
use tracing::{debug, error};

/// An error running the AQC client
#[derive(Debug, thiserror::Error)]
pub enum AqcError {
    /// A channel was closed.
    #[error("channel closed")]
    ChannelClosed,
    /// An error creating a quic connection.
    #[error("connect error: {0}")]
    Connect(#[from] connection::Error),
    /// An error using a stream.
    #[error("stream error: {0}")]
    Stream(#[from] stream::Error),
    /// An error starting an s2n quic client.
    #[error("start error: {0}")]
    Start(#[from] StartError),
    /// An infallible error.
    #[error("infallible error: {0}")]
    Infallible(#[from] std::convert::Infallible),
    /// An io error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An internal AQC error.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
    /// A std error.
    #[error("std error: {0}")]
    Std(#[from] Box<dyn std::error::Error>),
    /// A buggy error.
    #[error("buggy error: {0}")]
    Buggy(#[from] buggy::Bug),
}

/// Runs a server listening for quic channel requests from other peers.
pub async fn run_channels(mut server: Server, sender: mpsc::Sender<AqcChannelType>) {
    loop {
        match server.accept().await {
            Some(conn) => {
                let (channel, (bi_sender, uni_sender)) = AqcBidirectionalChannel::new(
                    LabelId::default(),
                    AqcBidiChannelId::from(Id::default()),
                    conn.handle(),
                );
                if sender
                    .send(AqcChannelType::Bidirectional { channel })
                    .await
                    .is_err()
                {
                    error!("Sender closed. Unable to send channel");
                    return;
                } else {
                    tokio::spawn(handle_streams(conn, bi_sender, uni_sender));
                }
            }
            None => {
                debug!("Server connection terminated");
                break;
            }
        }
    }
}

async fn handle_streams(
    mut conn: Connection,
    bi_sender: mpsc::Sender<BidirectionalStream>,
    uni_sender: mpsc::Sender<ReceiveStream>,
) {
    loop {
        match conn.accept().await {
            Ok(Some(stream)) => match stream {
                PeerStream::Bidirectional(stream) => {
                    if bi_sender.send(stream).await.is_err() {
                        error!("error sending bi stream");
                    }
                }
                PeerStream::Receive(stream) => {
                    if uni_sender.send(stream).await.is_err() {
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

/// Indicates whether the channel is unidirectional or bidirectional
pub enum AqcChannelDirection {
    /// Data can only be sent in one direction.
    UNIDIRECTIONAL,
    /// Data can be sent in either direction
    BIDIRECTIONAL,
}

/// Indicates the type of channel
#[derive(Debug)]
pub enum AqcChannelType {
    /// Used to send data to a peer.
    Sender {
        /// The sending end of a unidirectional channel.
        sender: AqcChannelSender,
    },
    /// Used to receive data from a peer.
    Receiver {
        /// The receiving end of a unidirectional channel.
        receiver: AqcChannelReceiver,
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
pub struct AqcChannelSender {
    label_id: LabelId,
    handle: Handle,
}

impl AqcChannelSender {
    /// Create a new channel with the given id and conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub fn new(label_id: LabelId, handle: Handle) -> Self {
        Self { label_id, handle }
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_unidirectional_stream(&mut self) -> Result<AqcSendStream> {
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

/// The receive end of a unidirectional channel.
/// Allows receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcChannelReceiver {
    label_id: LabelId,
    uni_receiver: mpsc::Receiver<ReceiveStream>,
}

impl AqcChannelReceiver {
    /// Create a new channel with the given conection handle.
    ///
    /// Returns the new channel and the sender used to send new streams to the
    /// channel.
    pub fn new(label_id: LabelId) -> (Self, mpsc::Sender<ReceiveStream>) {
        let (uni_sender, uni_receiver) = mpsc::channel(10);
        (
            Self {
                label_id,
                uni_receiver,
            },
            uni_sender,
        )
    }

    /// Get the channel id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Returns a unidirectional stream if one has been received.
    /// If no stream has been received return None.
    pub async fn receive_unidirectional_stream(&mut self) -> Result<Option<AqcReceiveStream>> {
        match self.uni_receiver.recv().await {
            Some(stream) => Ok(Some(AqcReceiveStream { receive: stream })),
            None => Ok(None),
        }
    }
}

/// A unique channel between two peers.
/// Allows sending and receiving data streams over a channel.
#[derive(Debug)]
pub struct AqcBidirectionalChannel {
    label_id: LabelId,
    aqc_id: AqcBidiChannelId,
    handle: Handle,
    uni_receiver: mpsc::Receiver<ReceiveStream>,
    bi_receiver: mpsc::Receiver<BidirectionalStream>,
}

impl AqcBidirectionalChannel {
    /// Create a new bidirectional channel with the given id and conection handle.
    pub fn new(
        label_id: LabelId,
        aqc_id: AqcBidiChannelId,
        handle: Handle,
    ) -> (
        Self,
        (
            mpsc::Sender<BidirectionalStream>,
            mpsc::Sender<ReceiveStream>,
        ),
    ) {
        let (bi_sender, bi_receiver) = mpsc::channel(10);
        let (uni_sender, uni_receiver) = mpsc::channel(10);
        (
            Self {
                label_id,
                aqc_id,
                handle,
                uni_receiver,
                bi_receiver,
            },
            (bi_sender, uni_sender),
        )
    }

    /// Get the channel label id.
    pub fn label_id(&self) -> LabelId {
        self.label_id
    }

    /// Get the aqc id.
    pub fn aqc_id(&self) -> AqcBidiChannelId {
        self.aqc_id
    }

    /// Returns a bidirectional stream if one has been received.
    /// If no stream has been received return None.
    pub async fn receive_bidirectional_stream(
        &mut self,
    ) -> Option<(AqcSendStream, AqcReceiveStream)> {
        match self.bi_receiver.recv().await {
            Some(stream) => {
                let (receive, send) = stream.split();
                Some((AqcSendStream { send }, AqcReceiveStream { receive }))
            }
            None => None,
        }
    }

    /// Returns a unidirectional stream if one has been received.
    /// If no stream has been received return None.
    pub async fn receive_unidirectional_stream(&mut self) -> Result<Option<AqcReceiveStream>> {
        match self.uni_receiver.recv().await {
            Some(stream) => Ok(Some(AqcReceiveStream { receive: stream })),
            None => Ok(None),
        }
    }

    /// Creates a new unidirectional stream for the channel.
    pub async fn create_unidirectional_stream(&mut self) -> Result<AqcSendStream> {
        let send = self.handle.open_send_stream().await?;
        Ok(AqcSendStream { send })
    }

    /// Creates a new bidirectional stream for the channel.
    pub async fn create_bidirectional_stream(
        &mut self,
    ) -> Result<(AqcSendStream, AqcReceiveStream)> {
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

/// Used to receive data from a peer.
pub struct AqcReceiveStream {
    receive: ReceiveStream,
}

impl AqcReceiveStream {
    /// Receive the next available data from a stream. If the stream has been
    /// closed, return None.
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

/// The maximum number of channels that haven't been received.
const MAXIMUM_UNRECEIVED_CHANNELS: usize = 20;

/// An AQC client. Used to create and receive channels.
#[derive(Debug)]
pub struct AqcClient {
    quic_client: Client,
    /// Holds channels that have created, but not yet been received.
    receiver: mpsc::Receiver<AqcChannelType>,
}

impl AqcClient {
    /// Create an Aqc client with the given certificate chain.
    pub fn new<T: provider::tls::Provider>(
        cert: T,
    ) -> Result<(AqcClient, mpsc::Sender<AqcChannelType>)> {
        let (sender, receiver) = mpsc::channel(MAXIMUM_UNRECEIVED_CHANNELS);
        let quic_client = Client::builder()
            .with_tls(cert)?
            .with_io("0.0.0.0:0")?
            .start()?;
        Ok((
            AqcClient {
                quic_client,
                receiver,
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

    /// Create a new channel to the given address.
    async fn create_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        direction: AqcChannelDirection,
    ) -> Result<AqcChannelType> {
        // TODO: Create the channel in the graph.
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let channel = match direction {
            AqcChannelDirection::UNIDIRECTIONAL => AqcChannelType::Sender {
                sender: AqcChannelSender::new(label_id, conn.handle()),
            },
            AqcChannelDirection::BIDIRECTIONAL => {
                let (channel, (bi_sender, uni_sender)) = AqcBidirectionalChannel::new(
                    label_id,
                    AqcBidiChannelId::from(Id::default()),
                    conn.handle(),
                );
                tokio::spawn(handle_streams(conn, bi_sender, uni_sender));
                AqcChannelType::Bidirectional { channel }
            }
        };
        Ok(channel)
    }

    /// Creates a new unidirectional channel to the given address.
    pub async fn create_unidirectional_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
    ) -> Result<AqcChannelSender> {
        match self
            .create_channel(addr, label_id, AqcChannelDirection::UNIDIRECTIONAL)
            .await?
        {
            AqcChannelType::Sender { sender } => Ok(sender),
            _ => buggy::bug!("Invalid channel type: expected Sender for unidirectional channel"),
        }
    }

    /// Creates a new bidirectional channel to the given address.
    pub async fn create_bidirectional_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
    ) -> Result<AqcBidirectionalChannel> {
        match self
            .create_channel(addr, label_id, AqcChannelDirection::BIDIRECTIONAL)
            .await?
        {
            AqcChannelType::Bidirectional { channel } => Ok(channel),
            _ => buggy::bug!(
                "Invalid channel type: expected Bidirectional for bidirectional channel"
            ),
        }
    }
}
