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
use channels::AqcPeerChannel;
use futures_util::task::noop_waker;
use s2n_quic::{self, client::Connect, provider, Client, Connection, Server};
use tarpc::context;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use super::{
    api::AqcChannelId,
    crypto::{ClientPresharedKeys, ServerPresharedKeys, CTRL_KEY, PSK_IDENTITY_CTRL},
};
use crate::error::{aranya_error, AqcError, IpcError};

pub mod channels;

/// An AQC client. Used to create and receive channels.
#[derive(Debug)]
pub(crate) struct AqcClient {
    quic_client: Client,
    client_keys: Arc<ClientPresharedKeys>,
    server_keys: Arc<ServerPresharedKeys>,
    /// Map of PSK identity to channel type
    channels: HashMap<Vec<u8>, AqcChannelInfo>,
    server: Server,
    daemon: DaemonApiClient,
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
        daemon: DaemonApiClient,
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

    /// Creates a new unidirectional channel to the given address.
    pub async fn create_uni_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        psks: AqcUniPsks,
    ) -> Result<channels::AqcSenderChannel, AqcError> {
        let channel_id = UniChannelId::from(*psks.channel_id());
        self.client_keys.load_psks(AqcPsks::Uni(psks));
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        Ok(channels::AqcSenderChannel::new(
            label_id,
            channel_id,
            conn.handle(),
        ))
    }

    /// Creates a new bidirectional channel to the given address.
    pub async fn create_bidi_channel(
        &mut self,
        addr: SocketAddr,
        label_id: LabelId,
        psks: AqcBidiPsks,
    ) -> Result<channels::AqcBidiChannel, AqcError> {
        let channel_id = BidiChannelId::from(*psks.channel_id());
        self.client_keys.load_psks(AqcPsks::Bidi(psks));
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        Ok(channels::AqcBidiChannel::new(label_id, channel_id, conn))
    }

    /// Receive the next available channel. If the channel is closed, return None.
    /// This method will return a channel created by a peer that hasn't been received yet.
    pub async fn receive_channel(&mut self) -> crate::Result<AqcPeerChannel> {
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
                self.receive_ctrl_message(&mut conn).await?;
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
            return Ok(AqcPeerChannel::new(
                channel_info.label_id,
                channel_info.channel_id,
                conn,
            ));
        }
    }

    /// Receive the next available channel. If there is no channel available,
    /// return Empty. If the channel is disconnected, return Disconnected. If disconnected
    /// is returned no channels will be available until the application is restarted.
    pub fn try_receive_channel(&mut self) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
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
                let result = futures_lite::future::block_on(self.receive_ctrl_message(&mut conn));

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
            return Ok(AqcPeerChannel::new(
                channel_info.label_id,
                channel_info.channel_id,
                conn,
            ));
        }
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
            .connect(Connect::new(addr).with_server_name("localhost"))
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

    async fn receive_ctrl_message(&mut self, conn: &mut Connection) -> crate::Result<()> {
        let mut stream = conn
            .accept_bidirectional_stream()
            .await
            .map_err(AqcError::ConnectionError)?
            .ok_or(AqcError::ConnectionClosed)?;
        let Ok(Some(ctrl_bytes)) = stream.receive().await else {
            error!("Failed to receive control message or stream closed");
            return Err(AqcError::ConnectionClosed.into());
        };
        match postcard::from_bytes::<AqcCtrlMessage>(&ctrl_bytes) {
            Ok(ctrl) => {
                self.process_ctrl_message(ctrl.team_id, ctrl.ctrl).await?;
                // Send an ACK back
                let ack_msg = AqcAckMessage::Success;
                let ack_bytes = postcard::to_stdvec(&ack_msg).assume("can serialize")?;
                stream
                    .send(Bytes::from(ack_bytes))
                    .await
                    .map_err(AqcError::from)?;
                stream.close().await.map_err(AqcError::from)?;
            }
            Err(e) => {
                error!("Failed to deserialize AqcCtrlMessage: {}", e);
                let ack_msg =
                    AqcAckMessage::Failure(format!("Failed to deserialize AqcCtrlMessage: {}", e));
                let ack_bytes = postcard::to_stdvec(&ack_msg).assume("can serialize")?;
                let _ = stream.send(Bytes::from(ack_bytes)).await;
                let _ = stream.close().await;
                return Err(AqcError::Serde(e).into());
            }
        }
        Ok(())
    }

    /// Receives an AQC ctrl message.
    async fn process_ctrl_message(&mut self, team: TeamId, ctrl: AqcCtrl) -> crate::Result<()> {
        let (_peer, label_id, psks) = self
            .daemon
            .receive_aqc_ctrl(context::current(), team, ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;

        self.server_keys.load_psks(psks.clone());

        match psks {
            AqcPsks::Bidi(psks) => {
                for (_suite, psk) in psks {
                    self.channels.insert(
                        psk.identity.as_bytes().to_vec(),
                        AqcChannelInfo {
                            label_id,
                            channel_id: AqcChannelId::Bidi(*psk.identity.channel_id()),
                        },
                    );
                }
            }
            AqcPsks::Uni(psks) => {
                for (_suite, psk) in psks {
                    self.channels.insert(
                        psk.identity.as_bytes().to_vec(),
                        AqcChannelInfo {
                            label_id,
                            channel_id: AqcChannelId::Uni(*psk.identity.channel_id()),
                        },
                    );
                }
            }
        }

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

#[derive(Debug)]
struct AqcChannelInfo {
    label_id: LabelId,
    channel_id: AqcChannelId,
}

/// An AQC control message.
#[derive(serde::Serialize, serde::Deserialize)]
struct AqcCtrlMessage {
    /// The team id.
    pub team_id: TeamId,
    /// The control message.
    pub ctrl: AqcCtrl,
}

/// An AQC control message.
#[derive(serde::Serialize, serde::Deserialize)]
enum AqcAckMessage {
    /// The success message.
    Success,
    /// The failure message.
    Failure(String),
}
