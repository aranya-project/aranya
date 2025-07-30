#![warn(missing_docs)]

//! The AQC network implementation.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    task::{Context, Poll, Waker},
};

use aranya_crypto::aqc::{BidiChannelId, UniChannelId};
use aranya_daemon_api::{
    AqcBidiPsks, AqcCtrl, AqcPsks, AqcUniPsks, DaemonApiClient, LabelId, TeamId,
};
use aranya_util::{
    error::ReportExt as _,
    rustls::{NoCertResolver, SkipServerVerification},
    s2n_quic::read_to_end,
};
use buggy::BugExt as _;
use bytes::Bytes;
use channels::AqcPeerChannel;
use s2n_quic::{
    self,
    client::Connect,
    provider::{
        congestion_controller::Bbr,
        tls::rustls::{
            self as rustls_provider,
            rustls::{server::PresharedKeySelection, ClientConfig, ServerConfig},
        },
    },
    Client, Connection, Server,
};
use tarpc::context;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use super::crypto::{ClientPresharedKeys, ServerPresharedKeys, CTRL_PSK, PSK_IDENTITY_CTRL};
use crate::{
    aqc::net::channels::ChannelKeys,
    error::{aranya_error, AqcError, IpcError},
};

pub mod channels;

/// ALPN protocol identifier for Aranya QUIC Channels
const ALPN_AQC: &[u8] = b"aqc-v1";

/// An AQC client. Used to create and receive channels.
// TODO: query daemon to see if active AQC channels are invalid. Delete invalid channels.
#[derive(Debug)]
pub(crate) struct AqcClient {
    /// Local address of `quic_client`.
    client_addr: SocketAddr,
    /// Quic client state
    client_state: tokio::sync::Mutex<ClientState>,

    /// Local address of `server_state.quic_server`.
    server_addr: SocketAddr,
    /// Quic server state
    server_state: tokio::sync::Mutex<ServerState>,
    /// Key provider for `quic_server`.
    ///
    /// Inserting to this will add keys which the `server` will accept.
    server_keys: Arc<ServerPresharedKeys>,

    /// Map of PSK identity to channel type
    channels: std::sync::RwLock<HashMap<PskIdentity, AqcChannelInfo>>,

    daemon: DaemonApiClient,
}

#[derive(Debug)]
struct ClientState {
    /// Quic client used to create channels with peers.
    quic_client: Client,
    /// Key provider for `quic_client`.
    ///
    /// Modifying this will change the keys used by `quic_client`.
    client_keys: Arc<ClientPresharedKeys>,
}

impl ClientState {
    fn connect_ctrl(&mut self, addr: SocketAddr) -> s2n_quic::client::ConnectionAttempt {
        debug!("connect ctrl");
        self.client_keys.set_key(CTRL_PSK.clone());
        self.quic_client
            .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
    }

    fn connect_data(
        &mut self,
        addr: SocketAddr,
        psks: AqcPsks,
    ) -> s2n_quic::client::ConnectionAttempt {
        debug!("connect data");
        self.client_keys.load_psks(psks);
        self.quic_client
            .connect(Connect::new(addr).with_server_name(addr.ip().to_string()))
    }

    fn zeroize_psks(&mut self, identities: &[PskIdentity]) {
        debug!("zeroizing client psks");
        self.client_keys.zeroize_psks(identities);
    }

    fn clear(&mut self) {
        self.client_keys.clear();
    }
}

#[derive(Debug)]
struct ServerState {
    /// Quic server used to accept channels from peers.
    quic_server: Server,
    /// Receives latest selected PSK for accepted channel from server PSK provider.
    identity_rx: mpsc::Receiver<PskIdentity>,
}

/// Identity of a preshared key.
pub type PskIdentity = Vec<u8>;

impl AqcClient {
    pub async fn new(server_addr: SocketAddr, daemon: DaemonApiClient) -> Result<Self, AqcError> {
        let client_keys = Arc::new(ClientPresharedKeys::new(CTRL_PSK.clone()));

        // Create Client Config (INSECURE: Skips server cert verification)
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        client_config.preshared_keys = client_keys.clone(); // Pass the Arc<ClientPresharedKeys>

        // TODO(jdygert): enable after rustls upstream fix.
        // client_config.psk_kex_modes = vec![PskKexMode::PskOnly];

        let (server_keys, identity_rx) = ServerPresharedKeys::new();
        server_keys.insert(CTRL_PSK.clone());
        let server_keys = Arc::new(server_keys);

        // Create Server Config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertResolver::default()));
        server_config.alpn_protocols = vec![ALPN_AQC.to_vec()]; // Set field directly
        server_config.preshared_keys =
            PresharedKeySelection::Required(Arc::clone(&server_keys) as _);

        #[allow(deprecated)]
        let tls_client_provider = rustls_provider::Client::new(client_config);
        #[allow(deprecated)]
        let tls_server_provider = rustls_provider::Server::new(server_config);

        // Use the rustls server provider
        let server = Server::builder()
            .with_tls(tls_server_provider)? // Use the wrapped server config
            .with_io(server_addr)
            .assume("can set aqc server addr")?
            .with_congestion_controller(Bbr::default())?
            .start()?;

        let quic_client = Client::builder()
            .with_tls(tls_client_provider)?
            .with_io((Ipv4Addr::UNSPECIFIED, 0))
            .assume("can set aqc client addr")?
            .start()?;

        let server_addr = server.local_addr().assume("can get addr")?;
        let client_addr = quic_client.local_addr().assume("can get addr")?;

        Ok(AqcClient {
            client_addr,
            client_state: tokio::sync::Mutex::new(ClientState {
                quic_client,
                client_keys,
            }),
            server_keys,
            channels: std::sync::RwLock::new(HashMap::new()),
            daemon,
            server_addr,
            server_state: tokio::sync::Mutex::new(ServerState {
                quic_server: server,
                identity_rx,
            }),
        })
    }

    /// Get the client address.
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Get the server address.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Creates a new unidirectional channel to the given address.
    pub async fn create_uni_channel(
        &self,
        addr: SocketAddr,
        label_id: LabelId,
        psks: AqcUniPsks,
    ) -> Result<channels::AqcSendChannel, AqcError> {
        let channel_id = UniChannelId::from(*psks.channel_id());
        let Ok(mut conn) = self
            .client_state
            .lock()
            .await
            .connect_data(addr, AqcPsks::Uni(psks.clone()))
            .await
        else {
            error!("connection closed");
            let identities: Vec<PskIdentity> = psks
                .into_iter()
                .map(|(_, p)| p.identity.as_bytes().to_vec())
                .collect();
            self.zeroize_psks(identities).await;
            return Err(AqcError::ConnectionClosed);
        };
        conn.keep_alive(true)?;
        debug!("getting psk identities");
        let identities: Vec<PskIdentity> = psks
            .into_iter()
            .map(|(_, psk)| psk.identity.as_bytes().to_vec())
            .collect();
        debug!("got psk identities");
        let keys = ChannelKeys::new(
            identities,
            self.client_state.lock().await.client_keys.clone(),
            self.server_keys.clone(),
        );
        Ok(channels::AqcSendChannel::new(
            label_id,
            channel_id,
            conn.handle(),
            keys,
        ))
    }

    /// Creates a new bidirectional channel to the given address.
    pub async fn create_bidi_channel(
        &self,
        addr: SocketAddr,
        label_id: LabelId,
        psks: AqcBidiPsks,
    ) -> Result<channels::AqcBidiChannel, AqcError> {
        let channel_id = BidiChannelId::from(*psks.channel_id());
        let Ok(mut conn) = self
            .client_state
            .lock()
            .await
            .connect_data(addr, AqcPsks::Bidi(psks.clone()))
            .await
        else {
            debug!("connection closed");
            let identities: Vec<PskIdentity> = psks
                .into_iter()
                .map(|(_, p)| p.identity.as_bytes().to_vec())
                .collect();
            self.zeroize_psks(identities).await;
            return Err(AqcError::ConnectionClosed);
        };
        conn.keep_alive(true)?;
        debug!("fetching psk identities");
        let identities: Vec<PskIdentity> = psks
            .into_iter()
            .map(|(_, psk)| psk.identity.as_bytes().to_vec())
            .collect();
        debug!("received psk identities");
        let keys = ChannelKeys::new(
            identities,
            self.client_state.lock().await.client_keys.clone(),
            self.server_keys.clone(),
        );
        Ok(channels::AqcBidiChannel::new(
            label_id, channel_id, conn, keys,
        ))
    }

    /// Zeroize PSKs from client and server.
    async fn zeroize_psks(&self, identities: Vec<PskIdentity>) {
        debug!("zeroize client and server psks");
        self.client_state.lock().await.zeroize_psks(&identities);
        self.server_keys.zeroize_psks(&identities);
        for identity in identities {
            self.channels.write().expect("poisoned").remove(&identity);
        }
    }

    /// Receive the next available channel.
    pub async fn receive_channel(&mut self) -> crate::Result<AqcPeerChannel> {
        loop {
            debug!("accept a new connection");
            // Accept a new connection
            let mut server_state = self.server_state.lock().await;
            let Some(mut conn) = server_state.quic_server.accept().await else {
                error!("server connection terminated");
                return Err(crate::Error::Aqc(AqcError::ServerConnectionTerminated));
            };
            debug!("accepted connection");
            // Receive a PSK identity hint.
            // TODO: Instead of receiving the PSK identity hint here, we should
            // pull it directly from the connection.
            let identity = server_state
                .identity_rx
                .try_recv()
                .assume("identity received after accepting connection")?;
            debug!(
                "Processing connection accepted after seeing PSK identity hint: {:02x?}",
                identity
            );
            debug!("received PSK identity hint");
            // If the PSK identity hint is the control PSK, receive a control message.
            // This will update the channel map with the PSK and associate it with an
            // AqcChannel.
            if identity == PSK_IDENTITY_CTRL {
                debug!("receive ctrl message");
                self.receive_ctrl_message(&mut conn).await?;
                debug!("received ctrl message");
                continue;
            }
            // If the PSK identity hint is not the control PSK, check if it's in the channel map.
            // If it is, create a channel of the appropriate type. We should have already received
            // the control message for this PSK, if we don't we can't create a channel.
            let client_keys = self.client_state.lock().await.client_keys.clone();
            let channels = self.channels.read().expect("poisoned");
            let channel_info = channels.get(&identity).ok_or_else(|| {
                warn!(
                    "No channel info found in map for identity hint {:02x?}",
                    identity
                );
                AqcError::NoChannelInfoFound
            })?;
            let keys = ChannelKeys::new(vec![identity], client_keys, self.server_keys.clone());
            return Ok(AqcPeerChannel::new(
                channel_info.label_id,
                channel_info.channel_id,
                conn,
                keys,
            ));
        }
    }

    /// Receive the next available channel.
    ///
    /// If there is no channel available, return Empty.
    /// If the channel is closed, return Closed.
    pub fn try_receive_channel(&mut self) -> Result<AqcPeerChannel, TryReceiveError<crate::Error>> {
        let mut server_state = self
            .server_state
            .try_lock()
            .map_err(|_| TryReceiveError::Empty)?; // TODO: Is this really what we want?
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            // Accept a new connection
            let mut conn = match server_state.quic_server.poll_accept(&mut cx) {
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
            let identity = server_state
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
                    warn!(error = %e.report(), "Receiving control message failed, potential issue with connection.");
                    // Depending on desired behavior, you might return an error or continue.
                    // For now, let's assume it's an error if control message processing fails critically.
                    return Err(TryReceiveError::Error(e));
                }

                continue;
            }
            // If the PSK identity hint is not the control PSK, check if it's in the channel map.
            // If it is, create a channel of the appropriate type. We should have already received
            // the control message for this PSK, if we don't we can't create a channel.
            let channels = self.channels.read().expect("poisoned");
            let channel_info = channels.get(&identity).ok_or_else(|| {
                debug!(
                    "No channel info found in map for identity hint {:02x?}",
                    identity
                );
                TryReceiveError::Error(AqcError::NoChannelInfoFound.into())
            })?;
            let client_keys = futures_lite::future::block_on(self.client_state.lock())
                .client_keys
                .clone();
            let keys = ChannelKeys::new(vec![identity], client_keys, self.server_keys.clone());
            return Ok(AqcPeerChannel::new(
                channel_info.label_id,
                channel_info.channel_id,
                conn,
                keys,
            ));
        }
    }

    /// Send a control message to the given address.
    pub async fn send_ctrl(
        &self,
        addr: SocketAddr,
        ctrl: AqcCtrl,
        team_id: TeamId,
    ) -> Result<(), AqcError> {
        debug!("sending ctrl message");
        let mut conn = self.client_state.lock().await.connect_ctrl(addr).await?;
        let stream = conn.open_bidirectional_stream().await?;
        let (mut recv, mut send) = stream.split();

        let msg = AqcCtrlMessage { team_id, ctrl };
        let msg_bytes = postcard::to_stdvec(&msg).assume("can serialize")?;
        send.send(Bytes::from(msg_bytes)).await?;
        send.finish()?;

        let data = recv.receive().await.map_err(|err| match err {
            s2n_quic::stream::Error::StreamReset { .. } => AqcError::PeerCtrl,
            _ => AqcError::StreamError(err),
        })?;
        if data.is_some() {
            warn!("peer sent unexpected data")
        }

        Ok(())
    }

    async fn receive_ctrl_message(&self, conn: &mut Connection) -> crate::Result<()> {
        let stream = conn
            .accept_bidirectional_stream()
            .await
            .map_err(AqcError::ConnectionError)?
            .ok_or(AqcError::ConnectionClosed)?;
        let (mut recv, mut send) = stream.split();
        let ctrl_bytes = read_to_end(&mut recv).await.map_err(AqcError::from)?;
        self.process_ctrl_message(&ctrl_bytes)
            .await
            .inspect_err(|_| {
                if let Err(err) = send.reset(s2n_quic::application::Error::UNKNOWN) {
                    warn!(error = %err.report(), "could not notify peer of ctrl error");
                }
            })
    }

    /// Receives an AQC ctrl message.
    async fn process_ctrl_message(&self, ctrl_bytes: &[u8]) -> crate::Result<()> {
        let msg = postcard::from_bytes::<AqcCtrlMessage>(ctrl_bytes)
            .map_err(AqcError::InvalidCtrlMessage)?;

        let (label_id, psks) = self
            .daemon
            .receive_aqc_ctrl(context::current(), msg.team_id, msg.ctrl)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;

        self.server_keys.load_psks(psks.clone());

        let mut channels = self.channels.write().expect("poisoned");
        match psks {
            AqcPsks::Bidi(psks) => {
                for (_suite, psk) in psks {
                    channels.insert(
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
                    channels.insert(
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

    /// Close the AQC client.
    pub async fn close(&mut self) {
        warn!("AQC client close");
        self.channels.write().expect("poisoned").clear();
        self.client_state.lock().await.clear();
        self.server_keys.clear();
    }
}

impl Drop for AqcClient {
    fn drop(&mut self) {
        warn!("dropping AQC client");
        futures_lite::future::block_on(self.close());
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
    /// The  stream is closed.
    #[error("stream is closed")]
    StreamClosed,
    /// The channel is closed.
    #[error("channel is closed")]
    ChannelClosed,
}

#[derive(Debug)]
struct AqcChannelInfo {
    label_id: LabelId,
    channel_id: AqcChannelId,
}

/// An AQC Channel ID.
#[derive(Copy, Clone, Debug)]
enum AqcChannelId {
    Bidi(BidiChannelId),
    Uni(UniChannelId),
}

/// An AQC control message.
#[derive(serde::Serialize, serde::Deserialize)]
struct AqcCtrlMessage {
    /// The team id.
    team_id: TeamId,
    /// The control message.
    ctrl: AqcCtrl,
}
