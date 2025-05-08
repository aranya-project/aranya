//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::{fmt, marker::PhantomData, net::SocketAddr};
use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use aranya_policy_ifgen::VmEffect;
use aranya_runtime::{ClientState, Engine, GraphId, Sink, StorageProvider, VmPolicy};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinSet};
use tracing::{debug, error, info, instrument, trace};

use s2n_quic::{
    client::Connect,
    connection::Handle,
    provider::self,
    stream::{PeerStream, ReceiveStream, SendStream},
    Client as QuicClient, Connection, Server as QuicServer,
};

use super::prot::SyncProtocols;

/// QUIC Syncer protocol type.
pub const PROT:SyncProtocols = SyncProtocols::QUIC;

/// QUIC Syncer protocol version.
pub const VERSION: u16 = 1;

// TODO: get this PSK from keystore or config file.
// PSK is hard-coded to prototype the QUIC syncer until PSK key management is complete.
const PSK: &[u8] = "test_psk".as_bytes();

/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("./cert.pem");
/// TODO: remove this.
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("./key.pem");

/// A response to a sync request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}

/// Aranya QUIC sync client.
pub struct Client<EN, SP, CE> {
    /// Thread-safe Aranya client reference.
    pub(crate) aranya: Arc<Mutex<ClientState<EN, SP>>>,
    _eng: PhantomData<CE>,
}

impl<EN, SP, CE> Client<EN, SP, CE> {
    /// Creates a new [`Client`].
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>) -> Self {
        Client {
            aranya,
            _eng: PhantomData,
        }
    }
}

impl<EN, SP, CE> Client<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    /// Syncs with the peer.
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    #[instrument(skip_all)]
    pub async fn sync_peer<S>(&self, id: GraphId, sink: &mut S, addr: &Addr) -> Result<()>
    where
        S: Sink<<EN as Engine>::Effect>,
    {
        todo!();
    }
}

impl<EN, SP, CE> fmt::Debug for Client<EN, SP, CE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

/// The Aranya QUIC sync server.
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client reference.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// QUIC server.
    server: QuicServer,
    /// Stores a QUIC connection for each peer.
    conns: Arc<Mutex<BTreeMap<SocketAddr, Connection>>>,
    /// Tracks running tasks.
    set: JoinSet<()>,
}

impl<EN, SP> Server<EN, SP> {
    /// Creates a new `Server`.
    #[inline]
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>, server: QuicServer) -> Self {
        Self { aranya, server, conns: Arc::new(Mutex::new(BTreeMap::new())), set: JoinSet::new() }
    }

    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        todo!();
    }
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Begins accepting incoming requests.
    #[instrument(skip_all)]
    pub async fn serve(mut self) -> Result<()> {
        // Accept incoming QUIC connections
        while let Some(mut conn) = self.server.accept().await {
            info!("received incoming QUIC connection");
            let Ok(peer) = conn.remote_addr() else {
                error!("unable to get peer address from connection");
                continue;
            };
            let client = Arc::clone(&self.aranya);
            self.set.spawn(async move {
                loop {
                    // Accept incoming streams.
                    match conn.accept_receive_stream().await {
                        Ok(Some(stream)) => {
                            trace!("received incoming QUIC stream");
                            if let Err(e) = Self::sync(client.clone(), peer, stream).await {
                                error!(?e, ?peer, "unable to sync with peer");
                                break;
                            }
                        }
                        Ok(None) => {
                            debug!("QUIC connection was closed");
                            return;
                        }
                        Err(e) => {
                            error!("error receiving QUIC stream: {}", e);
                            return;
                        }
                    }
                }
            });
        }
        error!("server terminated");
        Ok(())
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(addr = %addr))]
    async fn sync(client: Arc<Mutex<ClientState<EN, SP>>>, addr: SocketAddr, stream: ReceiveStream) -> Result<()> {
        todo!();
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(
        client: Arc<Mutex<ClientState<EN, SP>>>,
        request: &[u8],
    ) -> Result<Box<[u8]>> {
        todo!();
    }
}
