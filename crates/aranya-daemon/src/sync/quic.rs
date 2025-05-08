//! Aranya QUIC client and server for syncing Aranya graph commands.
//!
//! The QUIC connections are secured with a rustls PSK.
//! A different PSK will be used for each Aranya team.
//!
//! If a QUIC connection does not exist with a certain peer, a new QUIC connection will be created.
//! Each sync request/response will use a single QUIC stream which is closed after the sync completes.

use core::{fmt, marker::PhantomData, net::SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use aranya_policy_ifgen::VmEffect;
use aranya_runtime::{ClientState, Engine, GraphId, Sink, StorageProvider, VmPolicy};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::instrument;

use super::prot::SyncProtocols;

/// QUIC Syncer protocol type.
pub const QUIC_SYNC_PROT:SyncProtocols = SyncProtocols::QUIC;

/// QUIC Syncer protocol version.
pub const QUIC_SYNC_VERSION: u16 = 1;

// TODO: get this PSK from keystore or config file.
// PSK is hard-coded to prototype the QUIC syncer until PSK key management is complete.
const PSK: &[u8] = "test_psk".as_bytes();

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
    // TODO: add listener.
}

impl<EN, SP> Server<EN, SP> {
    /// Creates a new `Server`.
    #[inline]
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>) -> Self {
        Self { aranya }
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
        todo!();
    }

    /// Responds to a sync.
    // TODO: add QUIC stream param.
    #[instrument(skip_all, fields(addr = %addr))]
    async fn sync(client: Arc<Mutex<ClientState<EN, SP>>>, addr: SocketAddr) -> Result<()> {
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
