//! Aranya TCP client and server for syncing Aranya graph commands.

use core::net::SocketAddr;

use anyhow::{bail, Context, Result};
use aranya_crypto::Rng;
use aranya_runtime::{
    Engine, GraphId, PeerCache, Sink, StorageProvider, SyncRequester, SyncResponder, SyncType,
    MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::{task::scope, Addr};
use buggy::bug;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info_span, instrument, Instrument};

use super::task::{SyncResponse, SyncState};
use crate::aranya::Client as AranyaClient;

/// Data used for sending sync requests and processing sync responses
pub struct State;

impl SyncState for State {
    /// Syncs with the peer.
    /// Aranya client sends a `SyncRequest` to peer then processes the `SyncResponse`.
    async fn sync_impl<S>(
        syncer: &mut super::task::Syncer<Self>,
        id: GraphId,
        sink: &mut S,
        peer: &Addr,
    ) -> Result<()>
    where
        S: Sink<<crate::EN as Engine>::Effect>,
    {
        // send the sync request.

        // TODO: Real server address.
        let server_addr = ();
        let mut sync_requester = SyncRequester::new(id, &mut Rng, server_addr);
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let (len, _) = {
            let mut client = syncer.client.lock().await;
            // TODO: save PeerCache somewhere.
            sync_requester
                .poll(&mut send_buf, client.provider(), &mut PeerCache::new())
                .context("sync poll failed")?
        };
        debug!(?len, "sync poll finished");
        send_buf.truncate(len);
        let mut stream = TcpStream::connect(peer.to_socket_addrs()).await?;
        let addr = stream.peer_addr()?;

        stream
            .write_all(&send_buf)
            .await
            .context("failed to write sync request")?;
        stream.shutdown().await?;
        debug!(?addr, "sent sync request");

        // get the sync response.
        let mut recv = Vec::new();
        stream
            .read_to_end(&mut recv)
            .await
            .context("failed to read sync response")?;
        debug!(?addr, n = recv.len(), "received sync response");

        // process the sync response.
        let resp =
            postcard::from_bytes(&recv).context("postcard unable to deserialize sync response")?;
        let data = match resp {
            SyncResponse::Ok(data) => data,
            SyncResponse::Err(msg) => bail!("sync error: {msg}"),
        };
        if data.is_empty() {
            debug!("nothing to sync");
            return Ok(());
        }
        if let Some(cmds) = sync_requester.receive(&data)? {
            debug!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                let mut client = syncer.client.lock().await;
                let mut trx = client.transaction(id);
                // TODO: save PeerCache somewhere.
                client
                    .add_commands(&mut trx, sink, &cmds)
                    .context("unable to add received commands")?;
                client.commit(&mut trx, sink).context("commit failed")?;
                // TODO: Update heads
                // client.update_heads(
                //     id,
                //     cmds.iter().filter_map(|cmd| cmd.address().ok()),
                //     heads,
                // )?;
                debug!("committed");
            }
        }

        Ok(())
    }
}

/// The Aranya TCP sync server.
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client reference.
    aranya: AranyaClient<EN, SP>,
    /// Used to receive sync requests and send responses.
    listener: TcpListener,
}

impl<EN, SP> Server<EN, SP> {
    /// Creates a new `Server`.
    #[inline]
    pub fn new(aranya: AranyaClient<EN, SP>, listener: TcpListener) -> Self {
        Self { aranya, listener }
    }

    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Begins accepting incoming requests.
    #[instrument(skip_all)]
    pub async fn serve(self) {
        scope(async move |s| {
            // accept incoming connections to the server
            loop {
                let incoming = self.listener.accept().await;
                let (mut stream, addr) = match incoming {
                    Ok(incoming) => incoming,
                    Err(err) => {
                        error!(err = %err, "stream failure");
                        continue;
                    }
                };
                debug!(?addr, "received sync request");

                let client = self.aranya.clone();
                s.spawn(
                    async move {
                        if let Err(err) = Self::sync(client, &mut stream, addr).await {
                            error!(%err, "request failure");
                        }
                    }
                    .instrument(info_span!("sync", %addr)),
                );
            }
        })
        .await;
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(addr = %addr))]
    async fn sync(
        client: AranyaClient<EN, SP>,
        stream: &mut TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        let mut recv = Vec::new();
        stream
            .read_to_end(&mut recv)
            .await
            .context("failed to read sync request")?;
        debug!(n = recv.len(), "received sync request");

        // Generate a sync response for a sync request.
        let resp = match Self::sync_respond(client, &recv).await {
            Ok(data) => SyncResponse::Ok(data),
            Err(err) => {
                error!(?err, "error responding to sync request");
                SyncResponse::Err(format!("{err:?}"))
            }
        };
        // Serialize the sync response.
        let data =
            &postcard::to_allocvec(&resp).context("postcard unable to serialize sync response")?;

        stream.write_all(data).await?;
        stream.shutdown().await?;
        debug!(n = data.len(), "sent sync response");

        Ok(())
    }

    /// Generates a sync response for a sync request.
    #[instrument(skip_all)]
    async fn sync_respond(client: AranyaClient<EN, SP>, request: &[u8]) -> Result<Box<[u8]>> {
        // TODO: Use real server address
        let server_address = ();
        let mut resp = SyncResponder::new(server_address);

        let SyncType::Poll {
            request,
            address: (),
        } = postcard::from_bytes(request)?
        else {
            bug!("Other sync types are not implemented");
        };

        resp.receive(request).context("sync recv failed")?;

        let mut buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        // TODO: save PeerCache somewhere.
        let len = resp
            .poll(
                &mut buf,
                client.lock().await.provider(),
                &mut PeerCache::new(),
            )
            .context("sync resp poll failed")?;
        debug!(len = len, "sync poll finished");
        buf.truncate(len);
        Ok(buf.into())
    }
}
