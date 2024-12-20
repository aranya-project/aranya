//! Aranya.

use std::{borrow::Cow, future::Future, marker::PhantomData, net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use aranya_crypto::{Csprng, Rng, UserId};
use aranya_fast_channels::Label;
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actor, VmAction, VmEffect};
use aranya_policy_vm::Value;
use aranya_runtime::{
    vm_action, ClientError, ClientState, Engine, GraphId, PeerCache, Policy, Session, Sink,
    StorageProvider, SyncRequester, SyncResponder, VmPolicy, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinSet,
};
use tracing::{debug, error, info, info_span, instrument, warn, Instrument};

use crate::{
    policy::{ActorExt, ChanOp, Effect, KeyBundle, Role},
    vm_policy::{MsgSink, VecSink},
};

/// A response to a sync request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Success.
    Ok(Box<[u8]>),
    /// Failure.
    Err(String),
}

/// Aranya client.
pub struct Client<EN, SP, CE> {
    /// Thread-safe Aranya client reference.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
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
        // send the sync request.
        let mut syncer = SyncRequester::new(id, &mut Rng);
        let mut send_buf = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let (len, _) = {
            let mut client = self.aranya.lock().await;
            // TODO: save PeerCache somewhere.
            syncer
                .poll(&mut send_buf, client.provider(), &mut PeerCache::new())
                .context("sync poll failed")?
        };
        debug!(?len, "sync poll finished");
        send_buf.truncate(len);
        let mut stream = TcpStream::connect(addr.to_socket_addrs()).await?;
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
        if let Some(cmds) = syncer.receive(&data)? {
            debug!(num = cmds.len(), "received commands");
            if !cmds.is_empty() {
                let mut client = self.aranya.lock().await;
                let mut trx = client.transaction(id);
                // TODO: save PeerCache somewhere.
                client
                    .add_commands(&mut trx, sink, &cmds, &mut PeerCache::new())
                    .context("unable to add received commands")?;
                client.commit(&mut trx, sink).context("commit failed")?;
                debug!("committed");
            }
        }

        Ok(())
    }

    /// Creates the team.
    /// Creates a new graph, adds the `CreateTeam` command to the root of the graph.
    /// Returns the [`GraphId`] of the newly created graph.
    #[instrument(skip_all)]
    pub async fn create_team(
        &self,
        owner_keys: KeyBundle,
        nonce: Option<&[u8]>,
    ) -> Result<(GraphId, Vec<Effect>)> {
        let mut sink = VecSink::new();
        let id = self
            .aranya
            .lock()
            .await
            .new_graph(
                &[0u8],
                vm_action!(create_team(
                    owner_keys,
                    nonce.unwrap_or(&Rng.bytes::<[u8; 16]>()),
                )),
                &mut sink,
            )
            .context("unable to create new team")?;
        Ok((id, sink.collect()?))
    }

    /// Returns an implementation of [`Actions`] for a particular
    /// storage.
    #[instrument(skip_all, fields(id = %id))]
    pub fn actions(&self, id: &GraphId) -> impl Actions<EN, SP, CE> {
        ActionsImpl {
            aranya: Arc::clone(&self.aranya),
            graph_id: *id,
            _eng: PhantomData,
        }
    }

    /// Create new ephemeral Session.
    /// Once the Session has been created, call `session_receive` to add an ephemeral command to the Session.
    #[instrument(skip_all, fields(id = %id))]
    pub async fn session_new(&self, id: &GraphId) -> Result<Session<SP, EN>> {
        let session = self.aranya.lock().await.session(*id)?;
        Ok(session)
    }

    /// Receives an ephemeral command from another ephemeral Session.
    /// Assumes an ephemeral Session has already been created before adding an ephemeral command to the Session.
    #[instrument(skip_all)]
    pub async fn session_receive(
        &self,
        session: &mut Session<SP, EN>,
        command: &[u8],
    ) -> Result<Vec<Effect>> {
        let client = self.aranya.lock().await;
        let mut sink = VecSink::new();
        session.receive(&client, &mut sink, command)?;
        Ok(sink.collect()?)
    }
}

/// Implements [`Actions`] for a particular storage.
struct ActionsImpl<EN, SP, CE> {
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    graph_id: GraphId,
    _eng: PhantomData<CE>,
}

impl<EN, SP, CE> Actions<EN, SP, CE> for ActionsImpl<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    #[instrument(skip_all)]
    async fn with_actor<F>(&self, f: F) -> Result<Vec<Effect>>
    where
        F: FnOnce(&mut ActorImpl<'_, EN, SP, CE, VecSink<EN::Effect>>) -> Result<()>,
    {
        let mut sink = VecSink::new();
        // Make sure we drop the lock as quickly as possible.
        {
            let mut client = self.aranya.lock().await;
            let mut actor = ActorImpl::new(&mut client, &mut sink, &self.graph_id);
            f(&mut actor)?;
        }

        let total = sink.effects.len();
        for (i, effect) in sink.effects.iter().enumerate() {
            debug!(i, total, effect = effect.name);
        }

        Ok(sink.collect()?)
    }

    /// Creates a new ephemeral session and invokes an action on it.
    /// Returns the [`MsgSink`] of serialized ephemeral commands added to the graph
    /// and a vector of [`Effect`]s produced by the action.
    #[instrument(skip_all)]
    #[allow(clippy::type_complexity)] // 2advanced4u
    async fn session_action<'a, F>(&self, f: F) -> Result<(Vec<Box<[u8]>>, Vec<Effect>)>
    where
        F: FnOnce() -> <<EN as Engine>::Policy as Policy>::Action<'a>,
    {
        let mut client = self.aranya.lock().await;
        let mut session = client.session(self.graph_id)?;
        let mut sink = VecSink::new();
        let mut msg_sink = MsgSink::new();
        session.action(&client, &mut sink, &mut msg_sink, f())?;
        Ok((msg_sink.into_cmds(), sink.collect()?))
    }
}

/// The Aranya sync server.
/// Used to listen for incoming `SyncRequests` and respond with `SyncResponse` when they are received.
pub struct Server<EN, SP> {
    /// Thread-safe Aranya client reference.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// Used to receive sync requests and send responses.
    listener: TcpListener,
    /// Tracks running tasks.
    set: JoinSet<()>,
}

impl<EN, SP> Server<EN, SP> {
    /// Creates a new `Server`.
    #[inline]
    pub fn new(aranya: Arc<Mutex<ClientState<EN, SP>>>, listener: TcpListener) -> Self {
        Self {
            aranya,
            listener,
            set: JoinSet::new(),
        }
    }

    /// Returns the local address the sync server bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

impl<EN, SP> Server<EN, SP>
where
    EN: Engine + Send + Sync + 'static,
    SP: StorageProvider + Send + Sync + 'static,
{
    /// Begins accepting incoming requests.
    #[instrument(skip_all)]
    pub async fn serve(mut self) -> Result<()> {
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

            let client = Arc::clone(&self.aranya);
            self.set.spawn(
                async move {
                    if let Err(err) = Self::sync(client, &mut stream, addr).await {
                        error!(%err, "request failure");
                    }
                }
                .instrument(info_span!("sync", %addr)),
            );
        }
    }

    /// Responds to a sync.
    #[instrument(skip_all, fields(addr = %addr))]
    async fn sync(
        client: Arc<Mutex<ClientState<EN, SP>>>,
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
    async fn sync_respond(
        client: Arc<Mutex<ClientState<EN, SP>>>,
        request: &[u8],
    ) -> Result<Box<[u8]>> {
        let mut resp = SyncResponder::new();
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

/// A programmatic API for policy actions.
pub trait Actions<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    /// Invokes `f` with an [`ActorImpl`].
    fn with_actor<F>(&self, f: F) -> impl Future<Output = Result<Vec<Effect>>> + Send
    where
        F: FnOnce(&mut ActorImpl<'_, EN, SP, CE, VecSink<EN::Effect>>) -> Result<()> + Send;

    #[allow(clippy::type_complexity)]
    /// Performs a session action.
    fn session_action<'a, F>(
        &self,
        f: F,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send
    where
        F: FnOnce() -> <<EN as Engine>::Policy as Policy>::Action<'a> + Send;

    /// Terminates the team.
    #[instrument(skip_all)]
    fn terminate_team(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(|actor| {
            actor.terminate_team()?;
            Ok(())
        })
        .in_current_span()
    }

    /// Adds a Member instance to the team.
    #[instrument(skip_all)]
    fn add_member(&self, keys: KeyBundle) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.add_member(keys)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Remove a Member instance from the team.
    #[instrument(skip(self), fields(user_id = %user_id))]
    fn remove_member(&self, user_id: UserId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.remove_member(user_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Assigns role to a team member.
    #[instrument(skip_all)]
    fn assign_role(
        &self,
        user_id: UserId,
        role: Role,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_role(user_id.into(), role)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Revokes role from a team member.
    #[instrument(skip_all)]
    fn revoke_role(
        &self,
        user_id: UserId,
        role: Role,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.revoke_role(user_id.into(), role)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Defines an AFC label.
    #[instrument(skip(self), fields(label = %label))]
    fn define_label(&self, label: Label) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.define_label(i64::from(label.to_u32()))?;
            Ok(())
        })
        .in_current_span()
    }

    /// Undefines an AFC label.
    #[instrument(skip(self), fields(label = %label))]
    fn undefine_label(&self, label: Label) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.undefine_label(i64::from(label.to_u32()))?;
            Ok(())
        })
        .in_current_span()
    }

    /// Grants an app permission to use an AFC label.
    #[instrument(skip(self), fields(user_id = %user_id, label = %label, op = %op))]
    fn assign_label(
        &self,
        user_id: UserId,
        label: Label,
        op: ChanOp,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_label(user_id.into(), i64::from(label.to_u32()), op)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Revokes an AFC label.
    #[instrument(skip(self), fields(user_id = %user_id, label = %label))]
    fn revoke_label(
        &self,
        user_id: UserId,
        label: Label,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%user_id, %label, "revoking AFC label");
        self.with_actor(move |actor| {
            actor.revoke_label(user_id.into(), i64::from(label.to_u32()))?;
            Ok(())
        })
        .in_current_span()
    }

    /// Sets a network name.
    #[instrument(skip(self), fields(user_id = %user_id, net_identifier = %net_identifier))]
    fn set_network_name(
        &self,
        user_id: UserId,
        net_identifier: String,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%user_id, %net_identifier, "setting network name");
        self.with_actor(move |actor| {
            actor.set_network_name(user_id.into(), net_identifier)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Sets a network name.
    #[instrument(skip(self), fields(user_id = %user_id))]
    fn unset_network_name(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%user_id, "unsetting network name");
        self.with_actor(move |actor| {
            actor.unset_network_name(user_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a bidirectional AFC channel.
    #[instrument(skip(self), fields(peer_id = %peer_id, label = %label))]
    fn create_bidi_channel(
        &self,
        peer_id: UserId,
        label: Label,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_bidi_channel(peer_id.into(), i64::from(label.to_u32()))?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a bidirectional AFC channel off graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(peer_id = %peer_id, label = %label))]
    fn create_bidi_channel_off_graph(
        &self,
        peer_id: UserId,
        label: Label,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "create_bidi_channel",
            args: Cow::Owned(vec![
                Value::from(peer_id),
                Value::from(i64::from(label.to_u32())),
            ]),
        })
        .in_current_span()
    }

    /// Creates a unidirectional AFC channel.
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label = %label))]
    fn create_uni_channel(
        &self,
        seal_id: UserId,
        open_id: UserId,
        label: Label,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_uni_channel(seal_id.into(), open_id.into(), i64::from(label.to_u32()))?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a unidirectional AFC channel.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label = %label))]
    fn create_uni_channel_off_graph(
        &self,
        seal_id: UserId,
        open_id: UserId,
        label: Label,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "create_uni_channel",
            args: Cow::Owned(vec![
                Value::from(seal_id),
                Value::from(open_id),
                Value::from(i64::from(label.to_u32())),
            ]),
        })
        .in_current_span()
    }
}

/// An implementation of [`Actor`].
/// Simplifies the process of calling an action on the Aranya graph.
/// Enables more consistency and less repeated code for each action.
pub struct ActorImpl<'a, EN, SP, CE, S> {
    client: &'a mut ClientState<EN, SP>,
    sink: &'a mut S,
    graph_id: &'a GraphId,
    _eng: PhantomData<CE>,
}

impl<'a, EN, SP, CE, S> ActorImpl<'a, EN, SP, CE, S>
where
    EN: Engine<Policy = VmPolicy<CE>> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    S: Sink<<EN as Engine>::Effect>,
{
    /// Creates an [`ActorImpl`].
    pub fn new(
        client: &'a mut ClientState<EN, SP>,
        sink: &'a mut S,
        graph_id: &'a GraphId,
    ) -> Self {
        ActorImpl {
            client,
            sink,
            graph_id,
            _eng: PhantomData,
        }
    }
}

impl<EN, SP, CE, S> Actor for ActorImpl<'_, EN, SP, CE, S>
where
    EN: Engine<Policy = VmPolicy<CE>> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync,
    S: Sink<<EN as Engine>::Effect>,
{
    /// Calls action on Aranya graph.
    #[instrument(skip_all)]
    fn call_action(&mut self, action: VmAction<'_>) -> Result<(), ClientError> {
        self.client.action(*self.graph_id, self.sink, action)
    }
}

impl<CS: aranya_crypto::CipherSuite> TryFrom<&PublicKeys<CS>> for KeyBundle {
    type Error = postcard::Error;
    fn try_from(pk: &PublicKeys<CS>) -> Result<Self, Self::Error> {
        Ok(Self {
            ident_key: postcard::to_allocvec(&pk.ident_pk)?,
            enc_key: postcard::to_allocvec(&pk.enc_pk)?,
            sign_key: postcard::to_allocvec(&pk.sign_pk)?,
        })
    }
}
