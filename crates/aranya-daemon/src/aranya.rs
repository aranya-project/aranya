//! Aranya.

use std::{borrow::Cow, future::Future, marker::PhantomData, net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use aranya_aqc_util::LabelId;
use aranya_crypto::{Csprng, DeviceId, Rng};
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actor, VmAction, VmEffect};
use aranya_policy_vm::Value;
use aranya_runtime::{
    vm_action, ClientError, ClientState, Engine, GraphId, PeerCache, Policy, Session, Sink,
    StorageProvider, SyncRequester, SyncResponder, SyncType, VmPolicy, MAX_SYNC_MESSAGE_SIZE,
};
use aranya_util::Addr;
use buggy::bug;
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

        // TODO: Real server address.
        let server_addr = ();
        let mut syncer = SyncRequester::new(id, &mut Rng, server_addr);
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
    EN: Engine + Send + 'static,
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
    #[instrument(skip(self), fields(device_id = %device_id))]
    fn remove_member(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.remove_member(device_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Assigns role to a team member.
    #[instrument(skip_all)]
    fn assign_role(
        &self,
        device_id: DeviceId,
        role: Role,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_role(device_id.into(), role)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Revokes role from a team member.
    #[instrument(skip_all)]
    fn revoke_role(
        &self,
        device_id: DeviceId,
        role: Role,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.revoke_role(device_id.into(), role)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Sets an AFC network name.
    #[instrument(skip(self), fields(device_id = %device_id, net_identifier = %net_identifier))]
    #[cfg(feature = "afc")]
    fn set_afc_network_name(
        &self,
        device_id: DeviceId,
        net_identifier: String,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, %net_identifier, "setting AFC network name");
        self.with_actor(move |actor| {
            actor.set_afc_network_name(device_id.into(), net_identifier)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Sets an AFC network name.
    #[instrument(skip(self), fields(device_id = %device_id))]
    #[cfg(feature = "afc")]
    fn unset_afc_network_name(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, "unsetting AFC network name");
        self.with_actor(move |actor| {
            actor.unset_afc_network_name(device_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Create a label.
    #[instrument(skip(self), fields(name = %name))]
    fn create_label(&self, name: String) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_label(name)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Delete a label.
    #[instrument(skip(self), fields(label_id = %label_id))]
    fn delete_label(&self, label_id: LabelId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.delete_label(label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Assigns a label to a device.
    #[instrument(skip(self), fields(device_id = %device_id, label_id = %label_id, op = %op))]
    fn assign_label(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_label(device_id.into(), label_id.into(), op)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Revokes a label.
    #[instrument(skip(self), fields(device_id = %device_id, label_id = %label_id))]
    fn revoke_label(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, %label_id, "revoking AQC label");
        self.with_actor(move |actor| {
            actor.revoke_label(device_id.into(), label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Sets an AQC network name.
    #[instrument(skip(self), fields(device_id = %device_id, net_identifier = %net_identifier))]
    fn set_aqc_network_name(
        &self,
        device_id: DeviceId,
        net_identifier: String,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, %net_identifier, "setting AQC network name");
        self.with_actor(move |actor| {
            actor.set_aqc_network_name(device_id.into(), net_identifier)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Sets an AQC network name.
    #[instrument(skip(self), fields(device_id = %device_id))]
    fn unset_aqc_network_name(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, "unsetting AQC network name");
        self.with_actor(move |actor| {
            actor.unset_aqc_network_name(device_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a bidirectional AFC channel.
    #[instrument(skip(self), fields(peer_id = %peer_id, label_id = %label_id))]
    #[cfg(feature = "afc")]
    fn create_afc_bidi_channel(
        &self,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_afc_bidi_channel(peer_id.into(), label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a bidirectional AQC channel off graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(peer_id = %peer_id, label_id = %label_id))]
    fn create_aqc_bidi_channel_off_graph(
        &self,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "create_aqc_bidi_channel",
            args: Cow::Owned(vec![Value::from(peer_id), Value::from(label_id)]),
        })
        .in_current_span()
    }

    /// Creates a unidirectional AQC channel.
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label_id = %label_id))]
    fn create_aqc_uni_channel(
        &self,
        seal_id: DeviceId,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_aqc_uni_channel(seal_id.into(), open_id.into(), label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a unidirectional AQC channel.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label_id = %label_id))]
    fn create_aqc_uni_channel_off_graph(
        &self,
        seal_id: DeviceId,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "create_aqc_uni_channel",
            args: Cow::Owned(vec![
                Value::from(seal_id),
                Value::from(open_id),
                Value::from(label_id),
            ]),
        })
        .in_current_span()
    }

    /// Creates a bidirectional AQC channel.
    #[instrument(skip(self), fields(peer_id = %peer_id, label_id = %label_id))]
    fn create_aqc_bidi_channel(
        &self,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_aqc_bidi_channel(peer_id.into(), label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a bidirectional AFC channel off graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(peer_id = %peer_id, label_id = %label_id))]
    #[cfg(feature = "afc")]
    fn create_afc_bidi_channel_off_graph(
        &self,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "create_afc_bidi_channel",
            args: Cow::Owned(vec![
                Value::from(peer_id),
                Value::from(label_id.into_id()), // TODO: LabelId -> Value conversion
            ]),
        })
        .in_current_span()
    }

    /// Creates a unidirectional AFC channel.
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label_id = %label_id))]
    #[cfg(feature = "afc")]
    fn create_afc_uni_channel(
        &self,
        seal_id: DeviceId,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_afc_uni_channel(seal_id.into(), open_id.into(), label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a unidirectional AFC channel.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label_id = %label_id))]
    #[cfg(feature = "afc")]
    fn create_afc_uni_channel_off_graph(
        &self,
        seal_id: DeviceId,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "create_afc_uni_channel",
            args: Cow::Owned(vec![
                Value::from(seal_id),
                Value::from(open_id),
                Value::from(label_id.into_id()), // TODO: LabelId -> Value conversion
            ]),
        })
        .in_current_span()
    }

    /// Query devices on team off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_devices_on_team_off_graph(
        &self,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_devices_on_team",
            args: Cow::Owned(vec![]),
        })
        .in_current_span()
    }

    /// Query device role off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_device_role_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_device_role",
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .in_current_span()
    }

    /// Query device keybundle off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_device_keybundle_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_device_keybundle",
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .in_current_span()
    }

    /// Query device label assignments off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_device_label_assignments_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_device_label_assignments",
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .in_current_span()
    }

    /// Query AFC net identifier off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_afc_net_identifier_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_afc_net_identifier",
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .in_current_span()
    }

    /// Query AQC net identifier off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_aqc_net_identifier_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_aqc_net_identifier",
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .in_current_span()
    }

    /// Query label exists off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_label_exists_off_graph(
        &self,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_label_exists",
            args: Cow::Owned(vec![Value::from(label_id.into_id())]), // TODO: LabelId -> Value conversion
        })
        .in_current_span()
    }

    /// Query AQC labels off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_aqc_labels_off_graph(
        &self,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: "query_aqc_labels",
            args: Cow::Owned(vec![]),
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
