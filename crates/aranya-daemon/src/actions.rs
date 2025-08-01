//! Aranya graph actions/effects API.

use core::{future::Future, marker::PhantomData};
use std::{borrow::Cow, sync::Arc};

use anyhow::{Context, Result};
use aranya_aqc_util::LabelId;
use aranya_crypto::{Csprng, DeviceId, Rng};
use aranya_daemon_api::NetIdentifier;
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actor, VmAction, VmEffect};
use aranya_policy_vm::{ident, Text, Value};
use aranya_runtime::{
    vm_action, ClientError, ClientState, Engine, GraphId, Policy, Session, Sink, StorageProvider,
    VmPolicy,
};
use futures_util::TryFutureExt as _;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn, Instrument};

use crate::{
    aranya::Client,
    policy::{ActorExt, ChanOp, Effect, KeyBundle, Role},
    vm_policy::{MsgSink, VecSink},
};

/// Functions related to Aranya actions
impl<EN, SP, CE> Client<EN, SP>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
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
    pub(crate) async fn session_new(&self, id: &GraphId) -> Result<Session<SP, EN>> {
        let session = self.aranya.lock().await.session(*id)?;
        Ok(session)
    }

    /// Receives an ephemeral command from another ephemeral Session.
    /// Assumes an ephemeral Session has already been created before adding an ephemeral command to the Session.
    #[instrument(skip_all)]
    pub(crate) async fn session_receive(
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
    /// Aranya client graph state.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// Aranya graph ID.
    graph_id: GraphId,
    /// Crypto engine.
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
            debug!(i, total, effect = effect.name.as_str());
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

    /// Create a label.
    #[instrument(skip(self), fields(name = %name))]
    fn create_label(&self, name: Text) -> impl Future<Output = Result<Vec<Effect>>> + Send {
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
        net_identifier: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, %net_identifier, "setting AQC network name");
        self.with_actor(move |actor| {
            actor.set_aqc_network_name(device_id.into(), net_identifier)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Unsets an AQC network name.
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

    /// Queries all AQC network names off-graph.
    #[instrument(skip(self))]
    fn query_aqc_network_names_off_graph(
        &self,
    ) -> impl Future<Output = Result<Vec<(NetIdentifier, DeviceId)>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_aqc_network_names"),
            args: Cow::Owned(vec![]),
        })
        .and_then(|(_, effects)| {
            std::future::ready(
                effects
                    .into_iter()
                    .map(|eff| {
                        let Effect::QueryAqcNetworkNamesOutput(eff) = eff else {
                            anyhow::bail!("bad effect in query_network_names");
                        };
                        Ok((
                            NetIdentifier(eff.net_identifier),
                            DeviceId::from(eff.device_id),
                        ))
                    })
                    .collect(),
            )
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
            name: ident!("create_aqc_bidi_channel"),
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
            name: ident!("create_aqc_uni_channel"),
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

    /// Query devices on team off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_devices_on_team_off_graph(
        &self,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_devices_on_team"),
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
            name: ident!("query_device_role"),
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
            name: ident!("query_device_keybundle"),
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .in_current_span()
    }

    /// Query device label assignments off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_label_assignments_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_label_assignments"),
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
            name: ident!("query_aqc_net_identifier"),
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
            name: ident!("query_label_exists"),
            args: Cow::Owned(vec![Value::from(label_id)]),
        })
        .in_current_span()
    }

    /// Query labels off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_labels_off_graph(
        &self,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_labels"),
            args: Cow::Owned(vec![]),
        })
        .in_current_span()
    }
}

/// An implementation of [`Actor`].
/// Simplifies the process of calling an action on the Aranya graph.
/// Enables more consistency and less repeated code for each action.
#[derive(Debug)]
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
    fn new(client: &'a mut ClientState<EN, SP>, sink: &'a mut S, graph_id: &'a GraphId) -> Self {
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
