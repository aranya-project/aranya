//! Aranya graph actions/effects API.

use std::{borrow::Cow, future::Future, marker::PhantomData, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::{
    policy::{LabelId, RoleId},
    BaseId, Csprng, DeviceId, Rng,
};
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actor, VmAction, VmEffect};
use aranya_policy_text::Text;
use aranya_policy_vm::{ident, Value};
#[cfg(feature = "afc")]
use aranya_runtime::NullSink;
use aranya_runtime::{
    vm_action, ClientError, ClientState, Engine, GraphId, Policy, Session, Sink, StorageProvider,
    VmPolicy,
};
use futures_util::TryFutureExt as _;
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn, Instrument};

use crate::{
    aranya::Client,
    policy::{ActorExt, ChanOp, Effect, KeyBundle},
    vm_policy::{MsgSink, VecSink},
};

/// Container for complex AQC channel creation results.
#[derive(Debug)]
pub(crate) struct SessionData {
    /// The serialized messages
    #[cfg(feature = "afc")]
    pub ctrl: Vec<Box<[u8]>>,
    /// The effects produced
    pub effects: Vec<Effect>,
}

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
    #[instrument(skip_all, fields(%graph_id))]
    pub fn actions(&self, graph_id: GraphId) -> impl Actions<EN, SP, CE> {
        ActionsImpl {
            aranya: Arc::clone(&self.aranya),
            graph_id,
            _eng: PhantomData,
        }
    }

    /// Create new ephemeral Session.
    /// Once the Session has been created, call `session_receive` to add an ephemeral command to the Session.
    #[instrument(skip_all, fields(%graph_id))]
    pub(crate) async fn session_new(&self, graph_id: GraphId) -> Result<Session<SP, EN>> {
        let session = self.aranya.lock().await.session(graph_id)?;
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
    async fn session_action<'a, F>(&self, f: F) -> Result<SessionData>
    where
        F: FnOnce() -> <<EN as Engine>::Policy as Policy>::Action<'a>,
    {
        let mut client = self.aranya.lock().await;
        let mut session = client.session(self.graph_id)?;
        let mut sink = VecSink::new();
        let mut msg_sink = MsgSink::new();
        session.action(&client, &mut sink, &mut msg_sink, f())?;
        Ok(SessionData {
            #[cfg(feature = "afc")]
            ctrl: msg_sink.into_cmds(),
            effects: sink.collect()?,
        })
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

    /// Performs a session action.
    #[allow(clippy::type_complexity)]
    fn session_action<'a, F>(&self, f: F) -> impl Future<Output = Result<SessionData>> + Send
    where
        F: FnOnce() -> <<EN as Engine>::Policy as Policy>::Action<'a> + Send;

    /// Invokes `add_device`.
    #[instrument(skip_all)]
    fn add_device(
        &self,
        keys: KeyBundle,
        initial_role_id: Option<RoleId>,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.add_device(keys, initial_role_id.map(|id| id.into_id()))?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `add_label_managing_role`.
    #[instrument(skip(self), fields(%label_id, %managing_role_id))]
    fn add_label_managing_role(
        &self,
        label_id: LabelId,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.add_label_managing_role(label_id.into(), managing_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `add_perm_to_role`.
    #[instrument(skip(self), fields(%role_id, %perm))]
    fn add_perm_to_role(
        &self,
        role_id: RoleId,
        perm: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.add_perm_to_role(role_id.into(), perm)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `add_role_owner`.
    #[instrument(skip(self), fields(%role_id, %new_owning_role_id))]
    fn add_role_owner(
        &self,
        role_id: RoleId,
        new_owning_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.add_role_owner(role_id.into(), new_owning_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `assign_label_to_device`.
    #[instrument(skip(self), fields(%device_id, %label_id, %op))]
    fn assign_label_to_device(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_label_to_device(device_id.into(), label_id.into(), op)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `assign_role`.
    #[instrument(skip(self), fields(%device_id, %role_id))]
    fn assign_role(
        &self,
        device_id: DeviceId,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_role(device_id.into(), role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `assign_role_management_perm`.
    #[instrument(skip(self), fields(%target_role_id, %managing_role_id, %perm))]
    fn assign_role_management_perm(
        &self,
        target_role_id: RoleId,
        managing_role_id: RoleId,
        perm: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.assign_role_management_perm(
                target_role_id.into(),
                managing_role_id.into(),
                perm,
            )?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `change_role`.
    #[instrument(skip(self), fields(%device_id, %old_role_id, %new_role_id))]
    fn change_role(
        &self,
        device_id: DeviceId,
        old_role_id: RoleId,
        new_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.change_role(device_id.into(), old_role_id.into(), new_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `create_label`.
    #[instrument(skip(self), fields(%name, %managing_role_id))]
    fn create_label(
        &self,
        name: Text,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.create_label(name, managing_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Creates a unidirectional AFC channel.
    #[cfg(feature = "afc")]
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(open_id = %open_id, label_id = %label_id))]
    fn create_afc_uni_channel_off_graph(
        &self,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<SessionData>> + Send {
        self.session_action(move || VmAction {
            name: ident!("create_afc_uni_channel"),
            args: Cow::Owned(vec![Value::from(open_id), Value::from(label_id)]),
        })
        .in_current_span()
    }

    /// Invokes `delete_label`.
    #[instrument(skip(self), fields(%label_id))]
    fn delete_label(&self, label_id: LabelId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.delete_label(label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `query_device_keybundle`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(%device_id))]
    fn query_device_keybundle(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_device_keybundle"),
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_device_role`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(%device_id))]
    fn query_device_role(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_device_role"),
            args: Cow::Owned(vec![Value::from(device_id)]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_devices_on_team`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_devices_on_team(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_devices_on_team"),
            args: Cow::Owned(vec![]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_label`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(%label_id))]
    fn query_label(&self, label_id: LabelId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_label"),
            args: Cow::Owned(vec![Value::from(label_id)]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_labels`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_labels(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_labels"),
            args: Cow::Owned(vec![]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_labels_assigned_to_device`.
    #[instrument(skip(self), fields(%device))]
    fn query_labels_assigned_to_device(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_labels_assigned_to_device"),
            args: Cow::Owned(vec![Value::from(device.into_id())]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_team_roles`.
    #[instrument(skip(self))]
    fn query_team_roles(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_team_roles"),
            args: Cow::Owned(vec![]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `query_role_owners`.
    #[instrument(skip(self), fields(%role_id))]
    fn query_role_owners(
        &self,
        role_id: BaseId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.session_action(move || VmAction {
            name: ident!("query_role_owners"),
            args: Cow::Owned(vec![Value::Id(role_id)]),
        })
        .map_ok(|SessionData { effects, .. }| effects)
        .in_current_span()
    }

    /// Invokes `remove_device`.
    #[instrument(skip(self), fields(%device_id))]
    fn remove_device(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.remove_device(device_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `remove_perm_from_role`.
    #[instrument(skip(self), fields(%role_id, %perm))]
    fn remove_perm_from_role(
        &self,
        role_id: RoleId,
        perm: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.remove_perm_from_role(role_id.into(), perm)?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `remove_role_owner`.
    #[instrument(skip(self), fields(%role_id, %new_owning_role_id))]
    fn remove_role_owner(
        &self,
        role_id: RoleId,
        new_owning_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.remove_role_owner(role_id.into(), new_owning_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `revoke_label_from_device`.
    #[instrument(skip(self), fields(%device_id, %label_id))]
    fn revoke_label_from_device(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.revoke_label_from_device(device_id.into(), label_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `revoke_label_managing_role`.
    #[instrument(skip(self), fields(%label_id, %managing_role_id))]
    fn revoke_label_managing_role(
        &self,
        label_id: LabelId,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.revoke_label_managing_role(label_id.into(), managing_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `revoke_role`.
    #[instrument(skip(self), fields(%device_id, %role_id))]
    fn revoke_role(
        &self,
        device_id: DeviceId,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.revoke_role(device_id.into(), role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `revoke_role_management_perm`.
    #[instrument(skip(self), fields(%target_role_id, %managing_role_id, %perm))]
    fn revoke_role_management_perm(
        &self,
        target_role_id: RoleId,
        managing_role_id: RoleId,
        perm: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.revoke_role_management_perm(
                target_role_id.into(),
                managing_role_id.into(),
                perm,
            )?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `setup_default_roles`.
    #[instrument(skip(self), fields(%managing_role_id))]
    fn setup_default_roles(
        &self,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.setup_default_roles(managing_role_id.into())?;
            Ok(())
        })
        .in_current_span()
    }

    /// Invokes `terminate_team`.
    #[instrument(skip(self), fields(%team_id))]
    fn terminate_team(&self, team_id: GraphId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.with_actor(move |actor| {
            actor.terminate_team(team_id.into())?;
            Ok(())
        })
        .in_current_span()
    }
}

/// An implementation of [`Actor`].
///
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

#[cfg(feature = "afc")]
pub(crate) fn query_afc_channel_is_valid<EN, SP, CE>(
    aranya: &mut ClientState<EN, SP>,
    graph_id: GraphId,
    sender_id: DeviceId,
    receiver_id: DeviceId,
    label_id: LabelId,
) -> Result<bool>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect>,
    SP: StorageProvider,
    CE: aranya_crypto::Engine,
{
    let mut session = aranya.session(graph_id)?;
    let mut sink = VecSink::new();
    session.action(
        aranya,
        &mut sink,
        &mut NullSink,
        vm_action!(query_afc_channel_is_valid(sender_id, receiver_id, label_id)),
    )?;
    let effects = sink.collect()?;
    Ok(effects.iter().any(|e| {
        if let Effect::QueryAfcChannelIsValidResult(e) = e {
            return e.is_valid;
        }
        false
    }))
}
