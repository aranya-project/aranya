//! Aranya graph actions/effects API.

use std::{future::Future, marker::PhantomData, sync::Arc};

use anyhow::{Context, Result};
use aranya_crypto::{
    policy::{LabelId, RoleId},
    Csprng, DeviceId, Rng,
};
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actionable, VmEffect};
use aranya_policy_text::Text;
#[cfg(feature = "afc")]
use aranya_runtime::NullSink;
use aranya_runtime::{ClientState, Engine, GraphId, Session, StorageProvider, VmPolicy};
use futures_util::TryFutureExt as _;
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn, Instrument};

use crate::{
    aranya::Client,
    policy::{self, ChanOp, Effect, KeyBundle},
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
        let policy_data = &[0u8];
        let act = policy::create_team(
            owner_keys,
            nonce.unwrap_or(&Rng.bytes::<[u8; 16]>()).to_vec(),
        );
        let id = {
            let mut client = self.aranya.lock().await;
            act.with_action(|act| client.new_graph(policy_data, act, &mut sink))
                .context("unable to create new team")?
        };
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
    async fn call_persistent_action(
        &self,
        act: impl Actionable<Interface = policy::Persistent> + Send,
    ) -> Result<Vec<Effect>> {
        let mut sink = VecSink::new();
        // Make sure we drop the lock as quickly as possible.
        {
            let mut client = self.aranya.lock().await;
            act.with_action(|act| client.action(self.graph_id, &mut sink, act))?;
        }

        let total = sink.effects.len();
        for (i, effect) in sink.effects.iter().enumerate() {
            debug!(i, total, effect = effect.name.as_str());
        }

        Ok(sink.collect()?)
    }

    async fn call_session_action(
        &self,
        act: impl Actionable<Interface = policy::Ephemeral> + Send,
    ) -> Result<SessionData> {
        let mut sink = VecSink::new();
        let mut msg_sink = MsgSink::new();
        {
            let mut client = self.aranya.lock().await;
            let mut session = client.session(self.graph_id)?;
            act.with_action(|act| session.action(&client, &mut sink, &mut msg_sink, act))?;
        }
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
    /// Perform a persistent action.
    fn call_persistent_action(
        &self,
        act: impl Actionable<Interface = policy::Persistent> + Send,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send;

    #[allow(clippy::type_complexity)]
    /// Performs a session action.
    fn call_session_action(
        &self,
        act: impl Actionable<Interface = policy::Ephemeral> + Send,
    ) -> impl Future<Output = Result<SessionData>> + Send;

    /// Invokes `add_device`.
    #[instrument(skip_all)]
    fn add_device(
        &self,
        keys: KeyBundle,
        initial_role_id: Option<RoleId>,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::add_device(
            keys,
            initial_role_id.map(|id| id.as_base()),
        ))
        .in_current_span()
    }

    /// Invokes `create_role`.
    #[cfg(feature = "preview")]
    #[instrument(skip(self))]
    fn create_role(
        &self,
        role_name: Text,
        owning_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::create_role(role_name, owning_role_id.as_base()))
            .in_current_span()
    }

    /// Invokes `delete_role`.
    #[cfg(feature = "preview")]
    #[instrument(skip(self))]
    fn delete_role(&self, role_id: RoleId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::delete_role(role_id.as_base()))
            .in_current_span()
    }

    /// Invokes `add_label_managing_role`.
    #[instrument(skip(self), fields(%label_id, %managing_role_id))]
    fn add_label_managing_role(
        &self,
        label_id: LabelId,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::add_label_managing_role(
            label_id.as_base(),
            managing_role_id.as_base(),
        ))
        .in_current_span()
    }

    /// Invokes `add_perm_to_role`.
    #[instrument(skip(self), fields(%role_id, %perm))]
    fn add_perm_to_role(
        &self,
        role_id: RoleId,
        perm: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::add_perm_to_role(role_id.as_base(), perm))
            .in_current_span()
    }

    /// Invokes `add_role_owner`.
    #[instrument(skip(self), fields(%role_id, %new_owning_role_id))]
    fn add_role_owner(
        &self,
        role_id: RoleId,
        new_owning_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::add_role_owner(
            role_id.as_base(),
            new_owning_role_id.as_base(),
        ))
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
        self.call_persistent_action(policy::assign_label_to_device(
            device_id.as_base(),
            label_id.as_base(),
            op,
        ))
        .in_current_span()
    }

    /// Invokes `assign_role`.
    #[instrument(skip(self), fields(%device_id, %role_id))]
    fn assign_role(
        &self,
        device_id: DeviceId,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::assign_role(device_id.as_base(), role_id.as_base()))
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
        self.call_persistent_action(policy::assign_role_management_perm(
            target_role_id.as_base(),
            managing_role_id.as_base(),
            perm,
        ))
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
        self.call_persistent_action(policy::change_role(
            device_id.as_base(),
            old_role_id.as_base(),
            new_role_id.as_base(),
        ))
        .in_current_span()
    }

    /// Invokes `create_label`.
    #[instrument(skip(self), fields(%name, %managing_role_id))]
    fn create_label(
        &self,
        name: Text,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::create_label(name, managing_role_id.as_base()))
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
        self.call_session_action(policy::create_afc_uni_channel(
            open_id.as_base(),
            label_id.as_base(),
        ))
        .in_current_span()
    }

    /// Invokes `delete_label`.
    #[instrument(skip(self), fields(%label_id))]
    fn delete_label(&self, label_id: LabelId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::delete_label(label_id.as_base()))
            .in_current_span()
    }

    /// Invokes `query_device_keybundle`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(%device_id))]
    fn query_device_keybundle(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_device_keybundle(device_id.as_base()))
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
        self.call_session_action(policy::query_device_role(device_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_devices_on_team`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_devices_on_team(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_devices_on_team())
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_label`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(%label_id))]
    fn query_label(&self, label_id: LabelId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_label(label_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_labels`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_labels(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_labels())
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_labels_assigned_to_device`.
    #[instrument(skip(self), fields(%device))]
    fn query_labels_assigned_to_device(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_labels_assigned_to_device(device.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_team_roles`.
    #[instrument(skip(self))]
    fn query_team_roles(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_team_roles())
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_role_owners`.
    #[instrument(skip(self), fields(%role_id))]
    fn query_role_owners(
        &self,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_role_owners(role_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_role_assigners`.
    #[instrument(skip(self), fields(%role_id))]
    fn query_role_assigners(
        &self,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_role_assigners(role_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_role_revokers`.
    #[instrument(skip(self), fields(%role_id))]
    fn query_role_revokers(
        &self,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_role_revokers(role_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_role_deleters`.
    #[instrument(skip(self), fields(%role_id))]
    fn query_role_deleters(
        &self,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_role_deleters(role_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `query_role_permission_managers`.
    #[instrument(skip(self), fields(%role_id))]
    fn query_role_permission_managers(
        &self,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_session_action(policy::query_role_permission_managers(role_id.as_base()))
            .map_ok(|SessionData { effects, .. }| effects)
            .in_current_span()
    }

    /// Invokes `remove_device`.
    #[instrument(skip(self), fields(%device_id))]
    fn remove_device(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::remove_device(device_id.as_base()))
            .in_current_span()
    }

    /// Invokes `remove_perm_from_role`.
    #[instrument(skip(self), fields(%role_id, %perm))]
    fn remove_perm_from_role(
        &self,
        role_id: RoleId,
        perm: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::remove_perm_from_role(role_id.as_base(), perm))
            .in_current_span()
    }

    /// Invokes `remove_role_owner`.
    #[instrument(skip(self), fields(%role_id, %new_owning_role_id))]
    fn remove_role_owner(
        &self,
        role_id: RoleId,
        new_owning_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::remove_role_owner(
            role_id.as_base(),
            new_owning_role_id.as_base(),
        ))
        .in_current_span()
    }

    /// Invokes `revoke_label_from_device`.
    #[instrument(skip(self), fields(%device_id, %label_id))]
    fn revoke_label_from_device(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::revoke_label_from_device(
            device_id.as_base(),
            label_id.as_base(),
        ))
        .in_current_span()
    }

    /// Invokes `revoke_label_managing_role`.
    #[instrument(skip(self), fields(%label_id, %managing_role_id))]
    fn revoke_label_managing_role(
        &self,
        label_id: LabelId,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::revoke_label_managing_role(
            label_id.as_base(),
            managing_role_id.as_base(),
        ))
        .in_current_span()
    }

    /// Invokes `revoke_role`.
    #[instrument(skip(self), fields(%device_id, %role_id))]
    fn revoke_role(
        &self,
        device_id: DeviceId,
        role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::revoke_role(device_id.as_base(), role_id.as_base()))
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
        self.call_persistent_action(policy::revoke_role_management_perm(
            target_role_id.as_base(),
            managing_role_id.as_base(),
            perm,
        ))
        .in_current_span()
    }

    /// Invokes `setup_default_roles`.
    #[instrument(skip(self), fields(%managing_role_id))]
    fn setup_default_roles(
        &self,
        managing_role_id: RoleId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::setup_default_roles(managing_role_id.as_base()))
            .in_current_span()
    }

    /// Invokes `terminate_team`.
    #[instrument(skip(self), fields(%team_id))]
    fn terminate_team(&self, team_id: GraphId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::terminate_team(team_id.as_base()))
            .in_current_span()
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
    policy::query_afc_channel_is_valid(
        sender_id.as_base(),
        receiver_id.as_base(),
        label_id.as_base(),
    )
    .with_action(|act| session.action(aranya, &mut sink, &mut NullSink, act))?;
    let effects = sink.collect()?;
    Ok(effects.iter().any(|e| {
        if let Effect::QueryAfcChannelIsValidResult(e) = e {
            return e.is_valid;
        }
        false
    }))
}
