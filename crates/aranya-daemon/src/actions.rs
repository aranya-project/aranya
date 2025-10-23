//! Aranya graph actions/effects API.

use core::marker::PhantomData;
use std::sync::Arc;

use anyhow::{Context, Result};
use aranya_crypto::{policy::LabelId, Csprng, DeviceId, Rng};
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actionable, VmEffect};
use aranya_policy_vm::Text;
use aranya_runtime::{
    vm_action, ClientState, Engine, GraphId, NullSink, Session, StorageProvider, VmPolicy,
};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

use crate::{
    aranya::Client,
    policy::{self, ChanOp, KeyBundle, Role},
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
    ) -> Result<(GraphId, Vec<policy::Effect>)> {
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

    #[instrument(skip_all, fields(id = %id))]
    pub fn actions(&self, id: &GraphId) -> PersistentActor<EN, SP, CE> {
        PersistentActor {
            aranya: Arc::clone(&self.aranya),
            graph_id: *id,
            _eng: PhantomData,
        }
    }

    #[instrument(skip_all, fields(id = %id))]
    pub fn ephemeral_actions(&self, id: &GraphId) -> EphemeralActor<EN, SP, CE> {
        EphemeralActor {
            aranya: Arc::clone(&self.aranya),
            graph_id: *id,
            _eng: PhantomData,
        }
    }

    #[instrument(skip_all, fields(id = %id))]
    pub fn queries(&self, id: &GraphId) -> QueryActor<EN, SP, CE> {
        QueryActor {
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
    ) -> Result<Vec<policy::Effect>> {
        let client = self.aranya.lock().await;
        let mut sink = VecSink::new();
        session.receive(&client, &mut sink, command)?;
        Ok(sink.collect()?)
    }
}

pub struct PersistentActor<EN, SP, CE> {
    /// Aranya client graph state.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// Aranya graph ID.
    graph_id: GraphId,
    /// Crypto engine.
    _eng: PhantomData<CE>,
}

impl<EN, SP, CE> PersistentActor<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    async fn call(
        &self,
        act: impl Actionable<Interface = policy::Persistent> + Send,
    ) -> Result<Vec<policy::Effect>> {
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

    /// Terminates the team.
    #[instrument(skip_all)]
    pub async fn terminate_team(&self) -> Result<policy::TeamTerminated> {
        self.call(policy::terminate_team()).await.and_then(get_one)
    }

    /// Adds a Member instance to the team.
    #[instrument(skip_all)]
    pub async fn add_member(&self, keys: KeyBundle) -> Result<policy::MemberAdded> {
        self.call(policy::add_member(keys)).await.and_then(get_one)
    }

    /// Remove a Member instance from the team.
    #[instrument(skip(self), fields(device_id = %device_id))]
    pub async fn remove_member(&self, device_id: DeviceId) -> Result<policy::MemberRemoved> {
        self.call(policy::remove_member(device_id.as_base()))
            .await
            .and_then(get_one)
    }

    /// Assigns role to a team member.
    #[instrument(skip_all)]
    pub async fn assign_role(&self, device_id: DeviceId, role: Role) -> Result<policy::Effect> {
        self.call(policy::assign_role(device_id.as_base(), role))
            .await
            .and_then(get_one)
    }

    /// Revokes role from a team member.
    #[instrument(skip_all)]
    pub async fn revoke_role(&self, device_id: DeviceId, role: Role) -> Result<policy::Effect> {
        self.call(policy::revoke_role(device_id.as_base(), role))
            .await
            .and_then(get_one)
    }

    /// Create a label.
    #[instrument(skip(self), fields(name = %name))]
    pub async fn create_label(&self, name: Text) -> Result<policy::LabelCreated> {
        self.call(policy::create_label(name))
            .await
            .and_then(get_one)
    }

    /// Delete a label.
    #[instrument(skip(self), fields(label_id = %label_id))]
    pub async fn delete_label(&self, label_id: LabelId) -> Result<policy::LabelDeleted> {
        self.call(policy::delete_label(label_id.as_base()))
            .await
            .and_then(get_one)
    }

    /// Assigns a label to a device.
    #[instrument(skip(self), fields(device_id = %device_id, label_id = %label_id, op = %op))]
    pub async fn assign_label(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
        op: ChanOp,
    ) -> Result<policy::LabelAssigned> {
        self.call(policy::assign_label(
            device_id.as_base(),
            label_id.as_base(),
            op,
        ))
        .await
        .and_then(get_one)
    }

    /// Revokes a label.
    #[instrument(skip(self), fields(device_id = %device_id, label_id = %label_id))]
    pub async fn revoke_label(
        &self,
        device_id: DeviceId,
        label_id: LabelId,
    ) -> Result<policy::LabelRevoked> {
        info!(%device_id, %label_id, "revoking label");
        self.call(policy::revoke_label(
            device_id.as_base(),
            label_id.as_base(),
        ))
        .await
        .and_then(get_one)
    }
}

pub struct EphemeralActor<EN, SP, CE> {
    /// Aranya client graph state.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// Aranya graph ID.
    graph_id: GraphId,
    /// Crypto engine.
    _eng: PhantomData<CE>,
}

type EphemeralOutput = (Vec<Box<[u8]>>, Vec<policy::Effect>);

impl<EN, SP, CE> EphemeralActor<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    async fn call(
        &self,
        act: impl Actionable<Interface = policy::Ephemeral> + Send,
    ) -> Result<(Vec<Box<[u8]>>, Vec<policy::Effect>)> {
        let mut sink = VecSink::new();
        let mut msg_sink = MsgSink::new();
        {
            let mut client = self.aranya.lock().await;
            let mut session = client.session(self.graph_id)?;
            act.with_action(|act| session.action(&client, &mut sink, &mut msg_sink, act))?;
        }
        Ok((msg_sink.into_cmds(), sink.collect()?))
    }

    /// Creates a unidirectional AFC channel.
    #[cfg(feature = "afc")]
    #[instrument(skip(self), fields(open_id = %open_id, label_id = %label_id))]
    pub async fn create_afc_uni_channel(
        &self,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> Result<EphemeralOutput> {
        self.call(policy::create_afc_uni_channel(
            open_id.as_base(),
            label_id.as_base(),
        ))
        .await
    }
}

pub struct QueryActor<EN, SP, CE> {
    /// Aranya client graph state.
    aranya: Arc<Mutex<ClientState<EN, SP>>>,
    /// Aranya graph ID.
    graph_id: GraphId,
    /// Crypto engine.
    _eng: PhantomData<CE>,
}

impl<EN, SP, CE> QueryActor<EN, SP, CE>
where
    EN: Engine<Policy = VmPolicy<CE>, Effect = VmEffect> + Send + 'static,
    SP: StorageProvider + Send + 'static,
    CE: aranya_crypto::Engine + Send + Sync + 'static,
{
    async fn query(
        &self,
        act: impl Actionable<Interface = policy::Ephemeral> + Send,
    ) -> Result<Vec<policy::Effect>> {
        let mut sink = VecSink::new();
        {
            let mut client = self.aranya.lock().await;
            let mut session = client.session(self.graph_id)?;
            act.with_action(|act| session.action(&client, &mut sink, &mut NullSink, act))?;
        }
        Ok(sink.collect()?)
    }

    /// Query devices on team.
    #[instrument(skip(self))]
    pub async fn query_devices_on_team(&self) -> Result<Vec<policy::QueryDevicesOnTeamResult>> {
        self.query(policy::query_devices_on_team())
            .await
            .and_then(get_many)
    }

    /// Query device role.
    #[instrument(skip(self))]
    pub async fn query_device_role(
        &self,
        device_id: DeviceId,
    ) -> Result<policy::QueryDeviceRoleResult> {
        self.query(policy::query_device_role(device_id.as_base()))
            .await
            .and_then(get_one)
    }

    /// Query device keybundle.
    #[instrument(skip(self))]
    pub async fn query_device_keybundle(
        &self,
        device_id: DeviceId,
    ) -> Result<policy::QueryDeviceKeyBundleResult> {
        self.query(policy::query_device_keybundle(device_id.as_base()))
            .await
            .and_then(get_one)
    }

    /// Query device label assignments.
    #[instrument(skip(self))]
    pub async fn query_label_assignments(
        &self,
        device_id: DeviceId,
    ) -> Result<Vec<policy::QueriedLabelAssignment>> {
        self.query(policy::query_label_assignments(device_id.as_base()))
            .await
            .and_then(get_many)
    }

    /// Query label exists.
    #[instrument(skip(self))]
    pub async fn query_label_exists(
        &self,
        label_id: LabelId,
    ) -> Result<policy::QueryLabelExistsResult> {
        self.query(policy::query_label_exists(label_id.as_base()))
            .await
            .and_then(get_one)
    }

    /// Query labels.
    #[instrument(skip(self))]
    pub async fn query_labels(&self) -> Result<Vec<policy::QueriedLabel>> {
        self.query(policy::query_labels()).await.and_then(get_many)
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

/// Extract a single expected effect of a given type.
fn get_one<E>(effects: Vec<policy::Effect>) -> Result<E>
where
    policy::Effect: TryInto<E, Error: std::error::Error + Send + Sync + 'static>,
{
    let mut iter = effects.into_iter();
    let effect = iter.next().context("no effects")?;
    if iter.next().is_some() {
        anyhow::bail!("too many effects");
    }
    effect.try_into().context("bad effect")
}

/// Extract many expected effect of a given type.
fn get_many<E>(effects: Vec<policy::Effect>) -> Result<Vec<E>>
where
    policy::Effect: TryInto<E, Error: std::error::Error + Send + Sync + 'static>,
{
    effects
        .into_iter()
        .map(|e| e.try_into().context("bad effect"))
        .collect()
}
