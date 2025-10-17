//! Aranya graph actions/effects API.

use core::{future::Future, marker::PhantomData};
use std::sync::Arc;

use anyhow::{Context, Result};
use aranya_aqc_util::LabelId;
use aranya_crypto::{Csprng, DeviceId, Rng};
#[cfg(feature = "aqc")]
use aranya_daemon_api::NetIdentifier;
use aranya_keygen::PublicKeys;
use aranya_policy_ifgen::{Actionable, VmEffect};
use aranya_policy_vm::Text;
use aranya_runtime::{vm_action, ClientState, Engine, GraphId, Session, StorageProvider, VmPolicy};
#[cfg(feature = "aqc")]
use futures_util::TryFutureExt as _;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn, Instrument};

use crate::{
    aranya::Client,
    policy::{self, ChanOp, Effect, KeyBundle, Role},
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
    ) -> Result<(Vec<Box<[u8]>>, Vec<Effect>)> {
        let mut sink = VecSink::new();
        let mut msg_sink = MsgSink::new();
        {
            let mut client = self.aranya.lock().await;
            let mut session = client.session(self.graph_id)?;
            act.with_action(|act| session.action(&client, &mut sink, &mut msg_sink, act))?;
        }
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
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send;

    /// Terminates the team.
    #[instrument(skip_all)]
    fn terminate_team(&self) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::terminate_team())
            .in_current_span()
    }

    /// Adds a Member instance to the team.
    #[instrument(skip_all)]
    fn add_member(&self, keys: KeyBundle) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::add_member(keys))
            .in_current_span()
    }

    /// Remove a Member instance from the team.
    #[instrument(skip(self), fields(device_id = %device_id))]
    fn remove_member(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::remove_member(device_id.into()))
            .in_current_span()
    }

    /// Assigns role to a team member.
    #[instrument(skip_all)]
    fn assign_role(
        &self,
        device_id: DeviceId,
        role: Role,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::assign_role(device_id.into(), role))
            .in_current_span()
    }

    /// Revokes role from a team member.
    #[instrument(skip_all)]
    fn revoke_role(
        &self,
        device_id: DeviceId,
        role: Role,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::revoke_role(device_id.into(), role))
            .in_current_span()
    }

    /// Create a label.
    #[instrument(skip(self), fields(name = %name))]
    fn create_label(&self, name: Text) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::create_label(name))
            .in_current_span()
    }

    /// Delete a label.
    #[instrument(skip(self), fields(label_id = %label_id))]
    fn delete_label(&self, label_id: LabelId) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        self.call_persistent_action(policy::delete_label(label_id.into()))
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
        self.call_persistent_action(policy::assign_label(device_id.into(), label_id.into(), op))
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
        self.call_persistent_action(policy::revoke_label(device_id.into(), label_id.into()))
            .in_current_span()
    }

    /// Sets an AQC network name.
    #[cfg(feature = "aqc")]
    #[instrument(skip(self), fields(device_id = %device_id, net_identifier = %net_identifier))]
    fn set_aqc_network_name(
        &self,
        device_id: DeviceId,
        net_identifier: Text,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, %net_identifier, "setting AQC network name");
        self.call_persistent_action(policy::set_aqc_network_name(
            device_id.into(),
            net_identifier,
        ))
        .in_current_span()
    }

    /// Unsets an AQC network name.
    #[cfg(feature = "aqc")]
    #[instrument(skip(self), fields(device_id = %device_id))]
    fn unset_aqc_network_name(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<Vec<Effect>>> + Send {
        info!(%device_id, "unsetting AQC network name");
        self.call_persistent_action(policy::unset_aqc_network_name(device_id.into()))
            .in_current_span()
    }

    /// Queries all AQC network names off-graph.
    #[cfg(feature = "aqc")]
    #[instrument(skip(self))]
    fn query_aqc_network_names_off_graph(
        &self,
    ) -> impl Future<Output = Result<Vec<(NetIdentifier, DeviceId)>>> + Send {
        self.call_session_action(policy::query_aqc_network_names())
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
    #[cfg(feature = "aqc")]
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(peer_id = %peer_id, label_id = %label_id))]
    fn create_aqc_bidi_channel_off_graph(
        &self,
        peer_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::create_aqc_bidi_channel(
            peer_id.into(),
            label_id.into(),
        ))
        .in_current_span()
    }

    /// Creates a unidirectional AQC channel.
    #[cfg(feature = "aqc")]
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self), fields(seal_id = %seal_id, open_id = %open_id, label_id = %label_id))]
    fn create_aqc_uni_channel_off_graph(
        &self,
        seal_id: DeviceId,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::create_aqc_uni_channel(
            seal_id.into(),
            open_id.into(),
            label_id.into(),
        ))
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
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::create_afc_uni_channel(
            open_id.into(),
            label_id.into(),
        ))
        .in_current_span()
    }

    /// Query devices on team off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_devices_on_team_off_graph(
        &self,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_devices_on_team())
            .in_current_span()
    }

    /// Query device role off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_device_role_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_device_role(device_id.into()))
            .in_current_span()
    }

    /// Query device keybundle off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_device_keybundle_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_device_keybundle(device_id.into()))
            .in_current_span()
    }

    /// Query device label assignments off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_label_assignments_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_label_assignments(device_id.into()))
            .in_current_span()
    }

    /// Query AQC net identifier off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_aqc_net_identifier_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_aqc_net_identifier(device_id.into()))
            .in_current_span()
    }

    /// Query AFC net identifier off-graph.
    #[cfg(feature = "afc")]
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_afc_net_identifier_off_graph(
        &self,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_aqc_net_identifier(device_id.into()))
            .in_current_span()
    }

    /// Query label exists off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_label_exists_off_graph(
        &self,
        label_id: LabelId,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_label_exists(label_id.into()))
            .in_current_span()
    }

    /// Query labels off-graph.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(self))]
    fn query_labels_off_graph(
        &self,
    ) -> impl Future<Output = Result<(Vec<Box<[u8]>>, Vec<Effect>)>> + Send {
        self.call_session_action(policy::query_labels())
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
