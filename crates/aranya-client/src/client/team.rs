use anyhow::Context as _;
use aranya_crypto::EncryptionPublicKey;
use aranya_daemon_api::{self as api, ObjectId, Rank, CS};
use aranya_id::custom_id;
use aranya_policy_text::Text;
use aranya_util::Addr;
use buggy::BugExt as _;
use tarpc::context;
use tracing::instrument;

use crate::{
    client::{
        Client, Device, DeviceId, Devices, KeyBundle, Label, LabelId, Labels, Permission, Role,
        RoleId, Roles,
    },
    config::SyncPeerConfig,
    error::{self, aranya_error, IpcError, Result},
    util::{ApiConv as _, ApiId},
};

custom_id! {
    /// Uniquely identifies an Aranya team.
    pub struct TeamId;
}
impl ApiId<api::TeamId> for TeamId {}

/// Represents an Aranya Team.
#[derive(Debug)]
pub struct Team<'a> {
    pub(super) client: &'a Client,
    pub(super) id: api::TeamId,
}

impl Team<'_> {
    /// Return the team's globally unique ID.
    pub fn team_id(&self) -> TeamId {
        TeamId::from_api(self.id)
    }

    /// Closes the team, preventing any further operations on it.
    #[instrument(skip(self))]
    pub async fn close_team(&self) -> Result<()> {
        self.client
            .daemon
            .close_team(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Encrypts the team's QUIC syncer PSK seed for a peer.
    /// `peer_enc_pk` is the public encryption key of the peer device.
    /// See [`KeyBundle::encryption`].
    #[instrument(skip(self))]
    pub async fn encrypt_psk_seed_for_peer(&self, peer_enc_pk: &[u8]) -> Result<Vec<u8>> {
        let peer_enc_pk: EncryptionPublicKey<CS> = postcard::from_bytes(peer_enc_pk)
            .context("bad peer_enc_pk")
            .map_err(error::other)?;
        let wrapped = self
            .client
            .daemon
            .encrypt_psk_seed_for_peer(context::current(), self.id, peer_enc_pk)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        let wrapped = postcard::to_allocvec(&wrapped).assume("can serialize")?;
        Ok(wrapped)
    }

    /// Adds a peer for automatic periodic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn add_sync_peer(&self, addr: Addr, config: SyncPeerConfig) -> Result<()> {
        self.client
            .daemon
            .add_sync_peer(context::current(), addr, self.id, config.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Immediately syncs with the peer.
    ///
    /// If `config` is `None`, default values (including those from the daemon) will
    /// be used.
    #[instrument(skip(self))]
    pub async fn sync_now(&self, addr: Addr, cfg: Option<SyncPeerConfig>) -> Result<()> {
        self.client
            .daemon
            .sync_now(context::current(), addr, self.id, cfg.map(Into::into))
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes a peer from automatic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn remove_sync_peer(&self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(context::current(), addr, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Adds a device to the team with an optional initial role.
    ///
    /// The device is assigned a default rank of the command author's
    /// rank minus one. Use [`Self::add_device_with_rank`] to specify an
    /// explicit rank.
    #[deprecated(note = "use `add_device_with_rank` to specify an explicit rank")]
    #[instrument(skip(self))]
    pub async fn add_device(&self, keys: KeyBundle, initial_role: Option<RoleId>) -> Result<()> {
        // Default to role_rank - 1 when an initial_role is provided,
        // otherwise fall back to author_rank - 1.
        let rank = match &initial_role {
            Some(role_id) => {
                let role_obj: ObjectId = ObjectId::transmute(*role_id);
                let role_rank = self.query_rank(role_obj).await?;
                Rank::new(role_rank.value() - 1)
            }
            None => {
                let device_id = self.client.get_device_id().await?;
                let device_obj: ObjectId = ObjectId::transmute(device_id);
                let author_rank = self.query_rank(device_obj).await?;
                Rank::new(author_rank.value() - 1)
            }
        };
        self.client
            .daemon
            .add_device_to_team_with_rank(
                context::current(),
                self.id,
                keys.into_api(),
                initial_role.map(RoleId::into_api),
                rank,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Adds a device to the team with an optional initial role and
    /// explicit rank.
    #[instrument(skip(self))]
    pub async fn add_device_with_rank(
        &self,
        keys: KeyBundle,
        initial_role: Option<RoleId>,
        rank: Rank,
    ) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team_with_rank(
                context::current(),
                self.id,
                keys.into_api(),
                initial_role.map(RoleId::into_api),
                rank,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the [`Device`] corresponding with `id`.
    pub fn device(&self, id: DeviceId) -> Device<'_> {
        Device {
            client: self.client,
            team_id: self.id,
            id: id.into_api(),
        }
    }

    /// Returns the list of devices on the team.
    #[instrument(skip(self))]
    pub async fn devices(&self) -> Result<Devices> {
        let data = self
            .client
            .daemon
            .devices_on_team(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            // This _should_ just be `into_iter`, but the
            // compiler chooses the `&Box` impl. It's the same
            // end result, though.
            .into_vec()
            .into_iter()
            .map(DeviceId::from_api)
            .collect();
        Ok(Devices { data })
    }

    /// Subscribe to hello notifications from a sync peer.
    ///
    /// This will request the peer to send hello notifications when their graph head changes.
    ///
    /// # Parameters
    ///
    /// * `peer` - The address of the sync peer to subscribe to.
    /// * `config` - Configuration for the hello subscription including delays and expiration.
    ///
    /// To automatically sync when receiving a hello message, call [`Self::add_sync_peer`] with
    /// [`crate::config::SyncPeerConfigBuilder::sync_on_hello`] set to `true`.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    pub async fn sync_hello_subscribe(
        &self,
        peer: Addr,
        config: crate::config::HelloSubscriptionConfig,
    ) -> Result<()> {
        // TODO(#709): Pass the config type directly into the daemon IPC and internal
        // daemon implementation instead of extracting individual fields here.
        self.client
            .daemon
            .sync_hello_subscribe(
                context::current(),
                peer,
                self.id,
                config.graph_change_debounce(),
                config.expiration(),
                config.periodic_interval(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Unsubscribe from hello notifications from a sync peer.
    ///
    /// This will stop receiving hello notifications from the specified peer.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    pub async fn sync_hello_unsubscribe(&self, peer: Addr) -> Result<()> {
        self.client
            .daemon
            .sync_hello_unsubscribe(context::current(), peer, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Sets up the default team roles.
    ///
    /// The `owning_role` parameter is accepted for backward
    /// compatibility but is ignored in the rank-based authorization
    /// model. Use [`Self::setup_default_roles_no_owning_role`] instead.
    ///
    /// It returns the roles that were created.
    #[deprecated(note = "use `setup_default_roles_no_owning_role` instead")]
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self, _owning_role: RoleId) -> Result<Roles> {
        self.setup_default_roles_no_owning_role().await
    }

    /// Sets up the default team roles.
    ///
    /// It returns the roles that were created.
    #[instrument(skip(self))]
    pub async fn setup_default_roles_no_owning_role(&self) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .setup_default_roles(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            // This _should_ just be `into_iter`, but the
            // compiler chooses the `&Box` impl. It's the same
            // end result, though.
            .into_vec()
            .into_iter()
            .map(Role::from_api)
            .collect();
        Ok(Roles { roles })
    }

    /// Creates a new role with the given rank.
    ///
    /// It returns the Role that was created.
    #[instrument(skip(self))]
    pub async fn create_role(&self, role_name: Text, rank: Rank) -> Result<Role> {
        let role = self
            .client
            .daemon
            .create_role(context::current(), self.id, role_name, rank)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Role::from_api(role))
    }

    /// Deletes a role.
    ///
    /// The role must not be assigned to any devices, nor should it own
    /// any other roles.
    #[instrument(skip(self))]
    pub async fn delete_role(&self, role_id: RoleId) -> Result<()> {
        self.client
            .daemon
            .delete_role(context::current(), self.id, role_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Adds a permission to a role.
    #[instrument(skip(self))]
    pub async fn add_perm_to_role(&self, role_id: RoleId, perm: Permission) -> Result<()> {
        self.client
            .daemon
            .add_perm_to_role(context::current(), self.id, role_id.into_api(), perm)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Removes a permission from a role.
    #[instrument(skip(self))]
    pub async fn remove_perm_from_role(&self, role_id: RoleId, perm: Permission) -> Result<()> {
        self.client
            .daemon
            .remove_perm_from_role(context::current(), self.id, role_id.into_api(), perm)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Changes the rank of an object.
    #[instrument(skip(self))]
    pub async fn change_rank(
        &self,
        object_id: ObjectId,
        old_rank: Rank,
        new_rank: Rank,
    ) -> Result<()> {
        self.client
            .daemon
            .change_rank(context::current(), self.id, object_id, old_rank, new_rank)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Queries the rank of an object.
    #[instrument(skip(self))]
    pub async fn query_rank(&self, object_id: ObjectId) -> Result<Rank> {
        self.client
            .daemon
            .query_rank(context::current(), self.id, object_id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns all of the roles for this team.
    #[instrument(skip(self))]
    pub async fn roles(&self) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .team_roles(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            // This _should_ just be `into_iter`, but the
            // compiler chooses the `&Box` impl. It's the same
            // end result, though.
            .into_vec()
            .into_iter()
            .map(Role::from_api)
            .collect();
        Ok(Roles { roles })
    }

    /// Deprecated: the `role` parameter is ignored and the returned
    /// [`Roles`] is always empty.
    #[deprecated(note = "role_owners is deprecated")]
    pub async fn role_owners(&self, _role: RoleId) -> Result<Roles> {
        tracing::warn!("role_owners is deprecated");
        Ok(Roles {
            roles: Vec::new().into(),
        })
    }
}

impl Team<'_> {
    /// Create a label.
    ///
    /// The `managing_role_id` parameter is accepted for backward
    /// compatibility but is ignored in the rank-based authorization
    /// model. The label is created with a default rank of the command
    /// author's rank minus one.
    ///
    /// Use [`Self::create_label_with_rank`] to specify an explicit rank.
    #[deprecated(note = "use `create_label_with_rank` to specify an explicit rank")]
    #[instrument(skip(self))]
    pub async fn create_label(
        &self,
        label_name: Text,
        _managing_role_id: RoleId,
    ) -> Result<LabelId> {
        // Default to author_rank - 1.
        let device_id = self.client.get_device_id().await?;
        let device_obj: ObjectId = ObjectId::transmute(device_id);
        let author_rank = self.query_rank(device_obj).await?;
        let rank = Rank::new(author_rank.value() - 1);
        self.client
            .daemon
            .create_label_with_rank(context::current(), self.id, label_name, rank)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(LabelId::from_api)
    }

    /// Create a label with an explicit rank.
    #[instrument(skip(self))]
    pub async fn create_label_with_rank(&self, label_name: Text, rank: Rank) -> Result<LabelId> {
        self.client
            .daemon
            .create_label_with_rank(context::current(), self.id, label_name, rank)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(LabelId::from_api)
    }

    /// Adds a managing role to a label.
    ///
    /// Deprecated: this method is a no-op.
    #[deprecated(note = "add_label_managing_role is deprecated")]
    pub async fn add_label_managing_role(
        &self,
        _label_id: LabelId,
        _managing_role: RoleId,
    ) -> Result<()> {
        tracing::warn!("add_label_managing_role is deprecated and is a no-op");
        Ok(())
    }

    /// Delete a label.
    #[instrument(skip(self))]
    pub async fn delete_label(&self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(context::current(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a label if it exists.
    #[instrument(skip(self))]
    pub async fn label(&self, label_id: LabelId) -> Result<Option<Label>> {
        let label = self
            .client
            .daemon
            .label(context::current(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .map(Label::from_api);
        Ok(label)
    }

    /// Returns the list of labels on the team.
    #[instrument(skip(self))]
    pub async fn labels(&self) -> Result<Labels> {
        let labels = self
            .client
            .daemon
            .labels(context::current(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .into_iter()
            .map(Label::from_api)
            .collect();
        Ok(Labels { labels })
    }
}
