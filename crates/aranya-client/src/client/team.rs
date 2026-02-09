use anyhow::Context as _;
use aranya_crypto::EncryptionPublicKey;
use aranya_daemon_api::{self as api, CS};
use aranya_id::custom_id;
use aranya_policy_text::Text;
use aranya_util::Addr;
use buggy::BugExt as _;
use tracing::instrument;

#[cfg(feature = "preview")]
use crate::client::{Permission, RoleManagementPermission};
use crate::{
    client::{
        create_ctx, Client, Device, DeviceId, Devices, KeyBundle, Label, LabelId, Labels, Role,
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
            .close_team(create_ctx(), self.id)
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
            .encrypt_psk_seed_for_peer(create_ctx(), self.id, peer_enc_pk)
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
            .add_sync_peer(create_ctx(), addr, self.id, config.into())
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
            .sync_now(create_ctx(), addr, self.id, cfg.map(Into::into))
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes a peer from automatic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn remove_sync_peer(&self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(create_ctx(), addr, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Adds a device to the team with an optional initial role.
    #[instrument(skip(self))]
    pub async fn add_device(&self, keys: KeyBundle, initial_role: Option<RoleId>) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(
                create_ctx(),
                self.id,
                keys.into_api(),
                initial_role.map(RoleId::into_api),
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
            .devices_on_team(create_ctx(), self.id)
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
                create_ctx(),
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
            .sync_hello_unsubscribe(create_ctx(), peer, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Sets up the default team roles.
    ///
    /// `owning_role` will be the initial owner of the default
    /// roles.
    ///
    /// It returns the the roles that were created.
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self, owning_role: RoleId) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .setup_default_roles(create_ctx(), self.id, owning_role.into_api())
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

    /// Creates a new role.
    ///
    /// `owning_role` will be the initial owner of the new role.
    ///
    /// It returns the Role that was created.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn create_role(&self, role_name: Text, owning_role: RoleId) -> Result<Role> {
        let role = self
            .client
            .daemon
            .create_role(create_ctx(), self.id, role_name, owning_role.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Role::from_api(role))
    }

    /// Deletes a role.
    ///
    /// The role must not be assigned to any devices, nor should it own
    /// any other roles.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn delete_role(&self, role_id: RoleId) -> Result<()> {
        self.client
            .daemon
            .delete_role(create_ctx(), self.id, role_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Adds a permission to a role.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn add_perm_to_role(&self, role_id: RoleId, perm: Permission) -> Result<()> {
        self.client
            .daemon
            .add_perm_to_role(create_ctx(), self.id, role_id.into_api(), perm)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Removes a permission from a role.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn remove_perm_from_role(&self, role_id: RoleId, perm: Permission) -> Result<()> {
        self.client
            .daemon
            .remove_perm_from_role(create_ctx(), self.id, role_id.into_api(), perm)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Adds `owning_role` as an owner of `role`.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn add_role_owner(&self, role: RoleId, owning_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .add_role_owner(
                create_ctx(),
                self.id,
                role.into_api(),
                owning_role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes an `owning_role` as an owner of `role`.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn remove_role_owner(&self, role: RoleId, owning_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .remove_role_owner(
                create_ctx(),
                self.id,
                role.into_api(),
                owning_role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the roles that own `role`.
    #[instrument(skip(self))]
    pub async fn role_owners(&self, role: RoleId) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .role_owners(create_ctx(), self.id, role.into_api())
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

    /// Assigns a role management permission to a managing role.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn assign_role_management_permission(
        &self,
        role: RoleId,
        managing_role: RoleId,
        perm: RoleManagementPermission,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_role_management_perm(
                create_ctx(),
                self.id,
                role.into_api(),
                managing_role.into_api(),
                perm,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revokes a role management permission from a managing
    /// role.
    #[cfg(feature = "preview")]
    #[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
    #[instrument(skip(self))]
    pub async fn revoke_role_management_permission(
        &self,
        role: RoleId,
        managing_role: RoleId,
        perm: RoleManagementPermission,
    ) -> Result<()> {
        self.client
            .daemon
            .revoke_role_management_perm(
                create_ctx(),
                self.id,
                role.into_api(),
                managing_role.into_api(),
                perm,
            )
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
            .team_roles(create_ctx(), self.id)
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
}

impl Team<'_> {
    /// Create a label.
    #[instrument(skip(self))]
    pub async fn create_label(
        &self,
        label_name: Text,
        managing_role_id: RoleId,
    ) -> Result<LabelId> {
        self.client
            .daemon
            .create_label(
                create_ctx(),
                self.id,
                label_name,
                managing_role_id.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(LabelId::from_api)
    }

    /// Delete a label.
    #[instrument(skip(self))]
    pub async fn delete_label(&self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(create_ctx(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Add label managing role
    #[instrument(skip(self))]
    pub async fn add_label_managing_role(
        &self,
        label_id: LabelId,
        managing_role_id: RoleId,
    ) -> Result<()> {
        self.client
            .daemon
            .add_label_managing_role(
                create_ctx(),
                self.id,
                label_id.into_api(),
                managing_role_id.into_api(),
            )
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
            .label(create_ctx(), self.id, label_id.into_api())
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
            .labels(create_ctx(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .into_iter()
            .map(Label::from_api)
            .collect();
        Ok(Labels { labels })
    }
}
