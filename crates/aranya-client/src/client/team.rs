use aranya_daemon_api::{self as api};
use aranya_id::custom_id;
use aranya_policy_text::Text;
use aranya_util::Addr;
use tracing::instrument;

use crate::{
    client::{
        object::ToObjectId, Client, Device, DeviceId, Devices, Label, LabelId, Labels, Permission,
        PublicKeyBundle, Rank, Role, RoleId, Roles,
    },
    config::SyncPeerConfig,
    error::{aranya_error, IpcError, Result},
    util::{rpc_context, ApiConv as _, ApiId},
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
            .close_team(rpc_context(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Encrypts the team's QUIC syncer PSK seed for a peer.
    #[deprecated(note = "PSK seeds are no longer used with mTLS authentication")]
    #[instrument(skip(self))]
    pub async fn encrypt_psk_seed_for_peer(&self, _peer_enc_pk: &[u8]) -> Result<Vec<u8>> {
        // With mTLS authentication, PSK seeds are no longer used.
        // Return empty vector for backward compatibility.
        Ok(Vec::new())
    }

    /// Adds a peer for automatic periodic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn add_sync_peer(&self, addr: Addr, config: SyncPeerConfig) -> Result<()> {
        self.client
            .daemon
            .add_sync_peer(rpc_context(), addr, self.id, config.into())
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
            .sync_now(rpc_context(), addr, self.id, cfg.map(Into::into))
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes a peer from automatic Aranya state syncing.
    #[instrument(skip(self))]
    pub async fn remove_sync_peer(&self, addr: Addr) -> Result<()> {
        self.client
            .daemon
            .remove_sync_peer(rpc_context(), addr, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Adds a device to the team with an optional initial role.
    ///
    /// Adds a device to the team with an optional initial role and
    /// explicit rank.
    ///
    /// Requires:
    /// - `AddDevice` permission
    /// - `caller_rank >= rank`
    #[instrument(skip(self))]
    pub async fn add_device(
        &self,
        keys: PublicKeyBundle,
        initial_role: Option<RoleId>,
        rank: Rank,
    ) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(
                rpc_context(),
                self.id,
                keys.into_api(),
                initial_role.map(RoleId::into_api),
                rank.into_api(),
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
            .devices_on_team(rpc_context(), self.id)
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
                rpc_context(),
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
            .sync_hello_unsubscribe(rpc_context(), peer, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}

impl Team<'_> {
    /// Sets up the default team roles (admin, operator, member).
    ///
    /// The owner role is created automatically when the team is created,
    /// so it is not included here.
    ///
    /// # Breaking change
    ///
    /// This method previously required an `owning_role` parameter.
    /// Owning roles no longer exist in the rank-based authorization
    /// model, so the parameter has been removed. Callers that
    /// previously passed an owning role can simply remove it:
    ///
    /// ```ignore
    /// // Before:
    /// team.setup_default_roles(owner_role_id).await?;
    ///
    /// // After:
    /// team.setup_default_roles().await?;
    /// ```
    ///
    /// It returns the roles that were created.
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .setup_default_roles(rpc_context(), self.id)
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
    /// Requires:
    /// - `CreateRole` permission
    /// - `caller_rank >= rank`
    ///
    /// It returns the Role that was created.
    #[instrument(skip(self))]
    pub async fn create_role(&self, role_name: Text, rank: Rank) -> Result<Role> {
        let role = self
            .client
            .daemon
            .create_role(rpc_context(), self.id, role_name, rank.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Role::from_api(role))
    }

    /// Deletes a role.
    ///
    /// The role must not be assigned to any devices.
    ///
    /// Requires:
    /// - `DeleteRole` permission
    /// - `caller_rank > role_rank`
    #[instrument(skip(self))]
    pub async fn delete_role(&self, role_id: RoleId) -> Result<()> {
        self.client
            .daemon
            .delete_role(rpc_context(), self.id, role_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Adds a permission to a role.
    ///
    /// Requires:
    /// - `ChangeRolePerms` permission
    /// - `caller_rank > role_rank`
    #[instrument(skip(self))]
    pub async fn add_perm_to_role(&self, role_id: RoleId, perm: Permission) -> Result<()> {
        self.client
            .daemon
            .add_perm_to_role(rpc_context(), self.id, role_id.into_api(), perm)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Removes a permission from a role.
    ///
    /// Requires:
    /// - `ChangeRolePerms` permission
    /// - `caller_rank > role_rank`
    #[instrument(skip(self))]
    pub async fn remove_perm_from_role(&self, role_id: RoleId, perm: Permission) -> Result<()> {
        self.client
            .daemon
            .remove_perm_from_role(rpc_context(), self.id, role_id.into_api(), perm)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(())
    }

    /// Queries all permissions assigned to a role.
    #[instrument(skip(self))]
    pub async fn role_perm(&self, role_id: RoleId) -> Result<Vec<Permission>> {
        let perms = self
            .client
            .daemon
            .query_role_perms(rpc_context(), self.id, role_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(perms)
    }

    /// Changes the rank of an object (device or label).
    ///
    /// Requires:
    /// - `ChangeRank` permission
    /// - `caller_rank > object_rank` (unless changing own rank)
    /// - `caller_rank >= new_rank`
    ///
    /// Note: Role ranks cannot be changed after creation. This maintains the
    /// invariant that `role_rank >= device_rank` for all devices assigned to
    /// the role. To effectively change a role's rank, create a new role with
    /// matching permissions at the desired rank, assign the new role to the
    /// devices that had the old role, then delete the old role.
    #[allow(private_bounds)]
    #[instrument(skip(self))]
    pub async fn change_rank(
        &self,
        object_id: impl ToObjectId,
        old_rank: Rank,
        new_rank: Rank,
    ) -> Result<()> {
        self.client
            .daemon
            .change_rank(
                rpc_context(),
                self.id,
                object_id.to_object_id().into_api(),
                old_rank.into_api(),
                new_rank.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Queries the rank of an object.
    #[allow(private_bounds)]
    #[instrument(skip(self))]
    pub async fn rank(&self, object_id: impl ToObjectId) -> Result<Rank> {
        self.client
            .daemon
            .query_rank(rpc_context(), self.id, object_id.to_object_id().into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(Rank::from_api)
    }

    /// Returns all of the roles for this team.
    #[instrument(skip(self))]
    pub async fn roles(&self) -> Result<Roles> {
        let roles = self
            .client
            .daemon
            .team_roles(rpc_context(), self.id)
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
    /// Create a label with an explicit rank.
    ///
    /// Requires:
    /// - `CreateLabel` permission
    /// - `caller_rank >= rank`
    #[instrument(skip(self))]
    pub async fn create_label(&self, label_name: Text, rank: Rank) -> Result<LabelId> {
        self.client
            .daemon
            .create_label(rpc_context(), self.id, label_name, rank.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(LabelId::from_api)
    }

    /// Delete a label.
    ///
    /// Requires:
    /// - `DeleteLabel` permission
    /// - `caller_rank > label_rank`
    #[instrument(skip(self))]
    pub async fn delete_label(&self, label_id: LabelId) -> Result<()> {
        self.client
            .daemon
            .delete_label(rpc_context(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns a label. Returns an error if the label does not exist.
    #[instrument(skip(self))]
    pub async fn label(&self, label_id: LabelId) -> Result<Label> {
        self.client
            .daemon
            .label(rpc_context(), self.id, label_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(Label::from_api)
    }

    /// Returns the list of labels on the team.
    #[instrument(skip(self))]
    pub async fn labels(&self) -> Result<Labels> {
        let labels = self
            .client
            .daemon
            .labels(rpc_context(), self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .into_iter()
            .map(Label::from_api)
            .collect();
        Ok(Labels { labels })
    }
}
