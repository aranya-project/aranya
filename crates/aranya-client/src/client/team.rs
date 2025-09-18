use anyhow::Context as _;
use aranya_crypto::EncryptionPublicKey;
use aranya_daemon_api::{self as api, CS};
use aranya_policy_text::Text;
use aranya_util::Addr;
use buggy::BugExt as _;
use tarpc::context;
use tracing::instrument;

use crate::{
    client::{
        ChanOp, Client, Device, DeviceId, Devices, InvalidNetIdentifier, KeyBundle, Label, LabelId,
        Labels, Role, RoleId, Roles,
    },
    config::SyncPeerConfig,
    error::{self, aranya_error, IpcError, Result},
    util::custom_id,
};

custom_id! {
    /// Uniquely identifies an Aranya team.
    pub struct TeamId;
}

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
    /// See [`KeyBundle::encoding`].
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
    #[instrument(skip(self))]
    pub async fn add_device(&self, keys: KeyBundle, initial_role: Option<RoleId>) -> Result<()> {
        self.client
            .daemon
            .add_device_to_team(
                context::current(),
                self.id,
                keys,
                initial_role.map(RoleId::into_api),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes `device` from the team.
    #[instrument(skip(self))]
    pub async fn remove_device(&self, device: DeviceId) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.id, device.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the [`Device`] corresponding with `id`.
    // TODO(eric): Should this return `Result<Device<'_>>?`
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
            .setup_default_roles(context::current(), self.id, owning_role.into_api())
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

    /// Adds `owning_role` as an owner of `role`.
    #[instrument(skip(self))]
    pub async fn add_role_owner(&self, role: RoleId, owning_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .add_role_owner(
                context::current(),
                self.id,
                role.into_api(),
                owning_role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes an `owning_role` as an owner of `role`.
    #[instrument(skip(self))]
    pub async fn remove_role_owner(&self, role: RoleId, owning_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .remove_role_owner(
                context::current(),
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
            .role_owners(context::current(), self.id, role.into_api())
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
    #[instrument(skip(self))]
    pub async fn assign_role_management_permission(
        &self,
        role: RoleId,
        managing_role: RoleId,
        perm: Text,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_role_management_perm(
                context::current(),
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
    #[instrument(skip(self))]
    pub async fn revoke_role_management_permission(
        &self,
        role: RoleId,
        managing_role: RoleId,
        perm: Text,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_role_management_perm(
                context::current(),
                self.id,
                role.into_api(),
                managing_role.into_api(),
                perm,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assigns `role` to `device`.
    #[instrument(skip(self))]
    pub async fn assign_role(&self, device: DeviceId, role: RoleId) -> Result<()> {
        self.client
            .daemon
            .assign_role(
                context::current(),
                self.id,
                device.into_api(),
                role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revokes `role` from `device`.
    #[instrument(skip(self))]
    pub async fn revoke_role(&self, device: DeviceId, role: RoleId) -> Result<()> {
        self.client
            .daemon
            .revoke_role(
                context::current(),
                self.id,
                device.into_api(),
                role.into_api(),
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
}

impl Team<'_> {
    /// Create a label.
    #[instrument(skip(self, label_name))]
    pub async fn create_label<T>(&self, label_name: T, managing_role_id: RoleId) -> Result<LabelId>
    where
        T: TryInto<Text>,
    {
        self.client
            .daemon
            .create_label(
                context::current(),
                self.id,
                label_name
                    .try_into()
                    // TODO(eric): Use a different error.
                    .map_err(|_| InvalidNetIdentifier(()))?,
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

    /// Assigns a label to a role.
    #[instrument(skip(self))]
    pub async fn assign_label_to_role(
        &self,
        role: RoleId,
        label: LabelId,
        op: ChanOp,
    ) -> Result<()> {
        self.client
            .daemon
            .assign_label_to_role(
                context::current(),
                self.id,
                role.into_api(),
                label.into_api(),
                op.to_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revokes a label from a role.
    #[instrument(skip(self))]
    pub async fn revoke_label_from_role(&self, role: RoleId, label: LabelId) -> Result<()> {
        self.client
            .daemon
            .revoke_label_from_role(
                context::current(),
                self.id,
                role.into_api(),
                label.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}
