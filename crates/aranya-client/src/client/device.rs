use std::{slice, vec};

use aranya_daemon_api as api;
use aranya_id::custom_id;
use serde::{Deserialize, Serialize};
use tarpc::context;
use tracing::instrument;

use crate::{
    client::{ChanOp, Client, Label, LabelId, Labels, Role, RoleId},
    error::{aranya_error, IpcError, Result},
    util::{impl_slice_iter_wrapper, impl_vec_into_iter_wrapper, ApiConv as _, ApiId},
};

/// A device's public key bundle.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct KeyBundle(api::KeyBundle);

impl KeyBundle {
    #[doc(hidden)]
    pub fn from_api(api: api::KeyBundle) -> Self {
        Self(api)
    }

    #[doc(hidden)]
    pub fn into_api(self) -> api::KeyBundle {
        self.0
    }

    /// Return public encryption key bytes.
    pub fn encryption(&self) -> &[u8] {
        &self.0.encryption
    }
}

custom_id! {
    /// Uniquely identifies a device.
    pub struct DeviceId;
}
impl ApiId<api::DeviceId> for DeviceId {}

/// A list of [`DeviceId`].
#[derive(Debug)]
pub struct Devices {
    pub(super) data: Box<[DeviceId]>,
}

impl Devices {
    /// Returns an iterator over the [`DeviceId`]s.
    pub fn iter(&self) -> IterDevices<'_> {
        IterDevices(self.data.iter())
    }

    #[doc(hidden)]
    pub fn __data(&self) -> &[DeviceId] {
        &self.data
    }
}

/// An iterator over [`DeviceId`]s.
#[derive(Clone, Debug)]
pub struct IterDevices<'a>(slice::Iter<'a, DeviceId>);

impl_slice_iter_wrapper!(IterDevices<'a> for DeviceId);

/// An owning iterator over [`DeviceId`]s.
#[derive(Clone, Debug)]
pub struct IntoIterDevices(vec::IntoIter<DeviceId>);

impl_vec_into_iter_wrapper!(IntoIterDevices for DeviceId);

/// Represents an Aranya device
#[derive(Debug)]
pub struct Device<'a> {
    pub(super) client: &'a Client,
    pub(super) id: api::DeviceId,
    pub(super) team_id: api::TeamId,
}

impl Device<'_> {
    /// Returns the device's globally unique ID.
    pub fn id(&self) -> DeviceId {
        DeviceId::from_api(self.id)
    }

    /// Returns device's key bundle.
    pub async fn keybundle(&self) -> Result<KeyBundle> {
        self.client
            .daemon
            .device_keybundle(context::current(), self.team_id, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(KeyBundle::from_api)
    }

    /// Removes `device` from the team.
    #[instrument(skip(self))]
    pub async fn remove_from_team(&self) -> Result<()> {
        self.client
            .daemon
            .remove_device_from_team(context::current(), self.team_id, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Assigns `role` to `device`.
    #[instrument(skip(self))]
    pub async fn assign_role(&self, role: RoleId) -> Result<()> {
        self.client
            .daemon
            .assign_role(context::current(), self.team_id, self.id, role.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revokes `role` from `device`.
    #[instrument(skip(self))]
    pub async fn revoke_role(&self, role: RoleId) -> Result<()> {
        self.client
            .daemon
            .revoke_role(context::current(), self.team_id, self.id, role.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Changes the `role` on a `device`
    #[instrument(skip(self))]
    pub async fn change_role(&self, old_role: RoleId, new_role: RoleId) -> Result<()> {
        self.client
            .daemon
            .change_role(
                context::current(),
                self.team_id,
                self.id,
                old_role.into_api(),
                new_role.into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the role assigned to the device, if any.
    pub async fn role(&self) -> Result<Option<Role>> {
        let role = self
            .client
            .daemon
            .device_role(context::current(), self.team_id, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .map(Role::from_api);
        Ok(role)
    }

    /// Returns a list of labels assiged to the device.
    pub async fn label_assignments(&self) -> Result<Labels> {
        let data = self
            .client
            .daemon
            .labels_assigned_to_device(context::current(), self.team_id, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            // This _should_ just be `into_iter`, but the
            // compiler chooses the `&Box` impl. It's the same
            // end result, though.
            .into_vec()
            .into_iter()
            .map(Label::from_api)
            .collect();
        Ok(Labels { labels: data })
    }

    /// Assigns `label` to the device.
    #[instrument(skip(self))]
    pub async fn assign_label(&self, label: LabelId, op: ChanOp) -> Result<()> {
        self.client
            .daemon
            .assign_label_to_device(
                context::current(),
                self.team_id,
                self.id,
                label.into_api(),
                op,
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Revokes `label` from the device.
    #[instrument(skip(self))]
    pub async fn revoke_label(&self, label: LabelId) -> Result<()> {
        self.client
            .daemon
            .revoke_label_from_device(context::current(), self.team_id, self.id, label.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }
}
