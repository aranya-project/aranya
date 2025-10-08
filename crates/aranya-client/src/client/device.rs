use std::{slice, vec};

use aranya_daemon_api as api;
use tarpc::context;
use tracing::instrument;

use crate::{
    client::{
        ChanOp, Client, InvalidNetIdentifier, KeyBundle, Label, LabelId, Labels, NetIdentifier,
        Role,
    },
    error::{aranya_error, IpcError, Result},
    util::{custom_id, impl_slice_iter_wrapper, impl_vec_into_iter_wrapper},
};

custom_id! {
    /// Uniquely identifies a device.
    pub struct DeviceId;
}

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
    }
}

impl Device<'_> {
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
}

impl Device<'_> {
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
}

impl Device<'_> {
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
                op.to_api(),
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

    /// Assigns an AQC network identifier to the device.
    #[cfg(feature = "aqc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "aqc")))]
    #[instrument(skip(self, net_identifier))]
    pub async fn assign_aqc_net_identifier<I>(&self, net_identifier: I) -> Result<()>
    where
        I: TryInto<NetIdentifier>,
    {
        self.client
            .daemon
            .assign_aqc_net_id(
                context::current(),
                self.team_id,
                self.id,
                net_identifier
                    .try_into()
                    .map_err(|_| InvalidNetIdentifier(()))?
                    .into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Removes the device's AQC network identifier.
    #[cfg(feature = "aqc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "aqc")))]
    #[instrument(skip(self, net_identifier))]
    pub async fn remove_aqc_net_identifier<I>(&self, net_identifier: I) -> Result<()>
    where
        I: TryInto<NetIdentifier>,
    {
        self.client
            .daemon
            .remove_aqc_net_id(
                context::current(),
                self.team_id,
                self.id,
                net_identifier
                    .try_into()
                    .map_err(|_| InvalidNetIdentifier(()))?
                    .into_api(),
            )
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the AQC network identifier assigned to the
    /// device, if any.
    // TODO(eric): documented whether this returns `None` if the
    // device does not exist or if the device exists but does not
    // have a net ID.
    #[cfg(feature = "aqc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "aqc")))]
    #[instrument(skip(self))]
    pub async fn aqc_net_id(&self) -> Result<Option<NetIdentifier>> {
        let id = self
            .client
            .daemon
            .aqc_net_id(context::current(), self.team_id, self.id)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?
            .map(|id| NetIdentifier(id.0));
        Ok(id)
    }
}
