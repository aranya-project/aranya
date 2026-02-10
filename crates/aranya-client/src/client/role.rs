use std::{slice, vec};

use aranya_daemon_api::{self as api};
use aranya_id::custom_id;
use aranya_policy_text::Text;

use crate::{
    client::DeviceId,
    util::{impl_slice_iter_wrapper, impl_vec_into_iter_wrapper, ApiConv as _, ApiId},
};

custom_id! {
    /// Uniquely identifies a role.
    pub struct RoleId;
}
impl ApiId<api::RoleId> for RoleId {}

impl From<RoleId> for aranya_daemon_api::ObjectId {
    fn from(id: RoleId) -> Self {
        let bytes: [u8; 32] = id.into();
        bytes.into()
    }
}

/// A role.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
pub struct Role {
    /// Uniquely identifies the role.
    pub id: RoleId,
    /// The human-readable name of the role.
    pub name: Text,
    /// The unique ID of the author of the role.
    pub author_id: DeviceId,
    /// Is this a default role?
    pub default: bool,
}

impl Role {
    pub(crate) fn from_api(v: api::Role) -> Self {
        Self {
            id: RoleId::from_api(v.id),
            name: v.name,
            author_id: DeviceId::from_api(v.author_id),
            default: v.default,
        }
    }
}

/// A set of [`Role`]s.
#[derive(Clone, Debug)]
pub struct Roles {
    pub(super) roles: Box<[Role]>,
}

impl Roles {
    /// Returns an iterator over the roles.
    pub fn iter(&self) -> IterRoles<'_> {
        IterRoles(self.roles.iter())
    }

    #[doc(hidden)]
    pub fn __into_data(self) -> Box<[Role]> {
        self.roles
    }
}

impl IntoIterator for Roles {
    type Item = Role;
    type IntoIter = IntoIterRoles;

    fn into_iter(self) -> Self::IntoIter {
        IntoIterRoles(self.roles.into_vec().into_iter())
    }
}

/// An iterator over [`Role`]s.
#[derive(Clone, Debug)]
pub struct IterRoles<'a>(slice::Iter<'a, Role>);

impl_slice_iter_wrapper!(IterRoles<'a> for Role);

/// An owning iterator over [`Role`]s.
#[derive(Clone, Debug)]
pub struct IntoIterRoles(vec::IntoIter<Role>);

impl_vec_into_iter_wrapper!(IntoIterRoles for Role);
