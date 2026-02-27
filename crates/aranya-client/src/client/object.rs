use core::fmt;

use aranya_daemon_api as api;
use aranya_id::{custom_id, Id, IdTag};

use crate::{
    client::{DeviceId, LabelId, RoleId, TeamId},
    util::ApiId,
};

custom_id! {
    /// An identifier for any object with a unique Aranya ID defined in the policy.
    pub struct ObjectId;
}
impl ApiId<api::ObjectId> for ObjectId {}

/// Marker trait for ID types that can be converted to [`ObjectId`].
///
/// Implemented for [`RoleId`], [`DeviceId`], [`LabelId`], and [`TeamId`].
pub trait IsObjectId: sealed::Sealed {}
impl IsObjectId for RoleId {}
impl IsObjectId for DeviceId {}
impl IsObjectId for LabelId {}
impl IsObjectId for TeamId {}
impl IsObjectId for ObjectId {}

/// Extension trait for converting typed IDs into [`ObjectId`].
///
/// Roles, devices, labels, and teams all have unique Aranya IDs
/// that can be treated as generic object IDs for rank queries and
/// other operations that accept any object type.
pub trait AsObjectId: sealed::Sealed + fmt::Debug {
    /// Converts this ID into an [`ObjectId`].
    fn to_object_id(self) -> ObjectId;
}

impl<Tag> AsObjectId for Id<Tag>
where
    Tag: IdTag,
    Id<Tag>: IsObjectId,
{
    fn to_object_id(self) -> ObjectId {
        ObjectId::transmute(self)
    }
}

mod sealed {
    use super::{DeviceId, LabelId, ObjectId, RoleId, TeamId};

    pub trait Sealed {}

    impl Sealed for RoleId {}
    impl Sealed for DeviceId {}
    impl Sealed for LabelId {}
    impl Sealed for TeamId {}
    impl Sealed for ObjectId {}
}

/// A numerical rank used for authorization in the rank-based hierarchy.
///
/// Higher-ranked objects can operate on lower-ranked objects.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Rank(api::Rank);

impl Rank {
    /// Creates a new rank from a raw value.
    pub const fn new(value: i64) -> Self {
        Self(api::Rank::new(value))
    }

    /// Returns the raw rank value.
    pub const fn value(self) -> i64 {
        self.0.value()
    }

    pub(crate) fn into_api(self) -> api::Rank {
        self.0
    }

    pub(crate) fn from_api(r: api::Rank) -> Self {
        Self(r)
    }
}

impl From<i64> for Rank {
    fn from(value: i64) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Rank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
