use crate::{text, Text};

/// Role management permission.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoleManagementPermission {
    /// Grants a managing role the ability to assign the target role
    /// to any device except itself.
    CanAssignRole,
    /// Grants a managing role the ability to revoke the target role
    /// from any device.
    CanRevokeRole,
    /// Grants a managing role the ability to change the permissions
    /// assigned to the target role.
    CanChangeRolePerms,
}

impl RoleManagementPermission {
    pub(crate) fn as_text(self) -> Text {
        match self {
            RoleManagementPermission::CanAssignRole => text!("CanAssignRole"),
            RoleManagementPermission::CanRevokeRole => text!("CanRevokeRole"),
            RoleManagementPermission::CanChangeRolePerms => text!("CanChangeRolePerms"),
        }
    }
}
