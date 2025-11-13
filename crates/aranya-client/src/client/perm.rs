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

/// Simple permission.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub enum Permission {
    // # Team management
    //
    /// The role can add a device to the team.
    AddDevice,
    /// The role can remove a device from the team.
    RemoveDevice,
    /// The role can terminate the team. This causes all team
    /// commands to fail until a new team is created.
    TerminateTeam,

    // # Roles
    //
    /// The role can create a role.
    CreateRole,
    /// The role can delete a role.
    DeleteRole,
    /// The role can assign a role to other devices.
    AssignRole,
    /// The role can revoke a role from other devices.
    RevokeRole,
    /// The role can set up default roles. This can only be done
    /// once, so this permission can only effectively be used by
    /// the `owner` role.
    SetupDefaultRole,
    /// The role can add a managing role to or remove a managing
    /// role from a target role.
    ChangeRoleManagingRole,

    // # Labels
    //
    /// The role can create a label.
    CreateLabel,
    /// The role can delete a label.
    DeleteLabel,
    /// The role can grant a target role the ability to manage a
    /// label. This management ability includes deleting a label
    /// and adding/revoking a label to a device.
    ChangeLabelManagingRole,
    /// The role can assign a label to a device. The role must
    /// also have label management permissions granted by a role
    /// with the `ChangeLabelManagingRole` permission above.
    AssignLabel,
    /// The role can revoke a label from a device. The role must
    /// also have label management permissions granted by a role
    /// with the `ChangeLabelManagingRole` permission above.
    RevokeLabel,

    // # AFC
    //
    /// The role can use AFC. This controls the ability to
    /// create or receive a unidirectional AFC channels.
    CanUseAfc,
    /// The role can create a unidirectional AFC channel.
    CreateAfcUniChannel,
}

impl Permission {
    pub(crate) fn as_text(self) -> Text {
        match self {
            Permission::AddDevice => text!("AddDevice"),
            Permission::RemoveDevice => text!("RemoveDevice"),
            Permission::TerminateTeam => text!("TerminateTeam"),
            Permission::CreateRole => text!("CreateRole"),
            Permission::DeleteRole => text!("DeleteRole"),
            Permission::AssignRole => text!("AssignRole"),
            Permission::RevokeRole => text!("RevokeRole"),
            Permission::SetupDefaultRole => text!("SetupDefaultRole"),
            Permission::ChangeRoleManagingRole => text!("ChangeRoleManagingRole"),
            Permission::CreateLabel => text!("CreateLabel"),
            Permission::DeleteLabel => text!("DeleteLabel"),
            Permission::ChangeLabelManagingRole => text!("ChangeLabelManagingRole"),
            Permission::AssignLabel => text!("AssignLabel"),
            Permission::RevokeLabel => text!("RevokeLabel"),
            Permission::CanUseAfc => text!("CanUseAfc"),
            Permission::CreateAfcUniChannel => text!("CreateAfcUniChannel"),
        }
    }
}
