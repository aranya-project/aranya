#![cfg(feature = "preview")]
#![cfg_attr(docsrs, doc(cfg(feature = "preview")))]

use aranya_daemon_api as api;

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

impl From<api::RoleManagementPerm> for RoleManagementPermission {
    fn from(value: api::RoleManagementPerm) -> Self {
        match value {
            api::RoleManagementPerm::CanAssignRole => RoleManagementPermission::CanAssignRole,
            api::RoleManagementPerm::CanRevokeRole => RoleManagementPermission::CanRevokeRole,
            api::RoleManagementPerm::CanChangeRolePerms => {
                RoleManagementPermission::CanChangeRolePerms
            }
        }
    }
}

impl From<RoleManagementPermission> for api::RoleManagementPerm {
    fn from(value: RoleManagementPermission) -> Self {
        match value {
            RoleManagementPermission::CanAssignRole => api::RoleManagementPerm::CanAssignRole,
            RoleManagementPermission::CanRevokeRole => api::RoleManagementPerm::CanRevokeRole,
            RoleManagementPermission::CanChangeRolePerms => {
                api::RoleManagementPerm::CanChangeRolePerms
            }
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
    /// The role can change role management permissions for roles.
    ChangeRoleManagementPerms,
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

impl From<api::SimplePerm> for Permission {
    fn from(value: api::SimplePerm) -> Self {
        match value {
            api::SimplePerm::AddDevice => Permission::AddDevice,
            api::SimplePerm::RemoveDevice => Permission::RemoveDevice,
            api::SimplePerm::TerminateTeam => Permission::TerminateTeam,
            api::SimplePerm::CreateRole => Permission::CreateRole,
            api::SimplePerm::DeleteRole => Permission::DeleteRole,
            api::SimplePerm::AssignRole => Permission::AssignRole,
            api::SimplePerm::RevokeRole => Permission::RevokeRole,
            api::SimplePerm::ChangeRoleManagementPerms => Permission::ChangeRoleManagementPerms,
            api::SimplePerm::SetupDefaultRole => Permission::SetupDefaultRole,
            api::SimplePerm::ChangeRoleManagingRole => Permission::ChangeRoleManagingRole,
            api::SimplePerm::CreateLabel => Permission::CreateLabel,
            api::SimplePerm::DeleteLabel => Permission::DeleteLabel,
            api::SimplePerm::ChangeLabelManagingRole => Permission::ChangeLabelManagingRole,
            api::SimplePerm::AssignLabel => Permission::AssignLabel,
            api::SimplePerm::RevokeLabel => Permission::RevokeLabel,
            api::SimplePerm::CanUseAfc => Permission::CanUseAfc,
            api::SimplePerm::CreateAfcUniChannel => Permission::CreateAfcUniChannel,
        }
    }
}

impl From<Permission> for api::SimplePerm {
    fn from(value: Permission) -> Self {
        match value {
            Permission::AddDevice => api::SimplePerm::AddDevice,
            Permission::RemoveDevice => api::SimplePerm::RemoveDevice,
            Permission::TerminateTeam => api::SimplePerm::TerminateTeam,
            Permission::CreateRole => api::SimplePerm::CreateRole,
            Permission::DeleteRole => api::SimplePerm::DeleteRole,
            Permission::AssignRole => api::SimplePerm::AssignRole,
            Permission::RevokeRole => api::SimplePerm::RevokeRole,
            Permission::ChangeRoleManagementPerms => api::SimplePerm::ChangeRoleManagementPerms,
            Permission::SetupDefaultRole => api::SimplePerm::SetupDefaultRole,
            Permission::ChangeRoleManagingRole => api::SimplePerm::ChangeRoleManagingRole,
            Permission::CreateLabel => api::SimplePerm::CreateLabel,
            Permission::DeleteLabel => api::SimplePerm::DeleteLabel,
            Permission::ChangeLabelManagingRole => api::SimplePerm::ChangeLabelManagingRole,
            Permission::AssignLabel => api::SimplePerm::AssignLabel,
            Permission::RevokeLabel => api::SimplePerm::RevokeLabel,
            Permission::CanUseAfc => api::SimplePerm::CanUseAfc,
            Permission::CreateAfcUniChannel => api::SimplePerm::CreateAfcUniChannel,
        }
    }
}
