---
policy-version: 2
---

# Default Policy

The default policy used by Aranya. It is the core component that our software is built on top
of, so any changes may affect the behavior of the system and could require updating other parts of
the code to get everything working together.

This policy can also be used as a template for writing other custom policies.

Note that the policy has been written for version beta of our product and includes several
limitations that will likely be changed for the MVP.

## Roles & Permissions

The MVP will likely support multiple role assignments per device, but we restrict to 1 role per device
for the beta. Hence, devices can only be onboarded to the team under the `Member` role and the role
assignment commands can be thought of as a promotion of the devices's single role. Similarly, only the
`Member` role can be removed from the team and so role revocation commands will simply demote any
higher role back down to `Member`.

* Owner:
  * Initialize/terminate Team.
  * Add (new) / remove Members.
  * Assign/revoke Owner role.
  * Assign/revoke Admin role.
  * Assign/revoke Operator role.
  * Define/undefine channel label.
  * Assign/revoke channel label.
  * Set/unset AQC address&name.

* Admin:
  * Assign/revoke Operator role.
  * Define/undefine channel label.
  * Revoke channel label.
  * Unset AQC network identifier.

* Operator:
  * Add (new) / remove Member.
  * Define channel label.
  * Assign/revoke channel label.
  * Set/unset AQC address&name.

* Member:
  * Create/delete AQC channel.

**Invariants**:

- Owner is the "root device" (has all permissions except sending data on AQC channels).
- A device can only have one role at a time.
- If the `Device` fact exists, then so will the `DeviceIdentKey`, `DeviceSignKey`, and `DeviceEncKey`
  facts. Similarly, the latter three facts are predicated on the device fact.
- A device can only have one of each device key type at a time.
- Only the creator of the team is added as an `Owner`. All other devices are onboarded as `Member`s.
- Only onboarded devices can be assigned to a higher role than `Member`.
- Revoking A device's role will automatically set their role down to `Member`.
- Only a `Member` can be removed from the team. All other roles must be revoked from A device before
  they can be removed from the team.


### Imports & Global Constants

```policy
use aqc
use crypto
use device
use envelope
use idam
use perspective
```

### Enums & Structs

```policy

// Valid channel operations for a label assignment.
enum ChanOp {
    // The device can only receive data in channels with this
    // label.
    RecvOnly,
    // The device can only send data in channels with this
    // label.
    SendOnly,
    // The device can send and receive data in channels with this
    // label.
    SendRecv,
}

// Collection of public DeviceKeys for A device.
struct KeyBundle {
    ident_key bytes,
    sign_key bytes,
    enc_key bytes,
}

// The set of key IDs derived from each DeviceKey.
// NB: Key ID of the IdentityKey is the device ID.
struct KeyIds {
    device_id id,
    sign_key_id id,
    enc_key_id id,
}

// Defines a device on the team.
struct Device {
    // ID of the device.
    device_id id,
    // Device priority.
    priority int,
    // Signing key id.
    sign_key_id id,
    // Encryption key id.
    enc_key_id id,
}

// Defines a role on the team.
struct Role {
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // ID of device that created the role.
    author_id id,
}
```

### Facts

```policy
// Devices on the team.
fact Devices[device_id id]=>{device struct Device}

// A device's public IdentityKey
fact DeviceIdentKey[device_id id]=>{key bytes}

// A device's public SigningKey.
fact DeviceSignKey[device_id id]=>{key_id id, key bytes}

// A device's public EncryptionKey.
fact DeviceEncKey[device_id id]=>{key_id id, key bytes}

// A ID-based role on the team.
fact Roles[role_id id]=>{role struct Role}

// Records that a role was assigned to a device.
fact AssignedRole[role_id id, device_id id]=>{}

// Records that a role was assigned permission to execute a certain command.
// TODO: use enum permission key.
fact PermRole[perm string]=>{role_id id}

// Indicates that the team has been terminated.
fact TeamEnd[]=>{}

// Stores a Member's associated network identifier for AQC.
fact AqcMemberNetworkId[device_id id]=>{net_identifier string}
```

### Functions

```policy
// Returns a device if one exists.
function find_existing_device(device_id id) optional struct Devices {
    let device = query Devices[device_id: device_id]
    let has_ident = exists DeviceIdentKey[device_id: device_id]
    let has_sign = exists DeviceSignKey[device_id: device_id]
    let has_enc = exists DeviceEncKey[device_id: device_id]

    if device is Some {
        check has_ident
        check has_sign
        check has_enc
    } else {
        check !has_ident
        check !has_sign
        check !has_enc
    }

    // Return the resulting device struct for further checks.
    return device
}

// Returns whether the team exists.
// Returns true if the team exists, returns false otherwise.
// This should always be the first thing that is checked before executing a command on a team.
// The only command that doesn't run this check first is `CreateTeam`.
function team_exists() bool {
    // Check to see if team is active.
    return !exists TeamEnd[]=> {}
}

// Returns a valid Device after performing sanity checks per the stated invariants.
function get_valid_device(device_id id) struct Devices {
    // Get and return device info.
    let device = check_unwrap find_existing_device(device_id)
    return device
}

// Derives the key ID for each of the DeviceKeys in the bundle.
// (The IdentityKey's ID is the DeviceID.)
function derive_device_key_ids(device_keys struct KeyBundle) struct KeyIds {
    let device_id = idam::derive_device_id(device_keys.ident_key)
    let sign_key_id = idam::derive_sign_key_id(device_keys.sign_key)
    let enc_key_id = idam::derive_enc_key_id(device_keys.enc_key)

    return KeyIds {
        device_id: device_id,
        sign_key_id: sign_key_id,
        enc_key_id: enc_key_id,
    }
}

// Seals a serialized basic command into an envelope, using the stored SigningKey for this device.
function seal_command(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author_sign_pk = check_unwrap query DeviceSignKey[device_id: author_id]

    let signed = crypto::sign(author_sign_pk.key_id, payload)
    return envelope::new(
        parent_id,
        author_id,
        signed.command_id,
        signed.signature,
        payload,
    )
}

// Opens an envelope using the author's public device signing
// key, and if verification succeeds, returns the serialized
// basic command data .
function open_envelope(sealed_envelope struct Envelope) bytes {
    let author_id = envelope::author_id(sealed_envelope)
    let author_sign_pk = check_unwrap query DeviceSignKey[device_id: author_id]

    let verified_command = crypto::verify(
        author_sign_pk.key,
        envelope::parent_id(sealed_envelope),
        envelope::payload(sealed_envelope),
        envelope::command_id(sealed_envelope),
        envelope::signature(sealed_envelope),
    )
    return verified_command
}
```
#### RBAC Functions

```policy
finish function create_role(role struct Role) {
    create Roles[role_id: role.role_id]=>{role: role}
}

finish function delete_role(role struct Role) {
    delete Roles[role_id: role.role_id]
}

finish function assign_perm_role(perm string, role_id id) {
    create PermRole[perm: perm]=>{role_id: role_id}
}

finish function revoke_perm_role(perm string) {
    delete PermRole[perm: perm]
}

// Check if device has permission to execute the current command.
function device_has_permission(device_id id, perm string) bool {
    let role_perm_opt = query PermRole[perm: perm]
    if role_perm_opt is None {
        return false
    }
    let role_id = (unwrap role_perm_opt).role_id

    return exists AssignedRole[role_id: role_id, device_id: device_id]
}

// Check if the author device has higher priority than the target device.
// This means the author has permission to execute commands on the target.
function author_dominates_target(author_id id, target_id id) bool {
    // Check if the device has higher priority than the target device.
    let author_device = unwrap query Devices[device_id: author_id]
    let target_device = unwrap query Devices[device_id: target_id]
    if author_device.device.priority >= target_device.device.priority {
        return true
    }
    return false
}
```

#### Channel Functions

```policy
// Reports whether `size` is a valid PSK length (in bytes).
//
// Per the AQC specification, PSKs must be in the range [32, 2^16).
function is_valid_psk_length(size int) bool {
    return size >= 32 && size < 65536
}

// Returns the channel operation for a particular label.
function get_allowed_op(device_id id, label_id id) enum ChanOp {
    let assigned_label = check_unwrap query AssignedLabel[label_id: label_id, device_id: device_id]
    return assigned_label.op
}

// Returns the device's encoded public EncryptionKey.
function get_enc_pk(device_id id) bytes {
    let device_enc_pk = check_unwrap query DeviceEncKey[device_id: device_id]
    return device_enc_pk.key
}

// Selects the ID which doesn't match `Device_id`.
function select_peer_id(device_id id, id_a id, id_b id) id {
    if device_id == id_a {
        return id_b
    } else if device_id == id_b {
        return id_a
    } else {
        check false
    }
}
```

##### AQC Channel Functions

```policy
// Reports whether the devices have permission to create
// a bidirectional AQC channel with each other.
function can_create_aqc_bidi_channel(device1 id, device2 id, label_id id) bool {
    // Devices cannot create channels with themselves.
    //
    // This should have been caught by the AQC FFI, so check
    // instead of just returning false.
    check device1 != device2

    // Both devices must have permissions to read (recv) and
    // write (send) data.
    let device1_op = get_allowed_op(device1, label_id)
    if device1_op != ChanOp::SendRecv {
        return false
    }

    let device2_op = get_allowed_op(device2, label_id)
    if device2_op != ChanOp::SendRecv {
        return false
    }

    return true
}

// Reports whether the devices have permission to create
// a unidirectional AQC channel with each other.
function can_create_aqc_uni_channel(sender_id id, receiver_id id, label_id id) bool {
    // Devices cannot create channels with themselves.
    //
    // This should have been caught by the AQC FFI, so check
    // instead of just returning false.
    check sender_id != receiver_id

    // The writer must have permissions to write (send) data.
    let writer_op = get_allowed_op(sender_id, label_id)
    match writer_op {
        ChanOp::RecvOnly => { return false }
        ChanOp::SendOnly => {}
        ChanOp::SendRecv => {}
    }

    // The reader must have permission to read (receive) data.
    let reader_op = get_allowed_op(receiver_id, label_id)
    match reader_op {
        ChanOp::RecvOnly => {}
        ChanOp::SendOnly => { return false }
        ChanOp::SendRecv => {}
    }

    return true
}
```

## CreateTeam

The `CreateTeam` command is the initial command in the graph. It creates the Team and establishes
the author as the sole Owner of the Team.

```policy
// Creates a Team.
action create_team(owner_keys struct KeyBundle, nonce bytes) {
    publish CreateTeam {
        owner_keys: owner_keys,
        nonce: nonce,
    }
}

effect TeamCreated {
    // The DeviceID of the creator of the Team.
    owner_id id,
}

command CreateTeam {
    fields {
        // The initial owner's public DeviceKeys.
        owner_keys struct KeyBundle,
        // Random nonce to enforce this team's uniqueness.
        nonce bytes,
    }

    seal {
        let parent_id = perspective::head_id()
        let author_id = device::current_device_id()
        let payload = serialize(this)
        let author_sign_key_id = idam::derive_sign_key_id(this.owner_keys.sign_key)

        // Sign and enclose the serialized command into an Envelope with additional metadata.
        let signed = crypto::sign(author_sign_key_id, payload)
        return envelope::new(
            parent_id,
            author_id,
            signed.command_id,
            signed.signature,
            payload,
        )
    }

    open {
        let payload = envelope::payload(envelope)
        let author_sign_key = deserialize(payload).owner_keys.sign_key

        // Verify and return the enclosed command.
        let verified_command = crypto::verify(
            author_sign_key,
            envelope::parent_id(envelope),
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope),
        )
        return deserialize(verified_command)
    }

    policy {
        // Get author of command
        let author_id = envelope::author_id(envelope)
        // Derive the key ids from the device_keys
        let owner_key_ids = derive_device_key_ids(this.owner_keys)

        // Check that author_id matches the device_id being created
        check author_id == owner_key_ids.device_id

        // TODO: define const high priority for owner device.
        let device = Device {
            device_id: owner_key_ids.device_id,
            priority: 65000,
            sign_key_id: owner_key_ids.sign_key_id,
            enc_key_id: owner_key_ids.enc_key_id,
        }

        // A role's ID is the ID of the command that created it.
        let role_id = envelope::command_id(envelope)
        
        let role = Role {
            role_id: role_id,
            name: "owner",
            author_id: author_id,
        }

        finish {
            // Add device to team.
            add_new_device(this.owner_keys, owner_key_ids, device)
            // Create a new owner role.
            create_role(role)

            // TODO: assign default permissions to owner role.
            assign_perm_role("AddMember", role.role_id)
            assign_perm_role("RemoveMember", role.role_id)
            assign_perm_role("CreateRole", role.role_id)
            assign_perm_role("DeleteRole", role.role_id)
            assign_perm_role("AssignRole", role.role_id)
            assign_perm_role("RevokeRole", role.role_id)
            assign_perm_role("AssignRolePermission", role.role_id)
            assign_perm_role("RevokeRolePermission", role.role_id)

            // Assign owner role to device.
            create AssignedRole[role_id: role.role_id, device_id: author_id]=>{}

            emit TeamCreated {
                owner_id: author_id,
            }
        }
    }
}

// Adds the device to the Team.
finish function add_new_device(key_bundle struct KeyBundle, key_ids struct KeyIds, device struct Device) {
    create Devices[device_id: key_ids.device_id]=>{device: device}

    create DeviceIdentKey[device_id: key_ids.device_id]=>{key: key_bundle.ident_key}
    create DeviceSignKey[device_id: key_ids.device_id]=>{
        key_id: key_ids.sign_key_id,
        key: key_bundle.sign_key,
    }
    create DeviceEncKey[device_id: key_ids.device_id]=>{
        key_id: key_ids.enc_key_id,
        key: key_bundle.enc_key,
    }
}
```

**Invariants:**

- This is the initial command in the graph.
- Only an Owner will create this event.

## TerminateTeam

The `TerminateTeam` terminates a Team. It can only be done by the Owner.

```policy
// Terminates a Team.
action terminate_team() {
    publish TerminateTeam{}
}

effect TeamTerminated{
    owner_id id,
}

command TerminateTeam {
    fields {}

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Check that the team is active and return the author's info if they exist in the team.
        let author = get_valid_device(envelope::author_id(envelope))

        check device_has_permission(author.device_id, "TerminateTeam")

        finish {
            create TeamEnd[]=>{}

            emit TeamTerminated{
                owner_id: author.device_id,
            }
        }
    }
}
```

**Invariants:**

- This is the final command in the graph.
- Only an Owner can create this event.
- Once terminated, no further communication will occur over the team graph.


## AddMember

Add a member to a team.

```policy
// Adds a Member to the Team.
action add_member(device_keys struct KeyBundle, priority int){
    publish AddMember {
        device_keys: device_keys,
        priority: priority,
    }
}

// A Member was added to the Team.
effect MemberAdded {
    // The id of the device to be added.
    device_id id,
    // The device's set of public DeviceKeys.
    device_keys struct KeyBundle,
    // Priority of the device.
    priority int,
}

command AddMember {
    fields {
        // The new device's public DeviceKeys.
        device_keys struct KeyBundle,
        // Priority of the device.
        priority int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        // Derive the key IDs from the provided KeyBundle.
        let device_key_ids = derive_device_key_ids(this.device_keys)

        check device_has_permission(author.device_id, "AddMember")

        // Check that the Member doesn't already exist.
        check find_existing_device(device_key_ids.device_id) is None

        let device = Device {
            device_id: device_key_ids.device_id,
            priority: this.priority,
            sign_key_id: device_key_ids.sign_key_id,
            enc_key_id: device_key_ids.enc_key_id,
        }

        finish {
            add_new_device(this.device_keys, device_key_ids, device)

            emit MemberAdded {
                device_id: device_key_ids.device_id,
                device_keys: this.device_keys,
                priority: this.priority,
            }
        }
    }
}
```

**Invariants**:

- Members can only be added by Operators and Owners.
- Non-Member roles must first be added as a Member and can then get assigned to a higher role.


## RemoveMember

Remove a member from a team.

```policy
// Removes a Member from the Team.
action remove_member(device_id id){
    publish RemoveMember {
        device_id: device_id,
    }
}

// A Member was removed from the Team.
effect MemberRemoved {
    device_id id,
}

command RemoveMember{
    fields {
        // The removed device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let device = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "RemoveMember")
        check author_dominates_target(author.device_id, device.device_id)

        finish {
            remove_device(this.device_id)

            emit MemberRemoved {
                device_id: this.device_id,
            }
        }
    }
}

// Removes the device from the Team.
finish function remove_device(device_id id) {
    delete Devices[device_id: device_id]
    delete DeviceIdentKey[device_id: device_id]
    delete DeviceSignKey[device_id: device_id]
    delete DeviceEncKey[device_id: device_id]
}
```

**Invariants**:

- Members can only be removed by Operators and Owners.
- Removing non-Members requires revoking their higher role so the device is made into a Member first.

## AssignPriority

Assign priority to a device on a team.

## CreateRole

Create a new custom role.

```policy
// Create a new custom role.
action create_role(name string){
    publish CreateRole {
        name: name,
    }
}

command CreateRole {
    fields {
        // The name of the custom role.
        name string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        check device_has_permission(author.device_id, "CreateRole")

        // A role's ID is the ID of the command that created it.
        let role_id = envelope::command_id(envelope)

        let role = Role {
            role_id: role_id,
            name: this.name,
            author_id: author.device_id,
        }

        finish {
            create_role(role)

            emit RoleCreated {
                role: role,
            }
        }
    }
}

// A role was created on the team.
effect RoleCreated {
    role struct Role,
}
```

## DeleteRole

Delete a custom role.

```policy
// Delete a custom role.
action delete_role(role_id id){
    publish DeleteRole {
        role_id: role_id,
    }
}

command DeleteRole {
    fields {
        // ID of the role to delete.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        check device_has_permission(author.device_id, "DeleteRole")

        // Query role.
        let role = check_unwrap query Roles[role_id: this.role_id]

        finish {
            // Delete role.
            delete_role(role.role)

            // Return deleted role info.
            emit RoleDeleted {
                role: role.role,
            }
        }
    }
}

// A role was deleted from the team.
effect RoleDeleted {
    role struct Role
}
```

## AssignRole

Assign a role to a device.

```policy
// Assigns the specified role to the device.
action assign_role(device_id id, role_id id){
    publish AssignRole {
        device_id: device_id,
        role_id: role_id,
    }
}

command AssignRole {
    fields {
        // ID of the device to assign role to.
        device_id id,
        // ID of the role to assign to the device.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let device = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "AssignRole")
        check author_dominates_target(author.device_id, device.device_id)

        // Query role.
        let role = check_unwrap query Roles[role_id: this.role_id]

        finish {
            create AssignedRole[role_id: this.role_id, device_id: device.device_id]=>{}

            // Return assigned role info.
            emit RoleAssigned {
                device_id: device.device_id,
                role_id: role.role.role_id,
                name: role.role.name,
                author_id: author.device_id,
            }
        }
    }
}

// A role was assigned to a device on the team.
effect RoleAssigned {
    // ID of device the role was assigned to.
    device_id id,
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // ID of the device that assigned the role.
    author_id id,
}
```

**Invariants**:

TODO: fix these docs
- devices cannot assign roles to themselves.
- Only Owners can assign the Owner role.
- Only Owners can assign the Admin role.
- Only Owners and Admins can assign the Operator role.


## RevokeRole


```policy
// Revoke a role from a device.
action revoke_role(device_id id, role_id id){
    publish RevokeRole {
        device_id: device_id,
        role_id: role_id,
    }
}

command RevokeRole {
    fields {
        // ID of the device to revoke role from.
        device_id id,
        // ID of the role to revoke from the device.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let target = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "RevokeRole")
        check author_dominates_target(author.device_id, target.device_id)

        // Query role.
        let role = check_unwrap query Roles[role_id: this.role_id]

        finish {
            delete AssignedRole[role_id: this.role_id, device_id: target.device_id]

            // Return revoked role info.
            emit RoleRevoked {
                device_id: target.device_id,
                role_id: role.role.role_id,
                name: role.role.name,
                author_id: author.device_id,
            }
        }
    }
}

// A role was revoked from a device on the team.
effect RoleRevoked {
    // ID of device the role was revoked from.
    device_id id,
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // ID of the device that revoked the role.
    author_id id,
}
```

## AssignRolePermission

Assign permission to execute a certain command to the role.
Note: currently each command is only allowed to be executed by one role.

```policy

action assign_role_perm(role_id id, perm string) {
    publish AssignRolePermission{
        role_id: role_id,
        perm: perm,
    }
}

command AssignRolePermission {
    fields {
        // ID of the role to assign permission to.
        role_id id,
        // Permission to assign to the role.
        perm string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        check device_has_permission(author.device_id, "AssignRolePermission")

        // Query role.
        let role = check_unwrap query Roles[role_id: this.role_id]

        finish {
            assign_perm_role(this.perm, role.role.role_id)
    
            // Return deleted role info.
            emit RolePermissionAssigned {
                role_id: role.role.role_id,
                name: role.role.name,
                perm: this.perm,
                author_id: author.device_id,
            }
        }
    }
}

// A permission was assigned to a role on the team.
effect RolePermissionAssigned {
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // Permission assigned to the role.
    perm string,
    // ID of the device that assigned the permission.
    author_id id,
}
```

## RevokeRolePermission

Revoke permission to execute a certain command from the role.

```policy
action revoke_role_perm(role_id id, perm string) {
    publish RevokeRolePermission{
        role_id: role_id,
        perm: perm,
    }
}

command RevokeRolePermission {
    fields {
        // ID of the role to revoke permission from.
        role_id id,
        // Permission to revoke from the role.
        perm string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        check device_has_permission(author.device_id, "RevokeRolePermission")

        // Query role.
        let role = check_unwrap query Roles[role_id: this.role_id]

        if this.role_id == role.role.role_id {
            finish {
                revoke_perm_role(this.perm)

                // Return deleted role info.
                emit RolePermissionRevoked {
                    role_id: role.role.role_id,
                    name: role.role.name,
                    perm: this.perm,
                    author_id: author.device_id,
                }
            }
        }
    }
}

// A permission was revoked from a role on the team.
effect RolePermissionRevoked {
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // Permission revoked from the role.
    perm string,
    // ID of the device that revoked the permission.
    author_id id,
}
```

## SetAqcNetworkName

Associates a network name and address to a `Member` for use in AQC.

```policy
action set_aqc_network_name (device_id id, net_identifier string) {
    publish SetAqcNetworkName {
        device_id: device_id,
        net_identifier: net_identifier,
    }
}

effect AqcNetworkNameSet {
    device_id id,
    net_identifier string,
}

command SetAqcNetworkName {
    fields {
        device_id id,
        net_identifier string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let target = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "SetAqcNetworkName")
        check author_dominates_target(author.device_id, target.device_id)

        let net_id_exists = query AqcMemberNetworkId[device_id: target.device_id]

        if net_id_exists is Some {
            let net_id = unwrap net_id_exists
            finish {
                update AqcMemberNetworkId[device_id: target.device_id]=>{net_identifier: net_id.net_identifier} to {
                    net_identifier: this.net_identifier
                }

                emit AqcNetworkNameSet {
                    device_id: target.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        }
        else {
            finish {
                create AqcMemberNetworkId[device_id: this.device_id]=>{net_identifier: this.net_identifier}

                emit AqcNetworkNameSet {
                    device_id: target.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators can assign AQC network names to Members.
- Members can only be assigned to one AQC network name.

## UnsetAqcNetworkName

Dissociates an AQC network name and address from a `Member`.

```policy
action unset_aqc_network_name (device_id id) {
    publish UnsetAqcNetworkName {
        device_id: device_id,
    }
}

effect AqcNetworkNameUnset {
    device_id id,
}

command UnsetAqcNetworkName {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let target = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "UnsetAqcNetworkName")
        check author_dominates_target(author.device_id, target.device_id)

        check exists AqcMemberNetworkId[device_id: target.device_id]
        finish {
            delete AqcMemberNetworkId[device_id: target.device_id]

            emit AqcNetworkNameUnset {
                device_id: target.device_id,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators Operators can unset AQC network names from Members.

## CreateChannel

### AqcCreateChannel

#### AqcCreateBidiChannel

Creates a bidirectional AQC channel for off-graph messaging.
This is an ephemeral command, which means that it can only be
emitted within an ephemeral session so that it is not added to
the graph of commands. Furthermore, it cannot persist any changes
to the fact database.

The `create_aqc_bidi_channel` action creates the `ChannelKeys`, encapsulates them for the peer and the
author, and sends the encapsulations through the `AqcCreateBidiChannel` command. When processing the
command, the device will decapsulate their keys and store them in the shared memory DB.

```policy
action create_aqc_bidi_channel(peer_id id, label_id id) {
    let parent_cmd_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author = get_valid_device(author_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let ch = aqc::create_bidi_channel(
        parent_cmd_id,
        author.device.enc_key_id,
        author_id,
        peer_enc_pk,
        peer_id,
        label_id,
    )

    publish AqcCreateBidiChannel {
        channel_id: ch.channel_id,
        peer_id: peer_id,
        label_id: label_id,
        peer_encap: ch.peer_encap,
        author_secrets_id: ch.author_secrets_id,
        psk_length_in_bytes: ch.psk_length_in_bytes,
    }
}

// The effect that is emitted when the author of a bidirectional
// AQC channel successfully processes the `AqcCreateBidiChannel`
// command.
effect AqcBidiChannelCreated {
    // Uniquely identifies the channel.
    channel_id id,
    // The unique ID of the previous command.
    parent_cmd_id id,
    // The channel author's device ID.
    author_id id,
    // The channel author's encryption key ID.
    author_enc_key_id id,
    // The channel peer's device Id.
    peer_id id,
    // The channel peer's encoded public encryption key.
    peer_enc_pk bytes,
    // The channel label.
    label_id id,
    // A unique ID that the author can use to look up the
    // channel's secrets.
    author_secrets_id id,
    // The size in bytes of the PSK.
    //
    // Per the AQC specification, this must be at least 32 and
    // less than 2^16.
    psk_length_in_bytes int,
}

// The effect that is emitted when the peer of a bidirectional
// AQC channel successfully processes the `AqcCreateBidiChannel`
// command.
effect AqcBidiChannelReceived {
    // Uniquely identifies the channel.
    channel_id id,
    // The unique ID of the previous command.
    parent_cmd_id id,
    // The channel author's device ID.
    author_id id,
    // The channel author's encoded public encryption key.
    author_enc_pk bytes,
    // The channel peer's device Id.
    peer_id id,
    // The channel peer's encryption key ID.
    peer_enc_key_id id,
    // The channel label.
    label_id id,
    // The channel peer's encapsulated KEM shared secret.
    encap bytes,
    // The size in bytes of the PSK.
    //
    // Per the AQC specification, this must be at least 32 and
    // less than 2^16.
    psk_length_in_bytes int,
}

command AqcCreateBidiChannel {
    fields {
        // Uniquely identifies the channel.
        channel_id id,
        // The channel peer's device ID.
        peer_id id,
        // The label applied to the channel.
        label_id id,
        // The channel peer's encapsulated KEM shared secret.
        peer_encap bytes,
        // A unique ID that the author can use to look up the
        // channel's secrets.
        author_secrets_id id,
        // The size in bytes of the PSK.
        //
        // Per the AQC specification, this must be at least 32.
        psk_length_in_bytes int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let peer = get_valid_device(this.peer_id)

        check is_valid_psk_length(this.psk_length_in_bytes)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        check device_has_permission(author.device_id, "AqcCreateBidiChannel")

        // Check that both devices have been assigned to the label and have correct send/recv permissions.
        check can_create_aqc_bidi_channel(author.device_id, peer.device_id, label.label_id)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_device_id = device::current_device_id()

        if current_device_id == author.device_id {
            // We're the channel author.
            let peer_enc_pk = get_enc_pk(peer.device_id)

            finish {
                emit AqcBidiChannelCreated {
                    channel_id: this.channel_id,
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device.device_id,
                    author_enc_key_id: author.device.enc_key_id,
                    peer_id: peer.device.device_id,
                    peer_enc_pk: peer_enc_pk,
                    label_id: label.label_id,
                    author_secrets_id: this.author_secrets_id,
                    psk_length_in_bytes: this.psk_length_in_bytes,
                }
            }
        } else if current_device_id == peer.device_id {
            // We're the channel peer.
            let author_enc_pk = get_enc_pk(author.device_id)

            finish {
                emit AqcBidiChannelReceived {
                    channel_id: this.channel_id,
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device.device_id,
                    author_enc_pk: author_enc_pk,
                    peer_id: peer.device.device_id,
                    peer_enc_key_id: peer.device.enc_key_id,
                    label_id: label.label_id,
                    encap: this.peer_encap,
                    psk_length_in_bytes: this.psk_length_in_bytes,
                }
            }
        } else {
            // This is an off-graph session command, so only the
            // communicating peers should process this command.
            check false
        }
    }
}
```

**Invariants**:

- Devices can only create channels for the labels they've been
  assigned.
- A device can only write data to a uni channel if it has been
  granted either the `ChanOp::SendOnly` or `ChanOp::SendRecv`
  permission for the label assigned to the channel.
- A device can only read data from a uni channel if it has been
  granted either the `ChanOp::RecvOnly` or `ChanOp::SendRecv`
  permission for the label assigned to the channel.

#### AqcCreateUniChannel

Creates a bidirectional AQC channel for off-graph messaging.
This is an ephemeral command, which means that it can only be
emitted within an ephemeral session so that it is not added to
the graph of commands. Furthermore, it cannot persist any changes
to the fact database.

The `create_aqc_uni_channel` action creates the `ChannelKey`, encapsulates it for the peer, and sends
the encapsulation through the `AqcCreateUniChannel` command. When processing the command, the
corresponding recipient will decapsulate their key and store it in the shared memory DB.

```policy
action create_aqc_uni_channel(sender_id id, receiver_id id, label_id id) {
    let parent_cmd_id = perspective::head_id()
    let author = get_valid_device(device::current_device_id())
    let peer_id = select_peer_id(author.device_id, sender_id, receiver_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let ch = aqc::create_uni_channel(
        parent_cmd_id,
        author.device.enc_key_id,
        peer_enc_pk,
        sender_id,
        receiver_id,
        label_id,
    )

    publish AqcCreateUniChannel {
        channel_id: ch.channel_id,
        sender_id: sender_id,
        receiver_id: receiver_id,
        label_id: label_id,
        peer_encap: ch.peer_encap,
        author_secrets_id: ch.author_secrets_id,
        psk_length_in_bytes: ch.psk_length_in_bytes,
    }
}

// The effect that is emitted when the author of a unidirectional
// AQC channel successfully processes the `AqcCreateUniChannel`
// command.
effect AqcUniChannelCreated {
    // Uniquely identifies the channel.
    channel_id id,
    // The unique ID of the previous command.
    parent_cmd_id id,
    // The channel author's device ID.
    author_id id,
    // The device ID of the participant that can send data.
    sender_id id,
    // The device ID of the participant that can receive data.
    receiver_id id,
    // The channel author's encryption key ID.
    author_enc_key_id id,
    // The channel peer's encoded public encryption key.
    peer_enc_pk bytes,
    // The channel label.
    label_id id,
    // A unique ID that the author can use to look up the
    // channel's secrets.
    author_secrets_id id,
    // The size in bytes of the PSK.
    //
    // Per the AQC specification, this must be at least 32 and
    // less than 2^16.
    psk_length_in_bytes int,
}

// The effect that is emitted when the peer of a unidirectional
// AQC channel successfully processes the `AqcCreateUniChannel`
// command.
effect AqcUniChannelReceived {
    // Uniquely identifies the channel.
    channel_id id,
    // The unique ID of the previous command.
    parent_cmd_id id,
    // The channel author's device ID.
    author_id id,
    // The device ID of the participant that can send data.
    sender_id id,
    // The device ID of the participant that can receive data.
    receiver_id id,
    // The channel author's encryption key ID.
    author_enc_pk bytes,
    // The channel peer's encryption key ID.
    peer_enc_key_id id,
    // The channel label.
    label_id id,
    // The channel peer's encapsulated KEM shared secret.
    encap bytes,
    // The size in bytes of the PSK.
    //
    // Per the AQC specification, this must be at least 32 and
    // less than 2^16.
    psk_length_in_bytes int,
}

command AqcCreateUniChannel {
    fields {
        // Uniquely identifies the channel.
        channel_id id,
        // The device ID of the participant that can send data.
        sender_id id,
        // The device ID of the participant that can receive
        // data.
        receiver_id id,
        // The label applied to the channel.
        label_id id,
        // A unique ID that the author can use to look up the
        // channel's secrets.
        author_secrets_id id,
        // The channel peer's encapsulated KEM shared secret.
        peer_encap bytes,
        // The size in bytes of the PSK.
        //
        // Per the AQC specification, this must be at least 32.
        psk_length_in_bytes int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        // Ensure that the author is one of the channel
        // participants.
        check author.device_id == this.sender_id ||
              author.device_id == this.receiver_id

        let peer_id = if author.device_id == this.sender_id {
            :this.receiver_id
        } else {
            :this.sender_id
        }
        let peer = check_unwrap find_existing_device(peer_id)

        check is_valid_psk_length(this.psk_length_in_bytes)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        check device_has_permission(author.device_id, "AqcCreateUniChannel")

        // Check that both devices have been assigned to the label and have correct send/recv permissions.
        check can_create_aqc_uni_channel(this.sender_id, this.receiver_id, label.label_id)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_device_id = device::current_device_id()

        if current_device_id == author.device_id {
            // We authored this command.
            let peer_enc_pk = get_enc_pk(peer_id)

            finish {
                emit AqcUniChannelCreated {
                    channel_id: this.channel_id,
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    sender_id: this.sender_id,
                    receiver_id: this.receiver_id,
                    author_enc_key_id: author.device.enc_key_id,
                    peer_enc_pk: peer_enc_pk,
                    label_id: label.label_id,
                    author_secrets_id: this.author_secrets_id,
                    psk_length_in_bytes: this.psk_length_in_bytes,
                }
            }
        } else if current_device_id == peer.device_id {
            // We're the intended recipient of this command.
            let author_enc_pk = get_enc_pk(author.device_id)

            finish {
                emit AqcUniChannelReceived {
                    channel_id: this.channel_id,
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    sender_id: this.sender_id,
                    receiver_id: this.receiver_id,
                    author_enc_pk: author_enc_pk,
                    peer_enc_key_id: peer.device.enc_key_id,
                    label_id: label.label_id,
                    encap: this.peer_encap,
                    psk_length_in_bytes: this.psk_length_in_bytes,
                }
            }
        } else {
            // This is an off-graph session command, so only the
            // communicating peers should process this command.
            check false
        }
    }
}
```

**Invariants**:

- Members can only create channels for the labels they've been assigned.
- Members can only create unidirectional channels when the writer side has either
  `ChanOp::SendRecv` or `ChanOp::SendOnly` permissions for the label and the reader side has
  either `ChanOp::SendRecv` or `ChanOp::RecvOnly` permissions for the label.

#### Labels

##### CreateLabel

Establishes a whitelist of labels that can be assigned to Members.

```policy
// Records a label.
//
// `name` is a short description of the label. E.g., "TELEMETRY".
fact Label[label_id id]=>{name string, author_id id}

// Creates a label.
action create_label(name string) {
    publish CreateLabel {
        label_name: name,
    }
}

command CreateLabel {
    fields {
        // The label name.
        label_name string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        // A label's ID is the ID of the command that created it.
        let label_id = envelope::command_id(envelope)

        check device_has_permission(author.device_id, "CreateLabel")

        // Verify that the label does not already exist.
        //
        // This will happen in the `finish` block if we try to
        // create an already true label, but checking first
        // results in a nicer error (I think?).
        check !exists Label[label_id: label_id]

        finish {
            create Label[label_id: label_id]=>{name: this.label_name, author_id: author.device_id}

            emit LabelCreated {
                label_id: label_id,
                label_name: this.label_name,
                label_author_id: author.device_id,
            }
        }
    }
}

// The effect emitted when the `CreateLabel` command is
// successfully processed.
effect LabelCreated {
    // Uniquely identifies the label.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}
```

**Invariants**:

- Only Members cannot define labels.
- Owners, Admins and Operators are allowed to define labels.
- Label IDs must be cryptographically secure 32 byte Aranya IDs.

##### DeleteLabel

Removes a label from the whitelist. This operation will result in the label revocation across all Members that were assigned to it.

```policy
action delete_label(label_id id) {
    publish DeleteLabel {
        label_id: label_id,
    }
}

command DeleteLabel {
    fields {
        // The unique ID of the label being deleted.
        label_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))

        check device_has_permission(author.device_id, "DeleteLabel")
        // TODO: check dominance over devices assigned to label?

        // Verify that the label exists.
        //
        // This will happen in the `finish` block if we try to
        // create an already true label, but checking first
        // results in a nicer error (I think?).
        let label = check_unwrap query Label[label_id: this.label_id]

        finish {
            // Cascade deleting the label assignments.
            delete AssignedLabel[label_id: label.label_id, device_id: ?]

            delete Label[label_id: label.label_id]

            emit LabelDeleted {
                label_name: label.name,
                label_author_id: label.author_id,
                label_id: this.label_id,
                author_id: author.device_id,
            }
        }
    }
}

// The effect emitted when the `DeleteLabel` command is
// successfully processed.
effect LabelDeleted {
    // The label name.
    label_name string,
    // The label author's device ID.
    label_author_id id,
    // Uniquely identifies the label.
    label_id id,
    // The ID of the device that deleted the label.
    author_id id,
}
```

**Invariants**:

- Only Owners and Admins are allowed to delete labels.

##### Assign Label

Assigns a label to a Member.

```policy
// Records that a device was granted permission to use a label
// for certain channel operations.
fact AssignedLabel[label_id id, device_id id]=>{op enum ChanOp}

// Grants the device permission to use the label.
//
// - It is an error if the device does not exist.
// - It is an error if the label does not exist.
// - It is an error if the device has already been granted
//   permission to use this label.
action assign_label(device_id id, label_id id, op enum ChanOp) {
    publish AssignLabel {
        device_id: device_id,
        label_id: label_id,
        op: op,
    }
}

command AssignLabel {
    fields {
        // The target device.
        device_id id,
        // The label being assigned to the target device.
        label_id id,
        // The channel operations the device is allowed to used
        // the label for.
        op enum ChanOp,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let target = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "AssignLabel")
        check author_dominates_target(author.device_id, target.device_id)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // Verify that the device has not already been granted
        // permission to use the label.
        //
        // This will happen in the `finish` block if we try to
        // create an already true label, but checking first
        // results in a nicer error (I think?).
        check !exists AssignedLabel[label_id: label.label_id, device_id: target.device_id]

        finish {
            create AssignedLabel[label_id: label.label_id, device_id: target.device_id]=>{op: this.op}

            emit LabelAssigned {
                label_id: label.label_id,
                label_name: label.name,
                label_author_id: label.author_id,
                author_id: author.device_id,
            }
        }
    }
}

// The effect emitted when the `AssignLabel` command is
// successfully processed.
effect LabelAssigned {
    // The ID of the label that was assigned.
    label_id id,
    // The name of the label that was assigned.
    label_name string,
    // The ID of the author of the label.
    label_author_id id,
    // The ID of the device that assigned the label.
    author_id id,
}
```

**Invariants**:

- Label IDs must be cryptographically secure 32 byte Aranya IDs.
- Only Owners and Operators are allowed to assign labels.
- Only Members can be assigned to labels.
- Only labels that are defined are allowed to be assigned.

##### Revoke Label

Revokes a label from a Member. Note that peers communicating with this Member over a secure
channel under the revoked label should delete their channel once the label revocation command is
received.

```policy
// Revokes permission to use a label from a device.
//
// - It is an error if the device does not exist.
// - It is an error if the label does not exist.
// - It is an error if the device has not been granted permission
//   to use this label.
action revoke_label(device_id id, label_id id) {
    publish RevokeLabel {
        device_id: device_id,
        label_id: label_id,
    }
}

command RevokeLabel {
    fields {
        // The target device.
        device_id id,
        // The label being assigned to the target device.
        label_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_valid_device(envelope::author_id(envelope))
        let target = get_valid_device(this.device_id)

        check device_has_permission(author.device_id, "RevokeLabel")
        check author_dominates_target(author.device_id, target.device_id)

        let label = check_unwrap query Label[label_id: this.label_id]

        // Verify that the device has been granted permission to
        // use the label.
        //
        // This will happen in the `finish` block if we try to
        // create an already true label, but checking first
        // results in a nicer error (I think?).
        check exists AssignedLabel[label_id: label.label_id, device_id: target.device_id]

        finish {
            delete AssignedLabel[label_id: label.label_id, device_id: target.device_id]

            emit LabelRevoked {
                label_id: label.label_id,
                label_name: label.name,
                label_author_id: label.author_id,
                author_id: author.device_id,
            }
        }
    }
}

// The effect emitted when the `RevokeLabel` command is
// successfully processed.
effect LabelRevoked {
    // The ID of the label that was revoked.
    label_id id,
    // The name of the label that was revoked.
    label_name string,
    // The ID of the author of the label.
    label_author_id id,
    // The ID of the device that revoked the label.
    author_id id,
}
```

**Invariants**:

- Only Owners and Operators can revoke labels from Members.
- Only a label that was assigned can be revoked.

##### Label Queries

###### Query Label Exists

Queries whether a label exists.

```policy
// Emits `LabelExistsResult` for label if it exists.
action query_label_exists(label_id id) {
    publish QueryLabelExists {
        label_id: label_id,
    }
}

command QueryLabelExists {
    fields {
        label_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Get label if it exists
        let label = check_unwrap query Label[label_id: this.label_id]

        finish {
            emit QueryLabelExistsResult {
                label_id: label.label_id,
                label_name: label.name,
                label_author_id: label.author_id,
            }
        }
    }
}

effect QueryLabelExistsResult {
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}
```

**Invariants**:

- For a label to exist, it must have been created with the `CreateLabel` command.
- If a label has been deleted with the `DeleteLabel` command, this query will fail.

###### Query Labels

Queries for a list of all created labels.

```policy
// Emits `QueriedLabel` for all labels.
action query_labels() {
    map Label[label_id: ?] as f {
        publish QueryLabel {
            label_id: f.label_id,
            label_name: f.name,
            label_author_id: f.author_id,
        }
    }
}

command QueryLabel {
    fields {
        label_id id,
        label_name string,
        label_author_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueriedLabel {
                label_id: this.label_id,
                label_name: this.label_name,
                label_author_id: this.label_author_id,
            }
        }
    }
}

effect QueriedLabel {
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}
```

###### Query Label Assignments

Queries for a list labels assigned to a device.

```policy
// Emits `QueriedLabelAssignment` for all labels the device has
// been granted permission to use.
action query_label_assignments(device_id id) {
    // TODO: make this query more efficient when policy supports it.
    // The key order is optimized for `delete AssignedLabel`.
    map AssignedLabel[label_id: ?, device_id: ?] as f {
        if f.device_id == device_id {
            let label = check_unwrap query Label[label_id: f.label_id]
            publish QueryLabelAssignment {
                device_id: f.device_id,
                label_id: f.label_id,
                label_name: label.name,
                label_author_id: label.author_id,
            }
        }
    }
}

command QueryLabelAssignment {
    fields {
        device_id id,
        label_id id,
        label_name string,
        label_author_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueriedLabelAssignment {
                device_id: this.device_id,
                label_id: this.label_id,
                label_name: this.label_name,
                label_author_id: this.label_author_id,
            }
        }
    }
}

effect QueriedLabelAssignment {
    // The device's unique ID.
    device_id id,
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}
```

**Invariants**:

- Returns a list of labels assigned to the device via the `AssignLabel` command.
- A label that has been revoked from a device via the `RevokeLabel` command will not be returned.

### QueryDevicesOnTeam

Queries for a list devices on the team.

```policy
action query_devices_on_team() {
    map Devices[device_id:?] as f {
        publish QueryDevicesOnTeam { device_id: f.device_id }
    }
}

effect QueryDevicesOnTeamResult {
    device_id id,
}

command QueryDevicesOnTeam {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueryDevicesOnTeamResult {
                device_id: this.device_id,
            }
        }
    }
}
```

**Invariants**:

- The `Owner` device is automatically added to the team when the team is created.
- The rest of the devices listed have been added via the `AddMember` command.
- Devices in the list have not been removed from the team via a `RemoveMember` command.

### QueryDeviceKeyBundle

Queries device KeyBundle.

```policy

// Returns the device's key bundle.
function get_device_keybundle(device_id id) struct KeyBundle {
    let ident_key = check_unwrap query DeviceIdentKey[device_id: device_id]
    let sign_key = check_unwrap query DeviceSignKey[device_id: device_id]
    let enc_key = check_unwrap query DeviceEncKey[device_id: device_id]

    return KeyBundle {
        ident_key: ident_key.key,
        sign_key: sign_key.key,
        enc_key: enc_key.key,
    }
}

action query_device_keybundle(device_id id) {
    publish QueryDeviceKeyBundle {
        device_id: device_id,
    }
}

effect QueryDeviceKeyBundleResult {
    device_keys struct KeyBundle,
}

command QueryDeviceKeyBundle {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Check that the team is active and return the author's info if they exist in the team.
        let author = get_valid_device(this.device_id)
        let device_keys = get_device_keybundle(author.device_id)

        finish {
            emit QueryDeviceKeyBundleResult {
                device_keys: device_keys,
            }
        }
    }
}
```

**Invariants**:

- The owner will have a key bundle associated with it after creating the team.
- Each device that has been added to the team will have a key bundle associated with it.

### QueryAqcNetIdentifier

Queries AQC network identifier.

```policy

// Returns the device's AQC network identifier.
function get_aqc_net_identifier(device_id id) string {
    let net_identifier = check_unwrap query AqcMemberNetworkId[device_id: device_id]

    return net_identifier.net_identifier
}

action query_aqc_net_identifier(device_id id) {
    publish QueryAqcNetIdentifier {
        device_id: device_id,
    }
}

effect QueryAqcNetIdentifierResult {
    net_identifier string,
}

command QueryAqcNetIdentifier {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Check that the team is active and return the author's info if they exist in the team.
        let author = get_valid_device(this.device_id)
        let net_identifier = get_aqc_net_identifier(author.device_id)

        finish {
            emit QueryAqcNetIdentifierResult {
                net_identifier: net_identifier,
            }
        }
    }
}
```

**Invariants**:

- For a net identifier to be returned, it must have been created with the `SetAqcNetworkName` command.
- If `UnsetAqcNetworkName` has been invoked for the device, no network identifier will be returned.

### QueryTeamRoles

Queries a list of roles on the team.

```policy
// Emits `QueriedRole` for all roles.
action query_roles_on_team() {
    map Roles[role_id: ?] as f {
        publish QueryRole {
            role_id: f.role.role_id,
            role_name: f.role.name,
            role_author_id: f.role.author_id,
        }
    }
}

command QueryRole {
    fields {
        role_id id,
        role_name string,
        role_author_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let role = Role {
            role_id: this.role_id,
            name: this.role_name,
            author_id: this.role_author_id,
        }

        finish {
            emit QueriedRole {
                role: role,
            }
        }
    }
}

effect QueriedRole {
    role struct Role
}
```

## QueryAqcNetworkNames

Queries all associated AQC network names from the fact database.

```policy
action query_aqc_network_names() {
    map AqcMemberNetworkId[device_id: ?] as f {
        publish QueryAqcNetworkNamesCommand {
            net_identifier: f.net_identifier,
            device_id: f.device_id,
        }
    }
}

command QueryAqcNetworkNamesCommand {
    fields {
        net_identifier string,
        device_id id,
    }
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }
    policy {
        finish {
            emit QueryAqcNetworkNamesOutput {
                net_identifier: this.net_identifier,
                device_id: this.device_id,
            }
        }
    }
}

effect QueryAqcNetworkNamesOutput {
    net_identifier string,
    device_id id,
}
```

**Invariants**:

- A device's net identifier will only be returned if it was created by `SetAqcNetworkName` and
 wasn't yet removed by `UnsetAqcNetworkName`.

### QueryDeviceRoles

Queries a list of roles assigned to the device.

```policy
// Emits `QueriedRole` for all roles the device has
// been granted permission to use.
action query_device_roles(device_id id) {
    // TODO: make this query more efficient when policy supports it.
    // The key order is optimized for `delete AssignedRole`.
    map AssignedRole[role_id: ?, device_id: ?] as f {
        if f.device_id == device_id {
            let role = check_unwrap query Roles[role_id: f.role_id]
            publish QueryRoleAssignment {
                device_id: f.device_id,
                role_id: role.role_id,
                role_name: role.role.name,
                role_author_id: role.role.author_id,
            }
        }
    }
}

command QueryRoleAssignment {
    fields {
        device_id id,
        role_id id,
        role_name string,
        role_author_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let role = Role {
            role_id: this.role_id,
            name: this.role_name,
            author_id: this.role_author_id,
        }

        finish {
            emit QueriedRole {
                role: role,
            }
        }
    }
}
```

### QueryRolePermissions

Queries a list of permissions assigned to the role.

```policy
// Emits `QueriedRolePermision` for all permissions the role has
// been granted permission to use.
action query_role_perms(role_id id) {
    map PermRole[perm: ?] as f {
        if f.role_id == role_id {
            let role = check_unwrap query Roles[role_id: f.role_id]
            publish QueryRolePermissions {
                role_id: role.role_id,
                role_name: role.role.name,
                perm: f.perm,
                author_id: role.role.author_id,
            }
        }
    }
}

command QueryRolePermissions {
    fields {
        role_id id,
        role_name string,
        perm string,
        author_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueriedRolePermission {
                role_id: this.role_id,
                name: this.role_name,
                perm: this.perm,
                author_id: this.author_id,
            }
        }
    }
}

effect QueriedRolePermission {
    // The role's unique ID.
    role_id id,
    // The role name.
    name string,
    // The role permission.
    perm string,
    // The ID of the device that created the role.
    author_id id,
}
```
