---
policy-version: 2
---

# Overview

This Aranya's default policy. It provides the rules that underly
Aranya's core functionality. TODO: expand

As a reminder, Aranya policy files use the [literate
programming][lp] paradigm, so this document is both
a specification and source code. Code blocks are interpreted by
the policy compiler as policy source code. For more information
see Aranya's [policy language documentation][policy-lang].

# Policy

## Imports

```policy
use aqc
use crypto
use device
use envelope
use idam
use perspective
```

- `aqc`: AQC functionality, such as creating channels.
- `crypto`: core cryptographic functionality, like command
  signing and verification.
- `device`: provides information about the current device.
- `envelope`: provides access to the special
  [`Envelope`][envelope] type.
- `idam`: IDAM functionality, such access to device keys.
- `perspective`: provides information about the current
  perspective.

## Policy Basics

An [_action_][actions] is a function that is callable from the
application. Actions can perform data transformations and publish
zero or more _commands_ to the graph. Actions generally require
certain RBAC permissions; see the RBAC section for more
information.

An [_effect_][effects] is a special type of struct that sends
data back to the application and can be thought of as the
_output_ of an action.

A [_fact_][facts] is structured data derived from a _command_.
Facts are stored in a _fact database_, which the policy consults
when making enforcement decisions.

A [_command_][commands] is a signed data structure that devices
publish to the graph. Commands are signed with the device's
Signing Key.

### API Stability and Backward Compatibility

Actions and effects are part of a policy's public API.
Facts and commands are *not* part of a policy's public API.

## Base Cryptography

All commands (except for `CreateTeam`) are signed and verified
with the following routes.

```policy
// Signs the payload using the current device's Device Signing
// Key, then packages the data and signature into an `Envelope`.
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

// Opens an envelope using the author's public Device Signing
// Key.
//
// If verification succeeds, it returns the serialized basic
// command data. Otherwise, if verification fails, it raises
// a check error.
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

## Devices and Identity

An identity in Aranya is called a _device_. Each device has
a globally unique ID, called the _device ID_.

```policy
fact Device[device_id id]=>{sign_key_id id, enc_key_id id}
```

### Device Keys

A device has three key pairs, called the _device keys_. Each key
pair has a globally unique ID derived from the public half of the
pair.

#### Device Identity Key

The Device Identity Key is a signing key that identifies the
device. Devices use this key to sign administrative actions, like
rotating their other device keys.

A device's ID is derived from the public half of the Device
Identity Key.

```policy
// Records a the public half of a device's Identity Key.
fact DeviceIdentKey[device_id id]=>{key bytes}
```

#### Device Signing Key

The Device Signing Key is a signing key used to sign commands
that the device publishes to the graph.

```policy
// Records the public half of the device's Signing Key.
fact DeviceSignKey[device_id id]=>{key_id id, key bytes}
```

#### Device Encryption Key

The Device Encryption Key is a KEM key used to securely send
encapsulated secret keys to other devices. It is primarily used
by AQC.

```policy
// Records the public half of the device's Encryption Key.
fact DeviceEncKey[device_id id]=>{key_id id, key bytes}
```

### Device Functions

```policy
// Returns a device if one exists, or `None` otherwise.
function try_find_device(device_id id) optional struct Device {
    let device = query Device[device_id: device_id]
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
    return device
}

// Returns a valid Device after performing sanity checks per the
// stated invariants.
function must_find_device(device_id id) struct Device {
    let device = check_unwrap try_find_device(device_id)
    return device
}

// Collection of public Device Keys for A device.
struct KeyBundle {
    ident_key bytes,
    sign_key bytes,
    enc_key bytes,
}

// Returns the device's key bundle.
function must_find_device_keybundle(device_id id) struct KeyBundle {
    let ident_key = check_unwrap query DeviceIdentKey[device_id: device_id]
    let sign_key = check_unwrap query DeviceSignKey[device_id: device_id]
    let enc_key = check_unwrap query DeviceEncKey[device_id: device_id]

    return KeyBundle {
        ident_key: ident_key.key,
        sign_key: sign_key.key,
        enc_key: enc_key.key,
    }
}

// The set of key IDs derived from each Device Key.
// NB: Key ID of the Identity Key is the device ID.
struct KeyIds {
    device_id id,
    sign_key_id id,
    enc_key_id id,
}

// Derives the unique ID for each Device Key in the bundle.
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
```

### Device Queries

#### Query Devices On Team

Queries for a list devices on the team.

```policy
action query_devices_on_team() {
    map Device[device_id:?] as f {
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

#### Query Device Roles

Queries the roles assigned to a device.

```policy
action query_device_roles(device_id id) {
    map AssignedRole[device_id: id, role_id: ?] as f {
        publish QueryDeviceRoles {
            device_id: f.device_id,
            role_id: f.role_id,
        }
    }
}

effect QueryDeviceRolesResult {
    // The role's ID.
    role_id id,
    // The role's name.
    name string,
    // The ID of the device that created the role.
    author_id id,
}

command QueryDeviceRoles {
    fields {
        device_id id,
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = must_find_device(this.device_id)
        let role = check_unwrap query Role[role_id: this.role_id]

        finish {
            emit QueryDeviceRolesResult {
                role_id: role.role_id,
                name: role.name,
                author_id: author.device_id,
            }
        }
    }
}
```

### Query Device Key Bundle

Queries device's `KeyBundle`.

```policy
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
        let author = must_find_device(this.device_id)
        let device_keys = must_find_device_keybundle(author.device_id)

        finish {
            emit QueryDeviceKeyBundleResult {
                device_keys: device_keys,
            }
        }
    }
}
```

## Roles and Permissions

### Overview

Aranya uses [Role-Based Access Control][rbac] (RBAC) for system
authorization. Devices are only authorized to access certain
resources if they have been assigned the requisite role. Aranya
primarily uses RBAC to strict which commands devices are
authorized to publish, but custom policy can use roles for many
other purposes.

Conceptually, a role is a `(role_id, name, author_id)` tuple
where

- `role_id` is a globally unique ID for the role,
  cryptographically derived from the command that created the
  role.
- `name` is a human-readable name for the role. E.g., `admin` or
  `operator`.
- `author_id` is the globally unique ID of the device that
  created the role.

```policy
// An RBAC role.
fact Role[role_id id]=>{name string, author_id id}
```

Generating a role's ID from its originating command prevents
devices from accidentally creating the same role on diverging
branches, which could cause a fail-open security bug. See the
[design][aqc-label-design] of AQC labels for more information
about a similar situation.

```policy
// Returns the globally unique ID for a role created by the
// command in `evp`.
//
// NB: This function is deterministic and injective for the
// current policy. Calling it multiple times for the same
// envelope will always return the same ID.
function derive_role_id(evp struct Envelope) id {
    // The role ID is the ID of the command that created it.
    // TODO(eric): Or we could use H(cmd_id, ...).
    return envelope::command_id(evp)
}
```

Each role is managed by another role, called the _managing role_.
The manag**ing** role authorizes devices to assign and revoke the
manag**ed** role to and from **other** devices, respectively.

> **Note**: Upon team creation, the only role that exists is the
> `owner` role. Therefore, the `owner` role is managed by itself.
> It's roles all the way down.

### Role Scope

The _scope_ of a role is the aggregate set of resources that the
role authorizes devices to access. Resources themselves define
the role(s) that are required to access the resource. For
instance, each AQC label is associated with a "manager" role that
(among other things) authorizes devices to assign the label to
other devices. Devices with sufficient permissions can change
a role's scope; how this works depends on the resource.

#### Commands and Operations

Commands are a resource, but they are also an implementation
detail and not part of the policy's public API. Naively, this
would prevent devices from being able to change the role required
to publish a command.

To work around this, commands are not directly associated with
a role. Instead, commands are associated with one or more
_operations_, and each _operation_ is associated with a role.

```policy
// Records that a certain role is required to authorize a device
// to perform the operation.
fact OpRequiresRole[op string]=>{role_id id}

// Reports whether a device has permission to perform an
// operation.
function can_perform_op(device_id id, op string) bool {
    let op = query OpRequiresRole[op: op]
    if op is None {
        return false
    }
    let role_id = (unwrap op).role_id
    if !exists Role[role_id: role_id] {
        return false
    }
    return exists AssignedRole[device_id: device_id, role_id: role_id]
}

// Returns the `Device` corresponding with the author of the
// envelope iff the author is authorized to perform the operation.
//
// Otherwise, it raises a check error.
function get_authorized_device(evp struct Envelope, op string) struct Device {
    let device = must_find_device(envelope::author_id(evp))
    check can_perform_op(device.device_id, op)
    return device
}
```

Devices cannot change which operation that a command requires,
but they _can_ change which role is associated with the
operation.

```policy
// Updates (or creates) an operation -> role mapping.
action update_operation(op string, role_id id) {
    publish UpdateOperation {
        op: op,
        role_id: role_id,
    }
}

effect OperationUpdated {
    // The operation that was updated.
    op string,
    // The ID of the role that is now required to perform the
    // operation.
    role_id id,
    // The ID of the device that updated the operation.
    author_id id,
}

command UpdateOperation {
    fields {
        // The operation that is being updated.
        op string,
        // The ID of the role that is now required to perform the
        // operation.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "UpdateOperation")

        // The role must exist.
        let role = check_unwrap query Role[role_id: this.role_id]

        if exists OpRequiresRole[op: this.op] {
            // The operation already exists, so update the role.
            finish {
                update OpRequiresRole[op: this.op]=>{role_id: role.role_id} to {
                    role_id: role.role_id,
                }

                emit OperationUpdated {
                    op: this.op,
                    role_id: role.role_id,
                    author_id: author.device_id,
                }
            }
        } else {
            // Create a new operation -> role mapping.
            finish {
                create OpRequiresRole[op: this.op]=>{role_id: role.role_id}

                emit OperationUpdated {
                    op: this.op,
                    role_id: role.role_id,
                    author_id: author.device_id,
                }
            }
        }
    }
}
```

### Role Management

As previously mentioned, each role is managed by another role,
called the _managing role_. Devices that have been assigned the
managing role are allowed to assign the managed role to *any*
other device as well as revoke the managed role from *any* other
device. Devices are prohibited from assigning roles to or
revoking roles from themselves.

```policy
// Records that a particular role is required in order to assign
// the role to or revoke the role from *other* devices.
//
// Devices with the managing role are allowed to assign the role
// to any *other* device. Devices cannot assign the role to
// or revoke the role from themselves.
fact CanManageRole[target_role_id id]=>{managing_role_id id}

// Reports whether the device can manage the specified role.
function can_manage_role(device_id id, target_role_id id) bool {
    let managing_role = query CanManageRole[target_role_id: target_role_id]
    if managing_role is None {
        return false
    }
    let role_id = (unwrap managing_role).managing_role_id
    return exists AssignedRole[device_id: device_id, role_id: role_id]
}
```

### Role Creation

Upon creation, a team only has one role: the `owner` role,
assigned to the team owner. Afterward, the owner can create
additional roles as needed.

Devices are notified about new roles via the `RoleCreated`
effect.

```policy
// Emitted when a role is created.
effect RoleCreated {
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // ID of device that created the role.
    author_id id,
    // ID of the role that manages this role.
    managing_role_id id,
}
```

#### Custom Roles

> **Note**: Custom roles are under development and will be
> generally available after MVP.

#### Default Roles

The `setup_default_roles` action creates the following 'default'
roles:

- `admin`
    - Can assign and revoke the `operator` role.
    - Can define and undefine AQC labels.
    - TODO
- `operator`
    - TODO
- `member`
    - Can create and delete AQC channels (for labels they have
      been granted permission to use).

```policy
// Setup default roles on a team.
action setup_default_roles() {
    publish SetupDefaultRole {
        name: "admin",
    }
    publish SetupDefaultRole {
        name: "operator",
    }
    publish SetupDefaultRole {
        name: "member",
    }
}

command SetupDefaultRole {
    fields {
        name string
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "SetupDefaultRole")
        let role_id = derive_role_id(envelope)

        match this.name {
            "admin" => {
                finish {
                    create Role[role_id: role_id]=>{name: this.name, author_id: author.device_id}

                    // TODO: operations

                    emit RoleCreated {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                    }
                }
            }
            "operator" => {
                finish {
                    create Role[role_id: role_id]=>{name: this.name, author_id: author.device_id}

                    // TODO: operations

                    emit RoleCreated {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                    }
                }
            }
            "member" => {
                finish {
                    create Role[role_id: role_id]=>{name: this.name, author_id: author.device_id}

                    // TODO: operations

                    emit RoleCreated {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                    }
                }
            }
            // Invalid role name.
            _ => { check false }
        }
    }
}
```

### Role Deletion

TODO

### Role Assignment

A device can be assigned zero or more roles.

```policy
// Records that a device has been assigned a role.
fact AssignedRole[device_id id, role_id id]=>{}

// Reports whether the device has been assigned the role.
function has_role(device_id id, role_id id) bool {
    return exists AssignedRole[device_id: device_id, role_id: role_id]
}

// Assigns the specified role to the device.
action assign_role(device_id id, role_id id) {
    publish AssignRole {
        device_id: device_id,
        role_id: role_id,
    }
}

// Emitted when a device is assigned a role.
effect RoleAssigned {
    // The ID of the device that was assigned a role.
    device_id id,
    // The ID of the role that was assigned.
    role_id id,
    // The ID of the device that assigned the role.
    author_id id,
}

command AssignRole {
    fields {
        // The ID of the device being assigned the role.
        device_id id,
        // The ID of the role being assigned to the device.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "AssignRole")

        // The author must have permission to assign the role.
        check can_manage_role(author.device_id, this.role_id)

        let target = must_find_device(this.device_id)

        // The role must exist.
        let role = check_unwrap query Role[role_id: this.role_id]

        finish {
            create AssignedRole[device_id: target.device_id, role_id: role.role_id]=>{}

            emit RoleAssigned {
                device_id: target.device_id,
                role_id: role.role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Revocation

```policy
// Revokes the specified role from the device.
action revoke_role(device_id id, role_id id) {
    publish RevokeRole {
        device_id: device_id,
        role_id: role_id,
    }
}

// Emitted when a device has its role revoked.
effect RoleRevoked {
    // The ID of the device that had its role revoked.
    device_id id,
    // The ID of the role that was revoked.
    role_id id,
    // The ID of the device that revoked the role.
    author_id id,
}

command RevokeRole {
    fields {
        // The ID of the device having its role revoked.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "RevokeRole")

        // The author must have permission to revoke the role.
        check can_manage_role(author.device_id, this.role_id)

        let target = must_find_device(this.device_id)

        // The role must exist.
        let role = check_unwrap query Role[role_id: this.role_id]

        finish {
            delete AssignedRole[device_id: target.device_id, role_id: role.role_id]

            emit RoleRevoked {
                device_id: target.device_id,
                role_id: role.role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

## Teams

### Team Creation

Teams are the primary organizational unit in Aranya. Each graph
is associated with one team at a time.

```policy
// Indicates that `CreateTeam` has been published.
//
// At first glance this fact is seemingly redundant, since the ID
// of the `CreateTeam` command is the "graph ID," meaning without
// a `CreateTeam` command the graph cannot exist.
//
// However, this fact is required to ensure that we reject all
// subsequent `CreateTeam` commands.
fact TeamStart[]=>{team_id id}

// Reports whether the team exists.
//
// This should always be the first thing that is checked before
// executing a command on a team.
function team_exists() bool {
    // Check to see if team is active.
    return exists TeamStart[]=>{team_id: ?}
}
```

The initial command in the graph is the `CreateTeam` command,
which creates the `TeamStart` fact.

```policy
// Creates a Team.
action create_team(owner_keys struct KeyBundle, nonce bytes) {
    publish CreateTeam {
        owner_keys: owner_keys,
        nonce: nonce,
    }
}

// Emitted when a team is created.
effect TeamCreated {
    // The ID of the team.
    team_id id,
    // The ID of the device that owns the team.
    owner_id id,
}

command CreateTeam {
    fields {
        // The initial owner's public Device Keys.
        owner_keys struct KeyBundle,
        // Random nonce to enforce this team's uniqueness.
        nonce bytes,
    }

    // As the first command in the graph, the `CreateTeam`
    // command is sealed and opened differently than other
    // commands.
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
        check !team_exists()

        let author_id = envelope::author_id(envelope)

        let owner_key_ids = derive_device_key_ids(this.owner_keys)

        // The ID of a team is the ID of the command that created
        // it.
        let team_id = envelope::command_id(envelope)

        // The author must have signed the command with the same
        // device keys.
        check author_id == owner_key_ids.device_id

        // The ID of the 'owner' role.
        let owner_role_id = derive_role_id(envelope)

        finish {
            create TeamStart[]=>{team_id: team_id}

            add_new_device(this.owner_keys, owner_key_ids, owner_role_id)

            // Assign all the default operations to the owner
            // role.
            create OpRequiresRole[op: "AddDevice"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "RemoveDevice"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "AssignRole"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "RevokeRole"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "SetupDefaultRole"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "TerminateTeam"]=>{role_id: owner_role_id}

            emit TeamCreated {
                team_id: team_id,
                owner_id: author_id,
            }
        }
    }
}

// Adds the device to the Team.
// TODO: use `role_id`
finish function add_new_device(kb struct KeyBundle, keys struct KeyIds, role_id optional id) {
    create Device[device_id: keys.device_id]=>{
        sign_key_id: keys.sign_key_id,
        enc_key_id: keys.enc_key_id,
    }

    create DeviceIdentKey[device_id: keys.device_id]=>{
        key: kb.ident_key,
    }
    create DeviceSignKey[device_id: keys.device_id]=>{
        key_id: keys.sign_key_id,
        key: kb.sign_key,
    }
    create DeviceEncKey[device_id: keys.device_id]=>{
        key_id: keys.enc_key_id,
        key: kb.enc_key,
    }
}
```

### Team Termination

Teams can also be terminated with the `TerminateTeam` command.

```policy
// Terminates a Team.
action terminate_team() {
    publish TerminateTeam {}
}

effect TeamTerminated {
    // The ID of the team that was terminated.
    team_id id,
    // The ID of the device that terminated the team.
    owner_id id,
}

command TerminateTeam {
    fields {}

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "TerminateTeam")
        let team_id = check_unwrap query TeamStart[]=>{team_id: ?}

        finish {
            delete TeamStart[]=>{team_id: team_id}

            emit TeamTerminated {
                team_id: team_id,
                owner_id: author.device_id,
            }
        }
    }
}
```

### Adding Devices

```policy
// Adds a device  to the Team.
action add_device(device_keys struct KeyBundle, role_id optional id) {
    publish AddDevice {
        device_keys: device_keys,
    }
    if role_id is Some {
        publish AssignRole {
            device_id: device_keys.device_id,
            role_id: unwrap role_id,
        }
    }
}

// Emitted when a device is added to the team.
effect DeviceAdded {
    // The device's set of public Device Keys.
    device_keys struct KeyBundle,
}

command AddDevice {
    fields {
        // The new device's public Device Keys.
        device_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "AddDevice")

        // Derive the key IDs from the provided KeyBundle.
        let device_key_ids = derive_device_key_ids(this.device_keys)

        // The device must not already exist.
        check try_find_device(device_key_ids.device_id) is None

        finish {
            add_new_device(this.device_keys, device_key_ids, None)

            emit DeviceAdded {
                device_keys: this.device_keys,
            }
        }
    }
}
```

### Removing Devices

```policy
// Removes a device from the team.
action remove_device(device_id id) {
    publish RemoveDevice {
        device_id: device_id,
    }
}

// Emitted when a device is removed from the team.
effect DeviceRemoved {
    device_id id,
}

command RemoveDevice {
    fields {
        // The ID of the device being removed from the team.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "RemoveDevice")

        let target = must_find_device(this.device_id)

        // TODO: author dominates target?

        finish {
            remove_device(this.device_id)

            emit DeviceRemoved {
                device_id: this.device_id,
            }
        }
    }
}

// Removes the device from the Team.
finish function remove_device(device_id id) {
    delete Device[device_id: device_id]
    delete DeviceIdentKey[device_id: device_id]
    delete DeviceSignKey[device_id: device_id]
    delete DeviceEncKey[device_id: device_id]
}
```

## AQC

### Overview

[Aranya QUIC Channels][aqc] provide end-to-end encrypted,
topic-segmented communication between two devices in a team.

Channels are secured with TLS 1.3 using pre-shared keys (PSK)
derived from the participants' Device Encryption Keys using HPKE.

```policy
// Reports whether `size` is a valid PSK length (in bytes).
//
// Per the AQC specification, PSKs must be in the range [32, 2^16).
function is_valid_psk_length(size int) bool {
    return size >= 32 && size < 65536
}

// Returns the device's encoded public Encryption Key.
function get_enc_pk(device_id id) bytes {
    let device_enc_pk = check_unwrap query DeviceEncKey[device_id: device_id]
    return device_enc_pk.key
}
```

Channels are either bidirectional or unidirectional. In
a unidirectional channel one peer is permitted to send data and
the other to receive data.

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
```

### Labels

Labels provide AQC's topic segmentation. Devices can only
participate in a channel if they have been granted permission to
use the channel's label. Devices can be granted permission to use
an arbitrary number of labels.

```policy
// Records a label.
fact Label[label_id id]=>{name string, author_id id}
```

- `label_id` is a globally unique ID for the label,
  cryptographically derived from the command that created the
  label.
- `name` is a human-readable name for the label. E.g.,
  `telemetry`
- `author_id` is the globally unique ID of the device that
  created the label.

Generating a label's ID from its originating command prevents
devices from accidentally creating the same label on diverging
branches, which could cause a fail-open security bug. See the
[design][aqc-label-design] of AQC labels for more information.

```policy
// Returns the globally unique ID for a label created by the
// command in `evp`.
//
// NB: This function is deterministic and injective for the
// current policy. Calling it multiple times for the same
// envelope will always return the same ID.
function derive_label_id(evp struct Envelope) id {
    // The label ID is the ID of the command that created it.
    // TODO(eric): Or we could use H(cmd_id, ...).
    return envelope::command_id(evp)
}
```

Each label is managed by a role called the _managing role_. The
managing role authorizes devices to assign the label to and
revoke the label from **other** devices.

#### Label Management

As previously mentioned, each label is managed by a role, called
the label's _managing role_. Devices that have been assigned the
managing role are allowed to assign the label to *any* other
device as well as revoke the label from *any* other device.
Devices are prohibited from assigning labels to or revoking
labels from themselves.

```policy

// Records that a particular role is required in order to grant
// *other* devices permission to use the label.
//
// Devices with the role are allowed to grant any *other* device
// permission to use the label. Devices cannot grant themselves
// permission to use the label, even if they have the requisite
// role.
fact CanManageLabel[label_id id]=>{managing_role_id id}

// Reports whether the device can assign the label.
function can_manage_label(device_id id, label_id id) bool {
    let managing_role = query CanManageLabel[label_id: label_id]
    if managing_role is None {
        return false
    }
    let role_id = (unwrap managing_role).managing_role_id
    return exists AssignedRole[device_id: device_id, role_id: role_id]
}

// Changes the role required to grant *other* devices permission
// to use the label.
//
// Devices with the role are allowed to grant any *other* device
// permission to use the label. Devices cannot grant themselves
// permission to use the label, even if they have the requisite
// role.
action change_label_managing_role(label_id id, managing_role_id id) {
    publish ChangeLabelManagingRole {
        label_id: label_id,
        managing_role_id: managing_role_id,
    }
}

// Emitted when the `ChangeLabelManagingRole` command is
// successfully processed.
effect LabelUpdated {
    // Uniquely identifies the label.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
    // The ID of the role required to grant *other* devices
    // permission to use the label.
    managing_role_id id,
}

command ChangeLabelManagingRole {
    fields {
        // The label to update.
        label_id id,
        // The ID of the role required to grant *other* devices
        // permission to use the label.
        managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "ChangeLabelManagingRole")

        let label = check_unwrap query Label[label_id: this.label_id]

        // Only the author of the label is allowed to change the
        // managing role.
        check author.device_id == label.author_id

        let ctx = check_unwrap query CanManageLabel[label_id: label.label_id]
        let old_managing_role_id = ctx.managing_role_id

        // Make sure the role exists.
        let role = check_unwrap query Role[role_id: this.managing_role_id]
        let new_managing_role_id = this.managing_role_id

        finish {
            update CanManageLabel[label_id: label.label_id]=>{managing_role_id: old_managing_role_id} to {managing_role_id: new_managing_role_id}
            emit LabelUpdated {
                label_id: label.label_id,
                label_name: label.name,
                label_author_id: label.author_id,
                managing_role_id: new_managing_role_id,
            }
        }
    }
}
```

#### Label Creation

```policy
// Creates a label.
//
// - `name` is a short description of the label, like
//   "TELEMETRY".
// - `managing_role_id` specifies the ID of the role required to
//    grant other devices permission to use the label. Devices
//    are never allowed to assign labels to themselves.
action create_label(name string, managing_role_id id) {
    publish CreateLabel {
        label_name: name,
        managing_role_id: managing_role_id,
    }
}

// Emitted when the `CreateLabel` command is successfully
// processed.
effect LabelCreated {
    // Uniquely identifies the label.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
    // The ID of the role required to grant *other* devices
    // permission to use the label.
    managing_role_id id,
}

command CreateLabel {
    fields {
        // The label name.
        label_name string,
        // The ID of the role required to grant *other* devices
        // permission to use the label.
        managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "CreateLabel")

        // A label's ID is the ID of the command that created it.
        let label_id = derive_label_id(envelope)

        let role = check_unwrap query Role[role_id: this.managing_role_id]

        // Verify that the label does not already exist.
        //
        // This will happen in the `finish` block if we try to
        // create an already true label, but checking first
        // results in a nicer error (I think?).
        check !exists Label[label_id: label_id]

        finish {
            create Label[label_id: label_id]=>{name: this.label_name, author_id: author.device_id}
            create CanManageLabel[label_id: label_id]=>{managing_role_id: role.role_id}

            emit LabelCreated {
                label_id: label_id,
                label_name: this.label_name,
                label_author_id: author.device_id,
                managing_role_id: role.role_id,
            }
        }
    }
}
```

#### Label Deletion

Deleting a label revokes access from all devices who have been
granted permission to use it.

```policy
// Deletes a label.
action delete_label(label_id id) {
    publish DeleteLabel {
        label_id: label_id,
    }
}

// Emitted when the `DeleteLabel` command is successfully
// processed.
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

command DeleteLabel {
    fields {
        // The unique ID of the label being deleted.
        label_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_authorized_device(envelope, "DeleteLabel")

        // Verify that the label exists.
        //
        // This will happen in the `finish` block if we try to
        // create an already true label, but checking first
        // results in a nicer error (I think?).
        let label = check_unwrap query Label[label_id: this.label_id]

        // The author must have been granted permission to manage
        // this label.
        check can_manage_label(author.device_id, label.label_id)

        finish {
            // Cascade deleting the label assignments.
            delete AssignedLabel[label_id: label.label_id, device_id: ?]

            delete CanManageLabel[label_id: label.label_id]

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
```

#### Label Assignment

A device can be assigned zero or more labels.

```policy
// Records that a device was granted permission to use a label
// for certain channel operations.
fact AssignedLabel[label_id id, device_id id]=>{op enum ChanOp}
```

```policy
// Grants the device permission to use the label.
//
// - It is an error if the author does not have the role required
//   to assign this label.
// - It is an error if `device_id` refers to the author (devices
//   are never allowed to assign labels to themselves).
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

// Emitted when the `AssignLabel` command is successfully
// processed.
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

        let author = get_authorized_device(envelope, "AssignLabel")
        let target = must_find_device(this.device_id)

        // Devices are never allowed to assign labels to
        // themselves.
        //
        // Perform this check before we make more fact database
        // queries.
        check target.device_id != author.device_id

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // The author must have been granted permission to manage
        // this label.
        check can_manage_label(author.device_id, label.label_id)

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
```

#### Label Revocation

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

// Emitted when the `RevokeLabel` command is successfully
// processed.
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

        let author = get_authorized_device(envelope, "RevokeLabel")
        let target = must_find_device(this.device_id)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // The author must have been granted permission to manage
        // this label.
        check can_manage_label(author.device_id, label.label_id)

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
```

#### Label Queries

These queries publish ephemeral commands whose sole purpose is to
emit effects. It's a hack around defining a real query API in
policy, which is a post-MVP feature.

##### Query Label Exists

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

##### Query All Labels

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

##### Query Label Assignments

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

### Network IDs

Each device that wants to participate in an AQC channel must have
a _network identifier_.

```policy
// Stores a Member's associated network identifier for AQC.
fact AqcMemberNetworkId[device_id id]=>{net_identifier string}
```

```policy
action set_aqc_network_name(device_id id, net_identifier string) {
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

        let author = get_authorized_device(envelope, "SetAqcNetworkName")
        let device = must_find_device(this.device_id)

        let net_id = query AqcMemberNetworkId[device_id: this.device_id]

        if net_id is Some {
            let net_id = unwrap net_id
            finish {
                update AqcMemberNetworkId[device_id: this.device_id]=>{net_identifier: net_id.net_identifier} to {
                    net_identifier: this.net_identifier
                }

                emit AqcNetworkNameSet {
                    device_id: device.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        } else {
            finish {
                create AqcMemberNetworkId[device_id: this.device_id]=>{net_identifier: this.net_identifier}

                emit AqcNetworkNameSet {
                    device_id: device.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        }
    }
}
```

## UnsetAqcNetworkName

Dissociates an AQC network name and address from a device.

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

        let author = get_authorized_device(envelope, "UnsetAqcNetworkName")
        let device = must_find_device(this.device_id)

        check exists AqcMemberNetworkId[device_id: this.device_id]

        finish {
            delete AqcMemberNetworkId[device_id: this.device_id]

            emit AqcNetworkNameUnset {
                device_id: device.device_id,
            }
        }
    }
}
```

#### Query Network IDs

Queries all associated AQC network IDs from the fact database.

```policy
action query_aqc_network_names() {
    map AqcMemberNetworkId[device_id: ?] as f {
        publish QueryAqcNetworkNamesCommand {
            net_identifier: f.net_identifier,
            device_id: f.device_id,
        }
    }
}

effect QueryAqcNetworkNamesOutput {
    net_identifier string,
    device_id id,
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
```

### Bidirectional Channel Creation

Creates a bidirectional AQC channel for off-graph messaging.

```policy
action create_aqc_bidi_channel(peer_id id, label_id id) {
    let parent_cmd_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author = must_find_device(author_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let ch = aqc::create_bidi_channel(
        parent_cmd_id,
        author.enc_key_id,
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

// Returns the channel operation for a particular label.
function get_allowed_op(device_id id, label_id id) enum ChanOp {
    let assigned_label = check_unwrap query AssignedLabel[label_id: label_id, device_id: device_id]
    return assigned_label.op
}

// Emitted when the author of a bidirectional AQC channel
// successfully processes the `AqcCreateBidiChannel` command.
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

// Emitted when the peer of a bidirectional AQC channel
// successfully processes the `AqcCreateBidiChannel` command.
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
```

This is an ephemeral command, which means that it can only be
emitted within an ephemeral session so that it is not added to
the graph of commands. Furthermore, it cannot persist any changes
to the fact database.

```policy
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

        let author = get_authorized_device(envelope, "AqcCreateBidiChannel")
        let peer = must_find_device(this.peer_id)

        check is_valid_psk_length(this.psk_length_in_bytes)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // Check that both devices have been granted permission
        // to use the label for for send and recv.
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
                    author_id: author.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_id: peer.device_id,
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
                    author_id: author.device_id,
                    author_enc_pk: author_enc_pk,
                    peer_id: peer.device_id,
                    peer_enc_key_id: peer.enc_key_id,
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

### Unidirectional Channel Creation

Creates a unidirectional AQC channel for off-graph messaging.

```policy
action create_aqc_uni_channel(sender_id id, receiver_id id, label_id id) {
    let parent_cmd_id = perspective::head_id()
    let author = must_find_device(device::current_device_id())
    let peer_id = select_peer_id(author.device_id, sender_id, receiver_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let ch = aqc::create_uni_channel(
        parent_cmd_id,
        author.enc_key_id,
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

// Emitted when the author of a unidirectional AQC channel
// successfully processes the `AqcCreateUniChannel` command.
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

// Emitted when the peer of a unidirectional AQC channel
// successfully processes the `AqcCreateUniChannel` command.
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
```

This is an ephemeral command, which means that it can only be
emitted within an ephemeral session so that it is not added to
the graph of commands. Furthermore, it cannot persist any changes
to the fact database.

```policy
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

        let author = get_authorized_device(envelope, "AqcCreateUniChannel")

        // Ensure that the author is one of the channel
        // participants.
        check author.device_id == this.sender_id ||
              author.device_id == this.receiver_id

        let peer_id = if author.device_id == this.sender_id {
            :this.receiver_id
        } else {
            :this.sender_id
        }
        let peer = check_unwrap try_find_device(peer_id)

        check is_valid_psk_length(this.psk_length_in_bytes)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // Check that both devices have been granted permission
        // to use the label for their respective direcitons.
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
                    author_enc_key_id: author.enc_key_id,
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
                    peer_enc_key_id: peer.enc_key_id,
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

```policy
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

```policy
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
        let author = must_find_device(this.device_id)
        let net_identifier = get_aqc_net_identifier(author.device_id)

        finish {
            emit QueryAqcNetIdentifierResult {
                net_identifier: net_identifier,
            }
        }
    }
}
```

[envelope]: https://aranya-project.github.io/policy-language-v1/#envelope-type
[lp]: https://en.wikipedia.org/wiki/Literate_programming
[policy-lang]: https://aranya-project.github.io/policy-language-v2/
[actions]: https://aranya-project.github.io/policy-language-v1/#actions
[effects]: https://aranya-project.github.io/policy-language-v1/#effects
[commands]: https://aranya-project.github.io/policy-language-v1/#commands
[facts]: https://aranya-project.github.io/policy-language-v1/#facts
[rbac]: https://csrc.nist.gov/glossary/term/rbac
[aqc-label-design]: https://aranya-project.github.io/aranya-quic-channels/#label-design
[aqc]: https://aranya-project.github.io/aranya-quic-channels/
