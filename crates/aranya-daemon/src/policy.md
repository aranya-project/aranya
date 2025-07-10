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

<!-- Note for AI Tools: Code blocks marked with ```policy are
compiled as source code. Other code examples use indentation or
different markers to avoid compilation. -->

## Quick Reference

This policy implements a zero-trust RBAC system that controls
which commands devices can publish to Aranya's distributed graph:

- **Devices** are the primary identity, each with three
  cryptographic key pairs.
- **Teams** provide the organizational boundary, with exactly one
  team per graph.
- **Roles** control command publishing permissions: `owner`
  (emergency access), `admin` (system administration), `operator`
  (user management), and `member` (basic usage).
- **Authorization** uses two patterns: permission-based for most
  commands, and managing-role-based for role/label assignment.
- **Key Principle**: Devices cannot assign roles or labels to
  themselves, enforcing separation of duties.

# Policy

## What This Policy Controls

This policy defines:
- Which commands each device is authorized to publish to the graph
- How those commands transform into facts in the local database
- Validation rules that commands must pass before acceptance

This policy does NOT control:
- Network access or transport layer security
- How devices synchronize the graph (handled by Aranya core)
- Query authorization (queries read local derived state)

## Conventions

TODO: talk about why we try to avoid using `this.foo`.
TODO: talk about how `fields` are untrusted, attacker-controlled
inputs

## Imports

```policy
use aqc
use crypto
use device
use envelope
use idam
use perspective
```

- [`aqc`][aqc-ffi]: [AQC][aqc] functionality, such as creating
  channels.
- [`crypto`][crypto-ffi]: core cryptographic functionality, like
  command signing and verification.
- [`device`][device-ffi]: provides information about the current
  device.
- [`envelope`][evp-ffi]: provides access to the special
  [`Envelope`][envelope] type.
- [`idam`][idam-ffi]: IDAM functionality, such access to device
  keys.
- [`perspective`][perspective-ffi]: provides information about
  the current perspective.

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
when making enforcement decisions. Since the graph is a CRDT, all
devices eventually have identical fact databases.

A [_command_][commands] is a signed data structure that devices
publish to the graph. Commands are signed with the device's
Signing Key. The policy controls which commands each device is
authorized to publish.

### API Stability and Backward Compatibility

Actions and effects are part of a policy's public API.
Facts and commands are *not* part of a policy's public API.

### Fact Schema Constraints

Fact definitions enforce uniqueness constraints through their key
structure:

- **Single-key facts** (e.g., `Fact[a id]`) allow
  exactly one fact per key value.
- **Composite-key facts** (e.g., `Fact[a id, b id]`)
  allow exactly one fact per key combination.
- **Empty-key facts** (e.g., `TeamStart[]`) allow exactly one
  instance, implementing a singleton pattern.

These constraints are enforced at the storage layer - `create`
operations fail if a fact already exists with the same key, and
`delete` operations fail if the fact doesn't exist.

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
<!-- Section contains: Device facts, key management, device queries -->

An identity in Aranya is called a _device_. Each device has
a globally unique ID, called the _device ID_.

```policy
// Records the existence of a device.
// TODO(eric): We store the key IDs in the key facts themselves,
// do we want to continue storing key IDs here?
// Fact type: Single-key (one per device)
fact Device[device_id id]=>{sign_key_id id, enc_key_id id}

// Reports whether the invariants for the device are being upheld.
function valid_device_invariants(device_id id) bool {
    let device = query Device[device_id: device_id]
    if device is None {
        // The device does not exist, so there should not be any
        // signing keys for it either.
        check !exists DeviceIdentKey[device_id: device_id]
        check !exists DeviceSignKey[device_id: device_id]
        check !exists DeviceEncKey[device_id: device_id]
    } else {
        // The device DOES exist, so the device keys MUST also
        // exist and match the key IDs in `Device`.
        let dev = unwrap device

        let ident_key_fact = unwrap query DeviceIdentKey[device_id: device_id]
        check device_id == idam::derive_device_id(ident_key_fact.key)

        let sign_key_fact = unwrap query DeviceSignKey[device_id: device_id]
        check dev.sign_key_id == idam::derive_sign_key_id(sign_key_fact.key)
        check sign_key_fact.key_id == dev.sign_key_id

        let enc_key_fact = unwrap query DeviceEncKey[device_id: device_id]
        check dev.enc_key_id == idam::derive_enc_key_id(enc_key_fact.key)
        check enc_key_fact.key_id == dev.enc_key_id
    }

    // NB: Since this function uses `check` internally, it
    // doesn't need a return type. But policy v2 `function`s
    // *must* have a return type, so we return `true` here.
    //
    // We could use early returns to make this function have
    // a meaningful result, but that would obscure which
    // invariant was violated. We would only know that
    // `valid_device_invariants` failed, not that (for example)
    // `check ident_key_id == device_id` failed.
    return true
}
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
    // This function is a little too expensive to call every
    // time we need to get a device, so only uncomment this when
    // debugging/developing.
    //
    // In the future we'll be able to catch these invariant
    // violations in a more efficient manner. For example, the
    // policy compiler will be able to check for invariants like
    // "If fact A exists then so should fact B", internal
    // consistency checks (at the storage layer?) will be able
    // to check for corrupted records, etc.
    //
    // check valid_device_invariants(device_id)

    return query Device[device_id: device_id]
}

// Returns a device if it exist, or raises a check error
// otherwise.
function get_device(device_id id) struct Device {
    return check_unwrap try_find_device(device_id)
}

// Returns the device corresponding with the author of the
// envelope.
function get_author(evp struct Envelope) struct Device {
    return get_device(envelope::author_id(evp))
}

// Collection of public Device Keys for a device.
struct KeyBundle {
    ident_key bytes,
    sign_key bytes,
    enc_key bytes,
}

// Returns the device's key bundle.
//
// # Caveats
//
// This function does not directly check whether the device
// exists. However, it would be a very significant invariant
// violation if a device's key existed without the device also
// existing. See `valid_device_invariants`.
function get_device_keybundle(device_id id) struct KeyBundle {
    // This function is a little too expensive to call every
    // time we need to get a device, so only uncomment this when
    // debugging/developing.
    //
    // See the comment in `try_find_device`.
    //
    // check valid_device_invariants(device_id)

    let ident_key = check_unwrap query DeviceIdentKey[device_id: device_id]
    let sign_key = check_unwrap query DeviceSignKey[device_id: device_id]
    let enc_key = check_unwrap query DeviceEncKey[device_id: device_id]

    return KeyBundle {
        ident_key: ident_key.key,
        sign_key: sign_key.key,
        enc_key: enc_key.key,
    }
}

// The unique IDs for each Device Key.
struct DevKeyIds {
    // Uniquely identifies the Device Identity Key.
    device_id id,
    // Uniquely identifies the Device Signing Key.
    sign_key_id id,
    // Uniquely identifies the Device Encryption Key.
    enc_key_id id,
}

// Derives the unique ID for each Device Key in the bundle.
function derive_device_key_ids(device_keys struct KeyBundle) struct DevKeyIds {
    let device_id = idam::derive_device_id(device_keys.ident_key)
    let sign_key_id = idam::derive_sign_key_id(device_keys.sign_key)
    let enc_key_id = idam::derive_enc_key_id(device_keys.enc_key)

    return DevKeyIds {
        device_id: device_id,
        sign_key_id: sign_key_id,
        enc_key_id: enc_key_id,
    }
}
```

### Device Queries

Device queries retrieve information about devices on the team.

See [Query APIs][query-apis] for more information about the query
APIs.

#### Query Devices On Team

Queries for a list devices on the team.

```policy
// Emits `QueryDevicesOnTeamResult` for each device on the team.
action query_devices_on_team() {
    // Publishing `QueryDevicesOnTeam` emits
    // `QueryDevicesOnTeamResult`.
    map Device[device_id: ?] as f {
        publish QueryDevicesOnTeam {
            device_id: f.device_id
        }
    }
}

// Emitted when a device is queried by `query_devices_on_team`.
effect QueryDevicesOnTeamResult {
    // The ID of a device on the team.
    device_id id,
}

// A trampoline that forwards `device_id` to the effect.
command QueryDevicesOnTeam {
    fields {
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is an local query API.
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

#### Query Device Role

Queries the role assigned to a device.

```policy
// Emits `QueryDeviceRoleResult` for each role assigned to the
// device.
action query_device_role(device_id id) {
    publish QueryDeviceRole {
        device_id: device_id,
    }
}

// Emitted when a device's roles are queried by
// `query_device_roles`.
effect QueryDeviceRoleResult {
    // The role's ID.
    role_id id,
    // The role's name.
    name string,
    // The ID of the device that created the role.
    author_id id,
    // Is this a default role?
    default bool,
}

command QueryDeviceRole {
    fields {
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is an local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let device = get_device(this.device_id)
        let assigned_role = get_assigned_role(device.device_id)

        finish {
            emit QueryDeviceRolesResult {
                role_id: role.role_id,
                name: role.name,
                author_id: role.author_id,
                default: role.default,
            }
        }
    }
}
```

### Query Device Key Bundle

Queries device's `KeyBundle`.

```policy
// Emits `QueryDeviceKeyBundleResult` with the device's key
// bundle.
action query_device_keybundle(device_id id) {
    publish QueryDeviceKeyBundle {
        device_id: device_id,
    }
}

// Emitted when a device's key bundle is queried by
// `query_device_keybundle`.
effect QueryDeviceKeyBundleResult {
    // NB: We don't include the device ID here since the caller
    // of the action should already know it.
    device_keys struct KeyBundle,
}

command QueryDeviceKeyBundle {
    fields {
        // The device whose key bundle is being queried.
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is an local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // NB: A device's keys exist iff `fact Device` exists, so
        // we don't need to use `get_device` or anything
        // like that.
        let device_keys = get_device_keybundle(this.device_id)

        finish {
            emit QueryDeviceKeyBundleResult {
                device_keys: device_keys,
            }
        }
    }
}
```

## Roles and Permissions
<!-- Section contains: Role facts, permissions, assignment/revocation, default roles -->

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
fact Role[role_id id]=>{name string, author_id id, default bool}
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
// SECURITY INVARIANT: Prevents cross-branch permission confusion.
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

### Role Permissions

TODO: prose

```policy
// Records a permission granted by the role.
//
// # Caveats
//
// We do not yet support prefix deletion, so this fact is NOT
// deleted when a role is deleted. Use `role_has_perm` to verify
// whether a role grants a permission and use `device_has_perm`
// to verify whether a device has a permission.
fact RoleHasPerm[role_id id, perm string]=>{}

// Reports whether the role has the specified permission.
//
// # Errors
//
// It raises a check failure if the role does not exist or if the
// permission is invalid.
function role_has_perm(role_id id, perm string) bool {
    check exists Role[role_id: role_id]
    check is_valid_perm(perm)

    return exists RoleHasPerm[role_id: role_id, perm: perm]
}

// Reports whether the permission is valid.
function is_valid_perm(perm string) {
    match perm {
        "AddDevice" => { return true }
        "RemoveDevice" => { return true }

        "AssignRole" => { return true }
        "RevokeRole" => { return true }

        "CreateLabel" => { return true }
        "DeleteLabel" => { return true }
        "ChangeLabelManagingRole" => { return true }

        "AssignLabel" => { return true }
        "RevokeLabel" => { return true }

        "SetAqcNetworkName" => { return true }
        "UnsetAqcNetworkName" => { return true }

        "CreateAqcUniChannel" => { return true }
        "CreateAqcBidiChannel" => { return true }

        "TerminateTeam" => { return true }

        _ => { return false }
    }
}

// Reports whether the device has the specified permission.
//
// # Errors
//
// It raises a check failure if the permission is invalid.
//
// # Caveats
//
// This function does NOT check whether the device exists.
function device_has_perm(device_id id, perm string) bool {
    // TODO(eric): Decide whether to keep this.
    check exists Device[device_id: device_id]

    check is_valid_perm(perm)

    let role = check_unwrap query AssignedRole[device_id: device_id]
    return role_has_perm(f.role_id, perm)
}

// Adds a permission to the role.
action add_perm_to_role(role_id id, perm string) {
    publish AddPermToRole {
        role_id: role_id,
        perm: perm,
    }
}

// Emitted when a permission is added to a role.
effect PermAddedToRole {
    // The role that was updated.
    role_id id,
    // The permission that was added to the role.
    perm string,
    // The device that added the permission to the role.
    author_id id,
}

command AddPermToRole {
    fields {
        // The ID of the role to which the permission is being
        // added.
        role_id id,
        // The permission being added.
        perm string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // TODO(eric): We have to make sure that the author is
        // allowed to
        // 1. update this role
        // 2. add this *permission* to this role
        let author = get_author(envelope)

        // The permission must be valid.
        check is_valid_perm(this.perm)

        // The role must not already have the permission.
        //
        // TODO(eric): Should this case be a no-op or an error?
        check !role_has_perm(role.role_id, this.perm)

        finish {
            create RoleHasPerm[role_id: this.role_id, perm: this.perm]=>{}

            emit PermAddedToRole {
                role_id: this.role_id,
                perm: this.perm,
                author_id: author.device_id,
            }
        }
    }
}

// Removes the permission from the role.
action remove_perm_from_role(role_id id, perm string) {
    publish RemovePermFromRole {
        role_id: role_id,
        perm: perm,
    }
}

// Emitted when a permission is removed from a role.
effect PermRemovedFromRole {
    // The role from which the permission was removed.
    role_id id,
    // The permission that was removed from the role.
    perm string,
    // The device that removed the permission from the role.
    author_id id,
}

command RemovePermFromRole {
    fields {
        // The ID of the role from which the permission is being
        // removed.
        role_id id,
        // The permission being removed.
        perm string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)

        // The permission must be valid.
        check is_valid_perm(this.perm)

        // Removing a permission does not *escalate* privilege,
        // so unlike `AddPermToRole` we only need to check that
        // the author is allowed to update the role.
        check can_manage_role(author.device_id, this.role_id)

        // TODO(eric): Should this case be a no-op or an error?
        check role_has_perm(role.role_id, this.perm)

        finish {
            delete RoleHasPerm[role_id: this.role_id, perm: this.perm]

            effect PermRemovedFromRole {
                role_id: this.role_id,
                perm: this.perm,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Management

As previously mentioned, each role is "managed" by zero or more
other roles, called the _managing roles_. A device that has been
assigned one of the managing roles is allowed to do some or all
of the following:

- Assign the role to *any* device, except itself
- Revoke the role from *any* device
- Add a permission to the role (so long as the device is allowed
  to add that permission)
- Remove *any* permission from the role

```policy
// Grants devices who have been assigned the managing role
// permission to "manage" the target role.
fact CanManageRole[target_role_id id, managing_role_id id]=>{}

// Reports whether the device is allowed to manage the role.
//
// # Errors
//
// This function raises a check error if the device has not been
// assigned a role.
//
// # Caveats
//
// - This function does NOT check whether the device exists.
// - This function does NOT check whether the role exists.
function can_manage_role(device_id id, role_id id) bool {
    let device_role_id = check_unwrap get_assigned_role_id(device_id)

    // At this point we believe the following to be true:
    //
    // - `device_role_id` refers to a role that exists
    // - `device_role_id` refers to the role assigned to
    //   `device_id`
    //
    // We do NOT know whether `device_id` refers to a device
    // that exists.
    //
    // We do NOT know whether `role_id` refers to a role that
    // exists.
    return exists CanManageRole[
        target_role_id: target_role_id,
        managing_role_id: device_role_id,
    ]
}

// Changes the role required to manage the specified role.
//
// Devices with the managing role are allowed to assign the role
// to any *other* device. Devices cannot assign the role to
// or revoke the role from themselves.
//
// TODO(eric): Should we also take the old managing role as an
// argument?
action change_role_managing_role(
    target_role_id id,
    new_managing_role_id id,
) {
    publish ChangeRoleManagingRole {
        target_role_id: target_role_id,
        new_managing_role_id: new_managing_role_id,
    }
}

// Emitted when the `ChangeRoleManagingRole` command is
// successfully processed.
effect RoleManagingRoleChanged {
    // The ID of the role whose managing role was changed.
    target_role_id id,
    // The ID of the old managing role.
    old_managing_role_id id,
    // The ID of the new managing role.
    new_managing_role_id id,
    // The ID of the device that changed the managing role.
    author_id id,
}

command ChangeRoleManagingRole {
    fields {
        // The ID of the role whose managing role is being
        // changed.
        target_role_id id,
        // The ID of the new managing role.
        new_managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Devices are authorized to change a role's managing role
        // iff they have been assigned the managing role for the
        // role whose managing role is being changed (send help).
        // This negates the need for a "ChangeRoleManagingRole"
        // permission.
        //
        // TODO(eric): Is this analysis correct?
        let author = get_author(envelope)

        // The target role must exist.
        let target_role = check_unwrap query Role[role_id: this.target_role_id]

        // The new managing role must exist.
        let managing_role = check_unwrap query Role[role_id: this.new_managing_role_id]
        let new_managing_role_id = managing_role.role_id

        // The author must have permission to change the managing
        // role (which implies the old managing role must exist).
        let old_managing_role_id = check_unwrap get_managing_role_id(
            author.device_id,
            this.target_role_id,
        )

        finish {
            update CanManageRole[target_role_id: target_role.role_id]=>{
                managing_role_id: old_managing_role_id
            } to {
                managing_role_id: new_managing_role_id,
            }

            emit RoleManagingRoleChanged {
                target_role_id: target_role.role_id,
                old_managing_role_id: old_managing_role_id,
                new_managing_role_id: new_managing_role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Creation

Upon creation, a team only has one role: the `owner` role,
assigned to the team owner. Afterward, the owner can create
additional roles as needed.

Devices are notified about new roles via the `RoleCreated`
effect.

```policy
// The input to `create_default_role` since the policy language
// has neither named args nor good IDE support.
struct DefaultRole {
    // The ID of the role.
    role_id id,
    // The name of the role.
    name string,
    // The ID of the device that created the role.
    author_id id,
    // The ID of the role that manages this role.
    managing_role_id id,
}

// Creates the `Role` and `CanManageRole` facts for a default
// role.
finish function create_default_role(role struct DefaultRole) {
    // TODO(eric): check invariants like `managing_role_id` must
    // exist, author must exist, etc?

    create Role[role_id: role.role_id]=>{
        name: role.name,
        author_id: role.author_id,
        default: true,
    }
    create CanManageRole[target_role_id: role.role_id]=>{
        managing_role_id: role.managing_role_id,
    }
}

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
    // Is this a "default" role?
    default bool,
}
```

#### Custom Roles

> **Note**: Custom roles are under development and will be
> generally available after MVP.

#### Default Roles

The `setup_default_roles` action creates exactly three default
roles with fixed names. These names are enforced by the policy -
any attempt to create a default role with a different name will
fail.

- `admin`
    - Can create and delete AQC labels
    - Can change label managing roles
    - Can unset AQC network names
    - Typically manages the `operator` role
- `operator`
    - Can assign and revoke AQC labels
    - Can set and unset AQC network names
    - Typically manages the `member` role
- `member`
    - Can create and delete AQC channels (for labels they have
      been granted permission to use)

**Important**: The owner role (created during team creation) should
be used sparingly. After setting up default roles, the owner
credentials should be stored securely (e.g., in an HSM) and only
used for emergency "break glass" scenarios.

```policy
// TODO: create these?
fact RoleOwner[role_id id]=>{author_id id}
fact RoleAdmin[role_id id]=>{author_id id}
fact RoleOperator[role_id id]=>{author_id id}
fact RoleMember[role_id id]=>{author_id id}

// Setup default roles on a team.
action setup_default_roles(managing_role_id id) {
    publish SetupDefaultRole {
        name: "admin",
        managing_role_id: managing_role_id,
    }
    publish SetupDefaultRole {
        name: "operator",
        managing_role_id: managing_role_id,
    }
    publish SetupDefaultRole {
        name: "member",
        managing_role_id: managing_role_id,
    }
}

command SetupDefaultRole {
    fields {
        // The name of the default role.
        name string,
        // The ID of the role that manages this role.
        managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_perm(author.device_id, "SetupDefaultRole")

        let role_id = derive_role_id(envelope)

        match this.name {
            "admin" => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                    })

                    create RoleHasPerm[role_id: role_id, perm: "AddDevice"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "RemoveDevice"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "CreateLabel"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "DeleteLabel"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "ChangeLabelManagingRole"]=>{}

                    emit RoleCreated {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                        default: true,
                    }
                }
            }
            "operator" => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                    })

                    create RoleHasPerm[role_id: role_id, perm: "AssignLabel"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "RevokeLabel"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "SetAqcNetworkName"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "UnsetAqcNetworkName"]=>{}

                    emit RoleCreated {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                        default: true,
                    }
                }
            }
            "member" => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                    })

                    create RoleHasPerm[role_id: role_id, perm: "CreateAqcUniChannel"]=>{}
                    create RoleHasPerm[role_id: role_id, perm: "CreateAqcBidiChannel"]=>{}

                    emit RoleCreated {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                        default: true,
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

A device can be assigned zero or one roles.

```policy
// Records that a device has been assigned a role.
//
// TODO(eric): talk about how you also need to verify that the
// role exists!
fact AssignedRole[device_id id]=>{role_id id}

// Returns the role assigned to the device.
//
// # Errors
//
// This function raises a check error if the device has not been
// assigned a role.
//
// # Caveats
//
// - It does NOT check whether the device exists.
function get_assigned_role(device_id id) struct Role {
    let assigned_role = check_unwrap query AssignedRole[device_id: device_id]
    // Verify that the role exists.
    check exists Role[role_id: assigned_role.role_id]
    return assigned_role
}

// Returns the ID of the role assigned to the device.
//
// # Errors
//
// This function raises a check error if the device has not been
// assigned a role.
//
// # Caveats
//
// - It does NOT check whether the device exists.
function get_assigned_role_id(device_id id) id {
    return get_assigned_role(device_id).role_id
}

// Assigns the specified role to the device.
//
// # Required Permissions
//
// - `AssignRole`
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

        let author = get_author(envelope)

        // Devices cannot assign roles to themselves.
        check author.device_id != this.device_id

        // The author must have permission to assign the role.
        check device_has_perm(author.device_id, "AssignRole")
        check can_manage_role(author.device_id, this.role_id)

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        // At this point we believe the following to be true:
        //
        // - `this.device_id` refers to a device that exists
        // - `this.role_id` refers to a role that exists
        // - `author` is not assigning the role to itself
        // - `author` has the `AssignRole` permission
        // - `author` is allowed to manage `this.role_id`
        finish {
            create AssignedRole[device_id: this.device_id]=>{role_id: this.role_id}

            emit RoleAssigned {
                device_id: this.device_id,
                role_id: this.role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Changing

```policy
// Changes a device's role.
//
// # Required Permissions
//
// - `RevokeRole` for the old role
// - `AssignRole` for the new role
action change_role(
    device_id id,
    old_role_id id,
    new_role_id id,
) {
    publish ChangeRole {
        device_id: device_id,
        old_role_id: old_role_id,
        new_role_id: new_role_id,
    }
}

// Emitted when a device's role is changed.
effect RoleChanged {
    // The ID of the device whose role is being changed.
    device_id id,
    // The ID of the device's old role.
    old_role_id id,
    // The ID of the device's new role.
    new_role_id id,
    // The ID of the device that changed the device's role.
    author_id id,
}

command ChangeRole {
    fields {
        // The ID of the device being assigned the role.
        device_id id,
        // The ID of the device's old role.
        old_role_id id,
        // The new role being assigned to the device.
        new_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)

        // Devices cannot assign roles to themselves.
        check author.device_id != this.device_id

        // TODO(eric): Should this just be a no-op?
        check this.old_role_id != this.new_role_id

        // The author must have permission to revoke the old role.
        check exists Role[role_id: this.old_role_id]
        check can_manage_role(author.device_id, this.old_role_id)
        check device_has_perm(author.device_id, "RevokeRole")

        // The author must have permission to revoke the old role.
        check exists Role[role_id: this.new_role_id]
        check can_manage_role(author.device_id, this.new_role_id)
        check device_has_perm(author.device_id, "AssignRole")

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        // At this point we believe the following invariants to
        // be true:
        //
        // - `this.old_role_id` and `this.new_role_id` are
        //   different
        // - `this.old_role_id` refers to a role that exists
        // - `author` is allowed to manage `this.old_role_id`
        // - `author` has the `RevokeRole` permission
        // - `this.new_role_id` refers to a role that exists
        // - `author` is allowed to manage `this.new_role_id`
        // - `author` has the `AddRole` permission
        finish {
            update AssignedRole[device_id: this.device_id]=>{
                role_id: this.old_role_id,
            } to {
                role_id: this.new_role_id,
            }

            emit RoleChange {
                device_id: this.device_id,
                new_role_id: this.new_role_id,
                old_role_id: this.old_role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Revocation

```policy
// Revokes the specified role from the device.
//
// # Required Permissions
//
// - `RevokeRole`
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
        // The ID of the role being revoked.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)

        // The author must have permission to revoke the role.
        check device_has_perm(author.device_id, "RevokeRole")
        check can_manage_role(author.device_id, this.role_id)

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        // At this point we believe the following to be true:
        //
        // - `this.device_id` refers to a device that exists
        // - `this.role_id` refers to a role that exists
        // - `author` has the `RevokeRole` permission
        // - `author` is allowed to manage `this.role_id`
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

### Role Queries

```policy
// Emits `QueryTreamRolesResult` for each role on the team.
action query_team_roles() {
    map Role[role_id: ?] as f {
        publish QueryTeamRoles {
            role_id: f.role_id,
            name: f.name,
            author_id: f.author_id,
            default: f.default,
        }
    }
}

// Emitted when a role is queried by `query_team_roles`.
effect QueryTreamRolesResult {
    // The ID of the role.
    role_id id,
    // The name of the role.
    name string,
    // The ID of the device that created the role.
    author_id id,
    // Is this a default role?
    default bool,
}

// A trampoline command to forward data to `QueryTreamRolesResult`.
command QueryTeamRoles {
    fields {
        role_id id,
        name string,
        author_id id,
        default bool,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueryTreamRolesResult {
                role_id: role.role_id,
                name: role.name,
                author_id: role.author_id,
                default: role.default,
            }
        }
    }
}
```

## Teams
<!-- Section contains: Team creation/termination, device management -->

### Team Creation

Teams are the primary organizational unit in Aranya. Each graph
is associated with exactly one team.

```policy
// A singleton fact that indicates that `CreateTeam` has been
// published.
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

// Returns the current team ID.
//
// # Errors
//
// This function raises a check error if the team does not exist.
function team_id() id {
    let f = check_unwrap query TeamStart[]=>{team_id: ?}
    return f.team_id
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
        // NB: This is the only place in the policy file where we
        // invert this condition.
        check !team_exists()

        // TODO(eric): check that `this.nonce` length is like
        // 32 bytes or something? It *should* be cryptographically
        // secure, but we don't really have a way to check that
        // yet. And I'm not sure we want to have policy generate
        // the nonce for CreateTeam.

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

            add_new_device(this.owner_keys, owner_key_ids)

            create_default_role(DefaultRole {
                role_id: owner_role_id,
                name: "owner",
                author_id: author_id,
                // Initially, only the owner role can manage the
                // owner role.
                managing_role_id: owner_role_id,
            })

            // Assign all of the administrative permissions to
            // the owner role.
            create RoleHasPerm[role_id: owner_role_id, perm: "AddDevice"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "RemoveDevice"]=>{}

            create RoleHasPerm[role_id: owner_role_id, perm: "CreateLabel"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "DeleteLabel"]=>{}

            create RoleHasPerm[role_id: owner_role_id, perm: "AssignLabel"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "RevokeLabel"]=>{}

            create RoleHasPerm[role_id: owner_role_id, perm: "SetAqcNetworkName"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "UnsetAqcNetworkName"]=>{}

            create RoleHasPerm[role_id: owner_role_id, perm: "SetupDefaultRole"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "ChangeRoleManagingRole"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "ChangeLabelManagingRole"]=>{}
            create RoleHasPerm[role_id: owner_role_id, perm: "TerminateTeam"]=>{}

            // And now make sure that the owner has the owner
            // role, of course.
            create AssignedRole[device_id: author_id]=>{role_id: owner_role_id}

            // We don't have to emit the effects in a particular
            // order, but try to make it intuitive.
            emit TeamCreated {
                team_id: team_id,
                owner_id: author_id,
            }
            emit DeviceAdded {
                device_id: owner_key_ids.device_id,
                device_keys: this.owner_keys,
            }
            emit RoleCreated {
                role_id: owner_role_id,
                name: "owner",
                author_id: author_id,
                managing_role_id: owner_role_id,
                default: true,
            }
            emit RoleAssigned {
                device_id: author_id,
                role_id: owner_role_id,
                author_id: author_id,
            }
        }
    }
}

// Adds the device to the team.
finish function add_new_device(
    kb struct KeyBundle,
    keys struct DevKeyIds,
) {
    // TODO(eric): check that `kb` matches `keys`.

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
//
// # Required Permissions
//
// - `TerminateTeam`
action terminate_team(team_id id) {
    publish TerminateTeam {
        team_id: team_id,
    }
}

effect TeamTerminated {
    // The ID of the team that was terminated.
    team_id id,
    // The ID of the device that terminated the team.
    owner_id id,
}

command TerminateTeam {
    fields {
        // The ID of the team being terminated.
        team_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_perm(author.device_id, "TerminateTeam")

        // At this point we believe the following to be true:
        //
        // - `author` has the `TerminateTeam` permission
        finish {
            delete TeamStart[]=>{team_id: team_id}

            emit TeamTerminated {
                team_id: this.team_id,
                owner_id: author.device_id,
            }
        }
    }
}
```

### Adding Devices

```policy
// Adds a device to the team.
//
// # Required Permissions
//
// - `AddDevice`
action add_device(device_keys struct KeyBundle) {
    publish AddDevice {
        device_keys: device_keys,
    }
}

// Emitted when a device is added to the team.
effect DeviceAdded {
    // Uniquely identifies the device.
    device_id id,
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

        let author = get_author(envelope)
        check device_has_perm(author.device_id, "AddDevice")

        let dev_key_ids = derive_device_key_ids(this.device_keys)

        // At this point we believe the following to be true:
        //
        // - `author` has the `AddDevice` permission
        finish {
            add_new_device(this.device_keys, dev_key_ids)

            emit DeviceAdded {
                device_id: dev_key_ids.device_id,
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
    // The ID of the device that was removed from the team.
    device_id id,
    // The ID of the device that removed `device_id`.
    author_id id,
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

        let author = get_author(envelope)
        check device_has_perm(author.device_id, "RemoveDevice")

        // TODO(eric): check that author dominates target?

        // At this point we believe the following to be true:
        //
        // - `author` has the `RemoveDevice` permission
        // - `device_id` refers to a device that exists
        finish {
            delete Device[device_id: this.device_id]
            delete DeviceIdentKey[device_id: this.device_id]
            delete DeviceSignKey[device_id: this.device_id]
            delete DeviceEncKey[device_id: this.device_id]

            // TODO(eric): We can't delete this yet because the
            // storage layer does not yet support prefix deletion.
            // See https://github.com/aranya-project/aranya-core/issues/229
            //
            // delete AssignedLabel[label_id: ?, device_id: this.device_id]

            // TODO(eric): We *should* be deleting these, but we
            // don't really have a good way to delete "optional"
            // facts yet.
            //
            // It is a runtime error to delete a non-existent
            // fact and a device might not have either of these
            // facts, so we have to conditionally delete them.
            //
            // Policy v2 does not have a conditional version of
            // `delete`, so we can't use that.
            //
            // `finish` blocks can only contain CRUD and `emit`
            // statements, so we can't use conditionals here.
            //
            // As of policy v2, the only way to do this is to
            // duplicate the entire `finish` block:
            //
            // ```policy
            // let has_role = exists AssignedRole[device_id: this.device_id]
            // let has_net_id = exists AqcNetId[device_id: this.device_id]
            // if has_role && has_net_id {
            //     finish { ... }
            // } else if has_role {
            //     finish { ... }
            // } else if has_net_id {
            //     finish { ... }
            // } else {
            //     finish { ... }
            // }
            // ```
            //
            // But this generates a combinatorial explosion if
            // we start adding more optional facts that we need
            // to delete.
            //
            // So, we resign ourselves to leaving this stale
            // fact around.
            //
            // delete AssignedRole[device_id: this.device_id]
            // delete AqcNetId[device_id: this.device_id]

            emit DeviceRemoved {
                device_id: this.device_id,
            }
        }
    }
}
```

## AQC
<!-- Section contains: Channel types, labels, network IDs, channel creation -->

### Overview

[Aranya QUIC Channels][aqc] provide end-to-end encrypted,
topic-segmented communication between two devices in a team.

Channels are secured with TLS 1.3 using pre-shared keys (PSK)
derived from the participants' Device Encryption Keys using HPKE.

#### Channel Security Constraints

AQC channels enforce several critical security invariants:

- **No Self-Channels**: Devices cannot create channels with
  themselves. This is enforced by explicit checks in channel
  creation functions.
- **Author Must Be Participant**: The device creating a channel
  must be one of the two participants. You cannot create channels
  on behalf of other devices.
- **Label Permission Requirements**: Both devices must have
  appropriate permissions for the label (SendRecv for
  bidirectional, or appropriate Send/Recv for unidirectional).
- **Ephemeral Command Processing**: Channel creation commands are
  ephemeral and only processed by the two participating devices.
  Other devices will fail with `check false`.
- **Network ID Requirements**: Both devices should have network
  IDs set (currently not enforced - see TODO).

```policy
// Reports whether `size` is a valid PSK length (in bytes).
//
// Per the AQC specification, PSKs must be in the range [32, 2^16).
function is_valid_psk_length(size int) bool {
    return size >= 32 && size < 65536
}

// Returns the device's encoded public Encryption Key.
//
// # Caveats
//
// This function does not directly check whether the device
// exists. However, it would be a very significant invariant
// violation if a device's key existed without the device also
// existing. See `valid_device_invariants`.
function get_enc_pk(device_id id) bytes {
    // This function is a little too expensive to call every
    // time we need to get a device, so only uncomment this when
    // debugging/developing.
    //
    // See the comment in `try_find_device`.
    //
    // check valid_device_invariants(device_id)

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

As previously mentioned, each label is managed by zero or more
roles, called the label's _managing roles_. A device that has
been assigned one of the managing roles is allowed to do some or
all of the following:

- Assign the label to *any* device that is allowed to use AQC,
  except itself
- Revoke the label from *any* device

```policy
// Grants devices who have been assigned the managing role
// permission to "manage" the target label.
fact CanManageLabel[label_id id, managing_role_id id]=>{}

// Reports whether the device is allowed to manage the label.
//
// # Errors
//
// # Caveats
//
// - This function does NOT check whether the device exists.
// - This function does NOT check whether the label exists.
function can_manage_label(device_id id, label_id id) bool {
    let device_role_id = check_unwrap get_assigned_role_id(device_id)

    // At this point we believe the following to be true:
    //
    // - `device_role_id` refers to a role that exists
    // - `device_role_id` refers to the role assigned to
    //   `device_id`
    //
    // We do NOT know whether `device_id` refers to a device
    // that exists.
    //
    // We do NOT know whether `label_id` refers to a label that
    // exists.
    return exists CanManageLabel[
        label_id: label_id,
        managing_role_id: device_role_id,
    ]
}

// Adds a new role that can manage the label.
//
// # Required Permissions
//
// - `CanManageLabel`
action add_label_managing_role(label_id id, managing_role_id id) {
    publish AddLabelManagingRole {
        label_id: label_id,
        managing_role_id: managing_role_id,
    }
}

effect LabelManagingRoleAdded {
    // The ID of the label that was updated.
    label_id id,
    // The ID of the role that can manage the label.
    managing_role_id id,
    // The ID of the device that added the managing role.
    author_id id,
}

command AddLabelManagingRole {
    fields {
        // The label to update.
        label_id id,
        // The ID of the role that can manage the label.
        managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check can_manage_label(author.device_id, this.label_id)
        check device_has_perm(author.device_id, "AddLabelManagingRole")

        // The label must exist, otherwise we might create
        // `CanManageLabel` for a non-existent label.
        check exists Label[label_id: this.label_id]

        // At this point we believe the following to be true:
        //
        // - `author` has the `AddLabelManagingRole` permission
        // - `author` is allowed to manage `this.label_id`
        // - `this.label_id` refers to a label that exists
        finish {
            create CanManageLabel
                label_id: label.label_id,
                managing_role_id: new_managing_role_id,
            ]=>{}
            emit LabelManagingRoleAdded {
                label_id: this.label_id,
                managing_role_id: this.managing_role_id,
                author_id: author.device_id,
            }
        }
    }
}

// Revokes a label's managing role.
//
// # Required Permissions
//
// - `RevokeLabelManagingRole`
action revoke_label_managing_role(label_id id, managing_role_id id) {
    publish RevokeLabelManagingRole {
        label_id: label_id,
        managing_role_id: managing_role_id,
    }
}

// Emitted when a label's managing role is revoked.
effect LabelManagingRoleRevoked {
    // The ID of the label that was updated.
    label_id id,
    // The ID of the role that was revoked.
    managing_role_id id,
    // The ID of the device that revoked the managing role.
    author_id id,
}

command RevokeLabelManagingRole {
    fields {
        // The label to update.
        label_id id,
        // The ID of the role being revoked.
        managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check can_manage_label(author.device_id, this.label_id)
        check device_has_perm(author.device_id, "RevokeLabelManagingRole")

        // At this point we believe the following to be true:
        //
        // - `author` has the `RevokeLabelManagingRole` permission
        // - `author` is allowed to manage `this.label_id`
        finish {
            delete CanManageLabel[
                label_id: this.label_id,
                managing_role_id: this.managing_role_id,
            ]

            emit LabelManagingRoleRevoked {
                label_id: this.label_id,
                managing_role_id: this.managing_role_id,
                author_id: author.device_id,
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
//
// # Required Permissions
//
// - `CreateLabel`
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
    // The ID of the role required to manage the label.
    managing_role_id id,
}

command CreateLabel {
    fields {
        // The label name.
        label_name string,
        // The ID of the role required to manage the label.
        managing_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_perm(author.device_id, "CreateLabel")

        // A label's ID is the ID of the command that created it.
        let label_id = derive_label_id(envelope)

        check exists Role[role_id: this.managing_role_id]

        // At this point we believe the following to be true:
        //
        // - `author` has the `CreateLabel` permission
        // - `this.role_id` refers to a role that exists
        finish {
            create Label[label_id: label_id]=>{
                name: this.label_name,
                author_id: author.device_id,
            }
            create CanManageLabel[
                label_id: label_id,
                managing_role_id: this.role_id,
            ]=>{}

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
//
// # Required Permissions
//
// - `DeleteLabel`
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

        let author = get_author(envelope)
        check device_has_perm(author.device_id, "DeleteLabel")
        check can_manage_label(author.device_id, label.label_id)

        // At this point we believe the following to be true:
        //
        // - `author` has the `DeleteLabel` permission
        // - `author` is allowed to manage `this.label_id`
        finish {
            // TODO(eric): We can't delete these yet because the
            // storage layer does not yet support prefix deletion.
            // See https://github.com/aranya-project/aranya-core/issues/229
            //
            // delete AssignedLabel[label_id: label.label_id, device_id: ?]
            // delete CanManageLabel[label_id: label.label_id, managing_role_id: ?]

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
//
// # Required Permissions
//
// - `AssignLabel`
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

        let author = get_author(envelope)

        // Devices are never allowed to assign labels to
        // themselves.
        //
        // Perform this check before we make more fact database
        // queries.
        check author.device_id != this.device_id

        check device_has_perm(author.device_id, "AssignLabel")
        check can_manage_label(author.device_id, this.label_id)

        // The target device must exist, otherwise we'll create
        // an `AssignedLabel` fact for a device that that does
        // not exist.
        check exists Device[device_id: this.device_id]
        // Ditto for the label.
        check exists Label[label_id: this.label_id]

        // At this point we believe the following to be true:
        //
        // - `author` has the `AssignLabel` permission
        // - `author` is allowed to manage `this.label_id`
        // - `this.device_id` refers to a device that exists
        // - `this.label_id` refers to a label that exists
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
//
// # Required Permissions
//
// - `RevokeLabel`
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

        let author = get_author(envelope)
        check can_manage_label(author.device_id, this.label_id)
        check device_has_perm(author.device_id, "RevokeLabel")

        // At this point we believe the following to be true:
        //
        // - `author` has the `RevokeLabel` permission
        // - `author` is allowed to manage `this.label_id`
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

Label queries retrieve information about labels on the team.

See [Query APIs][query-apis] for more information about the query
APIs.

##### Query Label Exists

Queries whether a label exists.

```policy
// Emits `QueryLabelExistsResult` for the label.
action query_label_exists(label_id id) {
    publish QueryLabelExists {
        label_id: label_id,
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

command QueryLabelExists {
    fields {
        label_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

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

effect QueriedLabel {
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}

// Trampoline to forward info to `QueriedLabel`
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
```

##### Query Label Assignments

Queries for a list labels assigned to a device.

```policy
// Emits `QueryLabelAssignmentsResult` for all labels the device
// has been granted permission to use.
action query_label_assignments(device_id id) {
    // TODO: make this query more efficient when policy supports
    // it. The key order is optimized for `delete AssignedLabel`.
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

effect QueryLabelAssignmentsResult {
    // The device's unique ID.
    device_id id,
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
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
            emit QueryLabelAssignmentsResult {
                device_id: this.device_id,
                label_id: this.label_id,
                label_name: this.label_name,
                label_author_id: this.label_author_id,
            }
        }
    }
}
```

### Network IDs

Each device that wants to participate in an AQC channel must have
a _network identifier_.

```policy
// Stores a device's associated network identifier for AQC.
fact AqcNetId[device_id id]=>{net_id string}

// Returns the device's AQC network identifier, if it exists.
//
// # Caveats
//
// This function does NOT check whether the device exists.
function aqc_net_id(device_id id) optional string {
    let f = query AqcNetId[device_id: device_id]
    if f is Some {
        return Some((unwrap f).net_id)
    }
    return None
}

// TODO(eric): Why do we call it both a "network ID" and
// "network name"?

// Sets the device's AQC network name.
//
// # Required Permissions
//
// - `SetAqcNetworkName`
action set_aqc_network_name(device_id id, net_id string) {
    publish SetAqcNetworkName {
        device_id: device_id,
        net_id: net_id,
    }
}

// Emitted when a device's AQC network name is set.
effect AqcNetworkNameSet {
    // The ID of the device whose network name was set.
    device_id id,
    // The network name that was set.
    net_id string,
}

// TODO(eric): rename this to update/upsert/something?
command SetAqcNetworkName {
    fields {
        device_id id,
        net_id string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        let device = get_device(this.device_id)

        let opt_net_id = aqc_net_id(this.device_id)

        if opt_net_id is Some {
            let net_id = unwrap opt_net_id
            finish {
                update AqcNetId[device_id: this.device_id]=>{net_id: net_id} to {
                    net_id: this.net_id
                }

                emit AqcNetworkNameSet {
                    device_id: device.device_id,
                    net_id: this.net_id,
                }
            }
        } else {
            finish {
                create AqcNetId[device_id: this.device_id]=>{net_id: this.net_id}

                emit AqcNetworkNameSet {
                    device_id: device.device_id,
                    net_id: this.net_id,
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

        let author = get_author(envelope)
        let device = get_device(this.device_id)

        check exists AqcNetId[device_id: this.device_id]

        finish {
            delete AqcNetId[device_id: this.device_id]

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
    map AqcNetId[device_id: ?] as f {
        publish QueryAqcNetworkNamesCommand {
            net_id: f.net_id,
            device_id: f.device_id,
        }
    }
}

effect QueryAqcNetworkNamesOutput {
    net_id string,
    device_id id,
}

command QueryAqcNetworkNamesCommand {
    fields {
        net_id string,
        device_id id,
    }
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }
    policy {
        finish {
            emit QueryAqcNetworkNamesOutput {
                net_id: this.net_id,
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
    let author = get_device(author_id)
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

// Returns the channel operation for a particular label.
function get_allowed_chan_op_for_label(device_id id, label_id id) enum ChanOp {
    let assigned_label = check_unwrap query AssignedLabel[label_id: label_id, device_id: device_id]
    return assigned_label.op
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
    let device1_op = get_allowed_chan_op_for_label(device1, label_id)
    if device1_op != ChanOp::SendRecv {
        return false
    }

    let device2_op = get_allowed_chan_op_for_label(device2, label_id)
    if device2_op != ChanOp::SendRecv {
        return false
    }

    // TODO(eric): Check that both devices have network IDs.

    return true
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

        let author = get_author(envelope)
        let peer = get_device(this.peer_id)

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
    let author = get_device(device::current_device_id())
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

        let author = get_author(envelope)

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
    let writer_op = get_allowed_chan_op_for_label(sender_id, label_id)
    match writer_op {
        ChanOp::RecvOnly => { return false }
        ChanOp::SendOnly => {}
        ChanOp::SendRecv => {}
    }

    // The reader must have permission to read (receive) data.
    let reader_op = get_allowed_chan_op_for_label(receiver_id, label_id)
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
action query_aqc_net_id(device_id id) {
    publish QueryAqcNetIdentifier {
        device_id: device_id,
    }
}

effect QueryAqcNetIdentifierResult {
    net_id optional string,
}

command QueryAqcNetIdentifier {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Check that the team is active and return the author's
        // info if they exist in the team.
        let author = get_device(this.device_id)
        let net_id = aqc_net_id(author.device_id)

        finish {
            emit QueryAqcNetIdentifierResult {
                net_id: net_id,
            }
        }
    }
}
```

## Query APIs

Policy language v2 does not support defining queries against the
internal fact database, so the implementation of the query APIs
defined in this document are a little peculiar.

As background, Aranya supports ephemeral "off graph" commands.
These commands generally function the same as regular "on graph"
commands, except that they are not persisted (added to the graph)
after being evaluated.

The query APIs defined in this document use ephemeral commands
that read data from the fact database and emit effects with the
results. Query APIs that need to logically return lists use
`map` in the `action` to publish an ephemeral command per list
item.

Query APIs must still call `check team_exists()` to ensure that
data for closed teams is not returned.

## Known Bugs

- `AssignedRole` and `AssignedLabel` cannot be deleted without
  prefix deletion. See [aranya-core/229][issue #229] for more
  details.
- `AqcNetId` cannot reasonably be deleted without conditional
  deletion or a combinatorial explosion of `finish` blocks.

[actions]: https://aranya-project.github.io/policy-language-v1/#actions
[aqc-ffi]: https://crates.io/crates/aranya-aqc-util
[aqc-label-design]: https://aranya-project.github.io/aranya-quic-channels/#label-design
[aqc]: https://aranya-project.github.io/aranya-quic-channels/
[aranya-core/229]: https://github.com/aranya-project/aranya-core/issues/229
[commands]: https://aranya-project.github.io/policy-language-v1/#commands
[crypto-ffi]: https://crates.io/crates/aranya-crypto-ffi
[device-ffi]: https://crates.io/crates/aranya-device-ffi
[effects]: https://aranya-project.github.io/policy-language-v1/#effects
[envelope]: https://aranya-project.github.io/policy-language-v1/#envelope-type
[evp-ffi]: https://crates.io/crates/aranya-envelope-ffi
[facts]: https://aranya-project.github.io/policy-language-v1/#facts
[idam-ffi]: https://crates.io/crates/aranya-idam-ffi
[lp]: https://en.wikipedia.org/wiki/Literate_programming
[perspective-ffi]: https://crates.io/crates/aranya-perspective-ffi
[policy-lang]: https://aranya-project.github.io/policy-language-v2/
[rbac]: https://csrc.nist.gov/glossary/term/rbac
