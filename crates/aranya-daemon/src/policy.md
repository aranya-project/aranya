---
policy-version: 2
---

# Overview

This Aranya's default policy. It provides the rules that underlie
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
TODO: talk about how queries are `QueryXResult`, etc.

## Imports

```policy
use afc
use aqc
use crypto
use device
use envelope
use idam
use perspective
```

- [`afc`][afc-ffi]: [AFC][afc] functionality, such as creating
  channels.
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
by AFC and AQC.

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

### Device Generations

Each device has a _generation_, which is monotonically
incremented each time the device is removed from the team.

```policy
// Tracks the current logical generation for a device.
//
// Each time a device is removed from the team, its generation is
// bumped so that stale per-device state (for example, direct
// label assignments) becomes invalid.
//
// This fact persists across device removals so a re-added device
// starts with the latest generation number.
//
// # Foreign Keys
//
// - `device_id` refers to the `Device` fact
fact DeviceGeneration[device_id id]=>{generation int}

// Returns the device's current generation counter.

// # Caveats
//
// - It does NOT check whether the device exists.
//
// # Errors
//
// Raises a check error if the generation fact does not exist.
function get_device_gen(device_id id) int {
    let f = check_unwrap query DeviceGeneration[device_id: device_id]
    return f.generation
}
```

### Device Queries

Device queries retrieve information about devices on the team.

See [Query APIs][query-apis] for more information about the query
APIs.

#### `query_devices_on_team`

Returns all devices on the team.

```policy
// Emits `QueryDevicesOnTeamResult` for each device on the team.
ephemeral action query_devices_on_team() {
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
ephemeral command QueryDevicesOnTeam {
    fields {
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
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

#### `query_device_role`

Returns the role assigned to a device.

```policy
// Emits `QueryDeviceRoleResult` for each role assigned to the
// device.
ephemeral action query_device_role(device_id id) {
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

ephemeral command QueryDeviceRole {
    fields {
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let device = get_device(this.device_id)

        let assigned_role = try_get_assigned_role(device.device_id)
        if assigned_role is None {
            finish {}
        } else {
            let role = unwrap assigned_role
            finish {
                emit QueryDeviceRoleResult {
                    role_id: role.role_id,
                    name: role.name,
                    author_id: role.author_id,
                    default: role.default,
                }
            }
        }
    }
}
```

### `query_device_keybundle`

Returns a device's `KeyBundle`.

```policy
// Emits `QueryDeviceKeyBundleResult` with the device's key
// bundle.
ephemeral action query_device_keybundle(device_id id) {
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

ephemeral command QueryDeviceKeyBundle {
    fields {
        // The device whose key bundle is being queried.
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
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
// NB: This function is deterministic and injective for the
// current policy. Calling it multiple times for the same
// envelope will always return the same ID.
function derive_role_id(evp struct Envelope) id {
    // The role ID is the ID of the command that created it.
    // TODO(eric): Or we could use H(cmd_id, ...).
    return envelope::command_id(evp)
}
```

Each role is managed by one or more roles, called the _managing
roles_. For more information, see [Role
Management][role-management].

> **Note**: Upon team creation, the only role that exists is the
> `owner` role. Therefore, the `owner` role is managed by itself.
> It's roles all the way down.

### Role Scope

The _scope_ of a role is the aggregate set of resources that the
role authorizes devices to access. Resources themselves define
the role(s) that are required to access the resource. For
instance, each label is associated with a "manager" role that
(among other things) authorizes devices to assign the label to
other devices. Devices with sufficient permissions can change
a role's scope; how this works depends on the resource.

### Role Permissions

Each role has a set of zero or more permissions that it grants to
devices who have been assigned the role. Permissions come in two
different forms, simple and contextual.

#### Simple Permissions

Simple permissions are plain identifiers like `AddDevice` and
`TerminateTeam`. They have no additional context. Simple
permissions are statically defined in the policy file itself and
cannot be created or deleted at runtime.

```policy
enum SimplePerm {
    // Team management
    AddDevice,
    RemoveDevice,
    TerminateTeam,

    // Roles
    AssignRole,
    RevokeRole,
    SetupDefaultRole,
    ChangeRoleManagingRole,

    // Labels
    CreateLabel,
    DeleteLabel,
    ChangeLabelManagingRole,
    AssignLabel,
    RevokeLabel,

    // AQC
    CanUseAqc,
    SetAqcNetworkName,
    UnsetAqcNetworkName,
    CreateAqcUniChannel,
    CreateAqcBidiChannel,

    // AFC
    CanUseAfc,
    CreateAfcUniChannel,
    CreateAfcBidiChannel,
}

// Converts `perm` to a string.
function simple_perm_to_str(perm enum SimplePerm) string {
    match perm {
        SimplePerm::AddDevice => { return "AddDevice" }
        SimplePerm::RemoveDevice => { return "RemoveDevice" }
        SimplePerm::TerminateTeam => { return "TerminateTeam" }

        SimplePerm::AssignRole => { return "AssignRole" }
        SimplePerm::RevokeRole => { return "RevokeRole" }
        SimplePerm::SetupDefaultRole => { return "SetupDefaultRole" }
        SimplePerm::ChangeRoleManagingRole => { return "ChangeRoleManagingRole" }

        SimplePerm::CreateLabel => { return "CreateLabel" }
        SimplePerm::DeleteLabel => { return "DeleteLabel" }
        SimplePerm::ChangeLabelManagingRole => { return "ChangeLabelManagingRole" }
        SimplePerm::AssignLabel => { return "AssignLabel" }
        SimplePerm::RevokeLabel => { return "RevokeLabel" }

        SimplePerm::CanUseAqc => { return "CanUseAqc" }
        SimplePerm::SetAqcNetworkName => { return "SetAqcNetworkName" }
        SimplePerm::UnsetAqcNetworkName => { return "UnsetAqcNetworkName" }
        SimplePerm::CreateAqcUniChannel => { return "CreateAqcUniChannel" }
        SimplePerm::CreateAqcBidiChannel => { return "CreateAqcBidiChannel" }

        SimplePerm::CanUseAfc => { return "CanUseAfc" }
        SimplePerm::CreateAfcUniChannel => { return "CreateAfcUniChannel" }
        SimplePerm::CreateAfcBidiChannel => { return "CreateAfcBidiChannel" }
    }
}

// Returns the `SimplePerm` enum value corresponding to `perm`
// if `perm` is valid.
function try_parse_simple_perm(perm string) optional enum SimplePerm {
    match perm {
        //
        // Team management
        //
        "AddDevice" => { return Some(SimplePerm::AddDevice) }
        "RemoveDevice" => { return Some(SimplePerm::RemoveDevice) }
        "TerminateTeam" => { return Some(SimplePerm::TerminateTeam) }

        //
        // Roles
        //
        "AssignRole" => { return Some(SimplePerm::AssignRole) }
        "RevokeRole" => { return Some(SimplePerm::RevokeRole) }
        "ChangeRoleManagingRole" => { return Some(SimplePerm::ChangeRoleManagingRole) }

        //
        // Labels
        //
        "CreateLabel" => { return Some(SimplePerm::CreateLabel) }
        "DeleteLabel" => { return Some(SimplePerm::DeleteLabel) }
        "ChangeLabelManagingRole" => { return Some(SimplePerm::ChangeLabelManagingRole) }
        "AssignLabel" => { return Some(SimplePerm::AssignLabel) }
        "RevokeLabel" => { return Some(SimplePerm::RevokeLabel) }

        //
        // AQC
        //
        "CanUseAqc" => { return Some(SimplePerm::CanUseAqc) }
        "SetAqcNetworkName" => { return Some(SimplePerm::SetAqcNetworkName) }
        "UnsetAqcNetworkName" => { return Some(SimplePerm::UnsetAqcNetworkName) }
        "CreateAqcUniChannel" => { return Some(SimplePerm::CreateAqcUniChannel) }
        "CreateAqcBidiChannel" => { return Some(SimplePerm::CreateAqcBidiChannel) }

        //
        // AFC
        //
        "CanUseAfc" => { return Some(SimplePerm::CanUseAfc) }
        "CreateAfcUniChannel" => { return Some(SimplePerm::CreateAfcUniChannel) }
        "CreateAfcBidiChannel" => { return Some(SimplePerm::CreateAfcBidiChannel) }

        _ => { return None }
    }
}

// Records a simple permission granted by the role.
//
// # Caveats
//
// We do not yet support prefix deletion, so this fact is NOT
// deleted when a role is deleted. Use `role_has_simple_perm` to
// verify whether a role grants a permission and use
// `device_has_simple_perm` to verify whether a device has
// a permission.
//
// TODO(eric): Should this be
// 1. fact RoleHasPerm[role_id id, perm string]
// 2. fact RoleHasPerm[role_id id]=>{perm string}
// 3. fact RoleHasPerm[role_id id]=>{perm enum SimplePerm}
// 4. fact RoleHasPerm[role_id id, perm enum SimplePerm]
fact RoleHasPerm[role_id id, perm enum SimplePerm]=>{}

// A wrapper for `create RoleHasPerm`.
finish function assign_perm_to_role(role_id id, perm enum SimplePerm) {
    create RoleHasPerm[
        role_id: role_id,
        perm: perm,
    ]=>{}
}

// Reports whether the role has the specified permission.
//
// # Errors
//
// It raises a check failure if the role does not exist.
function role_has_simple_perm(role_id id, perm enum SimplePerm) bool {
    check exists Role[role_id: role_id]

    return exists RoleHasPerm[
        role_id: role_id,
        perm: perm,
    ]
}

// Reports whether the device has the specified permission.
//
// # Caveats
//
// This function does NOT check whether the device exists.
function device_has_simple_perm(device_id id, perm enum SimplePerm) bool {
    let role = check_unwrap query AssignedRole[device_id: device_id]
    return role_has_simple_perm(role.role_id, perm)
}

// Adds a permission to the role.
action add_perm_to_role(role_id id, perm_str string) {
    let perm = check_unwrap try_parse_simple_perm(perm_str)
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
    // TODO(eric): Should we convert this to an enum? That would
    // make `SimplePerm` part of the public API.
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
        perm enum SimplePerm,
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
        check can_change_role_perms(author.device_id, this.role_id)

        // The role must not already have the permission.
        //
        // TODO(eric): Should this case be a no-op or an error?
        check !role_has_simple_perm(this.role_id, this.perm)

        let perm_str = simple_perm_to_str(this.perm)

        finish {
            create RoleHasPerm[role_id: this.role_id, perm: this.perm]=>{}

            emit PermAddedToRole {
                role_id: this.role_id,
                perm: perm_str,
                author_id: author.device_id,
            }
        }
    }
}

// Removes the permission from the role.
action remove_perm_from_role(role_id id, perm_str string) {
    let perm = check_unwrap try_parse_simple_perm(perm_str)
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
    // TODO(eric): Should we convert this to an enum? That would
    // make `SimplePerm` part of the public API.
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
        perm enum SimplePerm,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)

        // Removing a permission does not *escalate* privilege,
        // so unlike `AddPermToRole` we only need to check that
        // the author is allowed to change the role's permissions.
        check can_change_role_perms(author.device_id, this.role_id)


        // TODO(eric): Should this case be a no-op or an error?
        check role_has_simple_perm(this.role_id, this.perm)

        let perm_str = simple_perm_to_str(this.perm)

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` is authorized to remove permissions from
        //   the role
        // - `this.role_id` refers to a role that exists
        // - `this.perm` is a valid permission string
        // - `this.role_id` currently has the permission `this.perm`
        finish {
            delete RoleHasPerm[role_id: this.role_id, perm: this.perm]

            emit PermRemovedFromRole {
                role_id: this.role_id,
                perm: perm_str,
                author_id: author.device_id,
            }
        }
    }
}
```

#### Contextual Permissions

Contextual permissions are generally stored in facts. Unlike
simple permissions, they do have additional context. They're
represented as non-empty tuples where the element(s) are the
_context_. For example, the `CanManageLabel(label_id)` fact
grants devices permission to manage a specific label.

### Role Ownership

As previously mentioned, each role is "owned" by zero or more
other roles, called the _owning roles_. The owning roles are
responsible for delegating management permissions of the role to
other roles.

```policy
// Records that the target role is owned by the owning role.
//
// Remember that each role has zero or more owners.
//
// # Foreign Keys
//
// - `target_role_id` refers to the `Role` fact
// - `owning_role_id` refers to the `Role` fact
fact OwnsRole[target_role_id id, owning_role_id id]=>{}

// Reports whether the device's role confers ownership of the
// target role.
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
//
// # Ensures
//
// If true, `OwnsRole(target_role_id, device_role_id)` holds.
function device_owns_role(device_id id, target_role_id id) bool {
    let device_role_id = get_assigned_role_id(device_id)

    // At this point we believe the following to be true:
    //
    // - `device_role_id` refers to a role that exists
    // - `device_role_id` refers to the role assigned to
    //   `device_id`
    //
    // We do NOT know whether `device_id` refers to a device
    // that exists.
    //
    // We do NOT know whether `target_role_id` refers to a role
    // that exists.
    return exists OwnsRole[
        target_role_id: target_role_id,
        owning_role_id: device_role_id,
    ]
}
```

The owning roles are allowed to add new owning roles or remove
existing owning roles, provided the device also holds the
`ChangeRoleManagingRole` simple permission.

```policy
// Adds a new owning role to the target role.
//
// # Required Permissions
//
// - `OwnsRole(target_role_id)`
// - `ChangeRoleManagingRole`
action add_role_owner(
    target_role_id id,
    new_owning_role id,
) {
    publish AddRoleOwner {
        target_role_id: target_role_id,
        new_role_owner: new_owning_role,
    }
}

// Emitted when the `AddRoleOwner` command is successfully
// processed.
effect RoleOwnerAdded {
    // The ID of the role whose owning role was changed.
    target_role_id id,
    // The ID of the new role owner.
    new_role_owner id,
    // The ID of the device that changed the owning role.
    author_id id,
}

command AddRoleOwner {
    fields {
        // The ID of the role whose owning role is being
        // changed.
        target_role_id id,
        // The ID of the new owning role.
        new_role_owner id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_simple_perm(author.device_id, SimplePerm::ChangeRoleManagingRole)
        check device_owns_role(author.device_id, this.target_role_id)

        // Make sure we uphold the invariants for `OwnsRole`.
        check exists Role[role_id: this.target_role_id]
        check exists Role[role_id: this.new_role_owner]
        check !exists OwnsRole[
            target_role_id: this.target_role_id,
            owning_role_id: this.new_role_owner,
        ]

        finish {
            create OwnsRole[
                target_role_id: this.target_role_id,
                owning_role_id: this.new_role_owner,
            ]=>{}

            emit RoleOwnerAdded {
                target_role_id: this.target_role_id,
                new_role_owner: this.new_role_owner,
                author_id: author.device_id,
            }
        }
    }
}

// Removes an owning role from the target role.
//
// # Required Permissions
//
// - `OwnsRole(target_role_id)`
// - `ChangeRoleManagingRole`
action remove_role_owner(
    target_role_id id,
    owning_role_id id,
) {
    publish RemoveRoleOwner {
        target_role_id: target_role_id,
        owning_role_id: owning_role_id,
    }
}

// Emitted when the `RemoveRoleOwner` command is successfully
// processed.
effect RoleOwnerRemoved {
    // The ID of the role whose owning role was changed.
    target_role_id id,
    // The ID of the owning role that was removed.
    owning_role_id id,
    // The ID of the device that changed the owning role.
    author_id id,
}

command RemoveRoleOwner {
    fields {
        // The ID of the role whose owning role is being
        // changed.
        target_role_id id,
        // The ID of the owning role that is being removed.
        owning_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_simple_perm(author.device_id, SimplePerm::ChangeRoleManagingRole)
        check device_owns_role(author.device_id, this.target_role_id)

        check exists OwnsRole[
            target_role_id: this.target_role_id,
            owning_role_id: this.owning_role_id,
        ]

        check at_least 2 OwnsRole[
            target_role_id: this.target_role_id,
            owning_role_id: ?,
        ]=>{}

        finish {
            delete OwnsRole[
                target_role_id: this.target_role_id,
                owning_role_id: this.owning_role_id,
            ]

            emit RoleOwnerRemoved {
                target_role_id: this.target_role_id,
                owning_role_id: this.owning_role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Management

The owning roles for a role are allowed to delegate the following
permissions to other roles, including to themselves:

- `CanAssignRole(role_id)`: grants devices the ability to assign
  the role to *any* device, except themselves.
- `CanRevokeRole(role_id)`: grants devices the ability to
  revoke the role from *any* device.
- `CanChangeRolePerms(role_id)`: grants devices the ability
  to change the permissions of the role.

```policy
// Grants devices who have been assigned the managing role
// permission to assign the target role to other devices.
//
// # Foreign Keys
//
// - `target_role_id` refers to the `Role` fact
// - `managing_role_id` refers to the `Role` fact
fact CanAssignRole[target_role_id id, managing_role_id id]=>{}

// Reports whether the device is allowed to assign the role to
// other devices.
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
//
// # Ensures
//
// If true, `CanAssignRole(target_role_id, device_role_id)` holds.
function can_assign_role(device_id id, target_role_id id) bool {
    let device_role_id = get_assigned_role_id(device_id)

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
    return exists CanAssignRole[
        target_role_id: target_role_id,
        managing_role_id: device_role_id,
    ]
}

// Grants devices who have been assigned the managing role
// permission to revoke the target role from other devices.
//
// # Foreign Keys
//
// - `target_role_id` refers to the `Role` fact
// - `managing_role_id` refers to the `Role` fact
fact CanRevokeRole[target_role_id id, managing_role_id id]=>{}

// Reports whether the device is allowed to revoke the role from
// other devices.
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
//
// # Ensures
//
// If true, `CanRevokeRole(target_role_id, device_role_id)` holds.
function can_revoke_role(device_id id, target_role_id id) bool {
    let device_role_id = get_assigned_role_id(device_id)

    // At this point we believe the following to be true:
    //
    // - `device_role_id` refers to a role that exists
    // - `device_role_id` refers to the role revoked to
    //   `device_id`
    //
    // We do NOT know whether `device_id` refers to a device
    // that exists.
    //
    // We do NOT know whether `role_id` refers to a role that
    // exists.
    return exists CanRevokeRole[
        target_role_id: target_role_id,
        managing_role_id: device_role_id,
    ]
}

// Grants devices who have been assigned the managing role
// permission to change the permissions of the target role.
//
// # Foreign Keys
//
// - `target_role_id` refers to the `Role` fact
// - `managing_role_id` refers to the `Role` fact
fact CanChangeRolePerms[target_role_id id, managing_role_id id]=>{}

// Reports whether the device is allowed to change the permissions
// of the role.
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
//
// # Ensures
//
// If true, `CanChangeRolePerms(target_role_id, device_role_id)` holds.
function can_change_role_perms(device_id id, target_role_id id) bool {
    let device_role_id = get_assigned_role_id(device_id)

    // At this point we believe the following to be true:
    //
    // - `device_role_id` refers to a role that exists
    // - `device_role_id` refers to the role revoked to
    //   `device_id`
    //
    // We do NOT know whether `device_id` refers to a device
    // that exists.
    //
    // We do NOT know whether `role_id` refers to a role that
    // exists.
    return exists CanChangeRolePerms[
        target_role_id: target_role_id,
        managing_role_id: device_role_id,
    ]
}

enum RoleManagementPerm {
    // Grants a device the ability to assign the role to any
    // device except itself.
    CanAssignRole,
    // Grants a device the ability to revoke the role from any
    // device.
    CanRevokeRole,
    // Grants a device the ability to change the permissions
    // assigned to the role.
    CanChangeRolePerms,
}

// Converts `RoleManagementPerm` to a string.
function role_management_perm_to_str(perm enum RoleManagementPerm) string {
    match perm {
        RoleManagementPerm::CanAssignRole => { return "CanAssignRole" }
        RoleManagementPerm::CanRevokeRole => { return "CanRevokeRole" }
        RoleManagementPerm::CanChangeRolePerms => { return "CanChangeRolePerms" }
    }
}

// Returns the `RoleManagementPerm` enum value corresponding to `perm`
// if `perm` is valid.
function try_parse_role_management_perm(perm string) optional enum RoleManagementPerm {
    match perm {
        "CanAssignRole" => { return Some(RoleManagementPerm::CanAssignRole) }
        "CanRevokeRole" => { return Some(RoleManagementPerm::CanRevokeRole) }
        "CanChangeRolePerms" => { return Some(RoleManagementPerm::CanChangeRolePerms) }
        _ => { return None }
    }
}

// Assigns a role management permission to a role.
//
// `perm` must be one of
// - `CanAssignRole`
// - `CanRevokeRole`
// - `CanChangeRolePerms`
//
// # Required Permissions
//
// - `OwnsRole(role_id)`
action assign_role_management_perm(
    target_role_id id,
    managing_role_id id,
    perm string,
) {
    let perm_enum = check_unwrap try_parse_role_management_perm(perm)
    publish AssignRoleManagementPerm {
        target_role_id: target_role_id,
        managing_role_id: managing_role_id,
        perm: perm_enum,
    }
}

// Emitted when the `AssignRoleManagementPerm` command is
// successfully processed.
effect RoleManagementPermAssigned {
    // The ID of the role whose management permission was
    // changed.
    target_role_id id,
    // The ID of the role that was granted the management
    // permission.
    managing_role_id id,
    // The permission that was granted.
    // TODO(eric): Should we convert this to an enum? That would
    // make `RoleManagementPerm` part of the public API.
    perm string,
    // The ID of the device that changed the management
    // permissions.
    author_id id,
}

command AssignRoleManagementPerm {
    fields {
        // The ID of the role whose management permission is being
        // assigned.
        target_role_id id,
        // The ID of the role that is being assigned the
        // management permission.
        managing_role_id id,
        // The permission that is being assigned.
        perm enum RoleManagementPerm,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_owns_role(author.device_id, this.target_role_id)

        // Make sure we uphold the invariants for
        // `CanAssignRole`, `CanRevokeRole`, and
        // `CanChangeRolePerms`.
        check exists Role[role_id: this.target_role_id]
        check exists Role[role_id: this.managing_role_id]

        let perm = role_management_perm_to_str(this.perm)

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` is authorized to assign management
        //    permissions for this role
        // - `this.target_role_id` refers to a role that exists
        // - `this.managing_role_id` refers to a role that exists
        // - `this.perm` is a valid role-management permission
        match this.perm {
            RoleManagementPerm::CanAssignRole => {
                check !exists CanAssignRole[
                    target_role_id: this.target_role_id,
                    managing_role_id: this.managing_role_id,
                ]
                finish {
                    create CanAssignRole[
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                    ]=>{}

                    emit RoleManagementPermAssigned {
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                        perm: perm,
                        author_id: author.device_id,
                    }
                }
            }
            RoleManagementPerm::CanRevokeRole => {
                check !exists CanRevokeRole[
                    target_role_id: this.target_role_id,
                    managing_role_id: this.managing_role_id,
                ]
                finish {
                    create CanRevokeRole[
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                    ]=>{}

                    emit RoleManagementPermAssigned {
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                        perm: perm,
                        author_id: author.device_id,
                    }
                }
            }
            RoleManagementPerm::CanChangeRolePerms => {
                check !exists CanChangeRolePerms[
                    target_role_id: this.target_role_id,
                    managing_role_id: this.managing_role_id,
                ]
                finish {
                    create CanChangeRolePerms[
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                    ]=>{}

                    emit RoleManagementPermAssigned {
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                        perm: perm,
                        author_id: author.device_id,
                    }
                }
            }
            _ => { check false }
        }
    }
}

// Revokes a role management permission from a role.
//
// `perm` must be one of
// - `CanAssignRole`
// - `CanRevokeRole`
// - `CanChangeRolePerms`
//
// # Required Permissions
//
// - `OwnsRole(role_id)`
action revoke_role_management_perm(
    target_role_id id,
    managing_role_id id,
    perm string,
) {
    let perm_enum = check_unwrap try_parse_role_management_perm(perm)
    publish RevokeRoleManagementPerm {
        target_role_id: target_role_id,
        managing_role_id: managing_role_id,
        perm: perm_enum,
    }
}

// Emitted when the `RevokeRoleManagementPerm` command is
// successfully processed.
effect RoleManagementPermRevoked {
    // The ID of the role whose management permission was
    // changed.
    target_role_id id,
    // The ID of the role that had its management permission
    // removed.
    managing_role_id id,
    // The permission that was revoked.
    // TODO(eric): Should we convert this to an enum? That would
    // make `RoleManagementPerm` part of the public API.
    perm string,
    // The ID of the device that changed the management
    // permissions.
    author_id id,
}

command RevokeRoleManagementPerm {
    fields {
        // The ID of the role whose management permission is being
        // removed.
        target_role_id id,
        // The ID of the role that is having its management
        // permission removed.
        managing_role_id id,
        // The permission that is being removed.
        perm enum RoleManagementPerm,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_owns_role(author.device_id, this.target_role_id)

        let perm = role_management_perm_to_str(this.perm)

        // At this point we believe the following to be true:
        //
        // - `author` is authorized to remove management
        //    permissions for this role
        // - `this.target_role_id` refers to a role that exists
        // - `this.managing_role_id` refers to a role that exists
        match this.perm {
            RoleManagementPerm::CanAssignRole => {
                check exists CanAssignRole[
                    target_role_id: this.target_role_id,
                    managing_role_id: this.managing_role_id,
                ]
                finish {
                    delete CanAssignRole[
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                    ]

                    emit RoleManagementPermRevoked {
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                        perm: perm,
                        author_id: author.device_id,
                    }
                }
            }
            RoleManagementPerm::CanRevokeRole => {
                check exists CanRevokeRole[
                    target_role_id: this.target_role_id,
                    managing_role_id: this.managing_role_id,
                ]
                finish {
                    delete CanRevokeRole[
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                    ]

                    emit RoleManagementPermRevoked {
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                        perm: perm,
                        author_id: author.device_id,
                    }
                }
            }
            RoleManagementPerm::CanChangeRolePerms => {
                check exists CanChangeRolePerms[
                    target_role_id: this.target_role_id,
                    managing_role_id: this.managing_role_id,
                ]
                finish {
                    delete CanChangeRolePerms[
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                    ]

                    emit RoleManagementPermRevoked {
                        target_role_id: this.target_role_id,
                        managing_role_id: this.managing_role_id,
                        perm: perm,
                        author_id: author.device_id,
                    }
                }
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
    // The ID of the initial role owner.
    owning_role_id id,
}

// Creates the following facts for a default role
//
// - Role
// - OwnsRole
// - CanAssignRole
// - CanRevokeRole
// - CanChangeRolePerms
finish function create_default_role(role struct DefaultRole) {
    // TODO(eric): check invariants like `managing_role_id` must
    // exist, author must exist, etc?

    create Role[role_id: role.role_id]=>{
        name: role.name,
        author_id: role.author_id,
        default: true,
    }
    create OwnsRole[
        target_role_id: role.role_id,
        owning_role_id: role.owning_role_id,
    ]=>{}
    create CanAssignRole[
        target_role_id: role.role_id,
        managing_role_id: role.owning_role_id,
    ]=>{}
    create CanRevokeRole[
        target_role_id: role.role_id,
        managing_role_id: role.owning_role_id,
    ]=>{}
    create CanChangeRolePerms[
        target_role_id: role.role_id,
        managing_role_id: role.owning_role_id,
    ]=>{}
}

// Emitted when a role is created.
effect RoleCreated {
    // ID of the role.
    role_id id,
    // Name of the role.
    name string,
    // ID of device that created the role.
    author_id id,
    // ID of the role that owns this role.
    owning_role_id id,
    // Is this a "default" role?
    default bool,
}
```

#### Custom Roles

> **Note**: Custom roles are under development and will be
> generally available after MVP.

#### Default Roles

The `setup_default_roles` action creates exactly three default
roles with fixed names.

- `admin`
    - Can create and delete labels
    - Can change label managing roles
    - Can unset AQC network names
    - Typically manages the `operator` role
- `operator`
    - Can assign and revoke labels
    - Can set and unset AQC network names
    - Typically manages the `member` role
- `member`
    - Can create and delete AFC and AQC channels (for labels they
      have been granted permission to use)

**Important**: The owner role (created during team creation) should
be used sparingly. After setting up default roles, the owner
credentials should be stored securely (e.g., in an HSM) and only
used for emergency "break glass" scenarios.

To guard against accidental replays, each default role records a
`DefaultRoleSeeded` fact the first time it is created. Subsequent
attempts to seed the same default role will fail the policy checks
before any storage writes occur, and the managing role supplied to
`setup_default_roles` must already exist on the team.

```policy
// TODO: create these?
fact RoleOwner[role_id id]=>{author_id id}
fact RoleAdmin[role_id id]=>{author_id id}
fact RoleOperator[role_id id]=>{author_id id}
fact RoleMember[role_id id]=>{author_id id}
fact DefaultRoleSeeded[name enum DefaultRoleName]=>{role_id id}

enum DefaultRoleName {
    Admin,
    Operator,
    Member,
}

function default_role_name_to_str(name enum DefaultRoleName) string {
    match name {
        DefaultRoleName::Admin => { return "admin" }
        DefaultRoleName::Operator => { return "operator" }
        DefaultRoleName::Member => { return "member" }
    }
}

// Setup default roles on a team.
action setup_default_roles(owning_role_id id) {
    publish SetupDefaultRole {
        name: DefaultRoleName::Admin,
        owning_role_id: owning_role_id,
    }
    publish SetupDefaultRole {
        name: DefaultRoleName::Operator,
        owning_role_id: owning_role_id,
    }
    publish SetupDefaultRole {
        name: DefaultRoleName::Member,
        owning_role_id: owning_role_id,
    }
}

command SetupDefaultRole {
    fields {
        // The name of the default role.
        name enum DefaultRoleName,
        // The ID of the role that manages this role.
        owning_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_simple_perm(author.device_id, SimplePerm::SetupDefaultRole)

        check exists Role[role_id: this.owning_role_id]
        check !exists DefaultRoleSeeded[name: this.name]

        let name = default_role_name_to_str(this.name)
        let role_id = derive_role_id(envelope)

        match this.name {
            DefaultRoleName::Admin => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: name,
                        author_id: author.device_id,
                        owning_role_id: this.owning_role_id,
                    })

                    assign_perm_to_role(role_id, SimplePerm::AddDevice)
                    assign_perm_to_role(role_id, SimplePerm::RemoveDevice)
                    assign_perm_to_role(role_id, SimplePerm::CreateLabel)
                    assign_perm_to_role(role_id, SimplePerm::DeleteLabel)
                    assign_perm_to_role(role_id, SimplePerm::ChangeLabelManagingRole)
                    assign_perm_to_role(role_id, SimplePerm::AssignRole)
                    assign_perm_to_role(role_id, SimplePerm::RevokeRole)

                    emit RoleCreated {
                        role_id: role_id,
                        name: name,
                        author_id: author.device_id,
                        owning_role_id: this.owning_role_id,
                        default: true,
                    }

                    create DefaultRoleSeeded[
                        name: this.name,
                    ]=>{role_id: role_id}
                }
            }
            DefaultRoleName::Operator => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: name,
                        author_id: author.device_id,
                        owning_role_id: this.owning_role_id,
                    })

                    assign_perm_to_role(role_id, SimplePerm::AssignLabel)
                    assign_perm_to_role(role_id, SimplePerm::RevokeLabel)
                    assign_perm_to_role(role_id, SimplePerm::SetAqcNetworkName)
                    assign_perm_to_role(role_id, SimplePerm::UnsetAqcNetworkName)
                    assign_perm_to_role(role_id, SimplePerm::AssignRole)
                    assign_perm_to_role(role_id, SimplePerm::RevokeRole)

                    emit RoleCreated {
                        role_id: role_id,
                        name: name,
                        author_id: author.device_id,
                        owning_role_id: this.owning_role_id,
                        default: true,
                    }

                    create DefaultRoleSeeded[
                        name: this.name,
                    ]=>{role_id: role_id}
                }
            }
            DefaultRoleName::Member => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: name,
                        author_id: author.device_id,
                        owning_role_id: this.owning_role_id,
                    })

                    assign_perm_to_role(role_id, SimplePerm::CanUseAqc)
                    assign_perm_to_role(role_id, SimplePerm::CreateAqcUniChannel)
                    assign_perm_to_role(role_id, SimplePerm::CreateAqcBidiChannel)

                    assign_perm_to_role(role_id, SimplePerm::CanUseAfc)
                    assign_perm_to_role(role_id, SimplePerm::CreateAfcUniChannel)
                    assign_perm_to_role(role_id, SimplePerm::CreateAfcBidiChannel)

                    emit RoleCreated {
                        role_id: role_id,
                        name: name,
                        author_id: author.device_id,
                        owning_role_id: this.owning_role_id,
                        default: true,
                    }

                    create DefaultRoleSeeded[
                        name: this.name,
                    ]=>{role_id: role_id}
                }
            }
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
// # Foreign Keys
//
// - `device_id` refers to the `Device` fact
// - `role_id` refers to the `Role` fact
//
// # Caveats
//
// This fact is NOT deleted when a role is deleted. Use one of
// the following functions to retrieve the role assigned to
// a device:
// - `try_get_assigned_role`
// - `get_assigned_role`
// - `get_assigned_role_id`
fact AssignedRole[device_id id]=>{role_id id}

// Secondary index over role assignments to support efficient
// queries keyed by `role_id`.
//
// # Invariants
//
// If `RoleAssignmentIndex[role_id: r, device_id: d]` exists,
// then `AssignedRole[device_id: d]=>{role_id: r}` also exists.
//
// # Foreign Keys
//
// - `role_id` refers to the `Role` fact
// - `device_id` refers to the `Device` fact
fact RoleAssignmentIndex[role_id id, device_id id]=>{}

// Records a new role assignment while keeping the index in sync.
finish function create_role_assignment(device_id id, role_id id) {
    create AssignedRole[device_id: device_id]=>{role_id: role_id}
    create RoleAssignmentIndex[role_id: role_id, device_id: device_id]=>{}
}

// Deletes an existing role assignment and its index entry.
finish function delete_role_assignment(device_id id, role_id id) {
    delete AssignedRole[device_id: device_id]
    delete RoleAssignmentIndex[role_id: role_id, device_id: device_id]
}

// Updates a device's role assignment and corresponding index entry.
finish function update_role_assignment(
    device_id id,
    old_role_id id,
    new_role_id id,
) {
    update AssignedRole[device_id: device_id]=>{role_id: old_role_id} to {
        role_id: new_role_id,
    }

    delete RoleAssignmentIndex[
        role_id: old_role_id,
        device_id: device_id,
    ]

    create RoleAssignmentIndex[
        role_id: new_role_id,
        device_id: device_id,
    ]=>{}
}

// Returns the role assigned to the device if it exists.
//
// # Caveats
//
// - It does NOT check whether the device exists.
function try_get_assigned_role(device_id id) optional struct Role {
    let assigned_role = query AssignedRole[device_id: device_id]
    if assigned_role is None {
        return None
    }
    return query Role[role_id: (unwrap assigned_role).role_id]
}

// Returns the role assigned to the device.
//
// # Errors
//
// This function raises a check error if the device has not been
// assigned a role or if the assigned role does not exist.
//
// # Caveats
//
// - It does NOT check whether the device exists.
function get_assigned_role(device_id id) struct Role {
    // NB: We could implement this with `try_get_assigned_role`,
    // but the generated check errors would be much less
    // informative, so we manually implement it instead.

    let assigned_role = check_unwrap query AssignedRole[device_id: device_id]

    // Verify that the assigned role exists.
    //
    // There are two reasons the role might not exist:
    //
    // 1. The role was deleted and the `AssignedRole` fact was
    //    not also deleted (which is currently acceptable since
    //    we do not support prefix deletion).
    // 2. We have an internal consistency error.
    //
    // Option (1) is the most likely and we can't really check
    // for (2) here.
    let role = check_unwrap query Role[role_id: assigned_role.role_id]

    return role
}

// Reports whether the provided role represents the default owner role.
function is_owner(role struct Role) bool {
    return role.default && role.name == "owner"
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

// Returns the ID of the role assigned to the device if it exists.
//
// # Caveats
//
// - It does NOT check whether the device exists.
function try_get_assigned_role_id(device_id id) optional id {
    let role = try_get_assigned_role(device_id)
    if role is None {
        return None
    }
    return Some((unwrap role).role_id)
}

// Assigns the specified role to the device.
//
// It is an error if the device has already been assigned a role.
//
// # Required Permissions
//
// - `AssignRole`
// - `CanAssignRole(role_id)`
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
        check device_has_simple_perm(author.device_id, SimplePerm::AssignRole)
        check can_assign_role(author.device_id, this.role_id)

        // Ensure the target role exists.
        check exists Role[role_id: this.role_id]

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        // Device must not already have a role assigned; use ChangeRole instead.
        check !exists AssignedRole[device_id: this.device_id]

        // Ensure the role index is also clear before creating a new assignment.
        check !exists RoleAssignmentIndex[
            role_id: this.role_id,
            device_id: this.device_id,
        ]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `this.device_id` refers to a device that exists
        // - `this.role_id` refers to a role that exists
        // - `author` is not assigning the role to itself
        // - `author` has the `AssignRole` permission
        // - `author` is allowed to manage `this.role_id`
        // - the device does not already hold `this.role_id`
        finish {
            create_role_assignment(this.device_id, this.role_id)

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
// - `CanRevokeRole(old_role_id)`
// - `CanAssignRole(new_role_id)`
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
        let old_role = check_unwrap query Role[role_id: this.old_role_id]
        check can_revoke_role(author.device_id, this.old_role_id)
        check device_has_simple_perm(author.device_id, SimplePerm::RevokeRole)

        // The author must have permission to revoke the old role.
        check exists Role[role_id: this.new_role_id]
        check can_assign_role(author.device_id, this.new_role_id)
        check device_has_simple_perm(author.device_id, SimplePerm::AssignRole)

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        let current_assignment = check_unwrap query AssignedRole[device_id: this.device_id]
        check current_assignment.role_id == this.old_role_id

        // Ensure the role index reflects the existing assignment before updating it.
        check exists RoleAssignmentIndex[
            role_id: this.old_role_id,
            device_id: this.device_id,
        ]

        if is_owner(old_role) {
            check at_least 2 RoleAssignmentIndex[
                role_id: this.old_role_id,
                device_id: ?,
            ]=>{}
        }

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
            update_role_assignment(
                this.device_id,
                this.old_role_id,
                this.new_role_id,
            )

            emit RoleChanged {
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
// - `CanRevokeRole(role_id)`
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
        check device_has_simple_perm(author.device_id, SimplePerm::RevokeRole)
        check can_revoke_role(author.device_id, this.role_id)

        let role = check_unwrap query Role[role_id: this.role_id]

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        let assignment = check_unwrap query AssignedRole[device_id: this.device_id]
        check assignment.role_id == this.role_id

        // Ensure the assignment index entry exists so we can remove it.
        check exists RoleAssignmentIndex[
            role_id: this.role_id,
            device_id: this.device_id,
        ]

        if is_owner(role) {
            check at_least 2 RoleAssignmentIndex[
                role_id: this.role_id,
                device_id: ?,
            ]=>{}
        }

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `this.device_id` refers to a device that exists
        // - `this.role_id` refers to a role that exists
        // - `author` has the `RevokeRole` permission
        // - `author` is allowed to manage `this.role_id`
        // - the owner role retains at least one assignment after this change
        finish {
            delete_role_assignment(this.device_id, this.role_id)

            emit RoleRevoked {
                device_id: this.device_id,
                role_id: this.role_id,
                author_id: author.device_id,
            }
        }
    }
}
```

### Role Queries

#### `query_team_roles`

```policy
// Emits `QueryTeamRolesResult` for each role on the team.
ephemeral action query_team_roles() {
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
effect QueryTeamRolesResult {
    // The ID of the role.
    role_id id,
    // The name of the role.
    name string,
    // The ID of the device that created the role.
    author_id id,
    // Is this a default role?
    default bool,
}

// A trampoline command to forward data to `QueryTeamRolesResult`.
ephemeral command QueryTeamRoles {
    fields {
        role_id id,
        name string,
        author_id id,
        default bool,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueryTeamRolesResult {
                role_id: this.role_id,
                name: this.name,
                author_id: this.author_id,
                default: this.default,
            }
        }
    }
}
```

#### `query_role_owners`

```policy
// Emits `QueryRoleOwnersResult` for each role that owns the specified role.
ephemeral action query_role_owners(role_id id) {
    map OwnsRole[target_role_id: role_id, owning_role_id: ?] as f {
        let maybe_role = query Role[role_id: f.owning_role_id]
        if maybe_role is Some {
            let role = unwrap maybe_role
            publish QueryRoleOwners {
                role_id: role.role_id,
                name: role.name,
                author_id: role.author_id,
                default: role.default,
            }
        }
    }
}

// Emitted when a role is queried by `query_role_owners`.
effect QueryRoleOwnersResult {
    // The ID of the owning role.
    role_id id,
    // The name of the owning role.
    name string,
    // The ID of the device that created the owning role.
    author_id id,
    // Is this a default role?
    default bool,
}

// A trampoline command to forward data to `QueryRoleOwnersResult`.
ephemeral command QueryRoleOwners {
    fields {
        role_id id,
        name string,
        author_id id,
        default bool,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        finish {
            emit QueryRoleOwnersResult {
                role_id: this.role_id,
                name: this.name,
                author_id: this.author_id,
                default: this.default,
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

            create DeviceGeneration[device_id: owner_key_ids.device_id]=>{generation: 0}

            add_new_device(this.owner_keys, owner_key_ids)

            create_default_role(DefaultRole {
                role_id: owner_role_id,
                name: "owner",
                author_id: author_id,
                // Initially, only the owner role can manage the
                // owner role.
                owning_role_id: owner_role_id,
            })

            // Assign all of the administrative permissions to
            // the owner role.
            assign_perm_to_role(owner_role_id, SimplePerm::AddDevice)
            assign_perm_to_role(owner_role_id, SimplePerm::RemoveDevice)

            assign_perm_to_role(owner_role_id, SimplePerm::CreateLabel)
            assign_perm_to_role(owner_role_id, SimplePerm::DeleteLabel)

            assign_perm_to_role(owner_role_id, SimplePerm::AssignLabel)
            assign_perm_to_role(owner_role_id, SimplePerm::RevokeLabel)

            assign_perm_to_role(owner_role_id, SimplePerm::AssignRole)
            assign_perm_to_role(owner_role_id, SimplePerm::RevokeRole)

            assign_perm_to_role(owner_role_id, SimplePerm::SetAqcNetworkName)
            assign_perm_to_role(owner_role_id, SimplePerm::UnsetAqcNetworkName)

            assign_perm_to_role(owner_role_id, SimplePerm::SetupDefaultRole)
            assign_perm_to_role(owner_role_id, SimplePerm::ChangeRoleManagingRole)
            assign_perm_to_role(owner_role_id, SimplePerm::ChangeLabelManagingRole)
            assign_perm_to_role(owner_role_id, SimplePerm::TerminateTeam)

            // And now make sure that the owner has the owner
            // role, of course.
            create_role_assignment(author_id, owner_role_id)

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
                owning_role_id: owner_role_id,
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

// Deletes the core device facts for `device_id`.
finish function delete_device_core(device_id id) {
    delete Device[device_id: device_id]
    delete DeviceIdentKey[device_id: device_id]
    delete DeviceSignKey[device_id: device_id]
    delete DeviceEncKey[device_id: device_id]
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
        check device_has_simple_perm(author.device_id, SimplePerm::TerminateTeam)

        let current_team_id = team_id()
        check this.team_id == current_team_id

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `TerminateTeam` permission
        // - the requested team matches the currently executing team
        finish {
            delete TeamStart[]

            emit TeamTerminated {
                team_id: current_team_id,
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
// - `CanAssignRole(role_id)` for the initial role, if provided.
action add_device(device_keys struct KeyBundle, initial_role_id optional id) {
    publish AddDevice {
        device_keys: device_keys,
    }
    if initial_role_id is Some {
        let role_id = unwrap initial_role_id
        publish AssignRole {
            device_id: derive_device_key_ids(device_keys).device_id,
            role_id: role_id,
        }
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
        check device_has_simple_perm(author.device_id, SimplePerm::AddDevice)

        let dev_key_ids = derive_device_key_ids(this.device_keys)

        check !exists Device[device_id: dev_key_ids.device_id]
        check !exists DeviceIdentKey[device_id: dev_key_ids.device_id]
        check !exists DeviceSignKey[device_id: dev_key_ids.device_id]
        check !exists DeviceEncKey[device_id: dev_key_ids.device_id]

        let existing_gen = query DeviceGeneration[device_id: dev_key_ids.device_id]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `AddDevice` permission
        // - the key material for `dev_key_ids` is not already
        //   present on the team
        //
        // Depending on whether the device has been seen before,
        // we either seed a new generation counter or reuse the
        // existing one.
        if existing_gen is None {
            finish {
                create DeviceGeneration[device_id: dev_key_ids.device_id]=>{generation: 0}

                add_new_device(
                    this.device_keys,
                    dev_key_ids,
                )
                emit DeviceAdded {
                    device_id: dev_key_ids.device_id,
                    device_keys: this.device_keys,
                }
            }
        } else {
            finish {
                add_new_device(
                    this.device_keys,
                    dev_key_ids,
                )
                emit DeviceAdded {
                    device_id: dev_key_ids.device_id,
                    device_keys: this.device_keys,
                }
            }
        }
    }
}
```

### Removing Devices

Removing the final owner would leave the team without a break-glass
principal, so any attempt to remove the last owner is rejected even if
initiated by another device.

```policy
// Removes a device from the team.
//
// # Required Permissions
//
// - `RemoveDevice`
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
        check device_has_simple_perm(author.device_id, SimplePerm::RemoveDevice)

        // The target device must exist.
        check exists Device[device_id: this.device_id]

        // TODO(eric): check that author dominates target?

        // Clean up optional per-device facts that may or may not
        // exist.
        let assigned_role = query AssignedRole[device_id: this.device_id]
        let aqc_net = query AqcNetId[device_id: this.device_id]
        let device_gen = check_unwrap query DeviceGeneration[device_id: this.device_id]
        let next_gen = device_gen.generation + 1

        if assigned_role is Some {
            let role_id = (unwrap assigned_role).role_id

            // Invariant check.
            check exists RoleAssignmentIndex[
                role_id: role_id,
                device_id: this.device_id,
            ]

            // The assigned role must exist.
            let role = check_unwrap query Role[role_id: role_id]

            // Ensure that a team always has at least one owner.
            if is_owner(role) {
                check at_least 2 RoleAssignmentIndex[
                    role_id: role_id,
                    device_id: ?,
                ]=>{}
            }

            if aqc_net is Some {
                finish {
                    delete AqcNetId[device_id: this.device_id]

                    update DeviceGeneration[device_id: this.device_id]=>{generation: device_gen.generation} to {
                        generation: next_gen
                    }
                    delete_role_assignment(this.device_id, role_id)
                    delete_device_core(this.device_id)

                    emit DeviceRemoved {
                        device_id: this.device_id,
                        author_id: author.device_id,
                    }
                }
            } else {
                finish {
                    update DeviceGeneration[device_id: this.device_id]=>{generation: device_gen.generation} to {
                        generation: next_gen
                    }
                    delete_role_assignment(this.device_id, role_id)
                    delete_device_core(this.device_id)

                    emit DeviceRemoved {
                        device_id: this.device_id,
                        author_id: author.device_id,
                    }
                }
            }
        } else {
            // TODO(eric): Consider adding an index on
            // `device_id` so we can sanity-check that no stray
            // role assignments remain.
            if aqc_net is Some {
                finish {
                    delete AqcNetId[device_id: this.device_id]

                    update DeviceGeneration[device_id: this.device_id]=>{generation: device_gen.generation} to {
                        generation: next_gen
                    }
                    delete_device_core(this.device_id)

                    emit DeviceRemoved {
                        device_id: this.device_id,
                        author_id: author.device_id,
                    }
                }
            } else {
                finish {
                    update DeviceGeneration[device_id: this.device_id]=>{generation: device_gen.generation} to {
                        generation: next_gen
                    }
                    delete_device_core(this.device_id)

                    emit DeviceRemoved {
                        device_id: this.device_id,
                        author_id: author.device_id,
                    }
                }
            }
        }
    }
}

// Reports whether a device can remove itself from the team.
// Owners can only remove themselves if there are other owners
// remaining. Other roles can always remove themselves.
function can_remove_self(device_id id) bool {
    let maybe_role = try_get_assigned_role(device_id)
    if maybe_role is None {
        // Device has no role, can be removed
        return true
    }
    let role = unwrap maybe_role
    if is_owner(role) {
        // Owner can only remove self if there are other owners
        return at_least 2 RoleAssignmentIndex[role_id: role.role_id, device_id: ?]=>{}
    }
    // All other roles can remove themselves
    return true
}
```

## AFC and AQC

### Labels

Labels provide topic segmentation for AFC and AQC. Devices can
only participate in a channel if they have been granted
permission to use the channel's label, either directly or through
their assigned role. Devices can be granted permission to use an
arbitrary number of labels.

```policy
// Records a label.
fact Label[label_id id]=>{name string, author_id id}
```

- `label_id` is a globally unique ID for the label,
  cryptographically derived from the command that created the
  label (see `derive_label_id`).
- `name` is a non-unique, human-readable name for the label.
  E.g., `telemetry`.
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
revoke the label from **any other** devices.

#### Label Management

As previously mentioned, each label is managed by zero or more
roles called the label's _managing roles_. A device that has been
assigned one of the managing roles is allowed to perform the
following:

- Assign the label to *any* device that is allowed to use AQC,
  except itself.
- Assign the label to *any* role that is allowed to use AQC,
  except for the device's current role.
- Revoke the label from *any* device.
- Revoke the label from *any* role.

```policy
// Grants devices who have been assigned the managing role
// permission to "manage" the target label.
//
// # Foreign Keys
//
// - `label_id` refers to the `Label` fact.
// - `managing_role_id` refers to the `Role` fact.
//
// # Caveats
//
// We do not yet support prefix deletion, so this fact is NOT
// deleted when the label or role are deleted. Use
// `can_manage_label` to verify whether a device is allowed to
// manage the label instead of checking this fact directly.
fact CanManageLabel[label_id id, managing_role_id id]=>{}

// Reports whether the device is allowed to manage the label.
//
// # Errors
//
// This function raises a check error if the device has not been
// assigned a role.
//
// # Caveats
//
// - This function does NOT check whether the device exists.
// - This function does NOT check whether the label exists.
//
// # Ensures
//
// If true, `CanManageLabel(label_id, device_role_id)` holds.
function can_manage_label(device_id id, label_id id) bool {
    let device_role_id = get_assigned_role_id(device_id)

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
// - `SimplePerm::ChangeLabelManagingRole`
// - `CanManageLabel(label_id)`
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
        check device_has_simple_perm(author.device_id, SimplePerm::ChangeLabelManagingRole)
        check can_manage_label(author.device_id, this.label_id)

        // Make sure we uphold `CanManageLabel`'s foreign keys.
        check exists Label[label_id: this.label_id]
        check exists Role[role_id: this.managing_role_id]

        check !exists CanManageLabel[
            label_id: this.label_id,
            managing_role_id: this.managing_role_id,
        ]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` is allowed to manage `this.label_id`
        // - `this.managing_role_id` refers to a role that exists
        // - `this.label_id` refers to a label that exists
        finish {
            create CanManageLabel[
                label_id: this.label_id,
                managing_role_id: this.managing_role_id,
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
// - `SimplePerm::ChangeLabelManagingRole`
// - `CanManageLabel(label_id)`
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
        check device_has_simple_perm(author.device_id, SimplePerm::ChangeLabelManagingRole)
        check can_manage_label(author.device_id, this.label_id)

        check exists CanManageLabel[
            label_id: this.label_id,
            managing_role_id: this.managing_role_id,
        ]

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
//   "manage" the label.
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
        check device_has_simple_perm(author.device_id, SimplePerm::CreateLabel)

        // A label's ID is the ID of the command that created it.
        let label_id = derive_label_id(envelope)

        // Make sure we uphold `CanManageLabel`'s foreign keys.
        check exists Role[role_id: this.managing_role_id]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `CreateLabel` permission
        // - `this.managing_role_id` refers to a role that exists
        finish {
            create Label[label_id: label_id]=>{
                name: this.label_name,
                author_id: author.device_id,
            }
            create CanManageLabel[
                label_id: label_id,
                managing_role_id: this.managing_role_id,
            ]=>{}

            emit LabelCreated {
                label_id: label_id,
                label_name: this.label_name,
                label_author_id: author.device_id,
                managing_role_id: this.managing_role_id,
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
// - `CanManageLabel(label_id)`
action delete_label(label_id id) {
    // TODO(eric): Should we add a `reason` field?
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
        check device_has_simple_perm(author.device_id, SimplePerm::DeleteLabel)
        check can_manage_label(author.device_id, this.label_id)

        // We can't query the label after it's been deleted, so
        // make sure we pull all of its info out of the fact
        // database.
        let label = check_unwrap query Label[label_id: this.label_id]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `DeleteLabel` permission
        // - `author` is allowed to manage `this.label_id`
        // - `this.label_id` refers to a label that exists
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
                label_id: label.label_id,
                author_id: author.device_id,
            }
        }
    }
}
```

#### Label Assignment

Labels can be assigned to both roles and devices. Assigning
a label to a role allows all devices who have been assigned that
role to use the label. Assigning a label to a device allows that
specific device to use the label.

Each label can be assigned to zero or more roles and devices *at
the same time*. For example, label `L` can be assigned to roles
`R1` and `R2` at the same time that it is also assigned to device
`D`. Similarly, roles and devices can be assigned zero or more
labels.

The labels assigned to a device and the labels assigned to the
device's role need not be mutually exclusive. They are permitted
to overlap, including having different `ChanOp`s. When
determining whether a device is allowed to use a label, the more
permissive `ChanOp` is used.

##### Label Assignment to Roles

```policy
// Records that a role was granted permission to use a label for
// certain channel operations.
//
// # Foreign Keys
//
// - `label_id` refers to the `Label` fact.
// - `role_id` refers to the `Role` fact.
//
// # Caveats
//
// We do not yet support prefix deletion, so this fact is NOT
// deleted when the label or the role are deleted. Use TODO to
// verify whether a role is allowed to use the label instead of
// checking this fact directly.
fact LabelAssignedToRole[label_id id, role_id id]=>{op enum ChanOp}

// Grants the role permission to use the label.
//
// - It is an error if the author does not have permission to assign
//   this label.
// - It is an error if `role_id` refers to the author's current
//   role.
// - It is an error if the role does not exist.
// - It is an error if the label does not exist.
// - It is an error if the role has already been granted
//   permission to use this label.
//
// # Required Permissions
//
// The author must have the following permissions:
// - `AssignLabel`
// - `CanManageLabel(label_id)`
//
// The target role must have the following permissions:
// - `CanUseAqc`
action assign_label_to_role(role_id id, label_id id, op enum ChanOp) {
    publish AssignLabelToRole {
        role_id: role_id,
        label_id: label_id,
        op: op,
    }
}

// Emitted when the `AssignLabelToRole` command is successfully
// processed.
effect AssignedLabelToRole {
    // The ID of the role that was assigned the label.
    role_id id,
    // The ID of the label that was assigned.
    label_id id,
    // The ID of the device that assigned the label.
    author_id id,
}

command AssignLabelToRole {
    fields {
        // The target role.
        role_id id,
        // The label being assigned to the target role.
        label_id id,
        // The channel operations the role is allowed to use the
        // label for.
        op enum ChanOp,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)

        // Devices are never allowed to assign labels to their
        // current role.
        //
        // Perform this check before we make more fact database
        // queries.
        let assigned_role_id = get_assigned_role_id(author.device_id)
        check assigned_role_id != this.role_id

        // The author must be allowed to assign this label.
        check device_has_simple_perm(author.device_id, SimplePerm::AssignLabel)
        check can_manage_label(author.device_id, this.label_id)

        // The role must be able to use AQC.
        check role_has_simple_perm(this.role_id, SimplePerm::CanUseAqc)

        // Make sure we uphold `AssignedLabelToRole`'s foreign
        // keys.
        //
        // NB: We do not check `exists Role[...]` because
        // `role_has_simple_perm` already checks whether the role
        // exists.
        check exists Label[label_id: this.label_id]
        check !exists LabelAssignedToRole[
            label_id: this.label_id,
            role_id: this.role_id,
        ]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `AssignLabel` permission
        // - `author` is allowed to manage `this.label_id`
        // - `this.role_id` refers to a role that exists
        // - `this.label_id` refers to a label that exists
        // - the label is not already assigned to `this.role_id`
        finish {
            create LabelAssignedToRole[
                label_id: this.label_id,
                role_id: this.role_id,
            ]=>{op: this.op}

            emit AssignedLabelToRole {
                role_id: this.role_id,
                label_id: this.label_id,
                author_id: author.device_id,
            }
        }
    }
}
```

##### Label Assignment to Devices

```policy
// Records that a device was granted permission to use a label
// for certain channel operations.
//
// # Foreign Keys
//
// - `label_id` refers to the `Label` fact.
// - `device_id` refers to the `Device` fact.
//
// # Caveats
//
// We do not yet support prefix deletion, so this fact is NOT
// deleted when the label or the role are deleted. Use TODO to
// verify whether a role is allowed to use the label instead of
// checking this fact directly.
fact LabelAssignedToDevice[label_id id, device_id id]=>{op enum ChanOp, device_gen int}

// Grants the device permission to use the label.
//
// - It is an error if the author does not have the role required
//   to assign this label.
// - It is an error if `device_id` refers to the author (devices
//   are never allowed to assign labels to themselves).
// - It is an error if the device does not exist.
// - It is an error if the label does not exist.
// - It is an error if the device has already been granted
//   permission to use this label for its current generation.
// - It is an error if the device is not permitted to use AQC.
//
// # Required Permissions
//
// - `AssignLabel`
// - `CanManageLabel(label_id)`
action assign_label_to_device(device_id id, label_id id, op enum ChanOp) {
    publish AssignLabelToDevice {
        device_id: device_id,
        label_id: label_id,
        op: op,
    }
}

// Emitted when the `AssignLabelToDevice` command is successfully
// processed.
effect AssignedLabelToDevice {
    // The ID of the device that was assigned the label.
    device id,
    // The ID of the label that was assigned.
    label_id id,
    // The ID of the device that assigned the label.
    author_id id,
}

command AssignLabelToDevice {
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

        check device_has_simple_perm(author.device_id, SimplePerm::AssignLabel)
        check can_manage_label(author.device_id, this.label_id)

        // Make sure we uphold `AssignedLabelToDevice`'s foreign
        // keys.
        check exists Device[device_id: this.device_id]
        check exists Label[label_id: this.label_id]

        // Devices must be fully configured for AQC before labels
        // can be assigned directly to them.
        check can_use_aqc(this.device_id)

        let existing_assignment = query LabelAssignedToDevice[
            label_id: this.label_id,
            device_id: this.device_id,
        ]

        let current_gen = get_device_gen(this.device_id)

        if existing_assignment is Some {
            // Only allow reuse when the stored assignment is
            // from an older device generation.
            let assignment = unwrap existing_assignment
            check assignment.device_gen < current_gen

            // At this point we believe the following to be true:
            //
            // - `author` has the `AssignLabel` permission
            // - `author` is allowed to manage `this.label_id`
            // - `this.device_id` refers to a device that exists
            // - `this.label_id` refers to a label that exists
            // - the existing assignment is stale because the device has
            //   been re-provisioned
            finish {
                update LabelAssignedToDevice[
                    label_id: this.label_id,
                    device_id: this.device_id,
                ]=>{
                    op: assignment.op,
                    device_gen: assignment.device_gen,
                } to {
                    op: this.op,
                    device_gen: current_gen,
                }

                emit AssignedLabelToDevice {
                    device: this.device_id,
                    label_id: this.label_id,
                    author_id: author.device_id,
                }
            }
        } else {
            // At this point we believe the following to be true:
            //
            // - `author` has the `AssignLabel` permission
            // - `author` is allowed to manage `this.label_id`
            // - `this.device_id` refers to a device that exists
            // - `this.label_id` refers to a label that exists
            finish {
                create LabelAssignedToDevice[
                    label_id: this.label_id,
                    device_id: this.device_id,
                ]=>{
                    op: this.op,
                    device_gen: current_gen,
                }

                emit AssignedLabelToDevice {
                    device: this.device_id,
                    label_id: this.label_id,
                    author_id: author.device_id,
                }
            }
        }
    }
}
```

#### Label Revocation

```policy
// Revokes permission to use a label from a role.
//
// - It is an error if the role does not exist.
// - It is an error if the label does not exist.
// - It is an error if the role has not been granted permission
//   to use this label.
//
// # Required Permissions
//
// - `RevokeLabel`
// - `CanManageLabel(label_id)`
action revoke_label_from_role(role_id id, label_id id) {
    publish RevokeLabelFromRole {
        role_id: role_id,
        label_id: label_id,
    }
}

// Emitted when the `RevokeLabelFromRole` command is successfully
// processed.
effect LabelRevokedFromRole {
    // The ID of the role that had the label revoked.
    role_id id,
    // The ID of the label that was revoked.
    label_id id,
    // The ID of the device that revoked the label.
    author_id id,
}

command RevokeLabelFromRole {
    fields {
        // The target role.
        role_id id,
        // The label being assigned to the target device.
        label_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_simple_perm(author.device_id, SimplePerm::RevokeLabel)
        check can_manage_label(author.device_id, this.label_id)

        check exists Role[role_id: this.role_id]
        check exists Label[label_id: this.label_id]
        check exists LabelAssignedToRole[
            label_id: this.label_id,
            role_id: this.role_id,
        ]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `RevokeLabel` permission
        // - `author` is allowed to manage `this.label_id`
        // - `this.role_id` refers to a role that exists
        // - `this.label_id` refers to a label that exists
        // - the label is currently assigned to `this.role_id`
        finish {
            delete LabelAssignedToRole[
                label_id: this.label_id,
                role_id: this.role_id,
            ]

            emit LabelRevokedFromRole {
                role_id: this.role_id,
                label_id: this.label_id,
                author_id: author.device_id,
            }
        }
    }
}

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
// - `CanManageLabel(label_id)`
action revoke_label_from_device(device_id id, label_id id) {
    publish RevokeLabelFromDevice {
        device_id: device_id,
        label_id: label_id,
    }
}

// Emitted when the `RevokeLabelFromDevice` command is
// successfully processed.
effect LabelRevokedFromDevice {
    // The ID of the label that was revoked.
    label_id id,
    // The name of the label that was revoked.
    label_name string,
    // The ID of the author of the label.
    label_author_id id,
    // The ID of the device that revoked the label.
    author_id id,
}

command RevokeLabelFromDevice {
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
        check device_has_simple_perm(author.device_id, SimplePerm::RevokeLabel)
        check can_manage_label(author.device_id, this.label_id)

        // We need to get label info before deleting
        let label = check_unwrap query Label[label_id: this.label_id]

        check exists LabelAssignedToDevice[
            label_id: this.label_id,
            device_id: this.device_id,
        ]

        // At this point we believe the following to be true:
        //
        // - the team is active
        // - `author` has the `RevokeLabel` permission
        // - `author` is allowed to manage `this.label_id`
        // - `this.label_id` refers to a label that exists
        finish {
            delete LabelAssignedToDevice[
                label_id: this.label_id,
                device_id: this.device_id,
            ]

            emit LabelRevokedFromDevice {
                label_id: this.label_id,
                label_name: label.name,
                label_author_id: label.author_id,
                author_id: author.device_id,
            }
        }
    }
}
```

#### Label Lookup

```policy
// Returns the channel operation for a particular label, or `None`
// if the device does not have permission to use the label.
//
// # Caveats
//
// - It does NOT check whether the device exists.
function get_allowed_chan_op_for_label(device_id id, label_id id) optional enum ChanOp {
    // First test to see if the device's role has been granted
    // permission to use the label.
    let role_id = get_assigned_role_id(device_id)
    let assigned_to_role = query LabelAssignedToRole[
        label_id: label_id,
        role_id: role_id,
    ]

    // Now see if the device was directly granted permission
    // to use the label.
    let assigned_to_dev = query LabelAssignedToDevice[
        label_id: label_id,
        device_id: device_id,
    ]

    let role_op = if assigned_to_role is Some {
        : Some((unwrap assigned_to_role).op)
    } else {
        : None
    }
    let device_op = device_assignment_op(device_id, assigned_to_dev)

    if role_op is None {
        return device_op
    }
    if device_op is None {
        return role_op
    }

    let role_op_val = unwrap role_op
    let device_op_val = unwrap device_op

    if chan_op_rank(role_op_val) >= chan_op_rank(device_op_val) {
        return Some(role_op_val)
    }
    return Some(device_op_val)
}

// Returns the channel operation for a device-specific label
// assignment if it matches the device's current generation.
function device_assignment_op(
    device_id id,
    assignment optional struct LabelAssignedToDevice,
) optional enum ChanOp {
    if assignment is None {
        return None
    }
    let assigned = unwrap assignment
    if label_assignment_matches_gen(
        device_id,
        assigned.device_gen,
    ) {
        return Some(assigned.op)
    }
    return None
}

// Reports whether a device's direct label assignment generation
// matches the device's current generation counter.
function label_assignment_matches_gen(
    device_id id,
    assignment_gen int,
) bool {
    let maybe_gen = query DeviceGeneration[device_id: device_id]
    if maybe_gen is None {
        return false
    }
    return (unwrap maybe_gen).generation == assignment_gen
}
```

#### Label Queries

Label queries retrieve information about labels on the team.

See [Query APIs][query-apis] for more information about the query
APIs.

##### `query_label`

Returns a specific label if it exists.

```policy
// Emits `QueryLabelResult` for the label if it exists.
// If the label does not exist then no effects are emitted.
ephemeral action query_label(label_id id) {
    publish QueryLabel {
        label_id: label_id,
    }
}

effect QueryLabelResult {
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}

ephemeral command QueryLabel {
    fields {
        label_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let maybe_label = query Label[label_id: this.label_id]
        if maybe_label is None {
            finish {}
        } else {
            let label = unwrap maybe_label
            finish {
                emit QueryLabelResult {
                    label_id: label.label_id,
                    label_name: label.name,
                    label_author_id: label.author_id,
                }
            }
        }
    }
}
```

##### `query_labels`

Returns a list of all labels that exist in the team.

```policy
// Emits one `QueryLabelsResult` for each label in the team.
// If the team does not have any labels then no effects are
// emitted.
ephemeral action query_labels() {
    map Label[label_id: ?] as f {
        publish QueryLabels {
            label_id: f.label_id,
            label_name: f.name,
            label_author_id: f.author_id,
        }
    }
}

effect QueryLabelsResult {
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}

// Trampoline to forward info to `QueriedLabelsResult`.
ephemeral command QueryLabels {
    fields {
        label_id id,
        label_name string,
        label_author_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueryLabelsResult {
                label_id: this.label_id,
                label_name: this.label_name,
                label_author_id: this.label_author_id,
            }
        }
    }
}
```

##### `query_labels_assigned_to_role`

Returns a list of all labels that have been assigned to
a particular role.

```policy
// Emits `QueryLabelsAssignedToRoleResult` for all labels that
// have been assigned to the role.
// If the role has not been assigned any labels, then no effects
// are emitted.
ephemeral action query_labels_assigned_to_role(role_id id) {
    // TODO: make this query more efficient when policy supports
    // it. The key order is optimized for `delete`.
    map LabelAssignedToRole[label_id: ?, role_id: ?] as f {
        if f.role_id == role_id {
            // Skip entries where the Label has been deleted.
            // This is necessary because LabelAssignedToRole
            // facts are not yet deleted because we do not have
            // prefix deletion.
            if exists Label[label_id: f.label_id] {
                let label = check_unwrap query Label[label_id: f.label_id]
                publish QueryLabelsAssignedToRole {
                    role_id: f.role_id,
                    label_id: f.label_id,
                    label_name: label.name,
                    label_author_id: label.author_id,
                }
            }
        }
    }
}

effect QueryLabelsAssignedToRoleResult {
    // The role the label is assigned to.
    role_id id,
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}

ephemeral command QueryLabelsAssignedToRole {
    fields {
        role_id id,
        label_id id,
        label_name string,
        label_author_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        if !exists Role[role_id: this.role_id] {
            // TODO(eric): Or should we raise a check error?
            finish {}
        } else {
            finish {
                emit QueryLabelsAssignedToRoleResult {
                    role_id: this.role_id,
                    label_id: this.label_id,
                    label_name: this.label_name,
                    label_author_id: this.label_author_id,
                }
            }
        }
    }
}
```

##### `query_labels_assigned_to_device`

```policy
// Emits `QueryLabelsAssignedToDeviceResult` for all labels the
// device has been granted permission to use.
ephemeral action query_labels_assigned_to_device(device_id id) {
    // TODO: make this query more efficient when policy supports
    // it. The key order is optimized for `delete`.
    map LabelAssignedToDevice[label_id: ?, device_id: ?] as f {
        if f.device_id == device_id {
            if label_assignment_matches_gen(f.device_id, f.device_gen) {
                let label = check_unwrap query Label[label_id: f.label_id]
                publish QueryLabelsAssignedToDevice {
                    device_id: f.device_id,
                    label_id: f.label_id,
                    label_name: label.name,
                    label_author_id: label.author_id,
                }
            }
        }
    }
}

effect QueryLabelsAssignedToDeviceResult {
    // The device's unique ID.
    device_id id,
    // The label's unique ID.
    label_id id,
    // The label name.
    label_name string,
    // The ID of the device that created the label.
    label_author_id id,
}

ephemeral command QueryLabelsAssignedToDevice {
    fields {
        device_id id,
        label_id id,
        label_name string,
        label_author_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        if !exists Device[device_id: this.device_id] {
            // TODO(eric): Or should we raise a check error?
            finish {}
        } else {
            finish {
                emit QueryLabelsAssignedToDeviceResult {
                    device_id: this.device_id,
                    label_id: this.label_id,
                    label_name: this.label_name,
                    label_author_id: this.label_author_id,
                }
            }
        }
    }
}
```

#### Label Directionality

AFC and AQC channels are either bidirectional or unidirectional.
In a unidirectional channel one peer is permitted to send data
and the other to receive data.

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

// Returns a numeric rank for `ChanOp` so permissions can be
// compared. Higher ranks are more permissive.
function chan_op_rank(op enum ChanOp) int {
    match op {
        ChanOp::RecvOnly => { return 0 }
        ChanOp::SendOnly => { return 1 }
        ChanOp::SendRecv => { return 2 }
    }
}
```

### AFC

#### AFC Bidirectional Channel Creation

Creates a bidirectional AFC channel for off-graph messaging. This is an
ephemeral command, which means that it can only be emitted within an
ephemeral session so that it is not added to the graph of commands.
Furthermore, it cannot persist any changes to the factDB.

The `create_afc_bidi_channel` action creates the `ChannelKeys`,
encapsulates them for the peer and the author, and sends the
encapsulations through the `AfcCreateBidiChannel` command. When
processing the command, the device will decapsulate their keys and store
them in the shared memory DB.

```policy
ephemeral action create_afc_bidi_channel(peer_id id, label_id id) {
    let parent_cmd_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author = get_device(author_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let ch = afc::create_bidi_channel(
        parent_cmd_id,
        author.enc_key_id,
        author_id,
        peer_enc_pk,
        peer_id,
        label_id,
    )

    publish AfcCreateBidiChannel {
        peer_id: peer_id,
        label_id: label_id,
        peer_encap: ch.peer_encap,
        channel_key_id: ch.key_id,
    }
}

// Reports whether the devices have permission to create
// a bidirectional AFC channel with each other.
//
// # Caveats
//
// - It does NOT check whether the devices exist.
function can_create_afc_bidi_channel(device1 id, device2 id, label_id id) bool {
    // Devices cannot create channels with themselves.
    //
    // This should have been caught by the AFC FFI, so check
    // instead of just returning false.
    check device1 != device2

    // Both devices must have permissions to read (recv) and
    // write (send) data.
    let device1_op = get_allowed_chan_op_for_label(device1, label_id)
    if device1_op is None {
        return false
    }
    if (unwrap device1_op) != ChanOp::SendRecv {
        return false
    }

    let device2_op = get_allowed_chan_op_for_label(device2, label_id)
    if device2_op is None {
        return false
    }
    if (unwrap device2_op) != ChanOp::SendRecv {
        return false
    }

    return true
}

// Emitted when the author of a bidirectional AFC channel
// successfully processes the `AfcCreateBidiChannel` command.
effect AfcBidiChannelCreated {
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
    author_secret_id id,
    // The channel key ID.
    channel_key_id id,
}

// Emitted when the peer of a bidirectional AFC channel
// successfully processes the `AfcCreateBidiChannel` command.
effect AfcBidiChannelReceived {
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
}

ephemeral command AfcCreateBidiChannel {
    fields {
        // The channel peer's device ID.
        peer_id id,
        // The label applied to the channel.
        label_id id,
        // The channel peer's encapsulated KEM shared secret.
        peer_encap bytes,
        // The channel key ID.
        channel_key_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_simple_perm(author.device_id, SimplePerm::CreateAfcBidiChannel)
        let peer = get_device(this.peer_id)

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // Check that both devices have been granted permission
        // to use the label for for send and recv.
        check can_create_afc_bidi_channel(author.device_id, peer.device_id, label.label_id)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_device_id = device::current_device_id()

        if current_device_id == author.device_id {
            // We're the channel author.
            let peer_enc_pk = get_enc_pk(peer.device_id)

            finish {
                emit AfcBidiChannelCreated {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_id: peer.device_id,
                    peer_enc_pk: peer_enc_pk,
                    label_id: label.label_id,
                    channel_key_id: this.channel_key_id,
                }
            }
        } else if current_device_id == peer.device_id {
            // We're the channel peer.
            let author_enc_pk = get_enc_pk(author.device_id)

            finish {
                emit AfcBidiChannelReceived {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    author_enc_pk: author_enc_pk,
                    peer_id: peer.device_id,
                    peer_enc_key_id: peer.enc_key_id,
                    label_id: label.label_id,
                    encap: this.peer_encap,
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

#### AFC Unidirectional Channel Creation

Creates a unidirectional AFC channel. This is an ephemeral command,
which means that it can only be emitted within an ephemeral session and
is not added to the graph of commands. Furthermore, it does not persist
any changes to the factDB.

The `create_afc_uni_channel` action creates the `ChannelKey`,
encapsulates it for the peer, and sends the encapsulation through the
`AfcCreateUniChannel` command. When processing the command, the
corresponding recipient will decapsulate their key and store it in the
shared memory DB.

```policy
ephemeral action create_afc_uni_channel(sender_id id, receiver_id id, label_id id) {
    let parent_cmd_id = perspective::head_id()
    let author = get_device(device::current_device_id())
    let peer_id = select_peer_id(author.device_id, sender_id, receiver_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let ch = afc::create_uni_channel(
        parent_cmd_id,
        author.enc_key_id,
        peer_enc_pk,
        sender_id,
        receiver_id,
        label_id,
    )

    publish AfcCreateUniChannel {
        sender_id: sender_id,
        receiver_id: receiver_id,
        label_id: label_id,
        peer_encap: ch.peer_encap,
        channel_key_id: ch.key_id,
    }
}

// Emitted when the author of a unidirectional AFC channel
// successfully processes the `AfcCreateUniChannel` command.
effect AfcUniChannelCreated {
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
    // The channel key ID.
    channel_key_id id,
}

// Emitted when the peer of a unidirectional AFC channel
// successfully processes the `AfcCreateUniChannel` command.
effect AfcUniChannelReceived {
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
}

ephemeral command AfcCreateUniChannel {
    fields {
        // The device ID of the participant that can send data.
        sender_id id,
        // The device ID of the participant that can receive
        // data.
        receiver_id id,
        // The label applied to the channel.
        label_id id,
        // The channel peer's encapsulated KEM shared secret.
        peer_encap bytes,
        // The ID of the AFC channel key.
        channel_key_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let author = get_author(envelope)
        check device_has_simple_perm(author.device_id, SimplePerm::CreateAfcUniChannel)

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

        // The label must exist.
        let label = check_unwrap query Label[label_id: this.label_id]

        // Check that both devices have been granted permission
        // to use the label for their respective directions.
        check can_create_afc_uni_channel(this.sender_id, this.receiver_id, label.label_id)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_device_id = device::current_device_id()

        if current_device_id == author.device_id {
            // We authored this command.
            let peer_enc_pk = get_enc_pk(peer_id)

            finish {
                emit AfcUniChannelCreated {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    sender_id: this.sender_id,
                    receiver_id: this.receiver_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_enc_pk: peer_enc_pk,
                    label_id: label.label_id,
                }
            }
        } else if current_device_id == peer.device_id {
            // We're the intended recipient of this command.
            let author_enc_pk = get_enc_pk(author.device_id)

            finish {
                emit AfcUniChannelReceived {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    sender_id: this.sender_id,
                    receiver_id: this.receiver_id,
                    author_enc_pk: author_enc_pk,
                    peer_enc_key_id: peer.enc_key_id,
                    label_id: label.label_id,
                    encap: this.peer_encap,
                }
            }
        } else {
            // This is an off-graph session command, so only the
            // communicating peers should process this command.
            check false
        }
    }
}

// Reports whether the devices have permission to create
// a unidirectional AFC channel with each other.
function can_create_afc_uni_channel(sender_id id, receiver_id id, label_id id) bool {
    // Devices cannot create channels with themselves.
    //
    // This should have been caught by the AFC FFI, so check
    // instead of just returning false.
    check sender_id != receiver_id

    // The writer must have permissions to write (send) data.
    let writer_op = get_allowed_chan_op_for_label(sender_id, label_id)
    if writer_op is None {
        return false
    }
    match unwrap writer_op {
        ChanOp::RecvOnly => { return false }
        ChanOp::SendOnly => {}
        ChanOp::SendRecv => {}
    }

    // The reader must have permission to read (receive) data.
    let reader_op = get_allowed_chan_op_for_label(receiver_id, label_id)
    if reader_op is None {
        return false
    }
    match unwrap reader_op {
        ChanOp::RecvOnly => {}
        ChanOp::SendOnly => { return false }
        ChanOp::SendRecv => {}
    }

    return true
}
```

### AQC

#### Overview

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
```

#### Network IDs

Each device that wants to participate in an AQC channel must be
assigned a _network identifier_. A network identifier is an
opaque string that is used to identify the device on the network.
This can be a hostname, an IP address, or any other string that
that operating system understands.

```policy
// Stores a device's associated network identifier for AQC.
fact AqcNetId[device_id id]=>{net_id string}

function can_use_aqc(device_id id) bool {
    // A device can use AQC if it has an AQC network ID.
    return exists AqcNetId[device_id: device_id]
}

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
        check device_has_simple_perm(author.device_id, SimplePerm::SetAqcNetworkName)
        let device = get_device(this.device_id)
        check device_has_simple_perm(author.device_id, SimplePerm::SetAqcNetworkName)

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

### UnsetAqcNetworkName

Dissociates an AQC network name and address from a device.

```policy
action unset_aqc_network_name(device_id id) {
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
        check device_has_simple_perm(author.device_id, SimplePerm::UnsetAqcNetworkName)
        let device = get_device(this.device_id)
        check device_has_simple_perm(author.device_id, SimplePerm::UnsetAqcNetworkName)

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

#### `query_aqc_net_id`

Returns the AQC nework ID for a device.

```policy
ephemeral action query_aqc_net_id(device_id id) {
    publish QueryAqcNetId {
        device_id: device_id,
    }
}

effect QueryAqcNetIdResult {
    // Network name assigned to the device.
    net_id optional string,
}

ephemeral command QueryAqcNetId {
    fields {
        // ID of device whose network name is being queried.
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Check that the team is active and return the author's
        // info if they exist in the team.
        let author = get_device(this.device_id)
        let net_id = aqc_net_id(author.device_id)

        finish {
            emit QueryAqcNetIdResult {
                net_id: net_id,
            }
        }
    }
}
```

#### `query_aqc_network_names`

Returns all associated AQC network IDs.

```policy
ephemeral action query_aqc_network_names() {
    map AqcNetId[device_id: ?] as f {
        publish QueryAqcNetworkNames {
            net_id: f.net_id,
            device_id: f.device_id,
        }
    }
}

effect QueryAqcNetworkNamesResult {
    // AQC network name assigned to device.
    net_id string,
    // Device ID of the device with assigned network name.
    device_id id,
}

ephemeral command QueryAqcNetworkNames {
    fields {
        // AQC network name assigned to device.
        net_id string,
        // Device ID of device with assigned network name.
        device_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is a local query API.
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        finish {
            emit QueryAqcNetworkNamesResult {
                net_id: this.net_id,
                device_id: this.device_id,
            }
        }
    }
}
```

### AQC Bidirectional Channel Creation

Creates a bidirectional AQC channel for off-graph messaging.

```policy
ephemeral action create_aqc_bidi_channel(peer_id id, label_id id) {
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

// Reports whether the devices have permission to create
// a bidirectional AQC channel with each other.
//
// # Caveats
//
// - It does NOT check whether the devices exist.
function can_create_aqc_bidi_channel(device1 id, device2 id, label_id id) bool {
    // Devices cannot create channels with themselves.
    //
    // This should have been caught by the AQC FFI, so check
    // instead of just returning false.
    check device1 != device2

    // Both devices must have permissions to read (recv) and
    // write (send) data.
    let device1_op = get_allowed_chan_op_for_label(device1, label_id)
    if device1_op is None {
        return false
    }
    if (unwrap device1_op) != ChanOp::SendRecv {
        return false
    }

    let device2_op = get_allowed_chan_op_for_label(device2, label_id)
    if device2_op is None {
        return false
    }
    if (unwrap device2_op) != ChanOp::SendRecv {
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

```policy
ephemeral command AqcCreateBidiChannel {
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
        check device_has_simple_perm(author.device_id, SimplePerm::CreateAqcBidiChannel)
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

### AQC Unidirectional Channel Creation

Creates a unidirectional AQC channel for off-graph messaging.

```policy
ephemeral action create_aqc_uni_channel(sender_id id, receiver_id id, label_id id) {
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

```policy
ephemeral command AqcCreateUniChannel {
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
        check device_has_simple_perm(author.device_id, SimplePerm::CreateAqcUniChannel)

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
        // to use the label for their respective directions.
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
    if writer_op is None {
        return false
    }
    match unwrap writer_op {
        ChanOp::RecvOnly => { return false }
        ChanOp::SendOnly => {}
        ChanOp::SendRecv => {}
    }

    // The reader must have permission to read (receive) data.
    let reader_op = get_allowed_chan_op_for_label(receiver_id, label_id)
    if reader_op is None {
        return false
    }
    match unwrap reader_op {
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

[//]: # (links)

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
