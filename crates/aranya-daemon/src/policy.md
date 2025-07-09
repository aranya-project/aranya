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
- **Authorization** uses two patterns: operation-based for most
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

- **Single-key facts** (e.g., `Device[device_id id]`) allow
  exactly one fact per key value.
- **Composite-key facts** (e.g., `AssignedRole[device_id id,
  role_id id]`) allow exactly one fact per key combination.
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
function must_find_device(device_id id) struct Device {
    let device = check_unwrap try_find_device(device_id)
    return device
}

// Collection of public Device Keys for a device.
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

#### Query Device Roles

Queries the roles assigned to a device.

```policy
// Emits `QueryDeviceRolesResult` for each role assigned to the
// device.
action query_device_roles(device_id id) {
    map AssignedRole[device_id: device_id, role_id: ?] as f {
        publish QueryDeviceRoles {
            device_id: f.device_id,
            role_id: f.role_id,
        }
    }
}

// Emitted when a device's roles are queried by
// `query_device_roles`.
effect QueryDeviceRolesResult {
    // The role's ID.
    role_id id,
    // The role's name.
    name string,
    // The ID of the device that created the role.
    author_id id,
    // Is this a default role?
    default bool,
}

// A trampoline that forwards `device_id` and `role_id` to the
// effect.
command QueryDeviceRoles {
    fields {
        device_id id,
        role_id id,
    }

    // TODO(eric): We don't really need to call `seal_command`
    // or `open_envelope` here since this is an local query API.
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
        // we don't need to use `must_find_device` or anything
        // like that.
        let device_keys = must_find_device_keybundle(this.device_id)

        finish {
            emit QueryDeviceKeyBundleResult {
                device_keys: device_keys,
            }
        }
    }
}
```

## Roles and Permissions
<!-- Section contains: Role facts, operations, assignment/revocation, default roles -->

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
//
// INVARIANT: Each operation maps to exactly one role at a time.
// The single-key structure ensures one-to-one mapping.
fact OpRequiresRole[op string]=>{role_id id}

// Shorthand for `update OpRequiresRole`.`
finish function update_op_requires_role(
    op string,
    old_role_id id,
    new_role_id id,
) {
    update OpRequiresRole[op: op]=>{
        role_id: old_role_id,
    } to {
        role_id: new_role_id,
    }
}

// Returns the device corresponding with the author of the
// envelope without checking whether it is authorized to perform
// any operations.
//
// In general, you should use `get_authorized_device` instead.
function get_possibly_unauthorized_device(evp struct Envelope) struct Device {
    let device = must_find_device(envelope::author_id(evp))
    return device
}

// Reports whether a device has permission to perform an
// operation.
//
// In most cases you should not need to use this function
// directly. Use `get_authorized_device` instead.
function can_perform_op(device_id id, op string) bool {
    let req = query OpRequiresRole[op: op]
    if req is None {
        return false
    }
    let role_id = (unwrap req).role_id
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
    let device = get_possibly_unauthorized_device(evp)
    check can_perform_op(device.device_id, op)
    return device
}
```

Devices cannot change which operation a command requires, but
they _can_ change which role is associated with the operation.

```policy
// Updates (or creates) an operation -> role mapping.
action update_operation(op string, role_id id) {
    publish UpdateOperation {
        op: op,
        new_role_id: role_id,
    }
}

// Emitted when `UpdateOperation` is successfully processed.
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
        new_role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // TODO(eric): I'm not entirely sure we want anybody
        // with the requisite role for "UpdateOperation" to be
        // able to change *every* op -> role mapping. This is
        // a very powerful operation: for example, a device with
        // the requisite role for "UpdateOperation" could
        // "downgrade" the role required to perform other
        // operations.
        //
        // Should we hide this API for MVP?
        let author = get_authorized_device(envelope, "UpdateOperation")

        // The new role must already exist.
        let role = check_unwrap query Role[role_id: this.new_role_id]
        let new_role_id = role.role_id

        let req = query OpRequiresRole[op: this.op]
        if req is Some {
            // The operation already exists, so update the role.
            let old_role_id = (unwrap req).role_id
            finish {
                update OpRequiresRole[op: this.op]=>{
                    role_id: old_role_id,
                } to {
                    role_id: new_role_id,
                }

                emit OperationUpdated {
                    op: this.op,
                    role_id: new_role_id,
                    author_id: author.device_id,
                }
            }
        } else {
            // Create a new operation -> role mapping.
            finish {
                create OpRequiresRole[op: this.op]=>{role_id: new_role_id}

                emit OperationUpdated {
                    op: this.op,
                    role_id: new_role_id,
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

// Returns `Some(managing_role_id)` if the device can manage
// `target_role_id`, or `None` otherwise.
// TODO(eric): I'm not a huge fan of this name.
function get_managing_role_id(device_id id, target_role_id id) optional id {
    let record = query CanManageRole[target_role_id: target_role_id]
    if record is None {
        return None
    }
    let role_id = (unwrap record).managing_role_id

    let is_assigned_role = exists AssignedRole[device_id: device_id, role_id: role_id]
    if !is_assigned_role {
        return None
    }
    return Some(role_id)
}

// Reports whether the device can manage the specified role.
//
// If you need to get the managing role ID, use
// `get_managing_role_id` instead.
function can_manage_role(device_id id, target_role_id id) bool {
    return get_managing_role_id(device_id, target_role_id) is Some
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
        // operation. In fact, a "ChangeRoleManagingRole"
        // operation would break role managing since each
        // operation requires exactly one role.
        //
        // TODO(eric): Is this analysis correct?
        let author = get_possibly_unauthorized_device(envelope)

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

### Authorization Patterns

This policy uses two distinct authorization patterns that serve
different purposes:

#### Operation-Based Authorization

Most commands use operation-based authorization, where the author
must have a role that has been granted permission to perform
a specific operation:

    let author = get_authorized_device(envelope, "OperationName")

This pattern provides flexibility - the owner can reassign
operations to different roles as organizational needs change.

#### Managing-Role-Based Authorization

Role and label assignment commands use a different pattern based
on the managing role relationship:

    // For role assignment
    check can_manage_role(author.device_id, target_role_id)

    // For label assignment
    check can_manage_label(author.device_id, label_id)

This pattern avoids circular dependencies that would arise with
operation-based auth. Without it, you would need a role to assign
that same role, creating an impossible bootstrap scenario.

**Note**: Devices are always prohibited from assigning roles or
labels to themselves, regardless of their permissions. This
prevents privilege escalation attacks.

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

        let author = get_authorized_device(envelope, "SetupDefaultRole")
        let role_id = derive_role_id(envelope)

        // For "admin"
        let update_op_role_id = (check_unwrap query OpRequiresRole[op: "UpdateOperation"]).role_id
        let create_label_role_id = (check_unwrap query OpRequiresRole[op: "CreateLabel"]).role_id
        let delete_label_role_id = (check_unwrap query OpRequiresRole[op: "DeleteLabel"]).role_id
        let change_label_managing_role_id = (check_unwrap query OpRequiresRole[op: "ChangeLabelManagingRole"]).role_id

        // For "admin" and "operator"
        let set_aqc_network_name_id = (check_unwrap query OpRequiresRole[op: "SetAqcNetworkName"]).role_id
        let unset_aqc_network_name_id = (check_unwrap query OpRequiresRole[op: "UnsetAqcNetworkName"]).role_id

        // For "operator"
        let assign_label_role_id = (check_unwrap query OpRequiresRole[op: "AssignLabel"]).role_id
        let revoke_label_role_id = (check_unwrap query OpRequiresRole[op: "RevokeLabel"]).role_id


        // For "member"
        let aqc_create_uni_channel_role_id = (check_unwrap query OpRequiresRole[op: "AqcCreateUniChannel"]).role_id
        let aqc_create_bidi_channel_role_id = (check_unwrap query OpRequiresRole[op: "AqcCreateBidiChannel"]).role_id

        match this.name {
            "admin" => {
                finish {
                    create_default_role(DefaultRole {
                        role_id: role_id,
                        name: this.name,
                        author_id: author.device_id,
                        managing_role_id: this.managing_role_id,
                    })

                    update_op_requires_role("AddDevice", update_op_role_id, role_id)
                    update_op_requires_role("CreateLabel", create_label_role_id, role_id)
                    update_op_requires_role("DeleteLabel", delete_label_role_id, role_id)
                    update_op_requires_role("ChangeLabelManagingRole", change_label_managing_role_id, role_id)
                    update_op_requires_role("SetAqcNetworkName", set_aqc_network_name_id, role_id)
                    update_op_requires_role("UnsetAqcNetworkName", unset_aqc_network_name_id, role_id)

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

                    update_op_requires_role("AssignLabel", assign_label_role_id, role_id)
                    update_op_requires_role("RevokeLabel", revoke_label_role_id, role_id)
                    update_op_requires_role("SetAqcNetworkName", set_aqc_network_name_id, role_id)
                    update_op_requires_role("UnsetAqcNetworkName", unset_aqc_network_name_id, role_id)

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

                    update_op_requires_role("AqcCreateUniChannel", aqc_create_uni_channel_role_id, role_id)
                    update_op_requires_role("AqcCreateBidiChannel", aqc_create_bidi_channel_role_id, role_id)

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

A device can be assigned zero or more roles.

```policy
// Records that a device has been assigned a role.
//
// INVARIANT: Composite key ensures each device-role pair is unique.
// A device cannot be assigned the same role multiple times.
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

        // Devices are authorized to assign roles iff they have
        // been assigned the managing role for the role being
        // assigned. This negates the need for an "AssignRole"
        // operation. In fact, an "AssignRole" operation would
        // break role assignment since each operation requires
        // exactly one role.
        //
        // TODO(eric): Is this analysis correct?
        let author = get_possibly_unauthorized_device(envelope)

        // Devices cannot assign roles to themselves.
        check author.device_id != this.device_id

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
        // The ID of the role being revoked.
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        // Devices are authorized to revoke roles iff they have
        // been assigned the managing role for the role being
        // revoked. This negates the need for a "RevokeRole"
        // operation. In fact, a "RevokeRole" operation would
        // break role revocation since each operation requires
        // exactly one role.
        //
        // TODO(eric): Is this analysis correct?
        let author = get_possibly_unauthorized_device(envelope)

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

### Role Queries

```policy
// Emits `QueryTeamRoles` for each role on the team.
action query_team_roles() {
    map Role[role_id: ?] as f {
        publish QueryTeamRoles { role_id: f.role_id }
    }
}

// Emitted when a role is queried by `query_team_roles`.
effect QueriedTeamRole {
    // The ID of the role.
    role_id id,
    // The name of the role.
    name string,
    // The ID of the device that created the role.
    author_id id,
    // Is this a default role?
    default bool,
}

command QueryTeamRoles {
    fields {
        role_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        check team_exists()

        let role = check_unwrap query Role[role_id: this.role_id]

        finish {
            emit QueriedTeamRole {
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
// Indicates that `CreateTeam` has been published.
//
// At first glance this fact is seemingly redundant, since the ID
// of the `CreateTeam` command is the "graph ID," meaning without
// a `CreateTeam` command the graph cannot exist.
//
// However, this fact is required to ensure that we reject all
// subsequent `CreateTeam` commands.
//
// INVARIANT: Empty key makes this a singleton - only one instance
// can exist. This enforces:
// - Only one team per graph
// - Team creation fails if a team already exists
// - Team termination is irreversible within the same graph
// Fact type: Singleton (empty key)
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

            // Assign all the default operations to the owner
            // role.
            create OpRequiresRole[op: "AddDevice"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "RemoveDevice"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "CreateLabel"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "DeleteLabel"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "AssignLabel"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "RevokeLabel"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "SetAqcNetworkName"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "UnsetAqcNetworkName"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "AqcCreateBidiChannel"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "AqcCreateUniChannel"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "SetupDefaultRole"]=>{role_id: owner_role_id}
            create OpRequiresRole[op: "ChangeLabelManagingRole"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "UpdateOperation"]=>{role_id: owner_role_id}

            create OpRequiresRole[op: "TerminateTeam"]=>{role_id: owner_role_id}

            // And now make sure that the owner has the owner
            // role, of course.
            create AssignedRole[
                device_id: author_id,
                role_id: owner_role_id,
            ]=>{}

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
            // TODO(eric): emit OperationUpdated..?
        }
    }
}

// Adds the device to the team.
finish function add_new_device(
    kb struct KeyBundle,
    keys struct DevKeyIds,
) {
    // TODO: check that `kb` matches `keys`.

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
        let team_id = team_id()

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
// Adds a device to the Team.
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

        let author = get_authorized_device(envelope, "AddDevice")

        let dev_key_ids = derive_device_key_ids(this.device_keys)

        // The device must not already exist.
        check try_find_device(dev_key_ids.device_id) is None

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

        let author = get_authorized_device(envelope, "RemoveDevice")
        let device_id = must_find_device(this.device_id).device_id

        // TODO(eric): check that author dominates target?

        finish {
            delete Device[device_id: device_id]
            delete DeviceIdentKey[device_id: device_id]
            delete DeviceSignKey[device_id: device_id]
            delete DeviceEncKey[device_id: device_id]

            // TODO(eric): We can't delete these yet because the
            // storage layer does not yet support prefix deletion.
            // See https://github.com/aranya-project/aranya-core/issues/229
            //
            // delete AssignedRole[device_id: device_id, role_id: ?]
            // delete AssignedLabel[label_id: ?, device_id: device_id]

            // TODO(eric): We *should* be deleting this, but we
            // don'y really have a good way to do that yet.
            //
            // It is a runtime error to delete a non-existent
            // fact and a device might not have this fact if it
            // doesn't use AQC, so we have to conditionally
            // delete `AqcNetId`.
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
            // let has_net_id = exists AqcNetId[device_id: device_id]
            // if has_net_id {
            //     finish {
            //         // Delete all the device facts.
            //         delete AqcNetId[device_id: device_id]
            //     }
            // } else {
            //     finish {
            //         // Delete all the device facts.
            //     }
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
            // delete AqcNetId[device_id: device_id]

            emit DeviceRemoved {
                device_id: this.device_id,
            }
        }
    }
}
```

#### Technical Limitations

Due to current storage layer limitations (see [issue
#229](https://github.com/aranya-project/aranya-core/issues/229)),
device removal cannot cascade delete the following facts:

- `AssignedRole` facts (role assignments)
- `AssignedLabel` facts (label assignments)
- `AqcNetId` facts (network identifiers)

These orphaned facts remain in the database but reference
non-existent devices. This is a known limitation that will be
addressed when the storage layer supports prefix deletion.

**CRITICAL**: Until this is resolved, orphaned assignments remain
in the database. When querying role or label assignments, you MUST
first verify the device exists using `try_find_device()` or
`must_find_device()`. Failing to do so could lead to security
vulnerabilities by treating removed devices as active.

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
        //
        // TODO(eric): Or how about just if you have the managing
        // role then you can change the managing role for the
        // label?
        check author.device_id == label.author_id

        let ctx = check_unwrap query CanManageLabel[label_id: label.label_id]
        let old_managing_role_id = ctx.managing_role_id

        // Make sure the role exists.
        let role = check_unwrap query Role[role_id: this.managing_role_id]
        let new_managing_role_id = this.managing_role_id

        finish {
            update CanManageLabel[label_id: label.label_id]=>{
                managing_role_id: old_managing_role_id,
            } to {
                managing_role_id: new_managing_role_id,
            }
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
//
// INVARIANT: Composite key ensures each label-device pair is unique.
// A device can have only one permission type (SendOnly, RecvOnly,
// or SendRecv) per label.
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
// Stores a device's associated network identifier for AQC.
fact AqcNetId[device_id id]=>{net_id string}

// Returns the device's AQC network identifier, if it exists.
function aqc_net_id(device_id id) optional string {
    let f = query AqcNetId[device_id: device_id]
    if f is Some {
        return Some((unwrap f).net_id)
    }
    return None
}

// TODO(eric): Why do we call it both a "network ID" and
// "network name"?

action set_aqc_network_name(device_id id, net_id string) {
    publish SetAqcNetworkName {
        device_id: device_id,
        net_id: net_id,
    }
}

effect AqcNetworkNameSet {
    device_id id,
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

        let author = get_authorized_device(envelope, "SetAqcNetworkName")
        let device = must_find_device(this.device_id)

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

        let author = get_authorized_device(envelope, "UnsetAqcNetworkName")
        let device = must_find_device(this.device_id)

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
        let author = must_find_device(this.device_id)
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
