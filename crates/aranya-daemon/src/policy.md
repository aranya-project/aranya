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
  * Define/undefine AFC label.
  * Assign/revoke AFC label.
  * Set/unset AFC address&name.

* Admin:
  * Assign/revoke Operator role.
  * Define/undefine AFC label.
  * Revoke AFC label.
  * Unset AFC network identifier.

* Operator:
  * Add (new) / remove Member.
  * Define AFC label.
  * Assign/revoke AFC label.
  * Set/unset AFC address&name.

* Member:
  * Create/delete AFC channel.

**Invariants**:

- Owner is the "root device" (has all permissions except sending data on AFC channel).
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
use afc
use crypto
use device
use envelope
use idam
use perspective
```

### Enums & Structs

```policy
// Defines the roles a team member may have.
enum Role {
    Owner,
    Admin,
    Operator,
    Member,
}

// Valid channel operations that a Member can get assigned to.
enum ChanOp {
    ReadOnly,
    WriteOnly,
    ReadWrite,
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
```

### Facts

```policy
// A device on the team.
fact Device[device_id id]=>{role enum Role, sign_key_id id, enc_key_id id}

// A device's public IdentityKey
fact DeviceIdentKey[device_id id]=>{key bytes}

// A device's public SigningKey.
fact DeviceSignKey[device_id id]=>{key_id id, key bytes}

// A device's public EncryptionKey.
fact DeviceEncKey[device_id id]=>{key_id id, key bytes}

// Indicates that the team has been terminated.
fact TeamEnd[]=>{}

// Records an AFC label that has been defined for use.
fact Label[label int]=>{}

// Records that A device is allowed to use an AFC label.
fact AssignedLabel[label int, device_id id]=>{op enum ChanOp}

// Stores a Member's associated network identifier for AFC.
fact AfcMemberNetworkId[device_id id]=>{net_identifier string}

// Stores a Member's associated network identifier for AQC.
fact AqcMemberNetworkId[device_id id]=>{net_identifier string}
```

### Functions

```policy
// Check if there is an existing device.
// Returns the device struct if so, otherwise returns `None`.
function find_existing_device(device_id id) optional struct Device {
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

    // Return the resulting device struct for further checks.
    return device
}

// Sanity checks the device per the stated invariants.
function get_valid_device(device_id id) struct Device {
    // Check to see if team is active.
    check !exists TeamEnd[]=> {}

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

// Verify team member has `Role::Owner`
function is_owner(role enum Role) bool {
    return role == Role::Owner
}

// Verify team member has `Role::Admin`
function is_admin(role enum Role) bool {
    return role == Role::Admin
}

// Verify team member has `Role::Operator`
function is_operator(role enum Role) bool {
    return role == Role::Operator
}

// Verify team member has `Role::Member`
function is_member(role enum Role) bool {
    return role == Role::Member
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

// Opens an envelope with the author's public SigningKey, and returns the contained serialized
// basic command once its been verified.
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

#### AFC Functions

```policy
// Reports whether `label` has the valid format for an AFC label, which is an unsigned, 32-bit integer.
function is_valid_label(label int) bool {
    return label >= 0 && label <= 4294967295
}

// Returns the channel operation for a particular label.
function get_allowed_op(device_id id, label int) enum ChanOp {
    let assigned_label = check_unwrap query AssignedLabel[label: label, device_id: device_id]
    return assigned_label.op
}

// Reports whether the devices have permission to create a bidirectional channel with each other.
function can_create_afc_bidi_channel(device1 id, device2 id, label int) bool {
    let device1_op = get_allowed_op(device1, label)
    let device2_op = get_allowed_op(device2, label)

    // Label must be valid.
    check is_valid_label(label)
    // Members can't create channels with themselves.
    check device1 != device2

    // Both devices must have permissions to encrypt and decrypt data.
    check device1_op == device2_op
    check device1_op == ChanOp::ReadWrite

    return true
}

// Returns the device's public EncryptionKey.
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

// Reports whether the devices have permission to create a unidirectional channel with each other.
function can_create_afc_uni_channel(writer_id id, reader_id id, label int) bool {
    let writer_op = get_allowed_op(writer_id, label)
    let reader_op = get_allowed_op(reader_id, label)

     // Label must be valid.
    check is_valid_label(label)
    // Members can't create channels with themselves.
    check writer_id != reader_id

    // Writer must have permissions to encrypt data.
    check writer_op == ChanOp::WriteOnly ||
        writer_op == ChanOp::ReadWrite
    // Reader must have permission to decrypt data.
    check reader_op == ChanOp::ReadOnly ||
        reader_op == ChanOp::ReadWrite

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

        finish {
            add_new_device(this.owner_keys, owner_key_ids, Role::Owner)

            emit TeamCreated {
                owner_id: author_id,
            }
        }
    }
}

// Adds the device to the Team.
finish function add_new_device(key_bundle struct KeyBundle, key_ids struct KeyIds, role enum Role) {
    create Device[device_id: key_ids.device_id]=>{
        role: role,
        sign_key_id: key_ids.sign_key_id,
        enc_key_id: key_ids.enc_key_id,
    }

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
        // Check that the team is active and return the author's info if they exist in the team.
        let author = get_valid_device(envelope::author_id(envelope))
        // Only the Owner can close the Team
        check is_owner(author.role)

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

```policy
// Adds a Member to the Team.
action add_member(device_keys struct KeyBundle){
    publish AddMember {
        device_keys: device_keys,
    }
}

// A Member was added to the Team.
effect MemberAdded {
    // The id of the device to be added.
    device_id id,
    // The device's set of public DeviceKeys.
    device_keys struct KeyBundle,
}

command AddMember {
    fields {
        // The new device's public DeviceKeys.
        device_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        // Derive the key IDs from the provided KeyBundle.
        let device_key_ids = derive_device_key_ids(this.device_keys)

        // Only Operator and Owner can add a Member.
        check is_operator(author.role) || is_owner(author.role)
        // Check that the Member doesn't already exist.
        check find_existing_device(device_key_ids.device_id) is None

        finish {
            add_new_device(this.device_keys, device_key_ids, Role::Member)

            emit MemberAdded {
                device_id: device_key_ids.device_id,
                device_keys: this.device_keys,
            }
        }
    }
}
```

**Invariants**:

- Members can only be added by Operators and Owners.
- Non-Member roles must first be added as a Member and can then get assigned to a higher role.


## RemoveMember

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
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Operators and Owners can remove a Member
        check is_operator(author.role) || is_owner(author.role)
        // Check that the device is a Member
        check is_member(device.role)

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
    delete Device[device_id: device_id]
    delete DeviceIdentKey[device_id: device_id]
    delete DeviceSignKey[device_id: device_id]
    delete DeviceEncKey[device_id: device_id]
}
```

**Invariants**:

- Members can only be removed by Operators and Owners.
- Removing non-Members requires revoking their higher role so the device is made into a Member first.


## AssignRole

```policy
// Assigns the specified role to the device.
action assign_role(device_id id, role enum Role){
    match role {
        Role::Owner => {
            // Assigns the Owner role.
            publish AssignOwner {
                device_id: device_id,
            }
        }
        Role::Admin => {
            // Assigns the Admin role.
            publish AssignAdmin {
                device_id: device_id,
            }
        }
        Role::Operator => {
            // Assigns the Operator role.
            publish AssignOperator {
                device_id: device_id,
            }
        }
        _ => { check false }
    }
}
```

### AssignOwner

```policy
// A device was assigned with the Owner role.
effect OwnerAssigned {
    device_id id,
}

command AssignOwner{
    fields {
        // The assigned device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only an Owner can assign the Owner role.
        check is_owner(author.role)
        // The device must not already have the Owner role.
        check device.role != Role::Owner

        finish {
            assign_role(device, Role::Owner)

            emit OwnerAssigned {
                device_id: this.device_id,
            }
        }
    }
}

// Assigns the device to the specified role.
finish function assign_role(device struct Device, role enum Role) {
    update Device[device_id: device.device_id]=>{
        role: device.role,
        sign_key_id: device.sign_key_id,
        enc_key_id: device.enc_key_id,
        } to {
            role: role,
            sign_key_id: device.sign_key_id,
            enc_key_id: device.enc_key_id,
        }
}
```

### AssignAdmin

```policy
// A device was assigned with the Admin role.
effect AdminAssigned {
    device_id id,
}

command AssignAdmin{
    fields {
        // The assigned device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only an Owner can assign the Admin role.
        check is_owner(author.role)
        // The device must not already have the Admin role.
        check device.role != Role::Admin

        finish {
            assign_role(device, Role::Admin)

            emit AdminAssigned {
                device_id: this.device_id,
            }
        }
    }
}
```


### AssignOperator

```policy
// A device was assigned with the Operator role.
effect OperatorAssigned {
    device_id id,
}

command AssignOperator{
    fields {
        // The assigned device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners and Admins can assign the Operator role.
        check is_owner(author.role) || is_admin(author.role)
        // The device must not already have the Operator role.
        check device.role != Role::Operator

        finish {
            assign_role(device, Role::Operator)

            emit OperatorAssigned {
                device_id: this.device_id,
            }
        }
    }
}
```


**Invariants**:

- devices cannot assign roles to themselves.
- Only Owners can assign the Owner role.
- Only Owners can assign the Admin role.
- Only Owners and Admins can assign the Operator role.


## RevokeRole

```policy
// Revokes the specified role from the device.
action revoke_role(device_id id, role enum Role){
    match role {
        Role::Owner => {
            // Revokes the Owner role.
            publish RevokeOwner {
                device_id: device_id,
            }
        }
        Role::Admin => {
            // Revokes the Admin role.
            publish RevokeAdmin {
                device_id: device_id,
            }
        }
        Role::Operator => {
            // Revokes the Operator role.
            publish RevokeOperator {
                device_id: device_id,
            }
        }
        _ => { check false }
    }
}
```

### RevokeOwner

```policy
// The Owner role was revoked from A device.
effect OwnerRevoked {
    device_id id,
}

command RevokeOwner{
    fields {
        // The revoked device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Owner can only revoke the role from itself.
        check author.device_id == this.device_id
        // Check that the device is an Owner.
        check is_owner(author.role)

        finish {
            revoke_role(device)

            emit OwnerRevoked {
                device_id: this.device_id,
            }
        }
    }
}

// Revokes the specified role from the device. This automatically sets their role to Member instead.
finish function revoke_role(device struct Device) {
    update Device[device_id: device.device_id]=>{
        role: device.role,
        sign_key_id: device.sign_key_id,
        enc_key_id: device.enc_key_id,
        } to {
            role: Role::Member,
            sign_key_id: device.sign_key_id,
            enc_key_id: device.enc_key_id,
            }
}
```

### RevokeAdmin

```policy
// The Admin role was revoke from A device.
effect AdminRevoked {
    device_id id,
}

command RevokeAdmin{
    fields {
        // The revoked device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners can revoke the Admin role.
        check is_owner(author.role)
        // Check that the device is an Admin.
        check is_admin(device.role)

        finish {
            revoke_role(device)

            emit AdminRevoked {
                device_id: this.device_id,
            }
        }
    }
}
```

### RevokeOperator

```policy
// The Operator role was revoke from A device.
effect OperatorRevoked {
    device_id id,
}

command RevokeOperator{
    fields {
        // The revoked device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners and Admins can revoke the Operator role.
        check is_owner(author.role) || is_admin(author.role)
        // Check that the device is an Operator.
        check is_operator(device.role)

        finish {
            revoke_role(device)

            emit OperatorRevoked {
                device_id: this.device_id,
            }
        }
    }
}
```

**Invariants**:

- Revoking a role from A device will assign them with the Member role.
- If all Owners revoke their own role, it is possible for the team to be left without any Owners.
- As long as there is at least one Owner in the team, new devices can continue to be added and
  assigned to the different roles.
- Only Owners can revoke the Admin role.
- Only Owners and Admins can revoke the Operator role.

## DefineLabel

Establishes a whitelist of AFC labels that can be assigned to Members.

```policy
// Defines an AFC label.
action define_label(label int) {
    publish DefineLabel {
        label: label,
    }
}

effect LabelDefined {
    label int,
}

command DefineLabel {
    fields {
        // The label being added.
        label int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))

        // Owners, Admins and Operators can define AFC labels.
        check is_owner(author.role) || is_admin(author.role) || is_operator(author.role)
        // It must be a valid AFC label that does not already exist.
        check is_valid_label(this.label)
        check !exists Label[label: this.label]

        finish {
            create Label[label: this.label]=>{}

            emit LabelDefined {
                label: this.label,
            }
        }
    }
}
```

**Invariants**:

- Only Members cannot define AFC labels.
- Owners, Admins and Operators are allowed to define AFC labels.
- AFC labels must be unsigned, 32-bit integers.

## UndefineLabel

Removes an AFC label from the whitelist. This operation will result in the AFC label revocation across all Members that were assigned to it.


```policy
// Undefines an AFC label.
action undefine_label(label int) {
    // In a single transaction, publish the command to undefine the AFC label as well as a
    // sequence of AFC label revocation commands to revoke it from each Member role.
    publish UndefineLabel {
        label: label,
    }

    // TODO: add back when transaction bug is resolved
    // map AssignedLabel[label: label, device_id: ?] as member {
    //     action revoke_label(member.device_id, label)
    // }
}

effect LabelUndefined {
    label int,
}

command UndefineLabel {
    fields {
        // The label being undefined.
        label int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))

        // Only Owners and Admins can undefine AFC labels.
        check is_owner(author.role) || is_admin(author.role)
        check exists Label[label: this.label]

        finish {
            delete Label[label: this.label]

            emit LabelUndefined {
                label: this.label,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Admins are allowed to undefine AFC labels.


## AssignLabel

Assigns an "AFC" label to a Member.

```policy
// Assigns the device a `label` to .
action assign_label(device_id id, label int, op enum ChanOp) {
    publish AssignLabel {
        device_id: device_id,
        label: label,
        op: op,
    }
}

effect LabelAssigned {
    // The device being assigned the label.
    device_id id,
    // The label being assigned.
    label int,
    // The operation that can be performed with the label.
    op enum ChanOp,
}

command AssignLabel {
    fields {
        // The device being assigned the label.
        device_id id,
        // The label being assigned.
        label int,
        // The operations that can be performed with the label.
        op enum ChanOp,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners and Operators can assign AFC labels to Members.
        check is_owner(author.role) || is_operator(author.role)
        check is_member(device.role)

        // Obviously it must be a valid label.
        check is_valid_label(this.label)
        // The label must exist.
        check exists Label[label: this.label]

        finish {
            create AssignedLabel[label: this.label, device_id: device.device_id]=>{op: this.op}

            emit LabelAssigned {
                device_id: device.device_id,
                label: this.label,
                op: this.op,
            }
        }
    }
}
```

**Invariants**:

- Labels must be unsigned, 32-bit integers.
- Only Owners and Operators are allowed to assign labels.
- Only Members can be assigned AFC labels.
- Only labels that are defined are allowed to be assigned.

## RevokeLabel
Revokes an AFC label from a Member. Note that peers communicating with this Member over an AFC
channel under the revoked label should delete their channel once the label revocation command is
received.

```policy
// Revokes the device's access to the AFC `label`.
action revoke_label(device_id id, label int) {
    publish RevokeLabel {
        device_id: device_id,
        label: label,
    }
}

effect LabelRevoked {
    // The device for whom the label is being revoked.
    device_id id,
    // The label being revoked.
    label int,
}

command RevokeLabel {
    fields {
        // The device for whom the label is being revoked.
        device_id id,
        // The label being revoked.
        label int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners, Admins, and Operators are allowed to revoke a label from a Member.
        check is_owner(author.role) || is_admin(author.role) || is_operator(author.role)
        check is_member(device.role)

        // Verify that AFC label has been assigned to this Member
        check exists AssignedLabel[label: this.label, device_id: device.device_id]

        finish {
            delete AssignedLabel[label: this.label, device_id: device.device_id]

            emit LabelRevoked {
                device_id: device.device_id,
                label: this.label,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators can revoke labels from Members.
- Only a label that was assigned can be revoked.


## SetAfcNetworkName
Associates a network name and address to a Member for use in AFC.

```policy
action set_afc_network_name (device_id id, net_identifier string) {
    publish SetAfcNetworkName {
        device_id: device_id,
        net_identifier: net_identifier,
    }
}

effect AfcNetworkNameSet {
    device_id id,
    net_identifier string,
}

command SetAfcNetworkName {
    fields {
        device_id id,
        net_identifier string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners and Operators can associate a network name.
        check is_owner(author.role) || is_operator(author.role)
        // Only Members can be associated a network name.
        check is_member(device.role)

        // TODO: check that the network identifier is valid.
        let net_id_exists = query AfcMemberNetworkId[device_id: this.device_id]

        if net_id_exists is Some {
            let net_id = unwrap net_id_exists
            finish {
                update AfcMemberNetworkId[device_id: this.device_id]=>{net_identifier: net_id.net_identifier} to {
                    net_identifier: this.net_identifier
                }

                emit AfcNetworkNameSet {
                    device_id: device.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        }
        else {
            finish {
                create AfcMemberNetworkId[device_id: this.device_id]=>{net_identifier: this.net_identifier}

                emit AfcNetworkNameSet {
                    device_id: device.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators can assign AFC network names to Members.
- Members can only be assigned to one AFC network name.

## UnsetAfcNetworkName
Dissociates an AFC network name and address from a Member.

```policy
action unset_afc_network_name (device_id id) {
    publish UnsetAfcNetworkName {
        device_id: device_id,
    }
}

effect AfcNetworkNameUnset {
    device_id id,
}

command UnsetAfcNetworkName {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners, Admins, and Operators can unset a Member's network name.
        check is_owner(author.role) || is_admin(author.role) || is_operator(author.role)
        check is_member(device.role)

        check exists AfcMemberNetworkId[device_id: this.device_id]
        finish {
            delete AfcMemberNetworkId[device_id: this.device_id]

            emit AfcNetworkNameUnset {
                device_id: device.device_id,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators Operators can unset AFC network names from Members.

## SetAqcNetworkName
Associates a network name and address to a Member for use in AQC.

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
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners and Operators can associate a network name.
        check is_owner(author.role) || is_operator(author.role)
        // Only Members can be associated a network name.
        check is_member(device.role)

        // TODO: check that the network identifier is valid.
        let net_id_exists = query AqcMemberNetworkId[device_id: this.device_id]

        if net_id_exists is Some {
            let net_id = unwrap net_id_exists
            finish {
                update AqcMemberNetworkId[device_id: this.device_id]=>{net_identifier: net_id.net_identifier} to {
                    net_identifier: this.net_identifier
                }

                emit AqcNetworkNameSet {
                    device_id: device.device_id,
                    net_identifier: this.net_identifier,
                }
            }
        }
        else {
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

**Invariants**:

- Only Owners and Operators can assign AQC network names to Members.
- Members can only be assigned to one AQC network name.

## UnsetAqcNetworkName
Dissociates an AQC network name and address from a Member.

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
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owners, Admins, and Operators can unset a Member's network name.
        check is_owner(author.role) || is_admin(author.role) || is_operator(author.role)
        check is_member(device.role)

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

**Invariants**:

- Only Owners and Operators Operators can unset AQC network names from Members.

## CreateChannel

### AfcCreateBidiChannel
Creates a bidirectional "AFC" channel for off-graph messaging. This is an ephemeral command, which
means that it can only be emitted within an ephemeral session so that it is not added to the graph
of commands. Furthermore, it cannot persist any changes to the factDB.

The `create_afc_bidi_channel` action creates the `ChannelKeys`, encapsulates them for the peer and the
author, and sends the encapsulations through the `AfcCreateBidiChannel` command. When processing the
command, the device will decapsulate their keys and store them in the shared memory DB.

```policy
action create_afc_bidi_channel(peer_id id, label int) {
    let parent_cmd_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author = get_valid_device(author_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let channel = afc::create_bidi_channel(
        parent_cmd_id,
        author.enc_key_id,
        author_id,
        peer_enc_pk,
        peer_id,
        label,
    )

    publish AfcCreateBidiChannel {
        peer_id: peer_id,
        label: label,
        peer_encap: channel.peer_encap,
        channel_key_id: channel.key_id,
    }
}

effect AfcBidiChannelCreated {
    parent_cmd_id id,
    author_id id,
    author_enc_key_id id,
    peer_id id,
    peer_enc_pk bytes,
    label int,
    channel_key_id id,
}

effect AfcBidiChannelReceived {
    parent_cmd_id id,
    author_id id,
    author_enc_pk bytes,
    peer_id id,
    peer_enc_key_id id,
    label int,
    encap bytes,
}

command AfcCreateBidiChannel {
    fields {
        peer_id id,
        label int,
        peer_encap bytes,
        channel_key_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let peer = check_unwrap find_existing_device(this.peer_id)

        // Only Members can create AFC channels with other peer Members
        check is_member(author.role)
        check is_member(peer.role)

        // Members must be different and both must have bidirectional permissions over valid label.
        check can_create_afc_bidi_channel(author.device_id, peer.device_id, this.label)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_device_id = device::current_device_id()

        // We authored this command.
        if current_device_id == author.device_id {
            let peer_enc_pk = get_enc_pk(peer.device_id)
            finish {
                emit AfcBidiChannelCreated {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_id: peer.device_id,
                    peer_enc_pk: peer_enc_pk,
                    label: this.label,
                    channel_key_id: this.channel_key_id,
                }
            }
        }
        // We're the intended recipient of this command.
        else if current_device_id == peer.device_id {
            let author_enc_pk = get_enc_pk(author.device_id)
            finish {
                emit AfcBidiChannelReceived {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    author_enc_pk: author_enc_pk,
                    peer_id: peer.device_id,
                    peer_enc_key_id: peer.enc_key_id,
                    label: this.label,
                    encap: this.peer_encap,
                }
            }
        }
        // Only the communicating peers should process this command.
        else {
            check false
        }
    }
}
```

**Invariants**:

- Only Members can create and communicate over AFC channels.
- Members can only create channels for the labels they've been assigned.
- Members can only communicate over a bidi channel when they have `ChanOp::ReadWrite` permission.


### AfcCreateUniChannel
Creates a unidirectional "AFC" channel. This is an ephemeral command, which means that it can only
be emitted within an ephemeral session and is not added to the graph of commands. Furthermore, it
does not persist any changes to the factDB.

The `create_afc_uni_channel` action creates the `ChannelKey`, encapsulates it for the peer, and sends
the encapsulation through the `AfcCreateUniChannel` command. When processing the command, the
corresponding recipient will decapsulate their key and store it in the shared memory DB.

```policy
action create_afc_uni_channel(writer_id id, reader_id id, label int) {
    let parent_cmd_id = perspective::head_id()
    let author = get_valid_device(device::current_device_id())
    let peer_id = select_peer_id(author.device_id, writer_id, reader_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let channel = afc::create_uni_channel(
        parent_cmd_id,
        author.enc_key_id,
        peer_enc_pk,
        writer_id,
        reader_id,
        label,
    )

    publish AfcCreateUniChannel {
        writer_id: writer_id,
        reader_id: reader_id,
        label: label,
        peer_encap: channel.peer_encap,
        channel_key_id: channel.key_id,
    }
}

effect AfcUniChannelCreated {
    parent_cmd_id id,
    author_id id,
    writer_id id,
    reader_id id,
    author_enc_key_id id,
    peer_enc_pk bytes,
    label int,
    channel_key_id id,
}

effect AfcUniChannelReceived {
    parent_cmd_id id,
    author_id id,
    writer_id id,
    reader_id id,
    author_enc_pk bytes,
    peer_enc_key_id id,
    label int,
    encap bytes,
}

command AfcCreateUniChannel {
    fields {
        // The DeviceID of the side that can encrypt data.
        writer_id id,
        // The DeviceID of the side that can decrypt data.
        reader_id id,
        // The label to use.
        label int,
        // The encapsulated key for the recipient of the command.
        peer_encap bytes,
        // The ID of the AFC channel key.
        channel_key_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))

        // Ensure that the author is half the channel and return the peer's info.
        let peer_id = select_peer_id(author.device_id, this.writer_id, this.reader_id)
        let peer = check_unwrap find_existing_device(peer_id)

        // Only Members can create AFC channels with other peer Members
        check is_member(author.role)
        check is_member(peer.role)

        // Both devices must have valid permissions.
        check can_create_afc_uni_channel(this.writer_id, this.reader_id, this.label)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_device_id = device::current_device_id()

        // We authored this command.
        if current_device_id == author.device_id {
            let peer_enc_pk = get_enc_pk(peer_id)

            finish {
                emit AfcUniChannelCreated {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    writer_id: this.writer_id,
                    reader_id: this.reader_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_enc_pk: peer_enc_pk,
                    label: this.label,
                    channel_key_id: this.channel_key_id,
                }
            }
        }
        // We're the intended recipient of this command.
        else if current_device_id == peer.device_id {
            let author_enc_pk = get_enc_pk(author.device_id)

            finish {
                emit AfcUniChannelReceived {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.device_id,
                    writer_id: this.writer_id,
                    reader_id: this.reader_id,
                    author_enc_pk: author_enc_pk,
                    peer_enc_key_id: peer.enc_key_id,
                    label: this.label,
                    encap: this.peer_encap,
                }
            }
        }
        // Only the communicating peers should process this command.
        else { check false}
    }
}
```

**Invariants**:

- Members can only create channels for the labels they've been assigned.
- Members can only create unidirectional channels when the writer side has either
  `ChanOp::ReadWrite` or `ChanOp::WriteOnly` permissions for the label and the reader side has
  either `ChanOp::ReadWrite` or `ChanOp::ReadOnly` permissions for the label.


<!-- TODO: add delete channel commands? -->





<!-- The commented out code below this line is not part of the beta, but could be needed for MVP -->

<!-- ## AddDevice
The `add_owner`, `add_admin`, `add_operator`, and `add_device` actions add an Owner, Admin, Operator,
and Member to the team, respectively.

### AddOwner

```policy
// Adds an Owner to the Team.
action add_owner(owner_keys struct KeyBundle){
    publish AddOwner {
        owner_keys: owner_keys,
    }
}

// An Owner was added to the Team.
effect OwnerAdded {
    device_id id,
    device_keys struct KeyBundle,
}

command AddOwner{
    fields {
        // The new owner's public DeviceKeys.
        owner_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        // Only Owner can add an Owner.
        check is_owner(author.role)

        // Derive the key IDs from the provided KeyBundle.
        let owner_key_ids = derive_device_key_ids(this.owner_keys)
        // Check that the Owner doesn't already exist.
        check find_existing_device(owner_key_ids.device_id) is None

        finish {
            add_new_device(this.owner_keys, owner_key_ids, Role::Owner)

            emit OwnerAdded {
                device_id: owner_key_ids.device_id,
                device_keys: this.owner_keys,
            }
        }
    }
}
```

### AddAdmin

```policy
// Adds a Admin to the Team.
action add_admin(admin_keys struct KeyBundle){
    publish AddAdmin {
        admin_keys: admin_keys,
    }
}

// A Admin was added to the Team.
effect AdminAdded {
    device_id id,
    device_keys struct KeyBundle,
}

command AddAdmin{
    fields {
        // The new admin's public DeviceKeys.
        admin_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        // Only Owner can add an Admin.
        check is_owner(author.role)

        // Derive the key IDs from the provided KeyBundle.
        let admin_key_ids = derive_device_key_ids(this.admin_keys)
        // Check that the Admin doesn't already exist.
        check find_existing_device(admin_key_ids.device_id) is None

        finish {
            add_new_device(this.admin_keys, admin_key_ids, Role::Admin)

            emit AdminAdded {
                device_id: admin_key_ids.device_id,
                device_keys: this.admin_keys,
            }
        }
    }
}
```

### AddOperator

```policy
// Adds a Operator to the Team.
action add_operator(operator_keys struct KeyBundle){
    publish AddOperator {
        operator_keys: operator_keys,
    }
}

// A Operator was added to the Team.
effect OperatorAdded {
    device_id id,
    device_keys struct KeyBundle,
}

command AddOperator{
    fields {
        // The new operator's public DeviceKeys.
        operator_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        // Only Admin can add an Operator.
        check is_admin(author.role)

        // Derive the key IDs from the provided KeyBundle.
        let operator_key_ids = derive_device_key_ids(this.operator_keys)
        // Check that the Admin doesn't already exist.
        check find_existing_device(operator_key_ids.device_id) is None

        finish {
            add_new_device(this.operator_keys, operator_key_ids, Role::Operator)

            emit OperatorAdded {
                device_id: device_key_ids.device_id,
                device_keys: this.operator_keys,
            }
        }
    }
}
```

**Invariants**:

- Owners can only be added by Owners or through the initial `CreateTeam` command.
- Admins can only be added by Owners.
- Operators can only be added by Admins.
- No role can add themselves.


## RemoveDevice
The `remove_owner`, `remove_admin`, `remove_operator`, and `remove_device` actions remove an Admin, Operator, and Member from the team, respectively.

### RemoveOwner

```policy
// Removes an Owner from the Team.
action remove_owner(device_id id){
    publish RemoveOwner {
        device_id: device_id,
    }
}

// An Owner was removed from the Team.
effect OwnerRemoved {
    device_id id,
}

command RemoveOwner{
    fields {
        // The removed device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))

        // Owner can only be remove by itself.
        check author.device_id == this.device_id
        // Check that the device is an Owner.
        check is_owner(author.role)

        finish {
            remove_device(this.device_id)

            emit OwnerRemoved {
                device_id: this.device_id,
            }
        }
    }
}
```

### RemoveAdmin

```policy
// Removes an Admin from the Team.
action remove_admin(device_id id){
    publish RemoveAdmin {
        device_id: device_id,
    }
}

// An Admin was removed from the Team.
effect AdminRemoved {
    device_id id,
}

command RemoveAdmin{
    fields {
        // The removed device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Owner can remove an Admin.
        check is_owner(author.role)
        // Check that the device is an Admin.
        check is_admin(device.role)

        finish {
            remove_device(this.device_id)

            emit AdminRemoved {
                device_id: this.device_id,
            }
        }
    }
}
```

### RemoveOperator

```policy
// Removes a Operator from the Team.
action remove_operator(device_id id){
    publish RemoveAdmin {
        device_id: device_id,
    }
}

// A Operator was removed from the Team.
effect OperatorRemoved {
    device_id id,
}

command RemoveOperator{
    fields {
        // The removed device's ID.
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        let device = check_unwrap find_existing_device(this.device_id)

        // Only Admin can remove a Operator
        check is_admin(author.role)
        // Check that the device is a Operator
        check is_operator(device.role)

        finish {
            remove_device(this.device_id)

            emit OperatorRemoved {
                device_id: this.device_id,
            }
        }
    }
}
```

**Invariants**:

- Owners cannot remove other Owners, but they can remove themselves.
- Admins can only be removed by Owners.
- Operators can only be removed by Admins or Owners.

## SendMessage

```policy
action send_message(plaintext string) {
    // Encryption uses the command's ParentID, which is the current head.
    let parent_id = perspective::head_id()
    // Generate a new key to use for message encryption.
    let key = idam::generate_group_key()
    // The author's public SigningKey is needed for encryption.
    let author_id = device::current_device_id()
    let author_sign_pk = unwrap query DeviceSignKey[device_id: author_id]
    let ciphertext = idam::encrypt_message(parent_id, plaintext, key.wrapped, author_sign_pk.key)
    publish Message{
        ciphertext: ciphertext,
        wrapped_key: key.wrapped,
    }
}
effect MessageReceived {
    device ID,
    plaintext bytes,
}
command Message {
    fields {
        ciphertext bytes,
        wrapped_key bytes,
    }
    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }
    policy {
        let author = get_valid_device(envelope::author_id(envelope))
        // Only A device can send a message
        check is_member(author.role)
        let author_sign_pk = check_unwrap query DeviceSignKey[device_id: author.device_id]
        let plaintext = idam::decrypt_message(
            parent_id,
            this.ciphertext,
            this.wrapped_key,
            author_sign_pk.key,
        )
        finish {
            emit MessageReceived{
                device: author.device_id,
                plaintext: plaintext,
            }
        }
    }
}
```
-->
