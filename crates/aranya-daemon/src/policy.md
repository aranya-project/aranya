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

* Admin:
  * Assign/revoke Operator role.

* Operator:
  * Add (new) / remove Member.

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

### QueryDevicesOnTeam
Queries devices on team.

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
        finish {
            emit QueryDevicesOnTeamResult {
                device_id: this.device_id,
            }
        }
    }
}
```

### QueryDeviceRole
Queries device role.

```policy
action query_device_role(device_id id) {
    publish QueryDeviceRole {
        device_id: device_id,
    }
}

effect QueryDeviceRoleResult {
    role enum Role,
}

command QueryDeviceRole {
    fields {
        device_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        // Check that the team is active and return the author's info if they exist in the team.
        let author = get_valid_device(this.device_id)

        finish {
            emit QueryDeviceRoleResult {
                role: author.role,
            }
        }
    }
}
```

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
