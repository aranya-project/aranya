---
policy-version: 1
---

# Default Policy Template

TODO:
- Verify action signatures, effects and commands struct fields are all correct.
- Are we going to continue referring to off-graph messaging as APS even though it means nothing?
- Add all missing checks and remove/update existing checks.
- Check and update all invariants.
- Add recall blocks

## Roles & Permissions

The MVP will likely support multiple role assignments per user, but we restrict to 1 role per user 
for the beta. Hence, for the beta product, role assignment commands below can be thought of as 
promoting the user's one role, while role revocation commands are a way to demote it. 

* Owner:
  * Initialize/terminate Team.
  * Add (new) / remove Members.
  * Assign/revoke Owner role.
  * Assign/revoke Admin role.
  * Assign/revoke Operator role.
  * Define/undefine APS label.
  * Assign/revoke APS label.
  * Set/unset APS address&name.

* Admin:
  * Assign/revoke Operator role.
  * Define/undefine APS label.
  * Set/unset APS address&name.

* Operator:
  * Add (new) / remove Member.
  * Define APS label.
  * Assign/revoke APS label.
  * Set/unset APS address&name.

* Member:
  * Create/delete APS channel.

**Invariants**:

- Owner is the "root user" (has all permissions except sending data on APS channel).
- A user can only have one role at a time.
- If the `User` fact exists, then so will the `UserIdentKey`, `UserSignKey`, and `UserEncKey` 
  facts. Similarly, the latter three facts are predicated on the user fact.
- A user can only have one of each user key type at a time.

<!-- For MVP:
- Entities permitted to assign a role can do so for any other entity in the hierarchy.
- Entities permitted to revoke a role can do so only for another entity whose highest assigned role 
  is lower than theirs.
- We use "<role> device" to refer to an entity whose highest assigned role is the one specified. -->


### Imports & Global Constants

```policy
use aps
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

// Collection of public UserKeys for a user.
struct KeyBundle {
    ident_key bytes,
    sign_key bytes,
    enc_key bytes,
}

// The set of key IDs derived from each UserKey.
// NB: Key ID of the IdentityKey is the user ID.
struct KeyIds {
    user_id id,
    sign_key_id id,
    enc_key_id id,
}
```

### Facts

```policy
// A user on the team.
fact User[user_id id]=>{role enum Role, sign_key_id id, enc_key_id id}

// A user's public IdentityKey
fact UserIdentKey[user_id id]=>{key bytes}

// A user's public SigningKey.
fact UserSignKey[user_id id]=>{key_id id, key bytes}

// A user's public EncryptionKey.
fact UserEncKey[user_id id]=>{key_id id, key bytes}

// Indicates that the team has been terminated.
fact TeamEnd[]=>{}

// Records an APS label that has been defined for use.
fact Label[label int]=>{} 

// Records that a user is allowed to use an APS label.
fact AssignedLabel[user_id id, label int]=>{op enum ChanOp}

// Stores a Member's associated network identifier for APS.
fact MemberNetworkId[user_id id]=>{net_identifier string}
```

### Functions

```policy
// Check if there is an existing user.
// Returns the user struct if so, otherwise returns `None`.
function find_existing_user(user_id id) optional struct User {
    let user = query User[user_id: user_id]
    let has_ident = exists UserIdentKey[user_id: user_id]
    let has_sign = exists UserSignKey[user_id: user_id]
    let has_enc = exists UserEncKey[user_id: user_id]

    if user is Some {
        check has_ident
        check has_sign
        check has_enc
    } else {
        check !has_ident
        check !has_sign
        check !has_enc
    }

    // Return the resulting User struct for further checks.
    return user
}

// Sanity checks the user per the stated invariants.
function get_valid_user(user_id id) struct User {
    // Check to see if team is active.
    check !exists TeamEnd[]=> {}

    // Get and return user info.
    let user = check_unwrap find_existing_user(user_id)
    return user
}

// Derives the key ID for each of the UserKeys in the bundle.
// (The IdentityKey's ID is the UserID.)
function derive_user_key_ids(user_keys struct KeyBundle) struct KeyIds {
    let user_id = idam::derive_user_id(user_keys.ident_key)
    let sign_key_id = idam::derive_sign_key_id(user_keys.sign_key)
    let enc_key_id = idam::derive_enc_key_id(user_keys.enc_key)

    return KeyIds {
        user_id: user_id,
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

// Seals a serialized basic command into an envelope, using the stored SigningKey for this user.
function seal_command(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let author_id = device::current_user_id()
    let author_sign_pk = check_unwrap query UserSignKey[user_id: author_id]
    
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
    let author_sign_pk = check_unwrap query UserSignKey[user_id: author_id]

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

#### APS Functions

```policy
// Reports whether `label` has the valid format for an APS label, which is an unsigned, 32-bit integer.
function is_valid_label(label int) bool {
    return label >= 0 && label <= 4294967295
}

// Returns the channel operation for a particular label.
function get_allowed_op(user_id id, label int) enum ChanOp {
    let assigned_label = check_unwrap query AssignedLabel[user_id: user_id, label: label]
    return assigned_label.op
}

// Reports whether the users have permission to create a bidirectional channel with each other.
function can_create_bidi_channel(user1 id, user2 id, label int) bool {
    let user1_op = get_allowed_op(user1, label)
    let user2_op = get_allowed_op(user2, label)

    // Label must be valid.
    check is_valid_label(label)
    // Members can't create channels with themselves.
    check user1 != user2

    // Both users must have permissions to encrypt and decrypt data.
    check user1_op == user2_op
    check user1_op == ChanOp::ReadWrite

    return true
}

// Returns the user's public EncryptionKey.
function get_enc_pk(user_id id) bytes {
    let user_enc_pk = check_unwrap query UserEncKey[user_id: user_id]
    return user_enc_pk.key
}

// Selects the ID which doesn't match `user_id`.
function select_peer_id(user_id id, id_a id, id_b id) id {
    if user_id == id_a {
        return id_b
    } else if user_id == id_b {
        return id_a
    } else {
        check false
    }
}

// Reports whether the users have permission to create a unidirectional channel with each other.
function can_create_uni_channel(writer_id id, reader_id id, label int) bool {
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
    // The UserID of the creator of the Team.
    owner_id id,
}

command CreateTeam {
    fields {
        // The initial owner's public UserKeys.
        owner_keys struct KeyBundle,
        // Random nonce to enforce this team's uniqueness.
        nonce bytes,
    }

    seal {
        let parent_id = perspective::head_id()
        let author_id = device::current_user_id()
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
        // Derive the key ids from the user_keys
        let owner_key_ids = derive_user_key_ids(this.owner_keys)

        // Check that author_id matches the user_id being created
        check author_id == owner_key_ids.user_id

        finish {
            add_new_user(this.owner_keys, owner_key_ids, Role::Owner)

            emit TeamCreated {
                owner_id: author_id,
            }
        }
    }
}

// Adds the user to the Team.
finish function add_new_user(key_bundle struct KeyBundle, key_ids struct KeyIds, role enum Role) {
    create User[user_id: key_ids.user_id]=>{
        role: role, 
        sign_key_id: key_ids.sign_key_id, 
        enc_key_id: key_ids.enc_key_id,
    }

    create UserIdentKey[user_id: key_ids.user_id]=>{key: key_bundle.ident_key}
    create UserSignKey[user_id: key_ids.user_id]=>{
        key_id: key_ids.sign_key_id, 
        key: key_bundle.sign_key,
    }
    create UserEncKey[user_id: key_ids.user_id]=>{
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
        let author = get_valid_user(envelope::author_id(envelope))
        // Only the Owner can close the Team
        check is_owner(author.role)

        finish {
            create TeamEnd[]=>{}

            emit TeamTerminated{
                owner_id: author.user_id,
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
action add_member(user_keys struct KeyBundle){
    publish AddMember {
        user_keys: user_keys,
    }
}

// A Member was added to the Team.
effect MemberAdded {
    // The id of the user to be added.
    user_id id,
    // The user's set of public UserKeys.
    user_keys struct KeyBundle,
}

command AddMember {
    fields {
        // The new user's public UserKeys.
        user_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        // Derive the key IDs from the provided KeyBundle.
        let user_key_ids = derive_user_key_ids(this.user_keys)

        // Only Operator and Owner can add a Member.
        check is_operator(author.role) || is_owner(author.role)
        // Check that the Member doesn't already exist.
        check find_existing_user(user_key_ids.user_id) is None

        finish {
            add_new_user(this.user_keys, user_key_ids, Role::Member)

            emit MemberAdded {
                user_id: user_key_ids.user_id,
                user_keys: this.user_keys,
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
action remove_member(user_id id){
    publish RemoveMember {
        user_id: user_id,
    }
}

// A Member was removed from the Team.
effect MemberRemoved {
    user_id id,
}

command RemoveMember{
    fields {
        // The removed user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only Operators and Owners can remove a Member
        check is_operator(author.role) || is_owner(author.role)
        // Check that the user is a Member
        check is_member(user.role)

        finish {
            remove_user(this.user_id)

            emit MemberRemoved {
                user_id: this.user_id,
            }
        }
    }
}

// Removes the user from the Team.
finish function remove_user(user_id id) {
    delete User[user_id: user_id]
    delete UserIdentKey[user_id: user_id]
    delete UserSignKey[user_id: user_id]
    delete UserEncKey[user_id: user_id]
}
```

**Invariants**:

- Members can only be removed by Operators and Owners.
- Removing non-Members requires revoking their higher role so the user is made into a Member first.


## AssignRole

```policy
// Assigns the specified role to the user.
action assign_role(user_id id, role enum Role){
    match role {
        Role::Owner => {
            // Assigns the Owner role.
            publish AssignOwner {
                user_id: user_id,
            }
        }
        Role::Admin => {
            // Assigns the Admin role.
            publish AssignAdmin {
                user_id: user_id,
            }
        }
        Role::Operator => {
            // Assigns the Operator role.
            publish AssignOperator {
                user_id: user_id,
            }
        }
        _ => { check false }
    }
}
```

### AssignOwner

```policy
// A user was assigned with the Owner role.
effect OwnerAssigned {
    user_id id,
}

command AssignOwner{
    fields {
        // The assigned user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only an Owner can assign the Owner role.
        check is_owner(author.role)
        // The user must not already have the Owner role.
        check user.role != Role::Owner

        finish {
            assign_role(user, Role::Owner)

            emit OwnerAssigned {
                user_id: this.user_id,
            }
        }
    }
}

// Assigns the user to the specified role.
finish function assign_role(user struct User, role enum Role) {
    update User[user_id: user.user_id]=>{
        role: user.role, 
        sign_key_id: user.sign_key_id, 
        enc_key_id: user.enc_key_id,
        } to {
            role: role, 
            sign_key_id: user.sign_key_id, 
            enc_key_id: user.enc_key_id,
        }
}
```

### AssignAdmin

```policy
// A user was assigned with the Admin role.
effect AdminAssigned {
    user_id id,
}

command AssignAdmin{
    fields {
        // The assigned user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only an Owner can assign the Admin role.
        check is_owner(author.role)
        // The user must not already have the Admin role.
        check user.role != Role::Admin

        finish {
            assign_role(user, Role::Admin)

            emit AdminAssigned {
                user_id: this.user_id,
            }
        }
    }
}
```


### AssignOperator

```policy
// A user was assigned with the Operator role.
effect OperatorAssigned {
    user_id id,
}

command AssignOperator{
    fields {
        // The assigned user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only Owners and Admins can assign the Operator role.
        check is_owner(author.role) || is_admin(author.role)
        // The user must not already have the Operator role.
        check user.role != Role::Operator

        finish {
            assign_role(user, Role::Operator)

            emit OperatorAssigned {
                user_id: this.user_id,
            }
        }
    }
}
```


**Invariants**:

- Users cannot assign roles to themselves.
- Only Owners can assign the Owner role.
- Only Owners can assign the Admin role.
- Only Owners and Admins can assign the Operator role.


## RevokeRole

```policy
// Revokes the specified role from the user.
action revoke_role(user_id id, role enum Role){
    match role {
        Role::Owner => {
            // Revokes the Owner role.
            publish RevokeOwner {
                user_id: user_id,
            }
        }
        Role::Admin => {
            // Revokes the Admin role.
            publish RevokeAdmin {
                user_id: user_id,
            }
        }
        Role::Operator => {
            // Revokes the Operator role.
            publish RevokeOperator {
                user_id: user_id,
            }
        }
        _ => { check false }
    }
}
```

### RevokeOwner

```policy
// The Owner role was revoked from a user.
effect OwnerRevoked {
    user_id id,
}

command RevokeOwner{
    fields {
        // The revoked user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Owner can only revoke the role from itself.
        check author.user_id == this.user_id
        // Check that the user is an Owner.
        check is_owner(author.role)

        finish {
            revoke_role(user)

            emit OwnerRevoked {
                user_id: this.user_id,
            }
        }
    }
}

// Revokes the specified role from the user. This automatically sets their role to Member instead.
finish function revoke_role(user struct User) {
    update User[user_id: user.user_id]=>{
        role: user.role, 
        sign_key_id: user.sign_key_id, 
        enc_key_id: user.enc_key_id,
        } to {
            role: Role::Member, 
            sign_key_id: user.sign_key_id, 
            enc_key_id: user.enc_key_id,
            }
}
```

### RevokeAdmin

```policy
// The Admin role was revoke from a user.
effect AdminRevoked {
    user_id id,
}

command RevokeAdmin{
    fields {
        // The revoked user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only Owners can revoke the Admin role.
        check is_owner(author.role)
        // Check that the user is an Admin.
        check is_admin(user.role)

        finish {
            revoke_role(user)

            emit AdminRevoked {
                user_id: this.user_id,
            }
        }
    }
}
```

### RevokeOperator

```policy
// The Operator role was revoke from a user.
effect OperatorRevoked {
    user_id id,
}

command RevokeOperator{
    fields {
        // The revoked user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)

        // Only Owners and Admins can revoke the Operator role.
        check is_owner(author.role) || is_admin(author.role)
        // Check that the user is an Operator.
        check is_operator(user.role)

        finish {
            revoke_role(user)

            emit OperatorRevoked {
                user_id: this.user_id,
            }
        }
    }
}
```

**Invariants**:

- Revoking a role from a user will assign them with the Member role.
- If all Owners revoke their own role, it is possible for the team to be left without any Owners.
- As long as there is at least one Owner in the team, new users can continue to be added and 
  assigned to the different roles.
- Only Owners can revoke the Admin role.
- Only Owners and Admins can revoke the Operator role.

## DefineLabel

```policy
// Defines an APS label.
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
        let author = get_valid_user(envelope::author_id(envelope))

        // Owners, Admins and Operators can define APS labels.
        check !is_member(author.role)
        // It must be a valid APS label.
        check is_valid_label(this.label)

        // TODO: add check that label was not previously created
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

- Only Members cannot define APS labels.
- Owners, Admins and Operators are allowed to define APS labels.
- APS labels must be unsigned, 32-bit integers.

## UndefineLabel

```policy
// Undefines an APS label.
action undefine_label(label int) {
    publish UndefineLabel {
        label: label,
    }
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
        let author = get_valid_user(envelope::author_id(envelope))

        // Only Owners and Admins can undefine APS labels.
        check is_owner(author.role) || is_admin(author.role)
        // TODO: check that the label exists.
        // TODO: handle users assigned to the undefine label (e.g., include checks elsewhere)

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

- Only Owners and Admins are allowed to undefine APS labels.


## AssignLabel

Assigns an "APS" label to a Member. 

```policy
// Assigns the user a `label` to .
action assign_label(user_id id, label int, op enum ChanOp) {
    publish AssignLabel {
        user_id: user_id,
        label: label,
        op: op,
    }
}

effect LabelAssigned {
    // The user being assigned the label.
    user_id id,
    // The label being assigned.
    label int,
    // The operation that can be performed with the label.
    op enum ChanOp,
}

command AssignLabel {
    fields {
        // The user being assigned the label.
        user_id id,
        // The label being assigned.
        label int,
        // The operations that can be performed with the label.
        op enum ChanOp,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)

        // Only Owners and Operators can assign APS labels to Members.
        check is_owner(author.role) || is_operator(author.role)
        check is_member(user.role)

        // Obviously it must be a valid label.
        check is_valid_label(this.label)
        // The label must exist.
        check exists Label[label: this.label]

        finish {
            create AssignedLabel[user_id: user.user_id, label: this.label]=>{op: this.op}

            emit LabelAssigned {
                user_id: user.user_id,
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
- Only Members can be assigned APS labels.
- Only labels that are defined are allowed to be assigned.

## RevokeLabel

```policy
// Revokes the user's access to the APS `label`.
action revoke_label(user_id id, label int) {
    publish RevokeLabel {
        user_id: user_id,
        label: label,
    }
}

effect LabelRevoked {
    // The user for whom the label is being revoked.
    user_id id,
    // The label being revoked.
    label int,
}

command RevokeLabel {
    fields {
        // The user for whom the label is being revoked.
        user_id id,
        // The label being revoked.
        label int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)

        // Only Owners and Operators are allowed to revoke a label from a Member.
        // TODO: Allow Admins to also revoke labels?
        check is_owner(author.role) || is_operator(author.role)
        check is_member(user.role)

        // Verify that APS label has been assigned.
        check exists AssignedLabel[user_id: user.user_id, label: this.label]

        finish {
            delete AssignedLabel[user_id: user.user_id, label: this.label]

            emit LabelRevoked {
                user_id: user.user_id,
                label: this.label,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators can revoke labels from Members.
- Only a label that was assigned can be revoked.


## SetNetworkName
Associates a network name and address to a Member for use in APS. 

```policy
action set_network_name (user_id id, net_identifier string) {
    publish SetNetworkName {
        user_id: user_id,
        net_identifier: net_identifier,
    }
}

effect NetworkNameSet {
    user_id id,
    net_identifier string,
}

command SetNetworkName {
    fields {
        user_id id,
        net_identifier string,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)

        // Only Owners and Operators can associate a network name.
        // TODO: allow also Admins to associate a network name to a Member?
        check is_owner(author.role) || is_operator(author.role)
        // Only Members can be associated a network name.
        check is_member(user.role)

        // TODO: Create APS FFI function for validating the network identifier.
        // check aps::is_valid_network_identifier(this.net_identifier)

        // TODO: Check if address already exists for the user and update the fact instead.

        finish {
            create MemberNetworkId[user_id: this.user_id]=>{net_identifier: this.net_identifier}

            emit NetworkNameSet {
                user_id: user.user_id,
                net_identifier: this.net_identifier,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators can assign network names to Members.
- Members can only be assigned to one network name.

## UnsetNetworkName

```policy
action unset_network_name (user_id id) {}

effect NetworkNameUnset {
    user_id id,
}

command UnsetNetworkName {
    fields {
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)

        // Only Owners and Operators can unset a Member's network name.
        check is_owner(author.role) || is_operator(author.role)
        check is_member(user.role)

        // TODO: Update checks (e.g., other permitted users)

        finish {
            delete MemberNetworkId[user_id: this.user_id]

            emit NetworkNameUnset {
                user_id: user.user_id,
            }
        }
    }
}
```

**Invariants**:

- Only Owners and Operators Operators can unset network names from Members.


## CreateChannel

### CreateBidChannel
Creates a bidirectional "APS" channel for off-graph messaging. This is an ephemeral command, which 
means that it can only be emitted within an ephemeral session so that it is not added to the graph 
of commands. Furthermore, it cannot persist any changes to the factDB.

The `create_bidi_channel` action creates the `ChannelKeys`, encapsulates them for the peer and the 
author, and sends the encapsulations through the `CreateBidiChannel` command. When processing the 
command, the user will decapsulate their keys and store them in the shared memory DB.

```policy
action create_bidi_channel(peer_id id, label int) {
    let parent_cmd_id = perspective::head_id()
    let author_id = device::current_user_id()
    let author = get_valid_user(author_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let channel = aps::create_bidi_channel(
        parent_cmd_id,
        author.enc_key_id,
        author_id,
        peer_enc_pk,
        peer_id,
        label,
    )

    publish CreateBidiChannel {
        peer_id: peer_id,
        label: label,
        peer_encap: channel.peer_encap,
        channel_key_id: channel.key_id,
    }
}

effect BidiChannelCreated {
    parent_cmd_id id,
    author_id id,
    author_enc_key_id id,
    peer_id id,
    peer_enc_pk bytes,
    label int,
    channel_key_id id,
}

effect BidiChannelReceived {
    parent_cmd_id id,
    author_id id,
    author_enc_pk bytes,
    peer_id id,
    peer_enc_key_id id,
    label int,
    encap bytes,
}

command CreateBidiChannel {
    fields {
        peer_id id,
        label int,
        peer_encap bytes,
        channel_key_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let peer = check_unwrap find_existing_user(this.peer_id)

        // Only Members can create APS channels with other peer Members
        check is_member(author.role)
        check is_member(peer.role)

        // Members must be different and both must have bidirectional permissions over valid label.
        check can_create_bidi_channel(author.user_id, peer.user_id, this.label)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_user_id = device::current_user_id()

        // We authored this command.
        if current_user_id == author.user_id {
            let peer_enc_pk = get_enc_pk(peer.user_id)
            finish {
                emit BidiChannelCreated {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.user_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_id: peer.user_id,
                    peer_enc_pk: peer_enc_pk,
                    label: this.label,
                    channel_key_id: this.channel_key_id,
                }
            }
        }
        // We're the intended recipient of this command.
        else if current_user_id == peer.user_id {
            let author_enc_pk = get_enc_pk(author.user_id)
            finish {
                emit BidiChannelReceived {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.user_id,
                    author_enc_pk: author_enc_pk,
                    peer_id: peer.user_id,
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

- Members can only create channels for the labels they've been assigned.
- Members can only create bidi channels for their labels that have `ChanOp::ReadWrite` permission.


### CreateUniChannel
Creates a unidirectional "APS" channel. This is an ephemeral command, which means that it can only 
be emitted within an ephemeral session and is not added to the graph of commands. Furthermore, it 
does not persist any changes to the factDB.

The `create_uni_channel` action creates the `ChannelKey`, encapsulates it for the peer, and sends 
the encapsulation through the `CreateUniChannel` command. When processing the command, the 
corresponding recipient will decapsulate their key and store it in the shared memory DB.

```policy
action create_uni_channel(writer_id id, reader_id id, label int) {
    let parent_cmd_id = perspective::head_id()
    let author = get_valid_user(device::current_user_id())
    let peer_id = select_peer_id(author.user_id, writer_id, reader_id)
    let peer_enc_pk = get_enc_pk(peer_id)

    let channel = aps::create_uni_channel(
        parent_cmd_id,
        author.enc_key_id,
        peer_enc_pk,
        writer_id,
        reader_id,
        label,
    )

    publish CreateUniChannel {
        writer_id: writer_id,
        reader_id: reader_id,
        label: label,
        peer_encap: channel.peer_encap,
        channel_key_id: channel.key_id,
    }
}

effect UniChannelCreated {
    parent_cmd_id id,
    author_id id,
    writer_id id,
    reader_id id,
    author_enc_key_id id,
    peer_enc_pk bytes,
    label int,
    channel_key_id id,
}

effect UniChannelReceived {
    parent_cmd_id id,
    author_id id,
    writer_id id,
    reader_id id,
    author_enc_pk bytes,
    peer_enc_key_id id,
    label int,
    encap bytes,
}

command CreateUniChannel {
    fields {
        // The UserID of the side that can encrypt data.
        writer_id id,
        // The UserID of the side that can decrypt data.
        reader_id id,
        // The label to use.
        label int,
        // The encapsulated key for the recipient of the command.
        peer_encap bytes,
        // The ID of the APS channel key.
        channel_key_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))

        // Ensure that the author is half the channel and return the peer's info.
        let peer_id = select_peer_id(author.user_id, this.writer_id, this.reader_id)
        let peer = check_unwrap find_existing_user(peer_id)

        // Only Members can create APS channels with other peer Members
        check is_member(author.role)
        check is_member(peer.role)

        // Both users must have valid permissions.
        check can_create_uni_channel(this.writer_id, this.reader_id, this.label)

        let parent_cmd_id = envelope::parent_id(envelope)
        let current_user_id = device::current_user_id()

        // We authored this command.
        if current_user_id == author.user_id {
            let peer_enc_pk = get_enc_pk(peer_id)

            finish {
                emit UniChannelCreated {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.user_id,
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
        else if current_user_id == peer.user_id {
            let author_enc_pk = get_enc_pk(author.user_id)

            finish {
                emit UniChannelReceived {
                    parent_cmd_id: parent_cmd_id,
                    author_id: author.user_id,
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










<!-- The commented out code below this line is not part of the beta, but could be needed for MVP -->

<!-- ## AddUser
The `add_owner`, `add_admin`, `add_operator`, and `add_user` actions add an Owner, Admin, Operator, 
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
    user_id id,
    user_keys struct KeyBundle,
}

command AddOwner{
    fields {
        // The new owner's public UserKeys.
        owner_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        // Only Owner can add an Owner.
        check is_owner(author.role)

        // Derive the key IDs from the provided KeyBundle.
        let owner_key_ids = derive_user_key_ids(this.owner_keys)
        // Check that the Owner doesn't already exist.
        check find_existing_user(owner_key_ids.user_id) is None

        finish {
            add_new_user(this.owner_keys, owner_key_ids, Role::Owner)

            emit OwnerAdded {
                user_id: owner_key_ids.user_id,
                user_keys: this.owner_keys,
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
    user_id id,
    user_keys struct KeyBundle,
}

command AddAdmin{
    fields {
        // The new admin's public UserKeys.
        admin_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        // Only Owner can add an Admin.
        check is_owner(author.role)

        // Derive the key IDs from the provided KeyBundle.
        let admin_key_ids = derive_user_key_ids(this.admin_keys)
        // Check that the Admin doesn't already exist.
        check find_existing_user(admin_key_ids.user_id) is None

        finish {
            add_new_user(this.admin_keys, admin_key_ids, Role::Admin)

            emit AdminAdded {
                user_id: admin_key_ids.user_id,
                user_keys: this.admin_keys,
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
    user_id id,
    user_keys struct KeyBundle,
}

command AddOperator{
    fields {
        // The new operator's public UserKeys.
        operator_keys struct KeyBundle,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        // Only Admin can add an Operator.
        check is_admin(author.role)

        // Derive the key IDs from the provided KeyBundle.
        let operator_key_ids = derive_user_key_ids(this.operator_keys)
        // Check that the Admin doesn't already exist.
        check find_existing_user(operator_key_ids.user_id) is None

        finish {
            add_new_user(this.operator_keys, operator_key_ids, Role::Operator)

            emit OperatorAdded {
                user_id: user_key_ids.user_id,
                user_keys: this.operator_keys,
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


## RemoveUser
The `remove_owner`, `remove_admin`, `remove_operator`, and `remove_user` actions remove an Admin, Operator, and Member from the team, respectively.

### RemoveOwner

```policy
// Removes an Owner from the Team.
action remove_owner(user_id id){
    publish RemoveOwner {
        user_id: user_id,
    }
}

// An Owner was removed from the Team.
effect OwnerRemoved {
    user_id id,
}

command RemoveOwner{
    fields {
        // The removed user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        
        // Owner can only be remove by itself.
        check author.user_id == this.user_id
        // Check that the user is an Owner.
        check is_owner(author.role)

        finish {
            remove_user(this.user_id)

            emit OwnerRemoved {
                user_id: this.user_id,
            }
        }
    }
}
```

### RemoveAdmin

```policy
// Removes an Admin from the Team.
action remove_admin(user_id id){
    publish RemoveAdmin {
        user_id: user_id,
    }
}

// An Admin was removed from the Team.
effect AdminRemoved {
    user_id id,
}

command RemoveAdmin{
    fields {
        // The removed user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only Owner can remove an Admin.
        check is_owner(author.role)
        // Check that the user is an Admin.
        check is_admin(user.role)

        finish {
            remove_user(this.user_id)

            emit AdminRemoved {
                user_id: this.user_id,
            }
        }
    }
}
```

### RemoveOperator

```policy
// Removes a Operator from the Team.
action remove_operator(user_id id){
    publish RemoveAdmin {
        user_id: user_id,
    }
}

// A Operator was removed from the Team.
effect OperatorRemoved {
    user_id id,
}

command RemoveOperator{
    fields {
        // The removed user's ID.
        user_id id,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author = get_valid_user(envelope::author_id(envelope))
        let user = check_unwrap find_existing_user(this.user_id)
        
        // Only Admin can remove a Operator
        check is_admin(author.role)
        // Check that the user is a Operator
        check is_operator(user.role)

        finish {
            remove_user(this.user_id)

            emit OperatorRemoved {
                user_id: this.user_id,
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
    let author_id = device::current_user_id()
    let author_sign_pk = unwrap query UserSignKey[user_id: author_id]
    let ciphertext = idam::encrypt_message(parent_id, plaintext, key.wrapped, author_sign_pk.key)
    publish Message{
        ciphertext: ciphertext,
        wrapped_key: key.wrapped,
    }
}
effect MessageReceived {
    user id,
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
        let author = get_valid_user(envelope::author_id(envelope))
        // Only a User can send a message
        check is_member(author.role)
        let author_sign_pk = check_unwrap query UserSignKey[user_id: author.user_id]
        let plaintext = idam::decrypt_message(
            parent_id, 
            this.ciphertext, 
            this.wrapped_key, 
            author_sign_pk.key,
        )
        finish {
            emit MessageReceived{
                user: author.user_id,
                plaintext: plaintext,
            }
        }
    }
}
``` 
-->
