# Getting Started with Aranya

Disclaimer: this document is a work in progress. The code given here is not
part of any tests and may break often during the initial releases or be missing
the full sequences required to complete some actions. Code referencing the
internals of the daemon is also incomplete and potentially outdated. Please
reference the API for more complete information.

In this document, we will walk through a scenario with five users initializing
and running Aranya. The users will create a team using Aranya and send messages
to each other using Aranya Fast Channels. There are a few things to keep in mind:

- Any policy actions are determined by the implemented policy. This walkthrough
  will use the default policy defined [here](/crates/aranya-daemon/src/policy.md).

- Security tip: This walkthrough is intended as an example to be run on a
  single machine. As such, a single machine is used to build all key bundles
  and run all daemons under a single user's profile. In production, each Aranya
  user's key bundle should be created under separate Linux users on their
  respective machines and preferably all private keys should be stored in a
  protected partition, such as an HSM, for maximum security. This avoids a
  single access point for all Aranya user keys in case a machine is compromised.

See the [examples](../examples) directory for example applications that
follow scenarios similar to the one described in this document. Also, see the
[overview documentation](overview.md) for more details on the components
used in this walkthrough.

# Outline

The walkthrough includes five users who will be referred to by their user role.
The actions performed by each user are based on the permissions assigned to
each role in the [default policy](/crates/aranya-daemon/src/policy.md). There
will be five users, `Owner`, `Admin`, `Operator`, `Member A` and `Member B`. We
will use the [`daemon`](/crates/aranya-daemon/src/daemon.rs) implementation for
this example.

Step 1. [Prepare the device environment](#prereqs)

Step 2: [Configure](#daemon-config), [build](#daemon-build) and [run](#daemon-run)
the daemon for each user

Step 3. Submit an action to the `Owner`'s daemon to [create a team](#create-team)

Step 4. Submit actions to [populate the team](#add-users-team) with the rest of
the users

Step 5. Submit an action to the `Admin`'s daemon to
[create an Aranya Fast Channels label](#create-afc-label)

Step 6. Submit actions to the `Operator`'s daemon to
[assign the Fast Channels label](#assign-afc-label) to `Member A` and `Member B`

Step 7. Submit an action to `Member A`'s daemon to
[create an Aranya Fast Channel](#create-afc-channel)

Step 8. Call the Fast Channels API from `Member A`'s daemon to
[send a message](#send-afc-msg). Optionally, call the Fast Channels API
from `Member B`'s daemon to send a message back.

# <a name="prereqs"></a>Prerequisites

## <a name="build-deps"></a>Build Dependencies

The following dependencies must be present on the device building Aranya:

- [Rust](https://www.rust-lang.org/tools/install)

The following platforms are not supported:

- Windows

# <a name="daemon"></a>Daemon

The [daemon](../crates/aranya-daemon) provides functionality for the
[client library](../crates/aranya-client) to maintain Aranya state, including
interacting with the graph and syncing with peers, and send off-graph messages
using Aranya Fast Channels. The daemon and client interact through the
[Daemon API](../crates/aranya-daemon-api/src/service.rs). The following
sections will walk through configuring and starting a long-running daemon
process.

For more details, see the
[Aranya Daemon's README](../crates/aranya-daemon/README.md).

## <a name="daemon-config"></a>Configuration

At runtime, the daemon takes in a configuration file with information used by
the daemon to network and operate. This includes a folder that contains
non-volatile information used by the daemon to operate, including private
cryptographic material belonging to the user, key storage accessed by Aranya
and graph storage for holding all fully processed commands. Additionally, the
daemon's config file also includes networking for syncing and off-graph
messaging. A complete example of a daemon configuration file can be found
[here](/crates/aranya-daemon/example.json).

Based on this example, create a configuration file for each user. Remember to
change the ports and other user-specific values for each user.

Now that the daemons have been configured, we can build and run them!

## <a name="daemon-build"></a>Build

To build the daemon, invoke `cargo build`:

```shell
$ cargo build --bin daemon --release
```

Since we have separate configuration files for each user, we only need one
build of the daemon. This step only needs to be performed once.

## <a name="daemon-run"></a>Run

To start the daemon for the owner, we run the following:

```shell
$ target/release/daemon <path to owner's daemon config>
```

Repeat this step for all users, substituting the associated configuration file
for each user:

```shell
$ target/release/daemon <path to admin's daemon config>
$ target/release/daemon <path to operator's daemon config>
$ target/release/daemon <path to member a's daemon config>
$ target/release/daemon <path to member b's daemon config>
```

Internally, the daemon is instantiated by loading the specified configuration
file. Once created, the daemon starts using its `run` method.

```rust
let daemon = Daemon::load(config).await?;

daemon.run().await
```

We will walk through the steps performed by the `run` method to set up Aranya
and Aranya Fast Channels next.

# <a name="aranya-afc-init"></a>Aranya and Fast Channels Initialization

The `run` method will first create the necessary objects to interact with
Aranya, including tools for storage, cryptography and syncing. The daemon's
`setup_aranya` method uses these items to instantiate the Aranya client for
submitting actions. Then, the daemon will call `setup_afc` to set up the
networking required to send messages to peers using Fast Channels. We will walk
through these setup methods in the following sections.

## <a name="setup-aranya"></a>Setup Aranya

Dependencies of Aranya include a crypto engine, policy engine, and storage
provider. Once running and before aranya can be setup, the daemon will
instantiate, by default, a key store and crypto engine. These are then passed
into the `setup_aranya` method, along with an external address for syncing and
the public portions of the device keys. The device keys are three asymmetric
cryptographic keys used to identify the device (`IdentityKey`), validate their
operations (`SigningKey`), and send encrypted data to them (`EncryptionKey`).

This input is then used to instantiate a policy engine and storage provider.

```rust
use aranya_crypto::{
	default::{DefaultCipherSuite, DefaultEngine},
	keystore::fs_keystore::Store as KeyStore,
};

use aranya_runtime::{
	storage::linear::libc::{
		FileManager,
		LinearStorageProvider
	},
	ClientState,
};

use crate::vm_policy::PolicyEngine;

const TEST_POLICY: &str = "/path/to/policy.md";

/// Creates the Aranya client and server.
async fn setup_aranya(
	&self,
	eng: DefaultEngine,
	store: KeyStore,
	pk: &PublicKeys<DefaultCipherSuite>,
	external_sync_addr: Addr,
) -> Result<(Client, Server)> {
	let user_id = pk.ident_pk.id()?;

	let aranya = ClientState::new(
		PolicyEngine<DefaultEngine, KeyStore>::new(
			TEST_POLICY, eng, store, user_id
		)?,
		LinearStorageProvider<FileManager>::new(
			FileManager::new(self.cfg.storage_path())
				.context("unable to create `FileManager`")?,
		),
	);
}
```

**NB**: This is an abbreviated version of the daemon's `setup_aranya` method, see
[here](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/src/daemon.rs#L141)
for the current implementation details.

The daemon receives actions from the user via the user client API. When the
client makes a call in the client library, it may invoke a command in the
daemon using an internal API. For more details on this API, see the
[aranya-daemon-api crate](../crates/aranya-daemon-api/src/service.rs).


## <a name="syncer"></a>Syncer

Once the Aranya client has been created by `setup_aranya`, the `run` method
will instantiate a `Syncer` for the device to be able to update their local
state of the DAG with its peers from the same team. In the process of syncing,
it will send a message, which holds some of the most recently seen state, to a
peer as a request to sync its local DAG with any missing commands that the peer
has. The `Syncer` uses its `sync` method which calls the Aranya client's
`sync_peer` method to send this request. Upon receiving the request, the peer
will compare these commands against their own version of state. If they have
seen new commands, the peer will respond with this new state. The `Syncer`
iterates over the list of peers and goes through this process at some
configured interval. Meanwhile, the `Syncer` also listens for and responds to
incoming sync requests. This is all done automatically by the daemon once a
team ID has been configured. The full implementation of this struct can be found
[here](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/src/sync.rs#L88).

## <a name="setup-afc"></a>Aranya Fast Channels

Before the client library can send data, the router component uses Fast
Channels to encrypt the data with the encryption key for that data's label.
On startup, the daemon uses the `setup_afc` method to initialize memory shared
by the daemon to write and the client to access channel keys used to
encrypt and decrypt Fast Channels data.

Before the client library can send data, the router component uses Fast
Channels to encrypt the data with the encryption key for that data's label. On
the other side of the channel, the peer's router receives the traffic on its
external network socket and uses Fast Channels to decrypt the data with the key
corresponding to the data's label. The keys used to encrypt and decrypt are
accessed by the client in the shared memory initialized by the daemon. The
router component then forwards the data as plaintext to the user's application.

Now that Aranya and Fast Channels are running, the daemon is ready to submit
actions!

# <a name="join-team"></a>Join a team

All Aranya operations, except for syncing, require users to join a team first.
There are two ways a user may join a team: creating a team or being added to
one. We will walk through each of these, first creating the team and then
adding users.

## <a name="create-team"></a>Create team

To create a team, the first user submits a `create_team` action which will
initialize a new graph for the team to operate on. This user is automatically
assigned the `Owner` role as part of the command.

Send a `create_team` action to the `Owner`'s daemon:

```rust
let client = Client::connect(owner_sock_path)?;
let team_id = client.create_team()?;
```

This will cause `Owner`'s daemon application to invoke the following action:

`aranya_client.create_team()`

A `CreateTeam` command is submitted on behalf of the first user to the daemon
to be processed by Aranya. If valid, the command will be added to the user's
graph of commands (i.e., their DAG), as the first node (or root) of the graph,
and returns to the user the team ID that uniquely identifies the team they
created. Additionally, a fact will be stored that associates `Owner` in the new
team with the `Owner` role. The team has now been created and the `Owner` can
add peers to sync with.

Peers are added to sync with using the client's `add_sync_peer` command. It
takes in the peer's external network address that the daemon can communicate
with. This method also takes in a time interval that tells the daemon how
often to attempt syncing with that peer. All team members must call the
`add_sync_peer` method in order to sync state with the rest of the team. For
example, the owner will make the following calls to begin syncing with the
rest of the team:

```rust
// Create an instance of a Team API to add sync peers.
let mut team = client.team(team_id);
let interval = Duration::from_millis(100);

team.add_sync_peer(admin_addr, interval).await?;
team.add_sync_peer(operator_addr, interval).await?;
team.add_sync_peer(member_a_addr, interval).await?;
team.add_sync_peer(member_b_addr, interval).await?;
```

Now, the `Owner` can start adding other team members!

**NB**: the team ID should be stored for use later in the walkthrough as it
will be used for adding other users to the team.

## <a name="add-users-team"></a>Add users to team

To be added to the team, a user first needs to send the public portion of their
user keys, the user key bundle, to an existing user in the team. This key
exchange is done outside of the daemon using something like `scp`. Further, the
existing user must have permission to add a user to the team. Based on the
implemented policy, all new users, except the `Owner`, are added to the team
with the `Member` role. Only users with the `Owner` role or `Operator` role may
add a new user to the team. To get the keybundle of the current user:


```rust
// Get the keybundle of the user that should be added as an admin:
let admin_kb = client.get_key_bundle()?;

// Send the keybundle to the Owner
// ...
```

Let's assume `Owner` has received the second user's keys and can add them to
the team and assign the `Admin` role. This involves two commands, `AddMember`
and `AssignAdmin`. The first is published by the `add_member` action which adds
the second user to the team and the second is published by the `assign_admin`
action which assigns the `Admin` role. `Owner` will use the daemon's `add_admin`
subcommand to submit these two commands:

```rust
// Create an instance of a Team API to add the admin using
// the ID of the team.
let team = client.team(team_id);

team.add_device_to_team(admin_kb)?;
team.assign_role(admin_device_id, Role::Admin)?;
```

If processed successfully, new `AddMember` and `AssignAdmin` commands will be
added to the graph and associates Admin to the team and their role.

**NB**: Remember that users must process commands locally before they can act
upon them. Thus, `Admin` must sync with a peer to receive the commands `Owner`
performed to onboard them onto the team before they can perform any commands
themself. The `Admin` can begin syncing with peers using the `add_sync_peer`
method described above. Remember, every user will have to add each team member
to sync with using this method.

To enable syncing, `Owner` should supply `Admin` with the team ID that will
allow them to sync. This happens outside of the daemon, using something like
`ssh`.

`Owner` can repeat these steps to add the rest of the users to the team. So,
after receiving the key bundle from the third, fourth, and fifth user, the
`Owner` will perform the following:

```rust
team.add_sync_peer(operator_addr, interval).await?;
team.add_device_to_team(operator_kb)?;
team.assign_role(operator_device_id, Role::Operator)?;
```

This subcommand will submit two actions, `add_member` and `assign_operator`.
The first will add the user to the team as a `Member` and the second will
assign them the `Operator` role. The last two users will only be added to the
team as `Member`s.

```rust
team.add_device_to_team(member_a_kb)?;
team.assign_role(member_a_device_id, Role::Member)?;

team.add_device_to_team(member_b_kb)?;
team.assign_role(member_b_device_id, Role::Member)?;
```

If these actions are processed successfully, new commands exist on the graph
that associate the team members with their newly assigned roles. Before the new
team members can submit actions, they must retrieve the team ID (remember this
happens externally) to sync state and receive the commands that have associated
them with the team. Once associated with the team and assigned a role, the users
can begin submitting actions!

Finally, network identifiers need to be assigned for the members that will use
Fast Channels. The network identifers are used by Fast Channels to properly
translate between network names and users.

```rust
let member_a_net_id = "127.0.0.1:8084";
let member_b_net_id = "127.0.0.1:8085";

operator_client.assign_net_identifier(member_a_device_id, member_a_net_id)?;
operator_client.assign_net_identifier(member_b_device_id, member_b_net_id)?;
```

# <a name="message-sending"></a>Message sending

Now that all users have been added to the team, they can begin sending
encrypted messages to each other, facilitated by Aranya Fast Channels. When
using Fast Channels, messages are not stored on the graph and are only one to
one between two users. We will walk through how users can send messages using
each of these methods.

## <a name="off-graph-messaging"></a>Off-graph messaging

Aranya Fast Channels provides functionality for encrypted peer to peer
messaging via channels. This section will walk through a bidirectional channel
being set up between `Member A` and `Member B`.

### <a name="create-afc-label"></a>Create an Aranya Fast Channels label

As mentioned, a channel label must be created so it can be associated with the
users and channel. Based on the default policy, an `Admin` can create a Fast
Channels label. So, `Admin`, who was assigned the `Admin` role, will submit an
action to the daemon to create the label.

```rust
// Have admin create the label using the team instance
// from the admin_client.team(team_id)
let label_num = 1337;
team.create_label(label_num)?;
```

This is an Aranya command, so the daemon passes it into the policy to be
processed. If it is successful, the label is stored as a fact on the graph.

### <a name="assign-afc-label"></a>Assign an Aranya Fast Channels label

Now that it exists, the label can be assigned to `Member A` and `Member B`.
Based on the default policy, the `Operator` role can assign Fast Channels
labels. So, `Operator`, who was assigned the `Operator` role, will submit the
action to assign the label. If processed successfully, the Aranya command for
assigning a Fast Channels label will create a fact that associates the label,
the user's `user_id`, and a channel operation. Since this is a bidirectional
channel, each user will be given the `ReadWrite` channel operation.

```rust

// Assign label_num (1337) to Member A and Member B using the operator's
// team instance.
team.assign_label(member_a_device_id, label_num)?;
team.assign_label(member_b_device_id, label_num)?;
```

Once these commands are submitted, they are processed by the policy. If found
valid, `Member A` and `Member B` are now both assigned the same label with the
ability to interact over a bidirectional channel.

### <a name="create-afc-channel"></a>Create an Aranya Fast Channel

The action for creating a bidirectional Fast Channel,
`create_bidi_channel`, is called within an Aranya session to produce the
ephemeral command, `CreateBidiChannel`, which contains the Fast Channels
channel keys.

Note: An ephemeral command is processed by Aranya but not added to the graph.

Now, `Member A` or `Member B` could create a Fast Channel.

```rust
let channel_id = member_a_client.create_bidi_channel(team_id, member_b_net_id, label_num)?;
```

The client library and daemon will handle the required communication to
transfer the ephemeral command to `Member B`. Once the command is received by
the `Router` on `Member B`'s device it is then evaluated by the recipient's
policy. If valid, the channel keys are stored in this user's shared memory
database. At this point, the channel is created and can be used for messaging
between `Member A` and `Member B`.

### <a name="send-afc-msg"></a>Send messages

To send a message, `Member A` will call Fast Channels's API, `send_data`, with
the message data and the channel ID.

```rust
// Sample data, can be any bytes
let data = vec![1, 1, 2, 3, 5];
// Send the data to over the channel to member A. The client library handles
// the transport.
member_a_client.send_data(channel_id, data)?;
```

This Fast Channels command will use the channel's encryption key to encrypt
the message and attach headers related to the contents. `Member B` can now read
the message!

Since this channel is bidirectional, `Member B` may also send a message to
`Member A`. In this case, `Member B` will submit a similar action with
the channel ID.

```rust
// Sample data, can be any bytes
let data = vec![8, 13, 21, 34, 55];
// Send the data to over the channel to member B. The client library handles
// the transport.
member_b_client.send_data(channel_id, data)?;
```

Great job, you've now successfully stood up Aranya daemons, created an Aranya
team, and sent messages using Aranya Fast Channels!
