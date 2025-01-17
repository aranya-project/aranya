# Aranya

Aranya is lovingly crafted and supported by [SpiderOak](https://spideroak.com). Aranya is licensed under the [AGPL](LICENSE.md)- if you want to use it commercially, drop us a line!

## What is it?

Aranya is a software development tool for governing access to data and services over a decentralized, zero-trust framework with secure end-to-end encrypted data exchange built-in.

Aranya has been designed with an emphasis on security, efficiency, and portability.

The root cause of cyber insecurity is complexity; and yet when we attempt to protect our systems, our solution is to add more.

Software developers must not expect customers to mitigate defects using external security tools and an endless cycle of patching. Software must become secure by design.

Aranya is our contribution to this effort. It is a batteries-included tool which allows developers to produce software with built-in micro-segmentation. This complete solution covers access management with user onboarding, authentication and authorization, freeing the developer to focus on the problem they wish to solve.

For users, software built on Aranya is less complex to operate securely, and is secure regardless of the network it is run on.

More documentation on Aranya is provided here:
- [Aranya Overview](https://github.com/aranya-project/aranya-docs/blob/main/docs/aranya-overview.md)
- [Getting Started With Aranya](docs/walkthrough.md)

## What's Contained In This Repo

This repository contains the following components:
- [Rust Client Library](crates/aranya-client)
- [Daemon Process](crates/aranya-daemon)
- [Aranya Policy](crates/aranya-daemon/src/policy.md)

### Rust Client Library

The [Rust Client Library](crates/aranya-client/) provides an interface for your
application to interface with the
[Aranya Daemon](crates/aranya-daemon-api/src/service.rs) in order to invoke
actions on and process affects from the Aranya graph. The library also provides
an interface to [Aranya Core](https://github.com/aranya-project/aranya-core)
for Aranya Fast Channels functionality. Refer to the
[client's README](crates/aranya-client/README.md) for more details on this
component.

### Daemon Process

The [daemon](crates/aranya-daemon/) is a long-running process that forwards
requests from the [client](crates/aranya-client) to the
[Aranya Core](https://github.com/aranya-project/aranya-core). Refer to the
[daemon's README](crates/aranya-daemon/README.md) for more information on
this component.

### Aranya Policy

The [Aranya Policy](crates/aranya-daemon/src/policy.md) is a security control policy written in Aranya's domain-specific policy language and executed by the Aranya runtime.

### Rust Example Application

An example Rust program for using Aranya is located here:
[Aranya Rust Example](templates/aranya-example)

Refer to the `aranya-example` crate's README for more information:
[Aranya Example README.md](templates/aranya-example/README.md)

## Dependencies

### Aranya Core

The [Aranya Core](https://github.com/aranya-project/aranya-core) repo has all the main components of Aranya that are needed for the core functionality to work. This is a library that includes the storage module (for DAG and FactDB), crypto module (with default crypto engine automatically selected), sync engine, and runtime client (including policy VM).

### Aranya Fast Channels

[Aranya Fast Channels](https://github.com/aranya-project/aranya-core/tree/main/crates/aranya-fast-channels) are encrypted channels between 2 peers that could be either bidirectional or unidirectional.

## Integration & Development

For a fully runnable example of Aranya, check out the
[`aranya-client-capi`](crates/aranya-client-capi/) C API
[example](examples/c/). This example covers team creation, syncing and sending
messages using Aranya Fast Channels.

### Supported Platforms

The following platforms are supported:
- Linux/arm64
- Linux/amd64
- MacOS

### Prerequisites

To use Aranya and run the examples, your system must have the
most recent version of the following tools:

- [Rust](https://www.rust-lang.org/tools/install)
- [cmake](https://cmake.org/download/)
- [clang](https://releases.llvm.org/download.html)
- [patchelf](https://github.com/NixOS/patchelf)
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation)

To view documentation for the `aranya-client-capi` C API, download
[doxygen](https://www.doxygen.nl/download.html).

### Install and Build Aranya

Download the source code from this repository or from [crates.io](https://crates.io):
- [client](https://crates.io/crates/aranya-client)
- [daemon](https://crates.io/crates/aranya-daemon)

#### From this repository:

`$ git clone git@github.com:aranya-project/aranya.git`

Once the source-code is downloaded, navigate to the Aranya project workspace and run:

`cargo build --release`

This will build the available Aranya crates.

#### From crates.io:

Run the following in your project's directory:
```bash
$ cargo add aranya-daemon
$ cargo add aranya-client
```

Or, add it to your project's `Cargo.toml`:
```
[dependencies]
aranya-daemon = { git = "git@github.com:aranya-project/aranya.git" }
aranya-client = { git = "git@github.com:aranya-project/aranya.git" }
```

#### Additional build options

This repository uses `cargo-make` to automate different tasks, including
building the code, documentation and examples. Once the repository is
downloaded and Rust is installed on your device, run the following to install
`cargo-make`:

`$ cargo install cargo-make`

Then, navigate to this directory and run the following to build Aranya:

`$ cargo make build-code`

Or, build the C API and its associated documentation:

`$ cargo make build-capi`

Run `$ cargo make` to see a list of all available tasks.

### Integrate Aranya
<!--
TODO: Add more information about actual integration steps. Need to get input.
Ways to integrate with Aranya:
- Add the Rust library to your project (as demonstrated above)
- Use the C API to integrate with the Aranya library
-->

Aranya provides a client library and the daemon executable which processes
requests sent from the client and handles syncing with team members.

There are a few ways you can integrate the Aranya library into your project:

1. Rust Library

Using the installation instructions above, get the code through this repository
or crates.io and add it to your project.

Integrate the [client](crates/aranya-client) library into your application. The
[client's README](crates/aranya-client/README.md) has more information on using
the Rust client.

2. `aranya-client-capi` C API
<!--
C API lets you call the aranya client from your C applications.
- In a real-world scenario, how would the daemon be integrated/set-up?
	- Just the rust executable?
- What else would they need to do to set-up using the aranya-client-capi stuff?
-->

Use the [`aranya-client-capi` C API](crates/aranya-client-capi/) to integrate
Aranya into your application.

See the [Aranya C example](examples/c/) for example usage of the
`aranya-client-capi` C API.

<!-- TODO: verify this is accurate -->
In both cases, the Aranya client will need to communicate with the Aranya
daemon. The [daemon's README](crates/aranya-daemon/README.md) contains
instructions for configuring and running the daemon.

After the daemon has started up, start the application.

### Example Applications

We have provided a runnable example application that uses the
[`aranya-client-capi` C API](crates/aranya-client-capi/). The example includes
five users who will be referred to by their user role, `Owner`, `Admin`,
`Operator`, `Member A` and `Member B`.

This example goes through the following steps:

Step 1: Configure, build and run the daemon for each user

Step 2. Submit an action to the `Owner`'s daemon to create a team

Step 3. Submit actions to populate the team with the rest of
the users

Step 4. Submit an action to the `Admin`'s daemon to create an Aranya Fast
Channels label

Step 5. Submit actions to the `Operator`'s daemon to assign the Fast Channels
label to `Member A` and `Member B`

Step 6. Submit an action to `Member A`'s daemon to create an Aranya Fast
Channel

Step 7. Call the Fast Channels API from `Member A`'s daemon to send a message.
Optionally, call the Fast Channels API from `Member B`'s daemon to send a
message back.

For instructions on running this example, see [here](examples/c/README.md).

### Example API calls

The following section will show an example of using Aranya to create a team in
Rust and using the [`aranya-client-capi` C API](crates/aranya-client-capi/).

#### Rust

```rust
let client = Client::connect(owner_sock_path)?;
let team_id = client.create_team()?;
```

#### C

The following snippet has been modified for simplicity. To see actual usage,
see the [C example](../examples/c/example.c#L162).

```C
// have owner create the team.
err = aranya_create_team(&team->clients.owner.client, &team->id);
EXPECT("error creating team", err);
```

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
