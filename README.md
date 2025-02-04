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
- [Aranya Overview](https://aranya-project.github.io/aranya-docs/overview/)
- [Getting Started With Aranya](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/)

## Contributing

Our `CONTRIBUTING.md` is located in the aranya-project organization's `.github` repo:
[CONTRIBUTING.md](https://github.com/aranya-project/.github/blob/main/CONTRIBUTING.md)

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

### Supported Platforms

The following platforms are supported:
- Linux/arm64
- Linux/amd64
- MacOS

### Prerequisites

To use Aranya and run the examples, your system must have the following tools:

- [Rust](https://www.rust-lang.org/tools/install) (find version info in the
[rust-toolchain.toml](rust-toolchain.toml))
- [cmake](https://cmake.org/download/) (v3.31)
- [clang](https://releases.llvm.org/download.html) (v18.1)
- [patchelf](https://github.com/NixOS/patchelf) (v0.18)
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23)

### Integrate Aranya

Aranya may be integrated into your application using one of the following:

1. [Rust library](#rust-lib)
2. [C API](#c-api)

#### <a href name="rust-lib"></a>Rust Library

First, install the Aranya client.

##### From this repository:

`$ git clone git@github.com:aranya-project/aranya.git`

Once the source-code is downloaded, navigate to the Aranya project workspace and run:

`cargo build --release`

This will build the Aranya [client](crates/aranya-client/) and the
[daemon](crates/aranya-daemon/) executable.

##### From crates.io:

Run the following in your project's directory:
```bash
$ cargo add aranya-client
```

Or, add it to your project's `Cargo.toml`:
```
[dependencies]
aranya-client = { git = "git@github.com:aranya-project/aranya.git" }
```

Integrate the client library into your application. The
[client's README](crates/aranya-client/README.md) has more information on using
the Rust client.

#### <a href name="c-api"></a>C API

Pre-built versions of the library are uploaded (along with the [header file](https://github.com/aranya-project/aranya/blob/main/crates/aranya-client-capi/output/aranya-client.h)) to each Aranya [release](https://github.com/aranya-project/aranya/releases).

Otherwise, build the [`aranya-client-capi` C API](crates/aranya-client-capi/)
for your target platform.

Aranya can then be integrated using `cmake`. A
[CMakeLists.txt](https://github.com/aranya-project/aranya/blob/main/examples/c/CMakeLists.txt)
is provided to make it easier to build the library into an application.

### Run Aranya

Regardless of the version of the Aranya library being integrated, you will need
the [Aranya Daemon](crates/aranya-daemon/) executable. A prebuilt version is
available for supported platforms in the Aranya
[release](https://github.com/aranya-project/aranya/releases). Otherwise,
build the daemon locally.

Before starting your application, run the daemon by providing the path to a
configuration file. Find more details on configuring and running the daemon
[here](crates/aranya-daemon/README.md).

Once the daemon is running, run your application and begin using Aranya!

### Example Applications

We have provided runnable example applications in both
[Rust](templates/aranya-example/) and [C](examples/c/). These examples will
configure and run the daemon automatically. The examples follow five users who
are referred to by their user role, `Owner`, `Admin`, `Operator`, `Member A`
and `Member B`.

The examples go through the following steps:

Step 1: Build or download the pre-built executable from the latest Aranya
release. After providing a unique configuration file for each user, run the
daemons.

Step 2. The `Owner` initializes the team

#### Example API calls

The following section will show an example of using Aranya to create a team
using the Rust library and C API.

##### Rust

The following snippet can be found in the
[Rust example](templates/aranya-example/src/main.rs#L140).

```rust
// create team.
info!("creating team");
let team_id = team
	.owner
	.client
	.create_team()
	.await
	.expect("expected to create team");
info!(?team_id);
```

##### C

The following snippet has been modified for simplicity. For actual usage,
see the [C example](examples/c/example.c#L169).

```C
// have owner create the team.
err = aranya_create_team(&team->clients.owner.client, &team->id);
EXPECT("error creating team", err);
```

Step 3. The `Owner` adds the `Admin` and `Operator` to the team. `Member A` and
`Member B` can either be added by the `Owner` or `Operator`.

Step 4. The `Admin` creates an Aranya Fast Channels label

Step 5. The `Operator` assigns the created Fast Channels label to `Member A`
and `Member B`

Step 6. `Member A` creates an Aranya Fast Channel

Step 7. `Member A` uses this channel to send a message to `Member B`.
Optionally, `Member B` may also send a message back to `Member A`.

For more details on how Aranya starts and the steps performed in the examples,
see the [walkthrough](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/).

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
