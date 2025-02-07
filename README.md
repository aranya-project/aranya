# Aranya

Aranya is lovingly crafted and supported by [SpiderOak](https://spideroak.com). Aranya is licensed under the [AGPL](LICENSE.md)- if you want to use it commercially, drop us a line!

## What is it?

Aranya is a software development tool for governing access to data and services over a decentralized, zero-trust framework with secure end-to-end encrypted data exchange built-in.

Aranya has been designed with an emphasis on security, efficiency, and portability.

The root cause of cyber insecurity is complexity; and yet when we attempt to protect our systems, our solution is to add more.

Software developers must not expect customers to mitigate defects using external security tools and an endless cycle of patching. Software must become secure by design.

Aranya is our contribution to this effort. It is a batteries-included tool which allows developers to produce software with built-in micro-segmentation. This complete solution covers access management with user onboarding, authentication and authorization, freeing the developer to focus on the problem they wish to solve.

For users, software built on Aranya is less complex to operate securely, and is secure regardless of the network it is run on.

Find more information on the [Aranya Project docs site](https://aranya-project.github.io/aranya-docs/).

## What's Contained In This Repo

This repository contains the following components:

- [Rust Client Library](crates/aranya-client/): interface for your application
to interact with the [Aranya Daemon](https://docs.rs/aranya-daemon-api/0.4.0/aranya_daemon_api/trait.DaemonApi.html) in order to invoke [Aranya Core](https://github.com/aranya-project/aranya-core) functionality. Refer to the `aranya-client`
[README](crates/aranya-client/README.md) for more details on this component.

- [Daemon Process](crates/aranya-daemon/): a long-running process that forwards
requests from the [client](crates/aranya-client) to the
[Aranya Core](https://github.com/aranya-project/aranya-core). Refer to the
`aranya-daemon` [README](crates/aranya-daemon/README.md) for more information
on this component.

- [Aranya Policy](crates/aranya-daemon/src/policy.md): a markdown file of the security control policy written in Aranya's domain-specific policy language and executed by the Aranya runtime.

For more information on Aranya's internal components, see the Aranya Core
[README](https://github.com/aranya-project/aranya-core/README.md).

## Getting Started

The following platforms are supported:
- Linux/arm64
- Linux/amd64
- MacOS

Aranya can be integrated into an existing project using the Rust Library or C
API. For a step-by-step tutorial on how to run Aranya as a standalone app, see
the [walkthrough](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/).

We currently provide the following integrations for Aranya:

1. [Rust library](#rust-lib)
2. [C API](#c-api)

### <a href name="rust-lib"></a>Rust Library

#### Dependencies

- [Rust](https://www.rust-lang.org/tools/install) (find version info in the
[rust-toolchain.toml](rust-toolchain.toml))
- (Optional) [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23)
- (Optional) Git for cloning the repository

> NOTE: we have tested using the specified versions above. Other versions of these tools may also work.

If you'd like to run the Rust example app, see [below](#example-applications).

#### Install

First, install the Aranya client.

**From this repository**:

`git clone git@github.com:aranya-project/aranya.git`

**From crates.io**:

Run the following in your project's directory:

`cargo add aranya-client`

Or, add it to your project's `Cargo.toml`:

```
[dependencies]
aranya-client = { version = ... }
```

#### Build

If the source code has been downloaded, navigate to the Aranya project
workspace.

Build the code using `cargo` or `cargo-make`.

**Using `cargo`**:

`cargo build --release`

**Using `cargo-make`**:

`cargo make build-code`

This will build the Aranya [client](crates/aranya-client/) and the
[daemon](crates/aranya-daemon/) executable. The built versions are available
in the `target/release` directory.

#### Integrate

Integrate the client library into your application. The `aranya-client`
[README](crates/aranya-client/README.md) has more information on using
the Rust client.

An example of the Rust client library being used to create a team follows:

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

This snippet can be found in the
[Rust example](templates/aranya-example/src/main.rs#L140).

Before starting your application, run the daemon by providing the path to a
[configuration file](crates/aranya-daemon/example.json). Find more details on
configuring and running the daemon in the `aranya-daemon`
[README](crates/aranya-daemon/README.md).

### <a href name="c-api"></a>C API

#### Dependencies

- [Rust](https://www.rust-lang.org/tools/install) (find version info in the
[rust-toolchain.toml](rust-toolchain.toml))
- [cmake](https://cmake.org/download/) (v3.31)
- [clang](https://releases.llvm.org/download.html) (v18.1)
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23)
- (Optional) Git for cloning the repository

> NOTE: we have tested using the specified versions above. Other versions of these tools may also work.

If you'd like to run the C example app, see [below](#example-applications).

#### Install

Pre-built versions of the library are uploaded (along with the [header file](https://github.com/aranya-project/aranya/blob/main/crates/aranya-client-capi/output/aranya-client.h)) to each Aranya [release](https://github.com/aranya-project/aranya/releases).

A prebuilt version of the `aranya-daemon` is available for supported platforms
in the Aranya [release](https://github.com/aranya-project/aranya/releases).

If your platform is unsupported, you must download the source code and build
locally.

**Download the source code**:

`git clone git@github.com:aranya-project/aranya.git`

#### Build

As mentioned, prebuilt versions of the Aranya C API library, header file, and
the Aranya daemon are uploaded to each Aranya
[release](https://github.com/aranya-project/aranya/releases).

Instructions for generating the Aranya client library and `aranya-client.h`
header file locally are available in the `aranya-client-capi`
[README](crates/aranya-client-capi/README.md).

To build the daemon locally, use `cargo` or `cargo-make`.

**Using `cargo`**:

`cargo build --release`

**Using `cargo-make`**:

`cargo make build-code`

The daemon executable will be available in the `target/release` directory.

#### Integrate

Aranya can then be integrated using `cmake`. A
[CMakeLists.txt](https://github.com/aranya-project/aranya/blob/main/examples/c/CMakeLists.txt)
is provided to make it easier to build the library into an application.

An example of the C API being used to create a team follows:

```C
// have owner create the team.
err = aranya_create_team(&team->clients.owner.client, &team->id);
EXPECT("error creating team", err);
```

This snippet has been modified for simplicity. For actual usage,
see the [C example](examples/c/example.c#L169).

Before starting your application, run the daemon by providing the path to a
[configuration file](crates/aranya-daemon/example.json). Find more details on
configuring and running the daemon in the `aranya-daemon`
[README](crates/aranya-daemon/README.md).

## Example Applications

We have provided runnable example applications in both
[Rust](templates/aranya-example/) and [C](examples/c/). These examples will
use the default policy that's contained in this repo to configure and run the
daemon automatically. The examples follow five users who are referred to by
their user role, `Owner`, `Admin`, `Operator`, `Member A` and `Member B`.

The examples go through the following steps:

Step 1: Build or download the pre-built executable from the latest Aranya
release. After providing a unique configuration file (see
[example.json](crates/aranya-daemon/example.json)) for each user, run the
daemons.

Step 2. The `Owner` initializes the team

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

## Contributing

Find information on contributing to the Aranya project in
[`CONTRIBUTING.md`](https://github.com/aranya-project/.github/blob/main/CONTRIBUTING.md).

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
