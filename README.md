# Aranya

Aranya is lovingly crafted and supported by [SpiderOak](https://spideroak.com). Aranya is licensed under the [AGPL](LICENSE.md)- if you want to use it commercially, drop us a line!

## What is it?

Aranya is a software development tool for governing access to data and services over a decentralized, zero-trust framework with secure end-to-end encrypted data exchange built-in.

Aranya has been designed with an emphasis on security, efficiency, and portability.

The root cause of cyber insecurity is complexity; and yet when we attempt to protect our systems, our solution is to add more.

Software developers must not expect customers to mitigate defects using external security tools and an endless cycle of patching. Software must become secure by design.

Aranya is our contribution to this effort. It is a batteries-included tool which allows developers to produce software with built-in micro-segmentation. This complete solution covers access management with device onboarding, authentication and authorization, freeing the developer to focus on the problem they wish to solve.

For users, software built on Aranya is less complex to operate securely, and is secure regardless of the network it is run on.

Find more information on the [Aranya Project docs site](https://aranya-project.github.io/aranya-docs/).

## What's Contained In This Repo

This repository contains the following components:

- [Rust Client Library](crates/aranya-client/): interface for your application
to interact with the [Aranya Daemon](https://docs.rs/aranya-daemon-api/latest/aranya_daemon_api/trait.DaemonApi.html) in order to invoke [Aranya Core](https://github.com/aranya-project/aranya-core) functionality. Refer to the `aranya-client`
[README](crates/aranya-client/README.md) for more details on this component.

- [Daemon Process](crates/aranya-daemon/): a long-running process that forwards
requests from the [client](crates/aranya-client) to the
[Aranya Core](https://github.com/aranya-project/aranya-core). Refer to the
`aranya-daemon` [README](crates/aranya-daemon/README.md) for more information
on this component.

- [Aranya Policy](crates/aranya-daemon/src/policy.md): a markdown file of the security control policy written in Aranya's domain-specific policy language and executed by the Aranya runtime.

For more information on Aranya's internal components, see the Aranya Core
[README](https://github.com/aranya-project/aranya-core/blob/main/README.md).

- [Aranya Examples](examples/): examples of how to integrate Aranya into an application. We currently support direct integration into Rust and C applications.

## Feature Flags

There are currently three classifications of feature sets we can build:
- Production - the default set of production ready features included in every build. Future changes are guaranteed to be backward compatible. Release artifacts are appended with *-default.
- Preview - production ready features with plans for long-term support. May introduce breaking changes but are designed with API stability in mind. Release artifacts are appended with *-preview.
- Experimental - experimental features with no backward compatibility or long-term support guarantees. These features may be unstable or introduce breaking changes in the future. Release artifacts are appended with *-experimental.

AFC is enabled by default.

Rather than requiring feature flags to be manually specified with `cargo build --features ...`, `cargo make` commands are provided in [Makefile.toml](Makefile.toml) for each feature set.

## Cargo Make

We rely heavely on `cargo make` targets to build software, run integration tests, perform unit tests, and run CICD checks. Here's how to install `cargo make`:
[cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation)

Building Aranya:
- `cargo make build` - builds release version of the daemon executable at [daemon](crates/aranya-daemon/).
- `cargo make build-capi` - builds the Aranya C API library including the [aranya-client.h](crates/aranya-client-capi/output/aranya-client.h) header file and `libaranya_client_capi.*` shared library artifact. The extension of the shared library artifact depends on what system it is built on. E.g. MacOS will have a `.dylib` extension while linux would have a `.so` extension.

Testing Aranya:
- `cargo make test` - runs Rust unit tests with all feature combinations

Examples (these are run as part of the CICD pipeline to ensure they do not break):
- `cargo make run-rust-example` - runs the default Rust example
- `cargo make run-rust-example-multi-node` - runs the multi-node Rust example
- `cargo make run-rust-example-onboarding` - runs the onboarding Rust example
- `cargo make run-capi-example` - runs the C example

A complete list of examples can be found at [examples](examples/):
- [Rust examples](examples/rust/)
- [C examples](examples/c/)

CICD checks:
- `cargo make security` - runs security checks such as `cargo-audit`, `cargo-deny` and `cargo-vet`
- `cargo make correctness` - runs correctness checks such as `cargo fmt`, `cargo clippy`, and `cargo-machete`
- `cargo make gen-docs-nightly` - generates `rustdocs` with Rust nightly

Performance metrics:
- `cargo make metrics`

Auto-formatting code:
- `cargo make fmt`

We allow certain targets to be run for specific sets of feature flags by appending `*-preview` or `*-experimental`:
- `cargo make build-preview`
- `cargo make build-experimental`
- `cargo make build-capi-lib-preview`
- `cargo make build-capi-lib-experimental`


A complete list of `cargo make` targets can be found in the [Makefile.toml](Makefile.toml) or by running `cargo make` in the workspace root without any arguments.

## Getting Started

The following platforms are supported:
- Linux/arm64
- Linux/amd64
- MacOS

Aranya can be integrated into an existing project using the options below. See [Example Applications](#example-applications) to run a standalone Aranya app in C or Rust, or for a step-by-step tutorial on how to manually configure and integrate the example scenario, see the [walkthrough](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/).

We currently provide the following integrations for Aranya:

1. [Rust library](#rust-lib)
2. [C API](#c-api)

### <a href name="rust-lib"></a>Rust Library

#### Dependencies

The following are needed to build and run Aranya code:
- [Rust](https://www.rust-lang.org/tools/install) (Find version info in the
[rust-toolchain.toml](rust-toolchain.toml))
> NOTE: When building with Rust, the compiler will automatically download and
> use the version specified by the `rust-toolchain.toml`.
- (Optional) [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23)
- (Optional) Git for cloning the repository

> NOTE: we have tested using the specified versions above. Other versions of these tools may also work.

If you'd like to run the Rust example app, see [below](#example-applications).

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
[Rust example](examples/rust/aranya-example/src/main.rs#L198).

Before starting your application, run the daemon by providing the path to a
[configuration file](crates/aranya-daemon/example.toml). Find more details on
configuring and running the daemon in the `aranya-daemon`
[README](crates/aranya-daemon/README.md).

### <a href name="c-api"></a>C API

#### Dependencies

- [Rust](https://www.rust-lang.org/tools/install) (find version info in the
[rust-toolchain.toml](rust-toolchain.toml))
> NOTE: When building with Rust, the compiler will automatically download and
> use the version specified by the `rust-toolchain.toml`.
- [cmake](https://cmake.org/download/) (v3.31)
- [clang](https://releases.llvm.org/download.html) (v18.1)
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23)
- (Optional) Git for cloning the repository

> NOTE: we have tested using the specified versions above. Other versions of these tools may also work.

If you'd like to run the C example app, see [below](#example-applications).

#### Install

Prebuilt versions of the library are uploaded (along with the [header file](https://github.com/aranya-project/aranya/blob/main/crates/aranya-client-capi/output/aranya-client.h)) to each Aranya [release](https://github.com/aranya-project/aranya/releases).

A prebuilt version of the `aranya-daemon` is available for supported platforms
in the Aranya [release](https://github.com/aranya-project/aranya/releases).

If your platform is unsupported, you may checkout the source code and build
locally.

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
[configuration file](crates/aranya-daemon/example.toml). Find more details on
configuring and running the daemon in the `aranya-daemon`
[README](crates/aranya-daemon/README.md).

## <a name="example-applications"></a>Example Applications

We have provided runnable example applications in both
[Rust](examples/rust) and [C](examples/c/). These examples will
use the default policy that's contained in this repo to configure and run the
daemon automatically. The examples follow five devices who are referred to by
their device role, `Owner`, `Admin`, `Operator`, `Member A` and `Member B`.

The examples go through the following steps:

Step 1: Build or download the prebuilt executable from the latest Aranya
release. After providing a unique configuration file (see
[example.toml](crates/aranya-daemon/example.toml)) for each device, run the
daemons.

Step 2. The `Owner` initializes the team

Step 3. The `Owner` adds the `Admin` and `Operator` to the team. `Member A` and
`Member B` can either be added by the `Owner` or `Operator`.

Step 4. The `Admin` creates an Aranya Fast Channel label

Step 5. The `Operator` assigns the created Fast Channel label to `Member A`
and `Member B`

Step 6. `Member A` creates a unidirectional send Aranya Fast Channel with `Member B`.

Step 7. `Member B` receives the channel by receiving a control message from `Member A`.

Step 8. `Member A` uses this channel to encrypt plaintext with `seal()` and send the ciphertext to `Member B`.

Step 9. `Member B` receives the ciphertext from `Member A` and decrypts it with `open()`.

For more details on how Aranya starts and the steps performed in the examples,
see the [walkthrough](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/).

## Contributing

Find information on contributing to the Aranya project in
[`CONTRIBUTING.md`](https://github.com/aranya-project/.github/blob/main/CONTRIBUTING.md).

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
