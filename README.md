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
- [Aranya Overview](docs/overview.md)
- [Getting Started With Aranya](docs/walkthrough.md)


## Getting Started

Install Rust:
<https://www.rust-lang.org/tools/install>

Download the source code from this repository or from [crates.io](https://crates.io):
- [client](https://crates.io/crates/aranya-client)
- [daemon](https://crates.io/crates/aranya-daemon)

Integrate the [client](crates/aranya-client) library into your application. The
[client's README](crates/aranya-client/README.md) has more information on using
the Rust client.

The [daemon's README](crates/aranya-daemon/README.md) contains instructions for
configuring and running the daemon.

After the daemon has started up, start the application.

### Rust Example Application

An example Rust program for using Aranya is located here:
[Aranya Rust Example](crates/aranya-example)

To generate a new workspace from the `crates/aranya-example` crate:
`cargo generate https://github.com/aranya-project/aranya crates/aranya-example`

Navigate into the new workspace directory:
`cd aranya-example`

Build the example:
`cargo build`

Run the example:
`cargo run`

Set the tracing log level with the `ARANYA_EXAMPLE` environment variable:
`ARANYA_EXAMPLE=info cargo run`

Refer to the `aranya-example` crate's README for more information:
[Aranya Example README.md](crates/aranya-example/README.md)

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

## Dependencies

### Aranya Core

The [Aranya Core](https://github.com/aranya-project/aranya-core) repo has all the main components of Aranya that are needed for the core functionality to work. This is a library that includes the storage module (for DAG and FactDB), crypto module (with default crypto engine automatically selected), sync engine, and runtime client (including policy VM).

### Aranya Fast Channels

[Aranya Fast Channels](https://github.com/aranya-project/aranya-core/tree/main/crates/aranya-fast-channels) are encrypted channels between 2 peers that could be either bidirectional or unidirectional.

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
