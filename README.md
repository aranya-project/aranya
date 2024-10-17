# Aranya

Aranya is a software development tool for governing access to data and services over a decentralized, zero-trust framework with secure end-to-end encrypted data exchange built-in.

Aranya has been designed with an emphasis on security, efficiency, and portability.

The root cause of cyber insecurity is complexity; and yet when we attempt to protect our systems, our solution is to add more.

Software developers must not expect customers to mitigate defects using external security tools and an endless cycle of patching. Software must become secure by design.

Aranya is our contribution to this effort. It is a batteries-included tool which allows developers to produce software with built-in micro-segmentation. This complete solution covers access management with user onboarding, authentication and authorization, freeing the developer to focus on the problem they wish to solve.

For users, software built on Aranya is less complex to operate securely, and is secure regardless of the network it is run on.

More documentation on Aranya is provided here:
- [Aranya Overview](docs/overview.md)
- [Aranya Technical Documentation](docs/tech-docs.md)
- [Getting Started With Aranya](docs/walkthrough.md)


## Getting Started

Install Rust:
<https://www.rust-lang.org/tools/install>

Download the source code from this repository or from [crates.io](https://crates.io):
- [client](https://crates.io/crates/aranya-client)
- [daemon](https://crates.io/crates/aranya-daemon)

Integrate the [client](crates/aranya-client) library into your application. Refer to the integration test here for an example:
[test](crates/aranya-daemon/tests/tests.rs)

Create a config file for the daemon before running it. Refer to this documentation on the JSON config file parameters:
[config](crates/aranya-daemon/src/config.rs)

Example daemon [config.json](crates/aranya-daemon/example.json) file:
```
{
	// The daemon's name.
	"name": "name",

	// The daemon's working directory.
	//
	// Must already exist.
	"work_dir": "/var/lib/work_dir",

	// Used to receive API requests from the user library client.
	"uds_api_path": "/var/run/uds.sock",

	// The path where the daemon should write its PID file.
	"pid_file": "/var/run/hub.pid",

	// Aranya sync server address.
	"sync_addr": "0.0.0.0:4321"
}
```

Build the [daemon](crates/aranya-daemon) crate and run it in the background.

After the daemon has started up, start the application.

## What's Contained In This Repo

This repository contains the following components:
- [Rust Client Library](crates/aranya-client)
- [Daemon Process](crates/aranya-daemon)
- [Aranya Policy](crates/aranya-daemon/src/policy.md)

### Rust Client Library

The [Rust Client Library](crates/aranya-client) is the library that your application will interface with.
By integrating the library into an application, IDAM/RBAC and secure data transmission can be easily added without needing to develop complex security architectures, protocols, and cryptography.

### Daemon Process

The [Daemon Process](crates/aranya-daemon) is a long-running executable that can interface with the [Aranya Core](https://github.com/aranya-project/aranya-core) library directly.

The daemon handles Aranya DAG maintenance for the application.

The daemon's responsibilities include:
- Periodically syncing state between networked Aranya peers to ensure they all have a consistent DAG.
- Interfacing with the [Aranya Core](https://github.com/aranya-project/aranya-core) library
- Receiving requests from the [Rust Client Library](crates/aranya-client) via the [Unix Domain Socket `tarpc` API](crates/aranya-daemon-api)

### Aranya Policy

The [Aranya Policy](crates/aranya-daemon/src/policy.md) is a security control policy written in Aranya's domain-specific policy language and executed by the Aranya runtime.

## Dependencies

### Aranya Core

The [Aranya Core](https://github.com/aranya-project/aranya-core) repo has all the main components of Aranya that are needed for the core functionality to work. This is a library that includes the storage module (for DAG and FactDB), crypto module (with default crypto engine automatically selected), sync engine, and runtime client (including policy VM).

### Aranya Fast Channels

[Aranya Fast Channels](https://github.com/aranya-project/aranya-core/tree/main/crates/aranya-fast-channels) are encrypted channels between 2 peers that could be either bidirectional or unidirectional.

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
