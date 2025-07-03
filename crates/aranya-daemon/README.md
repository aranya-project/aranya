# Aranya Daemon

[![Crates.io][crates-badge]][crates-url]
[![License][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/aranya-daemon.svg
[crates-url]: https://crates.io/crates/aranya-daemon
[license-badge]: https://img.shields.io/crates/l/aranya-daemon.svg
[license-url]: ../../LICENSE.md

## Overview

The Aranya Daemon is a long-running executable that is used to maintain
the state of Aranya after adding commands to the graph or syncing commands from
other peers by interacting directly with the
[Aranya Core](https://github.com/aranya-project/aranya-core) library. See
[here](../aranya-daemon-api/src/service.rs) for details on the Aranya
functionality available through the daemon.

The daemon's responsibilities include:
- Periodically syncing state between networked Aranya peers to ensure they all
  have consistent state. This includes the ability to add and remove sync peers,
  available to your application through the [Rust Client library](../aranya-client/).
- Invokes actions received from the client and handles effects from the
  [Aranya Core](https://github.com/aranya-project/aranya-core) library. See the
  [walkthrough](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/)
  for more details.
- Generates and maintains cryptographic keys for encrypting and decrypting data
  for Aranya and Fast Channels

Note: The Aranya Daemon supports a single device.

## Configuration

Create a config file for the daemon before running it. Refer to
this documentation on the JSON config file parameters:
[config](src/config.rs).

An example daemon configuration file can be found [here](test_configs/example.json).

## Running the daemon

Build and run the daemon crate:
```shell
$ cargo build --bin aranya-daemon --release
$ ./target/release/aranya-daemon <path to config>
```
