# Aranya Daemon

[![Crates.io][crates-badge]][crates-url]
[![License][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/aranya-daemon.svg
[crates-url]: https://crates.io/crates/aranya-daemon
[license-badge]: https://img.shields.io/crates/l/aranya-daemon.svg
[license-url]: https://github.com/aranya-project/aranya/blob/main/LICENSE.md

## Overview

The Aranya Daemon is a long-running executable that is used to maintain
the state of Aranya after adding commands to the graph or syncing commands from
other peers by interacting directly with the
[Aranya Core](https://github.com/aranya-project/aranya-core) library. See
[here](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon-api/src/service.rs) for details on the Aranya
functionality available through the daemon.

The daemon's responsibilities include:
- Periodically syncing state between networked Aranya peers to ensure they all
  have consistent state. This includes the ability to add and remove sync peers,
  available to your application through the [Rust Client library](../aranya-client/).
- Invokes actions received from the client and handles effects from the
  [Aranya Core](https://github.com/aranya-project/aranya-core) library. See the
  [walkthrough](https://aranya-project.github.io/getting-started/walkthrough/)
  for more details.
- Generates and maintains cryptographic keys for encrypting and decrypting data
  for Aranya and Fast Channels

Note: The Aranya Daemon supports a single device.

## Configuration

Create a config file for the daemon before running it. Refer to
this documentation on the TOML config file parameters:
[config](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/src/config.rs).

An example daemon configuration file can be found [here](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/example.toml).

Things to know before starting the daemon:
- `runtime_dir`, `state_dir`, `cache_dir`, `logs_dir` and `config_dir` must
  already exist. The daemon does not create them and exits if any is missing.
- The `[afc]` and `[sync.quic]` sections are required and must have
  `enable = true`. The daemon will not start with either disabled.
- `[sync.quic]` requires `root_certs_dir`, `device_cert` and `device_key`.
  Peers authenticate each other with mTLS, so every device needs a certificate
  signed by a CA in the other devices' `root_certs_dir`. Certificates are
  loaded once at startup; restart the daemon after replacing them. See
  [aranya-certgen](../aranya-certgen/README.md) for generating certificates.
- Unknown keys at the top level of the config file are ignored, so check
  spelling carefully.

## Running the daemon

Build and run the daemon crate:
```shell
$ cargo build --bin aranya-daemon --release
$ ./target/release/aranya-daemon --config <path to config>
```

The daemon writes logs to stderr. Set the log filter with the `ARANYA_DAEMON`
environment variable, which uses
[`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
syntax:
```shell
$ ARANYA_DAEMON=info ./target/release/aranya-daemon --config <path to config>
```

Sync peers added by the client are held in memory only. After the daemon
restarts, the application must add its sync peers again.
