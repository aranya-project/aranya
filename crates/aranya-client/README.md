# Rust Client

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![License][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/aranya-client.svg
[crates-url]: https://crates.io/crates/aranya-client
[docs-badge]: https://docs.rs/aranya-client/badge.svg
[docs-url]: https://docs.rs/aranya-client/latest/aranya_client/
[license-badge]: https://img.shields.io/crates/l/aranya-client.svg
[license-url]: https://github.com/aranya-project/aranya/blob/main/LICENSE.md

## Overview

Aranya's Rust Client is the library that your application will interface with.
By integrating the library into an application, IDAM/RBAC and secure data
transmission can be easily added without needing to develop complex security
architectures, protocols, and cryptography.

The Rust Client library is used as an interface to actions that are performed
by the [daemon](../aranya-daemon), which interacts directly with the
[Aranya Core](https://github.com/aranya-project/aranya-core) library.

The client provides the following functionality:
- Add and remove sync peers. The daemon will periodically attempt to sync
  Aranya state with any peers (as long as it is able to communicate with the
  peer over the network) in its configured sync peer list.
- Add and remove devices from the team as determined by the implemented policy
- Assign and revoke device roles as determined by the implemented policy
- Create, delete, assign and revoke labels used for attribute based controls
  and segmentation of data communicated between peers within Aranya Fast
  Channels as determined by the implemented policy.
- Create and delete Fast Channels channels as determined by the implemented
  policy
- Send and receive encrypted data using Aranya Fast Channels. Fast Channels
  supports encrypted data exchange over TCP transport.
Note: The functionality noted 'as determined by the implemented policy' are
defined in the [default policy](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/src/policy.md). As such, these
may differ depending on the policy implemented in your application.

## Examples

An instance of the daemon must be running before the client can perform
actions. Instructions for running an instance of the `daemon` binary can be
found in the `aranya-daemon` [README](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/README.md).

For a full demonstration of the client's capabilities, see the
[walkthrough](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/).
This also includes explanations for the steps performed by the daemon and
Aranya based on the client's actions.

Additionally, the [test module](tests/tests.rs) includes tests that have
multiple devices joining a team, syncing, and sending encrypted messages using
Aranya Fast Channels. Instructions for running these tests are below.

## Testing

To run the client tests from this directory, use:
```shell
$ cargo test
```
