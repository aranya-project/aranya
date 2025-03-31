# Daemon API

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![License][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/aranya-daemon-api.svg
[crates-url]: https://crates.io/crates/aranya-daemon-api
[docs-badge]: https://docs.rs/aranya-daemon-api/badge.svg
[docs-url]: https://docs.rs/aranya-daemon-api/latest/aranya_daemon_api/
[license-badge]: https://img.shields.io/crates/l/aranya-daemon-api.svg
[license-url]: ../../LICENSE.md

## Overview

The Aranya Daemon API is the interface between the Aranya
[client](../aranya-client/) and [daemon](../aranya-daemon/), which communicate
using [`tarpc`](https://crates.io/crates/tarpc) over Unix domain sockets. Think
of the daemon as the server, this crate being the API, and the client is the
consumer of this API.

This API also provides type conversions when translating from internal types
used by the daemon and external types used by the client. Ultimately, the
intention of this crate is to make it easier to update the API used by the
client and daemon to communicate.
