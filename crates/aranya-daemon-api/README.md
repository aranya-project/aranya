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

The Aranya Daemon API is the interface used for the tarpc Unix Domain Socket
API between the Aranya [client](../aranya-client/) and the
[daemon](../aranya-daemon/). Think of the daemon as the server, this is the API
and the client as the client of this API. This API also provides type
conversions when translating from internal types used by the daemon and
external types used by the client.

Ultimately, the intention of this crate is to make it easier to update the API
used by the client and daemon to communicate.
