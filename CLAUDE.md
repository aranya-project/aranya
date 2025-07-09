# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when
working with code in this repository.

## Overview

Aranya is a zero-trust security framework for decentralized
applications. The repository contains:

- **aranya-client**: Rust client library for applications to
  interact with the daemon
- **aranya-daemon**: Long-running process that handles Aranya
  Core operations and state management
- **aranya-client-capi**: C API bindings for the client library
- **aranya-daemon-api**: API definitions for daemon communication
- **aranya-keygen**: Key generation utilities
- **aranya-util**: Common utilities

The architecture follows a client-daemon pattern where
applications use the client library to communicate with a daemon
process that manages cryptographic operations, team state, and
peer synchronization.

## Build Commands

### Standard Build

```bash
cargo build --release
# or using cargo-make
cargo make build
```

### C API Build

```bash
cargo make build-capi  # Builds header, docs, and library
```

### Testing

```bash
cargo make test  # Run all unit tests
cargo test  # Standard cargo test
```

### Code Quality

```bash
cargo make correctness  # Run formatting, clippy, feature checks
cargo make fmt  # Format code (Rust + TOML)
cargo make clippy  # Run clippy lints
cargo make check-features  # Verify feature combinations
```

### Security Checks

```bash
cargo make security  # Run audit, deny, and vet checks
```

## Development Workflow

### Running Examples

```bash
# Rust example
cargo make run-rust-example

# C example
cargo make run-capi-example
```

### Daemon Development

The daemon requires a configuration file (see
`crates/aranya-daemon/example.toml`):

```bash
cargo build --bin aranya-daemon --release
./target/release/aranya-daemon <path-to-config>
```

## Architecture Notes

### Client-Daemon Communication

- Client library communicates with daemon via tarpc (RPC
  framework)
- Daemon maintains cryptographic state and handles peer
  synchronization
- Single daemon instance supports one device

### Policy System

- Team permissions and roles defined in
  `crates/aranya-daemon/src/policy.md`
- Roles: Owner, Admin, Operator, Member with hierarchical
  permissions
- Policy written in Aranya's domain-specific language

### Key Components

- **AQC (Aranya Quick Channels)**: Fast encrypted communication
  channels
- **Sync System**: Peer-to-peer state synchronization
  (`crates/aranya-daemon/src/sync/`)
- **Keystore**: Cryptographic key management
  (`crates/aranya-daemon/src/keystore.rs`)

### Toolchain Requirements

- See `rust-toolchain.toml`
- Nightly toolchain for formatting and some builds
- cargo-make for build automation
- cbindgen for C API header generation

## Testing Strategy

Tests are primarily integration tests that spin up multiple
daemon instances to simulate multi-device scenarios. The test
pattern involves:

1. Starting daemon processes with unique configurations
2. Creating teams and adding devices with different roles
3. Testing encrypted communication via Fast Channels
4. Verifying policy enforcement and permissions
