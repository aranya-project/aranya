# AGENTS.md

This document follows the [agents.md](https://agents.md) guidance and applies to any AI pair programmer or code assistant working in this repository.

## Repository Purpose

Aranya is a zero-trust security framework for decentralized applications. Devices join a shared CRDT-backed graph, and every command they can publish is mediated by the policy defined in `crates/aranya-daemon/src/policy.md`. That policy is a literate markdown file written in Aranya Policy Language v2 and compiled (via `policy-ifgen`) into the daemon during build.

## Code Structure Overview

- `crates/aranya-daemon/` – long-running daemon that enforces the policy, performs cryptography, manages device/team state, and coordinates CRDT sync. The `src/policy.md` file defines the RBAC model, device lifecycle, label management, and AQC permissions.
- `crates/aranya-client/` – Rust client library that applications link against to talk to the daemon over tarpc.
- `crates/aranya-client-capi/` – C bindings for the client library.
- `crates/aranya-daemon-api/` – shared RPC/service definitions.
- `crates/aranya-keygen/`, `crates/aranya-util/`, `crates/aranya-aqc-util/` – auxiliary crates for key generation, common utilities, and Aranya QUIC channels (AQC).
- `tests/` and integration harnesses – spin up multiple daemon instances to exercise policy enforcement, AQC flows, and sync behaviour end-to-end.

## Build & Test Commands

```
cargo build --release
cargo make build
cargo make build-capi

cargo make test

# Run tests in memory to avoid slow fsync
TMPDIR=/dev/shm cargo test

cargo make correctness   # fmt + clippy + feature checks
cargo make fmt
cargo make clippy
cargo make check-features
cargo make security      # audit / deny / vet

cargo make run-rust-example
cargo make run-capi-example

cargo build --bin aranya-daemon --release
./target/release/aranya-daemon <path-to-config>
```

These commands mirror the expectations from the original CLAUDE.md so assistants know how to build, lint, and run the components.

## Policy Language Notes

- `crates/aranya-daemon/src/policy.md` is the canonical source of authorization logic. Only code inside ```policy``` fences is compiled; the surrounding prose documents the invariants you must preserve.
- The file uses Policy Language v2 features (scoped `let`, expression `match`, block expressions). Respect the language constraints: e.g., no iteration outside actions, `finish` blocks only allow CRUD/emit statements, optionals require explicit `Some`/`None` blocks.
- Facts, commands, actions, and helper functions must maintain the invariants called out in the document (device key consistency, role ownership and management permissions, label and AQC checks, etc.). Helper finish-functions (such as the role-assignment helpers) keep related facts in lockstep—reuse them.
- Changing the policy regenerates Rust bindings during build. After edits, run `cargo test -p aranya-client` to exercise the integration suite (it spins up daemons and validates policy behaviour). If the sandbox blocks networking, report the failure reason explicitly.

## Architecture Notes

- **Client–Daemon pattern:** a single daemon per device handles crypto, policy enforcement, and graph sync while client libraries issue RPCs.
- **Keys/keystore:** `crates/aranya-daemon/src/keystore.rs` manages device keys; `crates/aranya-keygen` provides CLI utilities.
- **AQC (Aranya QUIC Channels):** implemented via `crates/aranya-aqc-util`; policy code governs label permissions, channel creation, and PSK limits.
- **Sync system:** lives under `crates/aranya-daemon/src/sync/`, using CRDT semantics so all devices converge.

## Expectations for AI Helpers

1. **Study the policy first.** Understand the invariants you are touching; confirm related facts/commands stay consistent.
2. **Preserve the literate style.** When behaviour changes, update both the code and the explanatory prose near it.
3. **Be explicit about security impact.** Highlight RBAC, label, device lifecycle, or AQC changes in your notes or PR descriptions.
4. **Validate changes.** Run the appropriate `cargo` / `cargo make` commands where possible. If tests cannot run (e.g., QUIC blocked in sandbox), state that explicitly.
5. **Follow repo conventions.** ASCII only, concise comments, use helper finish-functions, and avoid noisy diffs.
6. **Keep AGENTS.md and CLAUDE.md in sync.** `CLAUDE.md` is a symlink to this file; do not break the linkage.

When in doubt: consult `crates/aranya-daemon/src/policy.md`, maintain its documented invariants, and explain your reasoning for future maintainers (human or AI).
