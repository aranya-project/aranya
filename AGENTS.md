# AGENTS.md

## What is Aranya

Aranya is a zero-trust security framework for decentralized applications.

- Devices form a **team**, sharing a CRDT-backed DAG (directed acyclic graph).
- Every mutation is a **command**. Commands are synced to all devices and each device independently enforces the policy before accepting a command into its local graph (endpoint enforcement).
- The policy defines RBAC roles (owner / admin / operator / member plus application-defined custom roles), device lifecycle, label-based access control, and AFC (Aranya Fast Channels) permissions.
- There is no central authority -- every device stores a copy of the graph containing all commands it has generated or synced so far, and independently enforces the same policy. When all devices sync without generating new commands they converge to the same full graph, but at any point in time a device may have only a partial view. Devices converge via CRDT sync.
- Separation of duties is enforced: no device can self-promote or bypass the role hierarchy.
- The system has two planes:
  - **Control plane (on-graph):** commands stored in the DAG, broadcast to all devices via sync. Used for access-control operations (add device, assign role, manage labels). Low throughput (~100s msgs/sec), high resilience.
  - **Data plane (off-graph/AFC):** encrypted point-to-point channels between devices, governed by labels in policy. High throughput, low latency. Keys are negotiated on-graph but data flows off-graph.

For full documentation see <https://github.com/aranya-project/aranya-docs/> (includes guides, architecture deep-dives, and API reference; clone the repo for offline access).

## How It Fits Together

```
Application -> Client lib (tarpc RPC) -> Daemon -> Policy engine / Keystore / Sync
```

- One daemon per device; it owns crypto, policy enforcement, and graph sync.
- The daemon runs background sync continuously, exchanging commands with peers over QUIC so each device's graph stays up to date.
- Client libraries (Rust + C bindings) issue RPCs to the local daemon.
- Sync uses QUIC transport; CRDT semantics ensure all devices converge.
- Keys are managed by the daemon's keystore (`crates/aranya-daemon/src/keystore.rs`).

## Crate Map

| Crate | Purpose |
|---|---|
| `aranya-daemon` | Long-running daemon: policy, crypto, sync, device/team state |
| `aranya-client` | Rust client library (tarpc RPC to daemon) |
| `aranya-client-capi` | C bindings (cdylib) for aranya-client |
| `aranya-daemon-api` | Shared RPC/service definitions |
| `aranya-keygen` | CLI for generating device keys |
| `aranya-certgen` | CLI for generating root CA / signed P-256 certs |
| `aranya-util` | Shared utilities (QUIC helpers, async) |
| `aranya-metrics` | Observability: Datadog/Prometheus/TCP exporters |

Examples live in `examples/rust/` and `examples/c/`.

## Policy

The policy is the heart of Aranya. It lives at `crates/aranya-daemon/src/policy.md` as a literate markdown file (>100 KB). Only code inside ` ```policy ``` ` fences is compiled (via `policy-ifgen` at build time). The surrounding prose documents invariants -- always update prose when changing code.

Key sections in the policy: Devices & Identity, Roles & Permissions, Teams, AFC/Labels.

### Vocabulary

- **Action:** The application's entry point into the policy. Actions run **once, on the authoring device only**. They perform checks, prepare data, and `publish` zero or more commands. Actions execute atomically -- if any published command fails, the entire action is rolled back. Because actions only run locally, they are the right place for sensitive operations (e.g. encryption, secret handling) and for logic that should not be visible to other nodes. Iteration over facts (`map`) is only allowed inside actions.
- **Command:** The fundamental unit of the DAG. A command defines structured data (`fields` block), serialization (`seal`/`open` blocks), and validation + side-effects (`policy` and `recall` blocks). **Command `policy` blocks are executed on every device that receives the command** -- this is how endpoint enforcement works. This means command fields are visible to all nodes, so never put plaintext secrets in command fields. Any sensitive data must be encrypted before being placed in command fields (done in the action or in Rust code calling the action).
- **Effect:** A struct emitted from a `finish` block to communicate outcomes back to the application. Along with actions, effects form the only public interface of a policy -- everything else is an implementation detail.
- **Fact:** A key-value pair in the FactDB. Facts are the persistent state that policy reads (via `query`) and writes (via `create`/`update`/`delete` in `finish` blocks). Facts can be declared `immutable` (create/delete only, no update).
- **FFI:** Foreign function interface modules (`use crypto`, `use envelope`, `use device`, etc.) that bring external logic (cryptography, envelope inspection, device identity) into policy. FFI functions must be side-effect-free since policy may be evaluated more than once.

### Execution model

On the **authoring device** (runs once):
1. Application calls an **action** via the client library.
2. The action runs locally: it can do sensitive work, iterate facts, and `publish` zero or more **commands**.
3. For each command, the `seal` block serializes it into an envelope.
4. The `policy` block runs: it queries facts, runs `check` statements, and terminates with a `finish` block.
5. The `finish` block performs fact mutations (`create`/`update`/`delete`) and `emit`s **effects**. Effects are the mechanism for communicating outcomes back to the application -- e.g. `RoleCreated`, `LabelDeleted`, `AfcUniChannelCreated`. The application subscribes to effects and reacts accordingly.
6. If all commands succeed, the action is committed atomically. If any command fails, the entire action is rolled back.

On **every other device** (runs on sync):
7. The command envelope arrives via sync. The `open` block deserializes it.
8. The `policy` block runs again -- same checks, same finish logic. Effects are emitted on the receiving device too, so every device can react to the outcome. The receiving device must be able to fully evaluate the command with only the command fields and its local FactDB. This is why command fields cannot contain plaintext secrets.

### Ordering and recall

- The DAG stores commands with parent pointers forming a causal graph. A deterministic **weave** algorithm produces a total ordering of all commands, respecting causality and using command **priority** to break ties between concurrent (non-causal) commands.
- A command can be **recalled** if it was accepted in one ordering but fails when a new command arrives and changes the weave. The `recall` block (if defined) handles this by emitting compensating effects and/or adjusting facts. Check failures fall to recall; runtime exceptions use a default handler.
- Policy writers must design commands so that concurrent mutations to the same facts don't create unresolvable conflicts.

### Language restrictions

Policy Language v2. The language guarantees **bounded execution** -- there are no arrays, no general-purpose loops, and no recursion. Every policy evaluation is guaranteed to terminate. The only loop-like construct is `map` (iterate over matching facts), and it is restricted to actions only. Key restrictions:

- **`finish` blocks** may only contain `create`, `update`, `delete`, `emit`, and calls to `finish` functions. No `let`, no `query`, no control flow. Expressions are limited to named values and constants.
- **`finish` functions** follow the same rules as `finish` blocks (only CRUD/emit). They keep related fact mutations in lockstep -- reuse them.
- **`map`** (iteration over facts) is only valid inside actions, not in command policy/recall blocks.
- **`publish`** is only valid inside actions.
- **`check`** is valid in actions and policy blocks but not in recall blocks.
- **`let`** bindings are immutable and block-scoped (v2). Shadowing is a compile error.
- **Optionals** require explicit `Some`/`None` handling. `unwrap` causes a runtime exception on `None`; `check_unwrap` causes a check failure (which falls to recall).
- No fact can be mutated more than once in a single `finish` block (runtime exception).
- No recursion (actions, functions, or finish functions).
- v2 features: scoped `let`, match expressions, block expressions (`: expr` terminal), struct field insertion (`+StructName`), struct conversion (`as`), struct composition (`...`), struct subselection (`substruct`).

### Changing the policy

Changing the policy regenerates Rust bindings during build. Validate with:
```
cargo test -p aranya-client
```
This spins up daemons and exercises the integration suite against the new policy.

### AFC (Aranya Fast Channels)

AFC provides **high-throughput, low-latency encrypted channels** between devices on the data plane. Key concepts:

- Channels are **unidirectional** (one sender, one receiver). Created via the `create_afc_uni_channel(receiver_id, label_id)` ephemeral action.
- Access is governed by **labels**. A label is a named topic with a unique `label_id`; each label has one or more managing roles. Devices are assigned a `ChanOp` per label: `SendOnly`, `RecvOnly`, or `SendRecv`.
- Channel creation is **ephemeral** -- it does not persist to the DAG or mutate the FactDB. The sender generates a key (RFC 9180 KEM), encapsulates it for the receiver, and both sides store the key in shared memory.
- Both peers validate the channel: the label must exist, sender must have send permission, receiver must have receive permission, and both must have `CanUseAfc`.
- When role or label changes could invalidate existing channels, the policy emits a `CheckValidAfcChannels` signal effect so applications can re-validate.

## Build & Test

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

## Conventions

- ASCII only, concise comments.
- Reuse helper finish-functions in policy (they keep related facts in lockstep).
- Preserve literate style: update prose alongside policy code.
- `CLAUDE.md` is a symlink to `AGENTS.md` -- edit AGENTS.md, don't break the link.
