---
layout: page
title: Multi-Daemon Convergence Test
permalink: "/multi-daemon-convergence-test/"
---

# Multi-Daemon Convergence Test Specification

## Overview

This specification defines a test suite for validating Aranya daemon convergence behavior with a large number of nodes on a single device. The primary goal is to verify that all nodes in a network eventually reach a consistent state after commands are issued and synchronized across a defined network topology. We use a label command to easily track which nodes are up to date.

This specification is designed for use with [duvet](https://github.com/awslabs/duvet) for requirements traceability.

## Motivation

Existing Aranya integration tests typically use 5 nodes (`DevicesCtx` with owner, admin, operator, membera, memberb). While sufficient for testing role-based access control and basic synchronization, these tests do not exercise:

- Convergence behavior at scale (70+ nodes)
- Complex network topologies beyond fully-connected meshes
- Convergence time tracking and verification
- Resource utilization under load

This test suite addresses these gaps by providing a framework for large-scale convergence testing with configurable topologies.


## Test Architecture

### Node Context

The test uses a scalable node context that extends the patterns from `DeviceCtx` in the existing test infrastructure.

```rust
struct NodeCtx {
    /// Unique node identifier (0 to N-1)
    index: usize,
    /// Aranya client connection
    client: Client,
    /// Device's public key bundle
    pk: KeyBundle,
    /// Device ID
    id: DeviceId,
    /// Daemon handle
    daemon: DaemonHandle,
    /// Sync peers (indices of connected nodes)
    peers: Vec<usize>,
}
```

### Test Context

The test context manages all nodes and the configured topology.

```rust
struct TestCtx {
    /// All nodes in the test
    nodes: Vec<NodeCtx>,
    /// The topology used to connect nodes
    topology: Topology,
    /// The sync mode used for this test run
    sync_mode: SyncMode,
    /// Team ID for the test
    team_id: TeamId,
    /// Convergence tracker
    tracker: ConvergenceTracker,
}

enum Topology {
    Ring,
}

enum SyncMode {
    /// All nodes use interval-based polling to discover new commands
    Poll {
        /// How frequently each node polls its sync peers
        interval: Duration,
    },
    /// All nodes use hello notifications to trigger sync on graph changes
    Hello {
        /// Minimum time between hello notifications to the same peer
        debounce: Duration,
        /// How long a hello subscription remains valid before expiring
        subscription_duration: Duration,
    },
}
```

The `Topology` enum is expected to grow as additional topologies (star, mesh, etc.) are added in future extensions.

The `SyncMode` enum is expected to grow (e.g., `Mixed` mode) as additional sync strategies are validated.

### Convergence Tracker

Tracks convergence state across all nodes.

```rust
struct ConvergenceTracker {
    /// The label used to track convergence
    convergence_label: Label,
    /// Per-node convergence status
    node_status: Vec<ConvergenceStatus>,
    /// Timestamps for convergence measurements
    timestamps: ConvergenceTimestamps,
}

struct ConvergenceStatus {
    /// Whether this node has received the convergence label
    has_label: bool,
    /// Time when the label was received
    convergence_time: Option<Instant>,
}
```

## Requirements

### Test Configuration Requirements

#### CONF-001

The test MUST support configuring the number of nodes.

#### CONF-002

The test MUST scale to at least 70 nodes without failure.

#### CONF-003

The test MUST reject configurations with fewer than 3 nodes (the minimum for a valid ring).

#### CONF-004

In poll sync mode, the test MUST support configuring the sync interval between peers.

#### CONF-005

In poll sync mode, the default sync interval MUST be 1 second.

#### CONF-006

The test MUST support configuring a maximum test duration timeout.

#### CONF-007

The default maximum test duration MUST be 600 seconds (10 minutes).

#### CONF-008

The test MUST support configuring the sync mode (poll or hello).

#### CONF-009

The default sync mode MUST be poll.

#### CONF-010

In hello sync mode, the test MUST support configuring the hello notification debounce duration (minimum time between notifications to the same peer).

#### CONF-011

In hello sync mode, the test MUST support configuring the hello subscription duration (how long a subscription remains valid).

### Ring Topology Requirements

#### TOPO-001

In the ring topology, each node MUST connect to exactly two other nodes: its clockwise neighbor and its counter-clockwise neighbor.

#### TOPO-002

In the ring topology, sync peers MUST be configured bidirectionally, meaning if node A syncs with node B, node B MUST also sync with node A.

#### TOPO-003

The ring topology MUST form a single connected ring with no partitions.

#### TOPO-004

In the ring topology, no node MUST have more than 2 sync peers.

### Node Initialization Requirements

#### INIT-001

Each node MUST be initialized with a unique daemon instance.

#### INIT-002

Each node MUST have its own cryptographic keys.

#### INIT-003

All nodes MUST have unique device IDs.

#### INIT-004

Node initialization MUST occur in parallel batches to avoid resource exhaustion.

#### INIT-005

Node initialization MUST complete within a configurable timeout (default: 60 seconds per node batch).

#### INIT-006

The test MUST verify that all nodes started successfully.

### Team Setup Requirements

#### TEAM-001

A single team MUST be created by node 0 (the designated owner).

#### TEAM-002

All nodes MUST be added to the team before convergence testing begins.

#### TEAM-003

A shared QUIC sync seed MUST be distributed to all nodes during team setup.

#### TEAM-004

Each non-owner node MUST be added as a team member by the owner.

#### TEAM-005

Team configuration MUST be synchronized to all nodes before the convergence test phase.

#### TEAM-006

The test MUST verify that all nodes have received the team configuration.

### Sync Peer Configuration Requirements

#### SYNC-001

Each node MUST add its two ring neighbors as sync peers.

#### SYNC-002

Sync peer configuration MUST specify the sync interval.

#### SYNC-003

The sync peer address MUST be obtained from the neighbor node's local address.

#### SYNC-004

Sync peer configuration MUST complete before the convergence test phase.

#### SYNC-005

In poll sync mode, each node MUST poll its sync peers at the configured sync interval.

#### SYNC-006

In hello sync mode, each node MUST subscribe to hello notifications from its sync peers.

### Convergence Test Requirements

#### CONV-001

The test MUST assign a label to the source node's graph to mark the start of convergence testing.

#### CONV-002

The default source node for label assignment MUST be node 0.

#### CONV-003

The test MUST track when each node receives the convergence label.

#### CONV-004

Convergence MUST be defined as all nodes having received the convergence label.

#### CONV-005

The test MUST measure the total convergence time from label assignment to full convergence.

#### CONV-006

The test MUST fail if convergence is not achieved within the maximum test duration.

#### CONV-007

The test MUST report which nodes failed to converge if the timeout is reached.

### Convergence Verification Requirements

#### VERIFY-001

Each node's graph state MUST be queryable to determine whether it has received the convergence label.

#### VERIFY-002

The test MUST poll nodes periodically to check convergence status.

#### VERIFY-003

The polling interval MUST be configurable (default: 250 milliseconds).

#### VERIFY-004

A node MUST be considered converged when it has received the convergence label.

### Performance Measurement Requirements

#### PERF-001

The test MUST record the timestamp when the convergence label is assigned.

#### PERF-002

The test MUST record the timestamp when each node achieves convergence.

#### PERF-003

The test MUST calculate and report the following metrics:
- Minimum convergence time (fastest node)
- Maximum convergence time (slowest node)
- Mean convergence time
- Median convergence time
- Mode convergence time (convergence times SHOULD be bucketed to produce a meaningful mode)
- 95th percentile convergence time (p95)
- 99th percentile convergence time (p99)
- Standard deviation of convergence times

#### PERF-004

The test SHOULD report memory usage per node if available.

#### PERF-005

When a CSV export feature flag is enabled, the test MUST output raw convergence data as a CSV file after each test run.

#### PERF-006

The CSV output MUST include one row per node with the following columns: node index, label assignment time (T0), node convergence time, and convergence duration (time from T0 to node convergence).

### Error Handling Requirements

#### ERR-001

The test MUST fail if any node fails to initialize.

#### ERR-002

If a node fails to initialize, the test MUST report which node failed and the cause of the failure.

#### ERR-003

The test MUST handle sync failures between nodes.


### Cleanup Requirements

#### CLEAN-001

All daemon processes MUST be terminated when the test completes.

#### CLEAN-002

All temporary directories MUST be removed when the test completes.

#### CLEAN-003

Cleanup MUST occur even if the test fails or times out.

#### CLEAN-004

The test MUST use RAII patterns to ensure cleanup on panic.

## Expected Behavior

### Propagation Pattern

In a bidirectional ring of N nodes:

1. Node 0 assigns the convergence label at time T0
2. The label propagates in both directions (clockwise and counter-clockwise)
3. The antipode node receives the label last from both directions

**Poll sync mode:** Each node discovers new commands from its neighbors on the next poll cycle. Propagation speed is bounded by the sync interval.

**Hello sync mode:** When a node receives new commands, it sends hello notifications to its peers, which trigger immediate syncs. Propagation speed is bounded by network latency and processing time rather than the sync interval.

### Theoretical Convergence Time

#### Poll Sync Mode

For a ring of N nodes with sync interval S:
- Minimum hops to reach the farthest node: ceil(N/2)
- Each hop takes on average S/2 (the average delay between a command arriving at a node and the next poll discovering it)
- Theoretical average convergence time: ceil(N/2) * (S/2)

Actual convergence time will be higher due to:
- Sync timing variability
- Label processing time

#### Hello Sync Mode

For a ring of N nodes with hello sync:
- Minimum hops to reach the farthest node: ceil(N/2)
- Each hop is triggered by a hello notification and subsequent sync
- Theoretical convergence time approaches: ceil(N/2) * L (where L is the per-hop latency including notification delivery, sync execution, and processing)

Actual convergence time depends on:
- Hello notification debounce settings
- Network latency
- Label processing time

### Success Criteria

The test passes when:
1. All nodes successfully initialize
2. Team configuration propagates to all nodes
3. Convergence label reaches all nodes
4. Convergence is achieved within the timeout
5. No unrecoverable errors are reported during synchronization

## Future Extensions

### Planned Enhancements

1. **Topology Variations**
   - Star topology
   - Mesh topology
   - Random graph topology
   - Hierarchical topology

2. **Failure Injection**
   - Node failure simulation
   - Network partition simulation
   - Message loss simulation

3. **Scalability Testing**
   - 500 node tests
   - 1000 node tests
   - Resource utilization profiling

4. **Concurrent Commands**
   - Multiple simultaneous command sources
   - Conflict resolution verification
   - Merge behavior validation

5. **Mixed Sync Modes**
   - Heterogeneous sync mode configurations (some nodes poll, some use hello)
   - Performance comparison between sync modes under identical topologies

## Appendix

### Duvet Integration

This specification is designed for use with duvet. Requirements are marked with unique identifiers (e.g., `CONF-001`, `TOPO-002`) that can be referenced in implementation code using duvet annotations:

```rust
//= https://github.com/aranya-project/aranya-docs/docs/multi-daemon-convergence-test.md#CONF-002
//# The test MUST scale to at least 70 nodes without failure.
const MIN_SUPPORTED_NODE_COUNT: usize = 70;
```

To generate a requirements coverage report:

```bash
duvet report --spec docs/multi-daemon-convergence-test.md --source crates/aranya-client/tests/
```

### Related Documents

- [Sync Specification](/sync/)
- [Graph Traversal Optimization](/graph-traversal/)
- [Aranya Architecture](/aranya-architecture/)
