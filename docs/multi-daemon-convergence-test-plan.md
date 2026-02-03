# Multi-Daemon Convergence Test Implementation Plan

This document outlines the implementation plan for the multi-daemon convergence test as specified in [aranya-docs/multi-daemon-convergence-test.md](https://github.com/aranya-project/aranya-docs/blob/main/docs/multi-daemon-convergence-test.md).

## Overview

The goal is to implement a test suite that validates Aranya daemon convergence behavior with 100 nodes arranged in a bidirectional ring topology. This extends the existing 5-node `DevicesCtx` pattern to support large-scale convergence testing.

This implementation uses [duvet](https://github.com/awslabs/duvet) for automated requirements traceability, enabling CI validation that all specification requirements are covered by implementation and tests.

---

## Duvet Integration

### Specification Format

The specification at `aranya-docs/docs/multi-daemon-convergence-test.md` uses markdown headers for requirement IDs:

```markdown
#### CONF-001

The test MUST support configuring the number of nodes in the ring.
```

This generates a section anchor `#conf-001` (lowercase) that can be referenced in duvet annotations.

### Duvet Configuration

Create `.duvet/config.toml` in the repository root:

```toml
'$schema' = "https://awslabs.github.io/duvet/config/v0.4.0.json"

# Source files to scan for annotations
[[source]]
pattern = "crates/aranya-client/tests/ring/**/*.rs"
type = "implementation"

[[source]]
pattern = "crates/aranya-client/tests/ring_convergence.rs"
type = "test"

# Specification document
[[specification]]
source = "https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md"
format = "markdown"

# Report configuration
[report.html]
enabled = true
path = ".duvet/reports/report.html"
blob-link = "https://github.com/aranya-project/aranya/blob/${{ GITHUB_SHA || 'main' }}"
issue-link = "https://github.com/aranya-project/aranya/issues"

[report.json]
enabled = true
path = ".duvet/reports/report.json"

[report.snapshot]
enabled = true
path = ".duvet/snapshot.txt"
```

### Annotation Syntax

Duvet uses a two-part comment structure:
- `//=` - metadata line (target URL, annotation type)
- `//#` - requirement text (quoted from spec)

**Correct annotation format:**

```rust
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-002
//# The default node count MUST be 100 nodes.
const DEFAULT_NODE_COUNT: usize = 100;
```

**With annotation type (for tests):**

```rust
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The default node count MUST be 100 nodes.
#[test]
fn test_default_node_count() {
    assert_eq!(RingTestConfig::default().node_count, 100);
}
```

**For exceptions (intentionally not implementing):**

```rust
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#perf-005
//= type=exception
//= reason=Memory usage reporting requires platform-specific APIs not available in test environment
//# The test SHOULD report memory usage per node if available.
```

**For TODOs (planned but not yet implemented):**

```rust
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#prop-004
//= type=todo
//= tracking-issue=123
//# The test MUST verify that propagation occurs through both ring directions.
```

### Duvet Commands

```bash
# Install duvet
cargo install duvet --locked

# Extract requirements from spec (generates stub annotations)
duvet extract \
  --format markdown \
  --out .duvet/requirements \
  https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md

# Generate coverage report
duvet report

# CI mode - fails if coverage doesn't match snapshot
duvet report --ci

# View HTML report
open .duvet/reports/report.html
```

### Requirement Coverage Tracking

The specification contains 47 requirements across these categories:

| Category | Count | IDs |
|----------|-------|-----|
| Configuration | 7 | CONF-001 to CONF-007 |
| Topology | 5 | TOPO-001 to TOPO-005 |
| Initialization | 6 | INIT-001 to INIT-006 |
| Team Setup | 6 | TEAM-001 to TEAM-006 |
| Sync Peer Config | 4 | SYNC-001 to SYNC-004 |
| Convergence Test | 7 | CONV-001 to CONV-007 |
| Verification | 5 | VERIFY-001 to VERIFY-005 |
| Propagation | 4 | PROP-001 to PROP-004 |
| Performance | 5 | PERF-001 to PERF-005 |
| Error Handling | 5 | ERR-001 to ERR-005 |
| Cleanup | 4 | CLEAN-001 to CLEAN-004 |

---

## Existing Infrastructure Analysis

The implementation will build on the existing test infrastructure in `crates/aranya-client/tests/`:

| Component | Location | Purpose |
|-----------|----------|---------|
| `DevicesCtx` | `tests/common/mod.rs:44-64` | 5-device test context pattern |
| `DeviceCtx` | `tests/common/mod.rs:219-292` | Single device context with daemon lifecycle |
| `SyncPeerConfig` | `src/config.rs:18-121` | Sync peer configuration builder |
| `DaemonHandle` | `daemon/src/daemon.rs:55-80` | RAII daemon lifecycle management |
| `Client` | `src/client/mod.rs` | Client API for daemon interaction |

## Implementation Phases

### Phase 1: Core Data Structures

**Location:** `crates/aranya-client/tests/ring/mod.rs` (new file)

#### 1.1 RingTestConfig

```rust
// Spec base URL for duvet annotations
const SPEC: &str = "https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md";

/// Configuration for ring convergence tests
pub struct RingTestConfig {
    /// Number of nodes in the ring
    pub node_count: usize,
    /// Sync interval between peers
    pub sync_interval: Duration,
    /// Maximum test duration timeout
    pub max_duration: Duration,
    /// Convergence polling interval
    pub poll_interval: Duration,
    /// Node initialization timeout per batch
    pub init_timeout: Duration,
    /// Batch size for parallel node initialization
    pub init_batch_size: usize,
}

impl Default for RingTestConfig {
    fn default() -> Self {
        Self {
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-001
            //# The test MUST support configuring the number of nodes in the ring.

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-002
            //# The default node count MUST be 100 nodes.
            node_count: 100,

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-004
            //# The test MUST support configuring the sync interval between peers.

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-005
            //# The default sync interval MUST be 100 milliseconds.
            sync_interval: Duration::from_millis(100),

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-006
            //# The test MUST support configuring a maximum test duration timeout.

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-007
            //# The default maximum test duration MUST be 300 seconds (5 minutes).
            max_duration: Duration::from_secs(300),

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#verify-003
            //# The polling interval MUST be configurable (default: 250 milliseconds).
            poll_interval: Duration::from_millis(250),

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#init-005
            //# Node initialization MUST complete within a configurable timeout (default: 60 seconds per node batch).
            init_timeout: Duration::from_secs(60),

            init_batch_size: 10,
        }
    }
}
```

**Implementation Tasks:**
- [ ] Create `RingTestConfig` struct with builder pattern
- [ ] Implement `Default` with specified defaults (100 nodes, 100ms sync, 5min timeout)
- [ ] Add validation for minimum 3 nodes (CONF-003)
- [ ] Add environment variable overrides for CI flexibility

#### 1.2 NodeCtx

```rust
/// Context for a single node in the ring
///
/// Based on DeviceCtx but with ring-specific fields
pub struct NodeCtx {
    /// Unique node identifier (0 to N-1)
    pub index: usize,
    /// Aranya client connection
    pub client: Client,
    /// Device's public key bundle
    pub pk: KeyBundle,
    /// Device ID
    pub id: DeviceId,
    /// Daemon handle (RAII cleanup)
    daemon: DaemonHandle,
    /// Sync peers (indices of connected nodes)
    peers: Vec<usize>,
    /// Node's working directory
    work_dir: PathBuf,
}
```

**Implementation Tasks:**
- [ ] Adapt `DeviceCtx::new()` pattern for `NodeCtx::new(index, work_dir)`
- [ ] Implement `aranya_local_addr()` method for sync peer address retrieval
- [ ] Ensure proper RAII cleanup via `DaemonHandle`

#### 1.3 ConvergenceTracker

```rust
/// Tracks convergence state across all nodes
pub struct ConvergenceTracker {
    /// Expected commands that should propagate to all nodes
    expected_commands: HashSet<CommandId>,
    /// Per-node convergence status
    node_status: Vec<ConvergenceStatus>,
    /// Timestamps for metrics
    timestamps: ConvergenceTimestamps,
    /// Total sync operations counter
    sync_count: AtomicUsize,
}

pub struct ConvergenceStatus {
    /// Commands received by this node
    received_commands: HashSet<CommandId>,
    /// Whether this node has converged
    converged: bool,
    /// Time when convergence was achieved
    convergence_time: Option<Instant>,
}

pub struct ConvergenceTimestamps {
    /// When the test command was issued
    command_issued: Instant,
    /// When convergence was first detected
    first_convergence: Option<Instant>,
    /// When full convergence was achieved
    full_convergence: Option<Instant>,
}
```

**Implementation Tasks:**
- [ ] Implement `ConvergenceTracker::new(node_count)`
- [ ] Implement `add_expected_command(CommandId)`
- [ ] Implement `update_node_status(node_index, commands)`
- [ ] Implement `all_converged() -> bool`
- [ ] Implement metrics calculation methods (min, max, mean, median, std_dev)

#### 1.4 RingCtx

```rust
/// Main context for ring topology convergence tests
pub struct RingCtx {
    /// All nodes in the ring
    nodes: Vec<NodeCtx>,
    /// Test configuration
    config: RingTestConfig,
    /// Team ID for the test
    team_id: Option<TeamId>,
    /// Convergence tracker
    tracker: ConvergenceTracker,
    /// Temporary working directory (RAII cleanup)
    _work_dir: TempDir,
}
```

**Implementation Tasks:**
- [ ] Implement `RingCtx::new(config)` with parallel node initialization
- [ ] Implement topology configuration methods
- [ ] Implement convergence waiting and verification
- [ ] Implement metrics reporting

---

### Phase 2: Node Initialization (INIT-001 through INIT-006)

**Location:** `crates/aranya-client/tests/ring/init.rs` (new file)

#### 2.1 Parallel Batch Initialization

The existing `DevicesCtx` uses `try_join!` for 5 daemons. For 100 nodes, we need batch initialization.

```rust
impl RingCtx {
    /// Initialize all nodes in parallel batches
    ///
    /// Requirements: INIT-001, INIT-004, INIT-005
    pub async fn new(config: RingTestConfig) -> Result<Self> {
        let work_dir = TempDir::new()?;
        let mut nodes = Vec::with_capacity(config.node_count);

        // Initialize in batches to avoid resource exhaustion
        for batch_start in (0..config.node_count).step_by(config.init_batch_size) {
            let batch_end = (batch_start + config.init_batch_size).min(config.node_count);

            let batch_futures: Vec<_> = (batch_start..batch_end)
                .map(|i| {
                    let node_dir = work_dir.path().join(format!("node_{}", i));
                    NodeCtx::new(i, node_dir)
                })
                .collect();

            let batch_results = tokio::time::timeout(
                config.init_timeout,
                futures::future::try_join_all(batch_futures)
            ).await??;

            nodes.extend(batch_results);
        }

        // INIT-006: Verify all nodes started
        assert_eq!(nodes.len(), config.node_count);

        Ok(Self {
            nodes,
            config,
            team_id: None,
            tracker: ConvergenceTracker::new(config.node_count),
            _work_dir: work_dir,
        })
    }
}
```

**Implementation Tasks:**
- [ ] Implement batch initialization with configurable batch size (default: 10)
- [ ] Add timeout handling per batch (INIT-005)
- [ ] Add retry logic for transient initialization failures (ERR-001, ERR-002)
- [ ] Add verification that all nodes have unique DeviceIds (INIT-003)
- [ ] Add logging for initialization progress

#### 2.2 Key Generation

Each node generates its own keys via the daemon initialization process.

**Implementation Tasks:**
- [ ] Verify `Daemon::load()` generates unique keys (INIT-002)
- [ ] Extract `KeyBundle` from each node's client (INIT-003)

---

### Phase 3: Team Setup (TEAM-001 through TEAM-006)

**Location:** `crates/aranya-client/tests/ring/team.rs` (new file)

#### 3.1 Team Creation

```rust
impl RingCtx {
    /// Create team with node 0 as owner
    ///
    /// Requirements: TEAM-001, TEAM-003
    pub async fn create_team(&mut self) -> Result<TeamId> {
        let seed_ikm = rand::thread_rng().gen::<[u8; 32]>();

        let owner_cfg = CreateTeamConfig::builder()
            .quic_sync(CreateTeamQuicSyncConfig::builder()
                .seed_ikm(seed_ikm)
                .build()?)
            .build()?;

        let team = self.nodes[0].client.create_team(owner_cfg).await?;
        let team_id = team.team_id();

        // Add team to all other nodes
        let qs_cfg = AddTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        let add_cfg = AddTeamConfig::builder()
            .team_id(team_id)
            .quic_sync(qs_cfg)
            .build()?;

        for node in &self.nodes[1..] {
            node.client.add_team(add_cfg.clone()).await?;
        }

        self.team_id = Some(team_id);
        Ok(team_id)
    }
}
```

**Implementation Tasks:**
- [ ] Implement `create_team()` with node 0 as owner (TEAM-001, TEAM-003)
- [ ] Generate shared QUIC sync seed IKM
- [ ] Add team configuration to all nodes

#### 3.2 Member Addition

```rust
impl RingCtx {
    /// Add all nodes to the team as members
    ///
    /// Requirements: TEAM-002, TEAM-004
    pub async fn add_all_nodes_to_team(&mut self) -> Result<()> {
        let team_id = self.team_id.ok_or_else(|| anyhow!("Team not created"))?;
        let owner_team = self.nodes[0].client.team(team_id);

        // Add each non-owner node as a member
        for node in &self.nodes[1..] {
            owner_team.add_device(node.pk.clone()).await?;
        }

        // Initial sync to propagate team config
        self.sync_full_ring().await?;

        Ok(())
    }

    /// Verify all nodes have team configuration
    ///
    /// Requirements: TEAM-005, TEAM-006
    pub async fn verify_team_propagation(&self) -> Result<()> {
        let team_id = self.team_id.ok_or_else(|| anyhow!("Team not created"))?;
        let expected_device_count = self.nodes.len();

        for (i, node) in self.nodes.iter().enumerate() {
            let devices = node.client.team(team_id).devices().await?;
            let count = devices.iter().count();

            if count != expected_device_count {
                bail!("Node {} has {} devices, expected {}",
                      i, count, expected_device_count);
            }
        }

        Ok(())
    }
}
```

**Implementation Tasks:**
- [ ] Implement `add_all_nodes_to_team()` (TEAM-002, TEAM-004)
- [ ] Implement batch device addition for performance
- [ ] Implement `verify_team_propagation()` (TEAM-005, TEAM-006)

---

### Phase 4: Topology Configuration (TOPO-001 through TOPO-005)

**Location:** `crates/aranya-client/tests/ring/topology.rs` (new file)

#### 4.1 Ring Topology Setup

```rust
impl RingCtx {
    /// Configure bidirectional ring topology
    pub async fn configure_ring_topology(&mut self) -> Result<()> {
        let team_id = self.team_id.ok_or_else(|| anyhow!("Team not created"))?;
        let n = self.nodes.len();

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#sync-002
        //# Sync peer configuration MUST specify the sync interval.
        let config = SyncPeerConfig::builder()
            .interval(self.config.sync_interval)
            .build()?;

        // Configure each node's peers
        for i in 0..n {
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#topo-002
            //# For node at index `i` in a ring of size `N`:
            //# - The clockwise neighbor MUST be at index `(i + 1) % N`
            //# - The counter-clockwise neighbor MUST be at index `(i + N - 1) % N`
            let clockwise = (i + 1) % n;
            let counter_clockwise = (i + n - 1) % n;

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#topo-001
            //# Each node MUST connect to exactly two other nodes: its clockwise neighbor and its counter-clockwise neighbor.

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#topo-005
            //# No node MUST have more than 2 sync peers in the ring topology.

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#sync-003
            //# The sync peer address MUST be obtained from the neighbor node's local address.
            let cw_addr = self.nodes[clockwise].aranya_local_addr().await?;
            let ccw_addr = self.nodes[counter_clockwise].aranya_local_addr().await?;

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#sync-001
            //# Each node MUST add its two ring neighbors as sync peers.
            self.nodes[i].client.team(team_id)
                .add_sync_peer(cw_addr, config.clone())
                .await?;
            self.nodes[i].client.team(team_id)
                .add_sync_peer(ccw_addr, config.clone())
                .await?;

            // Track peers for verification
            self.nodes[i].peers = vec![clockwise, counter_clockwise];
        }

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#sync-004
        //# Sync peer configuration MUST complete before the convergence test phase.
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    /// Verify ring topology is correctly configured
    fn verify_topology(&self) -> Result<()> {
        let n = self.nodes.len();

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#topo-003
        //# Sync peers MUST be configured bidirectionally, meaning if node A syncs with node B, node B MUST also sync with node A.
        for i in 0..n {
            let expected_cw = (i + 1) % n;
            let expected_ccw = (i + n - 1) % n;

            assert_eq!(self.nodes[i].peers.len(), 2,
                       "Node {} should have exactly 2 peers", i);
            assert!(self.nodes[i].peers.contains(&expected_cw),
                    "Node {} missing clockwise peer {}", i, expected_cw);
            assert!(self.nodes[i].peers.contains(&expected_ccw),
                    "Node {} missing counter-clockwise peer {}", i, expected_ccw);
        }

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#topo-004
        //# The topology MUST form a single connected ring with no partitions.
        // BFS from node 0 should reach all nodes
        let mut visited = vec![false; n];
        let mut queue = VecDeque::new();
        queue.push_back(0);
        visited[0] = true;

        while let Some(node) = queue.pop_front() {
            for &peer in &self.nodes[node].peers {
                if !visited[peer] {
                    visited[peer] = true;
                    queue.push_back(peer);
                }
            }
        }

        if visited.iter().any(|&v| !v) {
            bail!("Ring topology is partitioned");
        }

        Ok(())
    }
}
```

**Implementation Tasks:**
- [ ] Implement `configure_ring_topology()` with neighbor calculation
- [ ] Implement `verify_topology()` for connectivity check
- [ ] Add error handling for peer configuration failures

---

### Phase 5: Convergence Testing (CONV-001 through CONV-007, VERIFY-001 through VERIFY-005)

**Location:** `crates/aranya-client/tests/ring/convergence.rs` (new file)

#### 5.1 Command Issuance

```rust
impl RingCtx {
    /// Issue a test command from the source node
    ///
    /// Requirements: CONV-001, CONV-002, PERF-001
    pub async fn issue_test_command(&mut self, source_node: usize) -> Result<()> {
        let team_id = self.team_id.ok_or_else(|| anyhow!("Team not created"))?;

        // Record timestamp before command
        self.tracker.timestamps.command_issued = Instant::now();

        // Issue a command that will propagate (e.g., create a label)
        let label_name = format!("convergence_test_{}", Uuid::new_v4());
        let label_id = self.nodes[source_node].client
            .team(team_id)
            .create_label(&label_name)
            .await?;

        // Track the expected command
        // Note: We need to identify the command ID from the label creation
        // This may require querying the graph or tracking via effects
        self.tracker.add_expected_command(/* command_id */);

        info!(source_node, ?label_id, "Test command issued");

        Ok(())
    }
}
```

**Implementation Tasks:**
- [ ] Implement `issue_test_command()` (CONV-001, CONV-002)
- [ ] Track command ID/address for convergence verification
- [ ] Record command issuance timestamp (PERF-001)

#### 5.2 Convergence Waiting

```rust
impl RingCtx {
    /// Wait for all nodes to converge
    pub async fn wait_for_convergence(&mut self) -> Result<()> {
        let start = Instant::now();
        let team_id = self.team_id.ok_or_else(|| anyhow!("Team not created"))?;

        loop {
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-006
            //# The test MUST fail if convergence is not achieved within the maximum test duration.
            if start.elapsed() > self.config.max_duration {
                //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-007
                //# The test MUST report which nodes failed to converge if the timeout is reached.
                let unconverged = self.tracker.get_unconverged_nodes();
                bail!("Convergence timeout after {:?}: nodes {:?} did not converge",
                      start.elapsed(), unconverged);
            }

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#verify-002
            //# The test MUST poll nodes periodically to check convergence status.
            self.check_all_nodes_convergence(team_id).await?;

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-004
            //# Convergence MUST be defined as all nodes having received all expected commands.
            if self.tracker.all_converged() {
                self.tracker.timestamps.full_convergence = Some(Instant::now());
                info!("Full convergence achieved in {:?}", start.elapsed());
                break;
            }

            tokio::time::sleep(self.config.poll_interval).await;
        }

        Ok(())
    }

    /// Check convergence status for all nodes
    async fn check_all_nodes_convergence(&mut self, team_id: TeamId) -> Result<()> {
        for (i, node) in self.nodes.iter().enumerate() {
            if self.tracker.node_status[i].converged {
                continue;  // Skip already converged nodes
            }

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#verify-001
            //# Each node's graph state MUST be queryable to determine received commands.
            let labels = node.client.team(team_id).labels().await?;

            // Check if expected label exists
            let has_expected = labels.iter()
                .any(|l| /* matches expected command */);

            if has_expected {
                //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#verify-004
                //# A node MUST be considered converged when it has received all expected commands.
                self.tracker.node_status[i].converged = true;
                self.tracker.node_status[i].convergence_time = Some(Instant::now());

                //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-003
                //# The test MUST track when each node receives the issued command.
                if self.tracker.timestamps.first_convergence.is_none() {
                    self.tracker.timestamps.first_convergence = Some(Instant::now());
                }

                debug!(node = i, "Node converged");
            }
        }

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#verify-005
        //# The test MUST verify that merged graphs are consistent (no conflicting commands).
        // Consistency is verified by successful convergence - if labels match, graphs are consistent

        Ok(())
    }
}
```

**Implementation Tasks:**
- [ ] Implement `wait_for_convergence()` with timeout handling
- [ ] Implement `check_all_nodes_convergence()` with graph queries
- [ ] Add detailed logging for convergence progress
- [ ] Implement consistency verification (VERIFY-005)

---

### Phase 6: Propagation Verification (PROP-001 through PROP-004)

**Location:** `crates/aranya-client/tests/ring/propagation.rs` (new file)

#### 6.1 Propagation Tracking

```rust
impl RingCtx {
    /// Verify bidirectional propagation
    ///
    /// Requirements: PROP-001, PROP-004
    pub fn verify_bidirectional_propagation(&self) -> Result<()> {
        // Analyze convergence times to verify both directions propagated
        let n = self.nodes.len();
        let times: Vec<_> = self.tracker.node_status.iter()
            .map(|s| s.convergence_time)
            .collect();

        // Nodes should converge roughly in order of distance from source
        // Clockwise: 1, 2, 3, ... n/2
        // Counter-clockwise: n-1, n-2, ... n/2+1
        // Node n/2 should be last (or close to last)

        // PROP-002, PROP-003: Verify maximum distance
        let max_distance = (n + 1) / 2;  // ceil(N/2)
        info!("Maximum propagation distance: {} hops", max_distance);

        Ok(())
    }
}
```

**Implementation Tasks:**
- [ ] Implement propagation path tracking
- [ ] Verify bidirectional propagation (PROP-001, PROP-004)
- [ ] Calculate and verify hop counts (PROP-002, PROP-003)

---

### Phase 7: Performance Metrics (PERF-001 through PERF-005)

**Location:** `crates/aranya-client/tests/ring/metrics.rs` (new file)

#### 7.1 Metrics Calculation

```rust
impl RingCtx {
    /// Calculate and report performance metrics
    ///
    /// Requirements: PERF-001 through PERF-005
    pub fn report_metrics(&self) {
        let command_issued = self.tracker.timestamps.command_issued;

        // Collect convergence times relative to command issuance
        let times: Vec<Duration> = self.tracker.node_status.iter()
            .filter_map(|s| s.convergence_time)
            .map(|t| t.duration_since(command_issued))
            .collect();

        if times.is_empty() {
            println!("No convergence data available");
            return;
        }

        // PERF-003: Calculate metrics
        let min = *times.iter().min().unwrap();
        let max = *times.iter().max().unwrap();
        let sum: Duration = times.iter().sum();
        let mean = sum / times.len() as u32;

        let mut sorted = times.clone();
        sorted.sort();
        let median = sorted[sorted.len() / 2];

        // Standard deviation
        let mean_nanos = mean.as_nanos() as f64;
        let variance: f64 = times.iter()
            .map(|t| {
                let diff = t.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>() / times.len() as f64;
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        println!("=== Convergence Metrics ===");
        println!("Nodes: {}", self.nodes.len());
        println!("Min convergence time: {:?}", min);
        println!("Max convergence time: {:?}", max);
        println!("Mean convergence time: {:?}", mean);
        println!("Median convergence time: {:?}", median);
        println!("Std deviation: {:?}", std_dev);
        println!("Total sync operations: {}", self.tracker.sync_count.load(Ordering::Relaxed));

        // PERF-005: Memory usage (if available)
        #[cfg(target_os = "linux")]
        {
            if let Ok(mem) = get_memory_usage() {
                println!("Total memory usage: {} MB", mem / 1024 / 1024);
            }
        }
    }
}
```

**Implementation Tasks:**
- [ ] Implement `report_metrics()` with all required calculations
- [ ] Add sync operation counting (PERF-004)
- [ ] Add optional memory usage reporting (PERF-005)

---

### Phase 8: Error Handling (ERR-001 through ERR-005)

**Location:** Integrated throughout implementation

#### 8.1 Error Handling Strategy

```rust
/// Custom error type for ring tests
#[derive(Debug, thiserror::Error)]
pub enum RingTestError {
    #[error("Node {0} initialization failed: {1}")]
    NodeInitFailed(usize, String),

    #[error("Sync failed between nodes {0} and {1}: {2}")]
    SyncFailed(usize, usize, String),

    #[error("Convergence timeout: {0} nodes did not converge")]
    ConvergenceTimeout(usize),

    #[error("Topology validation failed: {0}")]
    TopologyInvalid(String),
}
```

**Implementation Tasks:**
- [ ] Implement custom error types (ERR-005)
- [ ] Add graceful handling for initialization failures (ERR-001, ERR-002)
- [ ] Handle transient sync failures (ERR-003, ERR-004)
- [ ] Add comprehensive logging with context

---

### Phase 9: Cleanup (CLEAN-001 through CLEAN-004)

**Location:** Integrated via RAII patterns

#### 9.1 Cleanup Implementation

```rust
impl Drop for RingCtx {
    fn drop(&mut self) {
        // CLEAN-001: Daemon termination handled by DaemonHandle drop
        // CLEAN-002: TempDir cleanup handled by TempDir drop
        // CLEAN-004: RAII ensures cleanup on panic

        info!("Cleaning up {} nodes", self.nodes.len());
    }
}
```

**Implementation Tasks:**
- [ ] Verify DaemonHandle properly aborts all tasks (CLEAN-001)
- [ ] Verify TempDir cleanup (CLEAN-002)
- [ ] Add explicit cleanup method for test framework (CLEAN-003)
- [ ] Test cleanup on panic scenarios (CLEAN-004)

---

### Phase 10: Test Implementation

**Location:** `crates/aranya-client/tests/ring_convergence.rs` (new file)

#### 10.1 Main Test

```rust
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The default node count MUST be 100 nodes.
#[tokio::test(flavor = "multi_thread")]
async fn test_ring_convergence_100_nodes() -> Result<()> {
    init_tracing();

    let config = RingTestConfig::default();

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#init-001
    //= type=test
    //# Each node MUST be initialized with a unique daemon instance.
    let mut ring = RingCtx::new(config).await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#team-001
    //= type=test
    //# A single team MUST be created by node 0 (the designated owner).
    let team_id = ring.create_team().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#team-002
    //= type=test
    //# All nodes MUST be added to the team before convergence testing begins.
    ring.add_all_nodes_to_team().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#sync-001
    //= type=test
    //# Each node MUST add its two ring neighbors as sync peers.
    ring.configure_ring_topology().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#team-005
    //= type=test
    //# Team configuration MUST be synchronized to all nodes before the convergence test phase.

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#team-006
    //= type=test
    //# The test MUST verify that all nodes have received the team configuration.
    ring.verify_team_propagation().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-001
    //= type=test
    //# The test MUST issue a command from a designated source node.

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-002
    //= type=test
    //# The default source node for command issuance MUST be node 0.
    ring.issue_test_command(0).await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conv-005
    //= type=test
    //# The test MUST measure the total convergence time from command issuance to full convergence.
    ring.wait_for_convergence().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#perf-003
    //= type=test
    //# The test MUST calculate and report the following metrics:
    //# - Minimum convergence time (fastest node)
    //# - Maximum convergence time (slowest node)
    //# - Mean convergence time
    //# - Median convergence time
    //# - Standard deviation of convergence times
    ring.report_metrics();

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#prop-001
    //= type=test
    //# A command issued at node 0 MUST propagate through the ring in both directions.
    ring.verify_bidirectional_propagation()?;

    Ok(())
}

//= https://raw.githubusercontent.com/aranya-project/aranya-docs/claude/multi-daemon-convergence-test-v9iui/docs/multi-daemon-convergence-test.md#conf-003
//= type=test
//# The test MUST support a minimum of 3 nodes (the minimum for a valid ring).
#[tokio::test(flavor = "multi_thread")]
async fn test_ring_minimum_3_nodes() -> Result<()> {
    let config = RingTestConfig {
        node_count: 3,
        ..Default::default()
    };

    let mut ring = RingCtx::new(config).await?;
    let team_id = ring.create_team().await?;
    ring.add_all_nodes_to_team().await?;
    ring.configure_ring_topology().await?;
    ring.verify_team_propagation().await?;
    ring.issue_test_command(0).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ring_convergence_10_nodes() -> Result<()> {
    // Smaller test for faster CI feedback (not a spec requirement, but useful)
    let config = RingTestConfig {
        node_count: 10,
        ..Default::default()
    };

    let mut ring = RingCtx::new(config).await?;
    let team_id = ring.create_team().await?;
    ring.add_all_nodes_to_team().await?;
    ring.configure_ring_topology().await?;
    ring.verify_team_propagation().await?;
    ring.issue_test_command(0).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();

    Ok(())
}
```

**Implementation Tasks:**
- [ ] Create main 100-node test
- [ ] Create smaller 10-node test for CI
- [ ] Create minimum 3-node edge case test
- [ ] Add duvet annotations for requirements traceability

---

## File Structure

```
crates/aranya-client/tests/
├── common/
│   └── mod.rs              # Existing DevicesCtx (unchanged)
├── ring/
│   ├── mod.rs              # RingCtx, NodeCtx, RingTestConfig
│   ├── init.rs             # Node initialization
│   ├── team.rs             # Team setup
│   ├── topology.rs         # Ring topology configuration
│   ├── convergence.rs      # Convergence waiting and verification
│   ├── propagation.rs      # Propagation verification
│   └── metrics.rs          # Performance metrics
├── tests.rs                # Existing tests (unchanged)
└── ring_convergence.rs     # New ring convergence tests
```

---

## Dependencies

Add to `crates/aranya-client/Cargo.toml` (dev-dependencies):

```toml
[dev-dependencies]
# Existing deps...
uuid = { version = "1", features = ["v4"] }
```

---

## Implementation Order

1. **Week 1: Core Structures**
   - [ ] Create `ring/mod.rs` with data structures
   - [ ] Implement `RingTestConfig` with defaults
   - [ ] Implement `NodeCtx` based on `DeviceCtx`
   - [ ] Implement `ConvergenceTracker`

2. **Week 2: Initialization & Team Setup**
   - [ ] Implement batch node initialization
   - [ ] Implement team creation and member addition
   - [ ] Add initialization tests

3. **Week 3: Topology & Sync**
   - [ ] Implement ring topology configuration
   - [ ] Implement topology verification
   - [ ] Test sync peer configuration

4. **Week 4: Convergence Testing**
   - [ ] Implement command issuance
   - [ ] Implement convergence waiting
   - [ ] Implement convergence verification

5. **Week 5: Metrics & Polish**
   - [ ] Implement metrics calculation and reporting
   - [ ] Add propagation verification
   - [ ] Add error handling
   - [ ] Add duvet annotations

6. **Week 6: Testing & Documentation**
   - [ ] Run full 100-node test
   - [ ] Profile and optimize
   - [ ] Document findings
   - [ ] Generate duvet coverage report

---

## Testing Strategy

### Unit Tests
- `RingTestConfig` validation
- `ConvergenceTracker` metric calculations
- Topology neighbor calculations

### Integration Tests
- 3-node minimum ring
- 10-node quick feedback test
- 100-node full convergence test

### Performance Tests
- Memory usage under 100 nodes
- Convergence time benchmarks
- Sync operation counts

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| 100 daemons exhausts system resources | High | Batch initialization, configurable batch size |
| Convergence takes >5 minutes | Medium | Optimize sync interval, parallel sync |
| Flaky tests in CI | Medium | Increase timeouts for CI, retry logic |
| Port conflicts with 100 daemons | High | Use dynamic port allocation, verify unique addresses |

---

## Success Criteria

1. All 100 nodes initialize within 60 seconds
2. Team configuration propagates to all nodes
3. Ring topology is correctly configured
4. Test command converges within 5 minutes
5. **Duvet coverage: 100% of 47 requirements annotated** (MUST requirements covered by implementation or test annotations)
6. **Duvet CI check passes** (`duvet report --ci` returns success)
7. Test passes reliably in CI (>95% success rate)

---

## Duvet Compliance Checklist

Before marking implementation complete, verify:

- [ ] `.duvet/config.toml` created with correct spec URL and source patterns
- [ ] All 47 requirements have at least one annotation (`//=` + `//#`)
- [ ] Implementation annotations use `type=implementation` (default) or no type
- [ ] Test annotations use `type=test`
- [ ] Any exceptions documented with `type=exception` and `reason=...`
- [ ] `duvet report` generates HTML report without errors
- [ ] `duvet report --ci` passes (snapshot matches)
- [ ] CI workflow added to `.github/workflows/ci.yml`
- [ ] Coverage report uploaded as CI artifact

---

## References

- [Multi-Daemon Convergence Test Specification](https://github.com/aranya-project/aranya-docs/blob/main/docs/multi-daemon-convergence-test.md)
- [Duvet Requirements Traceability Tool](https://github.com/awslabs/duvet)
- [Duvet Configuration Schema](https://awslabs.github.io/duvet/config/v0.4.0.json)
- Existing test infrastructure: `crates/aranya-client/tests/common/mod.rs`
- Daemon implementation: `crates/aranya-daemon/src/daemon.rs`
