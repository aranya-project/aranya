//! Ring topology convergence test infrastructure.
//!
//! This module provides test infrastructure for validating Aranya daemon convergence
//! behavior with nodes arranged in a bidirectional ring topology.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use aranya_client::{
    client::{Client, DeviceId, KeyBundle, TeamId},
    Addr,
};
use aranya_crypto::dangerous::spideroak_crypto::{hash::Hash, rust::Sha256};
use aranya_daemon::DaemonHandle;
use aranya_daemon_api::SEED_IKM_SIZE;
use spideroak_base58::ToBase58 as _;
use tempfile::TempDir;

mod convergence;
mod init;
mod metrics;
mod team;
mod topology;

/// Configuration for ring convergence tests.
///
/// Provides configurable parameters for the test with sensible defaults
/// based on the multi-daemon convergence test specification.
#[derive(Clone, Debug)]
pub struct TestConfig {
    /// Number of nodes in the ring.
    //= docs/multi-daemon-convergence-test.md#conf-001
    //# The test MUST support configuring the number of nodes.
    pub node_count: usize,

    /// Sync interval between peers.
    //= docs/multi-daemon-convergence-test.md#conf-004
    //# The test MUST support configuring the sync interval between peers.
    pub sync_interval: Duration,

    /// Maximum test duration timeout.
    //= docs/multi-daemon-convergence-test.md#conf-006
    //# The test MUST support configuring a maximum test duration timeout.
    pub max_duration: Duration,

    /// Convergence polling interval.
    //= docs/multi-daemon-convergence-test.md#verify-003
    //# The polling interval MUST be configurable (default: 250 milliseconds).
    pub poll_interval: Duration,

    /// Node initialization timeout per batch.
    //= docs/multi-daemon-convergence-test.md#init-005
    //# Node initialization MUST complete within a configurable timeout (default: 60 seconds per node batch).
    pub init_timeout: Duration,

    /// Batch size for parallel node initialization.
    pub init_batch_size: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            //= docs/multi-daemon-convergence-test.md#conf-002
            //# The test MUST scale to at least 70 nodes without failure.
            node_count: 100,

            //= docs/multi-daemon-convergence-test.md#conf-005
            //# The default sync interval MUST be 1 second.
            sync_interval: Duration::from_secs(1),

            //= docs/multi-daemon-convergence-test.md#conf-007
            //# The default maximum test duration MUST be 600 seconds (10 minutes).
            max_duration: Duration::from_secs(600),

            poll_interval: Duration::from_millis(250),
            init_timeout: Duration::from_secs(60),
            init_batch_size: 10,
        }
    }
}

impl TestConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> TestConfigBuilder {
        TestConfigBuilder::default()
    }

    /// Validates the configuration.
    //= docs/multi-daemon-convergence-test.md#conf-003
    //# The test MUST reject configurations with fewer than 3 nodes (the minimum for a valid ring).
    pub fn validate(&self) -> Result<()> {
        if self.node_count < 3 {
            bail!("Ring requires at least 3 nodes, got {}", self.node_count);
        }
        Ok(())
    }
}

/// Builder for [`TestConfig`].
#[derive(Clone, Debug, Default)]
pub struct TestConfigBuilder {
    node_count: Option<usize>,
    sync_interval: Option<Duration>,
    max_duration: Option<Duration>,
    poll_interval: Option<Duration>,
    init_timeout: Option<Duration>,
    init_batch_size: Option<usize>,
}

#[allow(dead_code)]
impl TestConfigBuilder {
    /// Sets the number of nodes in the ring.
    pub fn node_count(mut self, count: usize) -> Self {
        self.node_count = Some(count);
        self
    }

    /// Sets the sync interval between peers.
    pub fn sync_interval(mut self, interval: Duration) -> Self {
        self.sync_interval = Some(interval);
        self
    }

    /// Sets the maximum test duration timeout.
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = Some(duration);
        self
    }

    /// Sets the convergence polling interval.
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = Some(interval);
        self
    }

    /// Sets the node initialization timeout per batch.
    pub fn init_timeout(mut self, timeout: Duration) -> Self {
        self.init_timeout = Some(timeout);
        self
    }

    /// Sets the batch size for parallel node initialization.
    pub fn init_batch_size(mut self, size: usize) -> Self {
        self.init_batch_size = Some(size);
        self
    }

    /// Builds the configuration, applying defaults for unset values.
    pub fn build(self) -> Result<TestConfig> {
        let default = TestConfig::default();
        let config = TestConfig {
            node_count: self.node_count.unwrap_or(default.node_count),
            sync_interval: self.sync_interval.unwrap_or(default.sync_interval),
            max_duration: self.max_duration.unwrap_or(default.max_duration),
            poll_interval: self.poll_interval.unwrap_or(default.poll_interval),
            init_timeout: self.init_timeout.unwrap_or(default.init_timeout),
            init_batch_size: self.init_batch_size.unwrap_or(default.init_batch_size),
        };
        config.validate()?;
        Ok(config)
    }
}

/// Context for a single node in the ring.
///
/// Based on `DeviceCtx` but with ring-specific fields for tracking
/// topology and convergence state.
pub struct NodeCtx {
    /// Unique node index (0 to N-1).
    pub index: usize,
    /// Aranya client connection.
    pub client: Client,
    /// Device's public key bundle.
    pub pk: KeyBundle,
    /// Device ID.
    pub id: DeviceId,
    /// Daemon handle (RAII cleanup).
    //= docs/multi-daemon-convergence-test.md#clean-001
    //# All daemon processes MUST be terminated when the test completes.

    //= docs/multi-daemon-convergence-test.md#clean-004
    //# The test MUST use RAII patterns to ensure cleanup on panic.
    #[expect(unused, reason = "manages daemon lifecycle")]
    daemon: DaemonHandle,
    /// Indices of sync peer nodes.
    pub peers: Vec<usize>,
    /// Node's working directory.
    #[expect(unused, reason = "for debugging")]
    work_dir: PathBuf,
}

impl NodeCtx {
    /// Returns the node's local address for sync peer configuration.
    pub async fn aranya_local_addr(&self) -> Result<Addr> {
        Ok(self.client.local_addr().await?)
    }

    /// Generates a unique shared memory path for AFC.
    fn get_shm_path(path: String) -> String {
        if cfg!(target_os = "macos") && path.len() > 31 {
            // Shrink the size of the team name down to 22 bytes to work within macOS's limits.
            let d = Sha256::hash(path.as_bytes());
            let t: [u8; 16] = d[..16].try_into().expect("expected shm path");
            return format!("/{}\0", t.to_base58());
        }
        path
    }
}

/// Tracks convergence status for a single node.
#[derive(Clone, Debug, Default)]
pub struct ConvergenceStatus {
    /// Whether this node has received the convergence label.
    pub has_label: bool,
    /// Time when the label was received.
    pub convergence_time: Option<Instant>,
}

/// Timestamps for tracking convergence phases.
#[derive(Clone, Debug)]
pub struct ConvergenceTimestamps {
    /// When the test command was issued.
    pub command_issued: Instant,
    /// When the first node (other than source) converged.
    pub first_convergence: Option<Instant>,
    /// When all nodes converged.
    pub full_convergence: Option<Instant>,
}

impl Default for ConvergenceTimestamps {
    fn default() -> Self {
        Self {
            command_issued: Instant::now(),
            first_convergence: None,
            full_convergence: None,
        }
    }
}

/// Tracks convergence state across all nodes.
pub struct ConvergenceTracker {
    /// The label used to track convergence.
    pub convergence_label: Option<String>,
    /// Per-node convergence status.
    pub node_status: Vec<ConvergenceStatus>,
    /// Timestamps for metrics.
    pub timestamps: ConvergenceTimestamps,
    /// Index of the source node that issued the command.
    pub source_node: usize,
}

impl ConvergenceTracker {
    /// Creates a new tracker for the given number of nodes.
    pub fn new(node_count: usize) -> Self {
        Self {
            convergence_label: None,
            node_status: vec![ConvergenceStatus::default(); node_count],
            timestamps: ConvergenceTimestamps::default(),
            source_node: 0,
        }
    }

    /// Sets the expected label name to track.
    pub fn set_convergence_label(&mut self, name: String) {
        self.convergence_label = Some(name);
    }

    /// Records that a node has converged.
    pub fn mark_converged(&mut self, node_index: usize) {
        if !self.node_status[node_index].has_label {
            self.node_status[node_index].has_label = true;
            self.node_status[node_index].convergence_time = Some(Instant::now());

            //= docs/multi-daemon-convergence-test.md#conv-003
            //# The test MUST track when each node receives the convergence label.
            if self.timestamps.first_convergence.is_none() && node_index != self.source_node {
                self.timestamps.first_convergence = Some(Instant::now());
            }
        }
    }

    /// Returns true if all nodes have converged.
    //= docs/multi-daemon-convergence-test.md#conv-004
    //# Convergence MUST be defined as all nodes having received the convergence label.
    pub fn all_converged(&self) -> bool {
        self.node_status.iter().all(|s| s.has_label)
    }

    /// Returns indices of nodes that have not converged.
    //= docs/multi-daemon-convergence-test.md#conv-007
    //# The test MUST report which nodes failed to converge if the timeout is reached.
    pub fn get_unconverged_nodes(&self) -> Vec<usize> {
        self.node_status
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.has_label)
            .map(|(i, _)| i)
            .collect()
    }
}

/// The topology used to connect nodes.
///
/// The enum is expected to grow as additional topologies (star, mesh, etc.)
/// are added in future extensions.
#[derive(Clone, Debug)]
pub enum Topology {
    Ring,
}

/// Main context for ring topology convergence tests.
///
/// Manages the lifecycle of all nodes and coordinates test execution.
pub struct TestCtx {
    /// All nodes in the ring.
    pub nodes: Vec<NodeCtx>,
    /// The topology used to connect nodes.
    pub topology: Topology,
    /// Test configuration.
    pub config: TestConfig,
    /// Team ID for the test.
    pub team_id: Option<TeamId>,
    /// Convergence tracker.
    pub tracker: ConvergenceTracker,
    /// Seed IKM for QUIC sync (shared by all nodes).
    seed_ikm: [u8; SEED_IKM_SIZE],
    /// Temporary working directory (RAII cleanup).
    //= docs/multi-daemon-convergence-test.md#clean-002
    //# All temporary directories MUST be removed when the test completes.

    //= docs/multi-daemon-convergence-test.md#clean-003
    //# Cleanup MUST occur even if the test fails or times out.
    _work_dir: TempDir,
}

impl TestCtx {
    /// Returns the number of nodes in the ring.
    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
