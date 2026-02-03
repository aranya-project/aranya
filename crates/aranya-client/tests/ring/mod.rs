//! Ring topology convergence test infrastructure.
//!
//! This module provides test infrastructure for validating Aranya daemon convergence
//! behavior with nodes arranged in a bidirectional ring topology.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
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
mod propagation;
mod team;
mod topology;

/// Configuration for ring convergence tests.
///
/// Provides configurable parameters for the test with sensible defaults
/// based on the multi-daemon convergence test specification.
#[derive(Clone, Debug)]
pub struct RingTestConfig {
    /// Number of nodes in the ring.
    //= docs/multi-daemon-convergence-test.md#conf-001
    //# The test MUST support configuring the number of nodes in the ring.
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

impl Default for RingTestConfig {
    fn default() -> Self {
        Self {
            //= docs/multi-daemon-convergence-test.md#conf-002
            //# The default node count MUST be 100 nodes.
            node_count: 100,

            //= docs/multi-daemon-convergence-test.md#conf-005
            //# The default sync interval MUST be 100 milliseconds.
            sync_interval: Duration::from_secs(1),

            //= docs/multi-daemon-convergence-test.md#conf-007
            //# The default maximum test duration MUST be 300 seconds (5 minutes).
            max_duration: Duration::from_secs(300),

            poll_interval: Duration::from_millis(250),
            init_timeout: Duration::from_secs(60),
            init_batch_size: 10,
        }
    }
}

impl RingTestConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> RingTestConfigBuilder {
        RingTestConfigBuilder::default()
    }

    /// Validates the configuration.
    //= docs/multi-daemon-convergence-test.md#conf-003
    //# The test MUST support a minimum of 3 nodes (the minimum for a valid ring).
    pub fn validate(&self) -> Result<()> {
        if self.node_count < 3 {
            bail!("Ring requires at least 3 nodes, got {}", self.node_count);
        }
        Ok(())
    }
}

/// Builder for [`RingTestConfig`].
#[derive(Clone, Debug, Default)]
pub struct RingTestConfigBuilder {
    node_count: Option<usize>,
    sync_interval: Option<Duration>,
    max_duration: Option<Duration>,
    poll_interval: Option<Duration>,
    init_timeout: Option<Duration>,
    init_batch_size: Option<usize>,
}

#[allow(dead_code)]
impl RingTestConfigBuilder {
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
    pub fn build(self) -> Result<RingTestConfig> {
        let default = RingTestConfig::default();
        let config = RingTestConfig {
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
    /// Whether this node has converged.
    pub converged: bool,
    /// Time when convergence was achieved (relative to command issuance).
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
    /// Name of the expected label that should propagate.
    pub expected_label_name: Option<String>,
    /// Per-node convergence status.
    pub node_status: Vec<ConvergenceStatus>,
    /// Timestamps for metrics.
    pub timestamps: ConvergenceTimestamps,
    /// Total sync operations counter.
    pub sync_count: AtomicUsize,
    /// Index of the source node that issued the command.
    pub source_node: usize,
}

impl ConvergenceTracker {
    /// Creates a new tracker for the given number of nodes.
    pub fn new(node_count: usize) -> Self {
        Self {
            expected_label_name: None,
            node_status: vec![ConvergenceStatus::default(); node_count],
            timestamps: ConvergenceTimestamps::default(),
            sync_count: AtomicUsize::new(0),
            source_node: 0,
        }
    }

    /// Sets the expected label name to track.
    pub fn set_expected_label(&mut self, name: String) {
        self.expected_label_name = Some(name);
    }

    /// Records that a node has converged.
    pub fn mark_converged(&mut self, node_index: usize) {
        if !self.node_status[node_index].converged {
            self.node_status[node_index].converged = true;
            self.node_status[node_index].convergence_time = Some(Instant::now());

            //= docs/multi-daemon-convergence-test.md#conv-003
            //# The test MUST track when each node receives the issued command.
            if self.timestamps.first_convergence.is_none() && node_index != self.source_node {
                self.timestamps.first_convergence = Some(Instant::now());
            }
        }
    }

    /// Returns true if all nodes have converged.
    //= docs/multi-daemon-convergence-test.md#conv-004
    //# Convergence MUST be defined as all nodes having received all expected commands.
    pub fn all_converged(&self) -> bool {
        self.node_status.iter().all(|s| s.converged)
    }

    /// Returns indices of nodes that have not converged.
    //= docs/multi-daemon-convergence-test.md#conv-007
    //# The test MUST report which nodes failed to converge if the timeout is reached.
    pub fn get_unconverged_nodes(&self) -> Vec<usize> {
        self.node_status
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.converged)
            .map(|(i, _)| i)
            .collect()
    }

    /// Increments the sync operation counter.
    #[allow(dead_code)]
    pub fn increment_sync_count(&self) {
        self.sync_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Main context for ring topology convergence tests.
///
/// Manages the lifecycle of all nodes and coordinates test execution.
pub struct RingCtx {
    /// All nodes in the ring.
    pub nodes: Vec<NodeCtx>,
    /// Test configuration.
    pub config: RingTestConfig,
    /// Team ID for the test.
    pub team_id: Option<TeamId>,
    /// Convergence tracker.
    pub tracker: ConvergenceTracker,
    /// Seed IKM for QUIC sync (shared by all nodes).
    seed_ikm: [u8; SEED_IKM_SIZE],
    /// Temporary working directory (RAII cleanup).
    _work_dir: TempDir,
}

impl RingCtx {
    /// Returns the number of nodes in the ring.
    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
