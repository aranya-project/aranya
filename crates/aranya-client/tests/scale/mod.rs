//! Scale convergence test infrastructure.
//!
//! This module provides test infrastructure for validating Aranya daemon convergence
//! behavior across configurable topologies.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
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
mod ring;
mod team;
mod topology;

/// Type-safe index into the node list (0 to N-1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeIndex(pub usize);

impl std::fmt::Display for NodeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The sync mode used for this test run.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-008
//# The test MUST support configuring the sync mode (poll or hello).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum SyncMode {
    /// All nodes use interval-based polling to discover new commands.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-005
    //# In poll sync mode, each node MUST poll its sync peers at the configured sync interval.
    Poll {
        /// How frequently each node polls its sync peers.
        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-004
        //# In poll sync mode, the test MUST support configuring the sync interval between peers.
        interval: Duration,
    },
    /// All nodes use hello notifications to trigger sync on graph changes.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-006
    //# In hello sync mode, each node MUST subscribe to hello notifications from its sync peers.
    Hello {
        /// Minimum time between hello notifications to the same peer.
        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-010
        //# In hello sync mode, the test MUST support configuring the hello notification debounce duration (minimum time between notifications to the same peer).
        debounce: Duration,
        /// How long a hello subscription remains valid before expiring.
        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-011
        //# In hello sync mode, the test MUST support configuring the hello subscription duration (how long a subscription remains valid).
        subscription_duration: Duration,
    },
}

//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-009
//# The default sync mode MUST be hello.
impl Default for SyncMode {
    fn default() -> Self {
        Self::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        }
    }
}

/// Configuration for scale convergence tests.
///
/// Provides configurable parameters for the test with sensible defaults
/// based on the multi-daemon convergence test specification.
#[derive(Clone, Debug)]
pub struct TestConfig {
    /// Human-readable name for this test run (shown in metrics output).
    pub test_name: String,

    /// Number of nodes in the test.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-001
    //# The test MUST support configuring the number of nodes.
    pub node_count: usize,

    /// The sync mode used for this test run.
    pub sync_mode: SyncMode,

    /// Maximum test duration timeout.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-006
    //# The test MUST support configuring a maximum test duration timeout.
    pub max_duration: Duration,

    /// Convergence polling interval.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#verify-003
    //# The polling interval MUST be configurable (default: 250 milliseconds).
    pub poll_interval: Duration,

    /// Node initialization timeout per batch.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-005
    //# Node initialization MUST complete within a configurable timeout (default: 60 seconds per node batch).
    pub init_timeout: Duration,

    /// Batch size for parallel node initialization.
    pub init_batch_size: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            test_name: String::from("default"),

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-002
            //# The test MUST scale to at least 70 nodes without failure.
            node_count: 100,

            sync_mode: SyncMode::default(),

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-007
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
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-003
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
    test_name: Option<String>,
    node_count: Option<usize>,
    sync_mode: Option<SyncMode>,
    max_duration: Option<Duration>,
    poll_interval: Option<Duration>,
    init_timeout: Option<Duration>,
    init_batch_size: Option<usize>,
}

#[allow(dead_code)]
impl TestConfigBuilder {
    /// Sets a human-readable name for this test run.
    pub fn test_name(mut self, name: impl Into<String>) -> Self {
        self.test_name = Some(name.into());
        self
    }

    /// Sets the number of nodes in the test.
    pub fn node_count(mut self, count: usize) -> Self {
        self.node_count = Some(count);
        self
    }

    /// Sets the sync mode (poll or hello).
    pub fn sync_mode(mut self, mode: SyncMode) -> Self {
        self.sync_mode = Some(mode);
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
            test_name: self.test_name.unwrap_or(default.test_name),
            node_count: self.node_count.unwrap_or(default.node_count),
            sync_mode: self.sync_mode.unwrap_or(default.sync_mode),
            max_duration: self.max_duration.unwrap_or(default.max_duration),
            poll_interval: self.poll_interval.unwrap_or(default.poll_interval),
            init_timeout: self.init_timeout.unwrap_or(default.init_timeout),
            init_batch_size: self.init_batch_size.unwrap_or(default.init_batch_size),
        };
        config.validate()?;
        Ok(config)
    }
}

/// Context for a single node in the test.
///
/// Based on `DeviceCtx` but with fields for tracking topology
/// and convergence state.
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
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#clean-001
    //# All daemon processes MUST be terminated when the test completes.

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#clean-004
    //# The test MUST use RAII patterns to ensure cleanup on panic.
    #[expect(unused, reason = "manages daemon lifecycle")]
    daemon: DaemonHandle,
    /// Indices of sync peer nodes.
    pub peers: Vec<NodeIndex>,
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
    pub source_node: NodeIndex,
}

impl ConvergenceTracker {
    /// Creates a new tracker for the given number of nodes.
    pub fn new(node_count: usize) -> Self {
        Self {
            convergence_label: None,
            node_status: vec![ConvergenceStatus::default(); node_count],
            timestamps: ConvergenceTimestamps::default(),
            source_node: NodeIndex(0),
        }
    }

    /// Sets the expected label name to track.
    pub fn set_convergence_label(&mut self, name: String) {
        self.convergence_label = Some(name);
    }

    /// Records that a node has converged.
    pub fn mark_converged(&mut self, node_index: NodeIndex) {
        if !self.node_status[node_index.0].has_label {
            self.node_status[node_index.0].has_label = true;
            self.node_status[node_index.0].convergence_time = Some(Instant::now());

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conv-003
            //# The test MUST track when each node receives the convergence label.
            if self.timestamps.first_convergence.is_none() && node_index != self.source_node {
                self.timestamps.first_convergence = Some(Instant::now());
            }
        }
    }

    /// Returns true if all nodes have converged.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conv-004
    //# Convergence MUST be defined as all nodes having received the convergence label.
    pub fn all_converged(&self) -> bool {
        self.node_status.iter().all(|s| s.has_label)
    }

    /// Returns indices of nodes that have not converged.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conv-007
    //# The test MUST report which nodes failed to converge if the timeout is reached.
    pub fn get_unconverged_nodes(&self) -> Vec<NodeIndex> {
        self.node_status
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.has_label)
            .map(|(i, _)| NodeIndex(i))
            .collect()
    }
}

/// A function that takes the total node count and returns the peer list
/// for each node. `peers[i]` contains the `NodeIndex`s of node `i`'s sync peers.
pub type TopologyConnectFn = fn(usize) -> Vec<Vec<NodeIndex>>;

/// The topology used to connect nodes.
///
/// The enum is expected to grow as additional topologies (star, mesh, etc.)
/// are added in future extensions.
#[derive(Clone)]
#[allow(dead_code)]
pub enum Topology {
    Ring,
    Custom { connect: TopologyConnectFn },
}

impl std::fmt::Debug for Topology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Topology::Ring => write!(f, "Ring"),
            Topology::Custom { .. } => write!(f, "Custom"),
        }
    }
}

/// Main context for scale convergence tests.
///
/// Manages the lifecycle of all nodes and coordinates test execution.
pub struct TestCtx {
    /// All nodes in the test.
    pub nodes: Vec<NodeCtx>,
    /// The topologies used to connect nodes (applied sequentially).
    /// `None` means no topology is configured automatically.
    pub topology: Option<Vec<Topology>>,
    /// The sync mode used for this test run.
    pub sync_mode: SyncMode,
    /// Test configuration.
    pub config: TestConfig,
    /// Team ID for the test.
    pub team_id: Option<TeamId>,
    /// Convergence tracker.
    pub tracker: ConvergenceTracker,
    /// Seed IKM for QUIC sync (shared by all nodes).
    seed_ikm: [u8; SEED_IKM_SIZE],
    /// Temporary working directory (RAII cleanup).
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#clean-002
    //# All temporary directories MUST be removed when the test completes.

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#clean-003
    //# Cleanup MUST occur even if the test fails or times out.
    _work_dir: TempDir,
}

impl TestCtx {
    /// Returns the number of nodes in the test.
    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Manually add a sync peer relationship between two nodes.
    pub async fn add_sync_peer(&mut self, from: NodeIndex, to: NodeIndex) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let to_addr = self.nodes[to.0].aranya_local_addr().await?;

        let peer_config = match &self.sync_mode {
            SyncMode::Poll { interval } => {
                aranya_client::SyncPeerConfig::builder()
                    .interval(*interval)
                    .build()
                    .context("unable to build sync peer config")?
            }
            SyncMode::Hello { .. } => aranya_client::SyncPeerConfig::builder()
                .sync_on_hello(true)
                .build()
                .context("unable to build sync peer config")?,
        };

        self.nodes[from.0]
            .client
            .team(team_id)
            .add_sync_peer(to_addr, peer_config)
            .await
            .with_context(|| {
                format!("node {} unable to add sync peer {}", from, to)
            })?;

        if let SyncMode::Hello {
            debounce,
            subscription_duration,
        } = &self.sync_mode
        {
            let hello_cfg = aranya_client::HelloSubscriptionConfig::builder()
                .graph_change_debounce(*debounce)
                .expiration(*subscription_duration)
                .build()
                .context("unable to build hello subscription config")?;
            self.nodes[from.0]
                .client
                .team(team_id)
                .sync_hello_subscribe(to_addr, hello_cfg)
                .await
                .with_context(|| {
                    format!(
                        "node {} unable to subscribe to hello from peer {}",
                        from, to
                    )
                })?;
        }

        self.nodes[from.0].peers.push(to);
        Ok(())
    }

    /// Remove a sync peer relationship between two nodes.
    #[allow(dead_code)]
    pub async fn remove_sync_peer(&mut self, from: NodeIndex, to: NodeIndex) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let to_addr = self.nodes[to.0].aranya_local_addr().await?;

        self.nodes[from.0]
            .client
            .team(team_id)
            .remove_sync_peer(to_addr)
            .await
            .with_context(|| {
                format!("node {} unable to remove sync peer {}", from, to)
            })?;

        if matches!(self.sync_mode, SyncMode::Hello { .. }) {
            self.nodes[from.0]
                .client
                .team(team_id)
                .sync_hello_unsubscribe(to_addr)
                .await
                .with_context(|| {
                    format!(
                        "node {} unable to unsubscribe from hello from peer {}",
                        from, to
                    )
                })?;
        }

        self.nodes[from.0].peers.retain(|&p| p != to);
        Ok(())
    }
}
