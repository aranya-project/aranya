//! Node initialization for scale convergence tests.

use std::{collections::HashSet, net::Ipv4Addr, path::PathBuf};

use anyhow::{bail, Context, Result};
use aranya_client::{client::Client, Addr};
use aranya_daemon::{
    config::{self as daemon_cfg, Config, Toggle},
    Daemon,
};
use aranya_daemon_api::SEED_IKM_SIZE;
use backon::{ExponentialBuilder, Retryable as _};
use tempfile::TempDir;
use tokio::fs;
use tracing::{info, instrument};

use crate::scale::{ConvergenceTracker, NodeCtx, TestConfig, TestCtx, Topology};

impl NodeCtx {
    /// Creates a new node context.
    ///
    /// This follows the `DeviceCtx::new()` pattern but uses a unique index
    /// for identification and AFC shared memory path generation.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-001
    //# Each node MUST be initialized with a unique daemon instance.
    #[instrument(skip(work_dir), fields(node_index = index))]
    pub(crate) async fn new(index: usize, work_dir: PathBuf, team_name: &str) -> Result<Self> {
        let addr_any = Addr::from((Ipv4Addr::LOCALHOST, 0));

        // Generate unique AFC shm path per node
        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-002
        //# Each node MUST have its own cryptographic keys.
        let afc_shm_path = {
            use aranya_daemon_api::shm;

            let path = Self::get_shm_path(format!("/{team_name}_{index:03}\0"));
            let path: Box<shm::Path> = path
                .as_str()
                .try_into()
                .context("unable to parse AFC shared memory path")?;
            let _ = shm::unlink(&path);
            path
        };

        // Setup daemon config
        let cfg = Config {
            name: format!("node_{index:03}"),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("log"),
            config_dir: work_dir.join("config"),
            afc: Toggle::Enabled(daemon_cfg::AfcConfig {
                shm_path: afc_shm_path,
                max_chans: 100,
            }),
            sync: daemon_cfg::SyncConfig {
                quic: Toggle::Enabled(daemon_cfg::QuicSyncConfig {
                    addr: addr_any,
                    client_addr: None,
                }),
            },
        };

        // Create directories
        for dir in [
            &cfg.runtime_dir,
            &cfg.state_dir,
            &cfg.cache_dir,
            &cfg.logs_dir,
            &cfg.config_dir,
        ] {
            fs::create_dir_all(dir)
                .await
                .with_context(|| format!("unable to create directory: {}", dir.display()))?;
        }
        let uds_path = cfg.uds_api_sock();

        // Load and start daemon
        let daemon = Daemon::load(cfg.clone())
            .await
            .context("unable to load daemon")?
            .spawn()
            .await
            .context("unable to start daemon")?;

        // Connect client with retry
        let client = (|| Client::builder().with_daemon_uds_path(&uds_path).connect())
            .retry(ExponentialBuilder::default())
            .await
            .context("unable to init client")?;

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-003
        //# All nodes MUST have unique device IDs.
        let pk = client
            .get_key_bundle()
            .await
            .context("unable to get key bundle")?;
        let id = client
            .get_device_id()
            .await
            .context("unable to get device id")?;

        Ok(Self {
            index,
            client,
            pk,
            id,
            daemon,
            peers: Vec::new(),
            work_dir,
        })
    }
}

impl TestCtx {
    /// Creates a new test context with all nodes initialized.
    ///
    /// Nodes are initialized in parallel batches to avoid resource exhaustion
    /// while still providing reasonable startup performance.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-004
    //# Node initialization MUST occur in parallel batches to avoid resource exhaustion.
    #[instrument(skip(config), fields(node_count = config.node_count))]
    pub async fn new(config: TestConfig, topology: Option<Vec<Topology>>) -> Result<Self> {
        config.validate()?;

        let work_dir = TempDir::new().context("unable to create temp dir")?;
        let mut nodes = Vec::with_capacity(config.node_count);
        let team_name = "scale_test";

        info!(
            node_count = config.node_count,
            batch_size = config.init_batch_size,
            "Initializing nodes"
        );

        // Initialize nodes in batches
        for batch_start in (0..config.node_count).step_by(config.init_batch_size) {
            let batch_end = (batch_start + config.init_batch_size).min(config.node_count);
            let batch_num = batch_start / config.init_batch_size + 1;
            let total_batches = config.node_count.div_ceil(config.init_batch_size);

            info!(
                batch = batch_num,
                total = total_batches,
                range = %format!("{batch_start}..{batch_end}"),
                "Initializing batch"
            );

            let batch_futures: Vec<_> = (batch_start..batch_end)
                .map(|i| {
                    let node_dir = work_dir.path().join(format!("node_{i:03}"));
                    NodeCtx::new(i, node_dir, team_name)
                })
                .collect();

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-005
            //# Node initialization MUST complete within a configurable timeout (default: 60 seconds per node batch).
            let batch_results = tokio::time::timeout(
                config.init_timeout,
                futures_util::future::try_join_all(batch_futures),
            )
            .await
            .context("batch initialization timed out")?
            .context("batch initialization failed")?;

            nodes.extend(batch_results);
        }

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-006
        //# The test MUST verify that all nodes started successfully.

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#err-001
        //# The test MUST fail if any node fails to initialize.
        if nodes.len() != config.node_count {
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#err-002
            //# If a node fails to initialize, the test MUST report which node failed and the cause of the failure.
            bail!(
                "Expected {} nodes but only {} initialized",
                config.node_count,
                nodes.len()
            );
        }

        // Verify all nodes have unique device IDs
        let unique_ids: HashSet<_> = nodes.iter().map(|n| n.id).collect();
        if unique_ids.len() != nodes.len() {
            bail!("Duplicate device IDs detected among nodes");
        }

        info!(
            node_count = nodes.len(),
            "All nodes initialized successfully"
        );

        // Generate shared seed IKM for QUIC sync
        let seed_ikm = {
            let mut buf = [0u8; SEED_IKM_SIZE];
            nodes[0].client.rand(&mut buf).await;
            buf
        };

        Ok(Self {
            nodes,
            topology,
            sync_mode: config.sync_mode.clone(),
            config: config.clone(),
            team_id: None,
            tracker: ConvergenceTracker::new(config.node_count),
            seed_ikm,
            _work_dir: work_dir,
        })
    }
}
