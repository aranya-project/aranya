//! Ring topology convergence tests.
//!
//! These tests validate Aranya daemon convergence behavior with nodes arranged
//! in a bidirectional ring topology, as specified in the multi-daemon convergence
//! test specification.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

mod scale;

use std::time::Duration;

use anyhow::Result;
use serial_test::serial;
use test_log::test;
use tracing::info;

use crate::scale::{NodeIndex, SyncMode, TestConfig, TestCtx, Topology};

// ---------------------------------------------------------------------------
// Helper: run a ring convergence test with the given config
// ---------------------------------------------------------------------------

async fn run_ring_convergence(config: TestConfig) -> Result<()> {
    let mut ring = TestCtx::new(config, Some(vec![Topology::Ring])).await?;

    ring.setup_team().await?;
    ring.sync_team_from_owner().await?;
    ring.configure_topology().await?;
    ring.verify_team_propagation().await?;

    ring.issue_test_command(NodeIndex(0)).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();

    Ok(())
}

// ---------------------------------------------------------------------------
// 3-node edge-case tests (minimum valid ring)
// ---------------------------------------------------------------------------

/// Tests ring convergence with the minimum 3 nodes.
///
/// This tests the edge case of the smallest valid ring.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-003
//= type=test
//# The test MUST reject configurations with fewer than 3 nodes (the minimum for a valid ring).
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_ring_minimum_3_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("3-node ring (poll)")
        .node_count(3)
        .max_duration(Duration::from_secs(60))
        .build()?;

    info!(node_count = config.node_count, "Starting 3-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("3-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with the minimum 3 nodes using hello sync mode.
///
/// This tests the edge case of the smallest valid ring with reactive syncing.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-008
//= type=test
//# The test MUST support configuring the sync mode (poll or hello).
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_ring_minimum_3_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("3-node ring (hello)")
        .node_count(3)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(60))
        .build()?;

    info!(node_count = config.node_count, "Starting 3-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("3-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 10-node tests (CI-friendly, not ignored)
// ---------------------------------------------------------------------------

/// Tests ring convergence with 10 nodes using poll sync mode.
///
/// This is a smaller test suitable for CI with reasonable execution time.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-001
//= type=test
//# The test MUST support configuring the number of nodes.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_ring_convergence_10_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("10-node ring (poll)")
        .node_count(10)
        .max_duration(Duration::from_secs(120))
        .build()?;

    info!(node_count = config.node_count, "Starting 10-node ring test (poll mode)");

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#init-001
    //= type=test
    //# Each node MUST be initialized with a unique daemon instance.
    let mut ring = TestCtx::new(config, Some(vec![Topology::Ring])).await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#team-001
    //= type=test
    //# A single team MUST be created by node 0 (the designated owner).
    ring.setup_team().await?;

    // Sync team configuration before setting up ring topology
    ring.sync_team_from_owner().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-001
    //= type=test
    //# Each node MUST add sync peers according to the configured topology.
    ring.configure_topology().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#team-006
    //= type=test
    //# The test MUST verify that all nodes have received the team configuration.
    ring.verify_team_propagation().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conv-002
    //= type=test
    //# The default source node for label assignment MUST be node 0.
    ring.issue_test_command(NodeIndex(0)).await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conv-005
    //= type=test
    //# The test MUST measure the total convergence time from label assignment to full convergence.
    ring.wait_for_convergence().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#perf-003
    //= type=test
    //# The test MUST calculate and report the following metrics.
    ring.report_metrics();

    info!("10-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 10 nodes using hello sync mode.
///
/// Validates that hello-based reactive syncing works for convergence.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-008
//= type=test
//# The test MUST support configuring the sync mode (poll or hello).
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_ring_convergence_10_nodes_hello() -> Result<()> {
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-010
    //= type=test
    //# In hello sync mode, the test MUST support configuring the hello notification debounce duration (minimum time between notifications to the same peer).

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-011
    //= type=test
    //# In hello sync mode, the test MUST support configuring the hello subscription duration (how long a subscription remains valid).
    let config = TestConfig::builder()
        .test_name("10-node ring (hello)")
        .node_count(10)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(120))
        .build()?;

    info!(node_count = config.node_count, "Starting 10-node ring test (hello mode)");

    let mut ring = TestCtx::new(config, Some(vec![Topology::Ring])).await?;

    ring.setup_team().await?;
    ring.sync_team_from_owner().await?;

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-006
    //= type=test
    //# In hello sync mode, each node MUST subscribe to hello notifications from its sync peers.
    ring.configure_topology().await?;
    ring.verify_team_propagation().await?;

    ring.issue_test_command(NodeIndex(0)).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();

    info!("10-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 20-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 20 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_20_nodes -- --ignored"]
async fn test_ring_convergence_20_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("20-node ring (poll)")
        .node_count(20)
        .max_duration(Duration::from_secs(200))
        .build()?;

    info!(node_count = config.node_count, "Starting 20-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("20-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 20 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_20_nodes_hello -- --ignored"]
async fn test_ring_convergence_20_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("20-node ring (hello)")
        .node_count(20)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(200))
        .build()?;

    info!(node_count = config.node_count, "Starting 20-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("20-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 30-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 30 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_30_nodes -- --ignored"]
async fn test_ring_convergence_30_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("30-node ring (poll)")
        .node_count(30)
        .max_duration(Duration::from_secs(300))
        .build()?;

    info!(node_count = config.node_count, "Starting 30-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("30-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 30 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_30_nodes_hello -- --ignored"]
async fn test_ring_convergence_30_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("30-node ring (hello)")
        .node_count(30)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(300))
        .build()?;

    info!(node_count = config.node_count, "Starting 30-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("30-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 40-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 40 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_40_nodes -- --ignored"]
async fn test_ring_convergence_40_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("40-node ring (poll)")
        .node_count(40)
        .max_duration(Duration::from_secs(400))
        .build()?;

    info!(node_count = config.node_count, "Starting 40-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("40-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 40 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_40_nodes_hello -- --ignored"]
async fn test_ring_convergence_40_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("40-node ring (hello)")
        .node_count(40)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(400))
        .build()?;

    info!(node_count = config.node_count, "Starting 40-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("40-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 50-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 50 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_50_nodes -- --ignored"]
async fn test_ring_convergence_50_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("50-node ring (poll)")
        .node_count(50)
        .max_duration(Duration::from_secs(400))
        .build()?;

    info!(node_count = config.node_count, "Starting 50-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("50-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 50 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_50_nodes_hello -- --ignored"]
async fn test_ring_convergence_50_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("50-node ring (hello)")
        .node_count(50)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(400))
        .build()?;

    info!(node_count = config.node_count, "Starting 50-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("50-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 60-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 60 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_60_nodes -- --ignored"]
async fn test_ring_convergence_60_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("60-node ring (poll)")
        .node_count(60)
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 60-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("60-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 60 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_60_nodes_hello -- --ignored"]
async fn test_ring_convergence_60_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("60-node ring (hello)")
        .node_count(60)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 60-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("60-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 70-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 70 nodes using poll sync mode.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The test MUST scale to at least 70 nodes without failure.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_70_nodes -- --ignored"]
async fn test_ring_convergence_70_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("70-node ring (poll)")
        .node_count(70)
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 70-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("70-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 70 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_70_nodes_hello -- --ignored"]
async fn test_ring_convergence_70_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("70-node ring (hello)")
        .node_count(70)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 70-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("70-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 80-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 80 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_80_nodes -- --ignored"]
async fn test_ring_convergence_80_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("80-node ring (poll)")
        .node_count(80)
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 80-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("80-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 80 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_80_nodes_hello -- --ignored"]
async fn test_ring_convergence_80_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("80-node ring (hello)")
        .node_count(80)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 80-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("80-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 90-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 90 nodes using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_90_nodes -- --ignored"]
async fn test_ring_convergence_90_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("90-node ring (poll)")
        .node_count(90)
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 90-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("90-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 90 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_90_nodes_hello -- --ignored"]
async fn test_ring_convergence_90_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("90-node ring (hello)")
        .node_count(90)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 90-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("90-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// 100-node tests
// ---------------------------------------------------------------------------

/// Tests ring convergence with 100 nodes using poll sync mode.
///
/// This is the full-scale test as specified in the requirements.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The test MUST scale to at least 70 nodes without failure.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_100_nodes -- --ignored"]
async fn test_ring_convergence_100_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("100-node ring (poll)")
        .node_count(100)
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 100-node ring test (poll mode)");
    run_ring_convergence(config).await?;
    info!("100-node ring convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests ring convergence with 100 nodes using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_100_nodes_hello -- --ignored"]
async fn test_ring_convergence_100_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("100-node ring (hello)")
        .node_count(100)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(600))
        .build()?;

    info!(node_count = config.node_count, "Starting 100-node ring test (hello mode)");
    run_ring_convergence(config).await?;
    info!("100-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration validation
// ---------------------------------------------------------------------------

/// Tests that invalid configurations are rejected.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_ring_config_validation() -> Result<()> {
    // Test that < 3 nodes is rejected
    let result = TestConfig::builder().node_count(2).build();
    assert!(result.is_err(), "Should reject node_count < 3");

    let result = TestConfig::builder().node_count(1).build();
    assert!(result.is_err(), "Should reject node_count < 3");

    // Test that >= 3 nodes is accepted
    let result = TestConfig::builder().node_count(3).build();
    assert!(result.is_ok(), "Should accept node_count >= 3");

    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-009
    //= type=test
    //# The default sync mode MUST be hello.
    let config = TestConfig::default();
    assert!(
        matches!(config.sync_mode, SyncMode::Hello { .. }),
        "Default sync mode should be Hello"
    );

    Ok(())
}
