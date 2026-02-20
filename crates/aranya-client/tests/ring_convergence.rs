//! Ring topology convergence tests.
//!
//! These tests validate Aranya daemon convergence behavior with nodes arranged
//! in a bidirectional ring topology, as specified in the multi-daemon convergence
//! test specification.

#![allow(
    clippy::arithmetic_side_effects,
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
// Helper: run a custom topology convergence test with the given config
// ---------------------------------------------------------------------------

async fn run_custom_convergence(config: TestConfig, topology: Topology) -> Result<()> {
    let mut ctx = TestCtx::new(config, Some(vec![topology])).await?;

    ctx.setup_team().await?;
    ctx.sync_team_from_owner().await?;
    ctx.configure_topology().await?;
    ctx.verify_team_propagation().await?;

    ctx.issue_test_command(NodeIndex(0)).await?;
    ctx.wait_for_convergence().await?;
    ctx.report_metrics();

    Ok(())
}

// ---------------------------------------------------------------------------
// Custom topology: dual ring with bridge
// ---------------------------------------------------------------------------

/// Builds a topology of two rings connected by a single bidirectional bridge.
///
/// Nodes are split evenly into two rings (ring A = first half, ring B = second
/// half). Within each ring, every node connects to its clockwise and
/// counter-clockwise neighbor. A single bridge connects the last node of
/// ring A to the first node of ring B (bidirectional).
///
/// ```text
///   Ring A: 0 - 1 - 2 - 3 - 4
///           |               |
///           +-------+-------+
///                   |
///               bridge (4 <-> 5)
///                   |
///           +-------+-------+
///           |               |
///   Ring B: 5 - 6 - 7 - 8 - 9
/// ```
///
/// Requires `n` to be even and `n >= 6` (each ring needs at least 3 nodes).
fn dual_ring_bridge_topology(n: usize) -> Vec<Vec<NodeIndex>> {
    assert!(n >= 6, "dual ring bridge requires at least 6 nodes");
    assert!(
        n.is_multiple_of(2),
        "dual ring bridge requires an even node count"
    );

    let half = n / 2;
    let mut peers = vec![vec![]; n];

    // Ring A: nodes [0, half)
    for (i, node_peers) in peers[..half].iter_mut().enumerate() {
        let cw = (i + 1) % half;
        let ccw = (i + half - 1) % half;
        node_peers.push(NodeIndex(cw));
        node_peers.push(NodeIndex(ccw));
    }

    // Ring B: nodes [half, n)
    for (i, node_peers) in peers[half..].iter_mut().enumerate() {
        let cw = half + (i + 1) % half;
        let ccw = half + (i + half - 1) % half;
        node_peers.push(NodeIndex(cw));
        node_peers.push(NodeIndex(ccw));
    }

    // Bridge: last node of ring A <-> first node of ring B
    let bridge_a = half - 1;
    let bridge_b = half;
    peers[bridge_a].push(NodeIndex(bridge_b));
    peers[bridge_b].push(NodeIndex(bridge_a));

    peers
}

/// Tests convergence with 10 nodes arranged in two 5-node rings connected
/// by a single bidirectional bridge, using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_dual_ring_bridge_10_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("10-node dual ring bridge (poll)")
        .node_count(10)
        .sync_mode(SyncMode::Poll {
            interval: Duration::from_secs(1),
        })
        .max_duration(Duration::from_secs(120))
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 10-node dual ring bridge test (poll mode)"
    );
    run_custom_convergence(config, Topology::Custom { connect: dual_ring_bridge_topology }).await?;
    info!("10-node dual ring bridge convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests convergence with 10 nodes arranged in two 5-node rings connected
/// by a single bidirectional bridge, using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_dual_ring_bridge_10_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("10-node dual ring bridge (hello)")
        .node_count(10)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(120))
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 10-node dual ring bridge test (hello mode)"
    );
    run_custom_convergence(config, Topology::Custom { connect: dual_ring_bridge_topology }).await?;
    info!("10-node dual ring bridge convergence test (hello mode) completed successfully");
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

    info!(
        node_count = config.node_count,
        "Starting 3-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 3-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 10-node ring test (poll mode)"
    );
    run_ring_convergence(config).await?;
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
    let config = TestConfig::builder()
        .test_name("10-node ring (hello)")
        .node_count(10)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(120))
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 10-node ring test (hello mode)"
    );
    run_ring_convergence(config).await?;
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

    info!(
        node_count = config.node_count,
        "Starting 20-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 20-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 30-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 30-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 40-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 40-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 50-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 50-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 60-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 60-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 70-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 70-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 80-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 80-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 90-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 90-node ring test (hello mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 100-node ring test (poll mode)"
    );
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

    info!(
        node_count = config.node_count,
        "Starting 100-node ring test (hello mode)"
    );
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
