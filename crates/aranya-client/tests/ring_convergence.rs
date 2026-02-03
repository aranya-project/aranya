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

mod ring;

use anyhow::Result;
use serial_test::serial;
use test_log::test;
use tracing::info;

use crate::ring::{RingCtx, RingTestConfig};

/// Tests ring convergence with 10 nodes.
///
/// This is a smaller test suitable for CI with reasonable execution time.
//= docs/multi-daemon-convergence-test.md#conf-001
//= type=test
//# The test MUST support configuring the number of nodes in the ring.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_ring_convergence_10_nodes() -> Result<()> {
    let config = RingTestConfig::builder()
        .node_count(10)
        .max_duration(std::time::Duration::from_secs(120))
        .build()?;

    info!(node_count = config.node_count, "Starting 10-node ring test");

    //= docs/multi-daemon-convergence-test.md#init-001
    //= type=test
    //# Each node MUST be initialized with a unique daemon instance.
    let mut ring = RingCtx::new(config).await?;

    //= docs/multi-daemon-convergence-test.md#team-001
    //= type=test
    //# A single team MUST be created by node 0 (the designated owner).
    ring.setup_team().await?;

    // Sync team configuration before setting up ring topology
    ring.sync_team_from_owner().await?;

    //= docs/multi-daemon-convergence-test.md#sync-001
    //= type=test
    //# Each node MUST add its two ring neighbors as sync peers.
    ring.configure_ring_topology().await?;
    ring.verify_topology()?;

    //= docs/multi-daemon-convergence-test.md#team-006
    //= type=test
    //# The test MUST verify that all nodes have received the team configuration.
    ring.verify_team_propagation().await?;

    //= docs/multi-daemon-convergence-test.md#conv-002
    //= type=test
    //# The default source node for command issuance MUST be node 0.
    ring.issue_test_command(0).await?;

    //= docs/multi-daemon-convergence-test.md#conv-005
    //= type=test
    //# The test MUST measure the total convergence time from command issuance to full convergence.
    ring.wait_for_convergence().await?;

    //= docs/multi-daemon-convergence-test.md#perf-003
    //= type=test
    //# The test MUST calculate and report the following metrics.
    ring.report_metrics();

    //= docs/multi-daemon-convergence-test.md#prop-001
    //= type=test
    //# A command issued at node 0 MUST propagate through the ring in both directions.
    ring.verify_bidirectional_propagation()?;

    info!("10-node ring convergence test completed successfully");
    Ok(())
}

/// Tests ring convergence with the minimum 3 nodes.
///
/// This tests the edge case of the smallest valid ring.
//= docs/multi-daemon-convergence-test.md#conf-003
//= type=test
//# The test MUST support a minimum of 3 nodes (the minimum for a valid ring).
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_ring_minimum_3_nodes() -> Result<()> {
    let config = RingTestConfig::builder()
        .node_count(3)
        .max_duration(std::time::Duration::from_secs(60))
        .build()?;

    info!(node_count = config.node_count, "Starting 3-node ring test");

    let mut ring = RingCtx::new(config).await?;

    ring.setup_team().await?;
    ring.sync_team_from_owner().await?;
    ring.configure_ring_topology().await?;
    ring.verify_topology()?;
    ring.verify_team_propagation().await?;

    ring.issue_test_command(0).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();
    ring.verify_bidirectional_propagation()?;

    info!("3-node ring convergence test completed successfully");
    Ok(())
}

/// Tests ring convergence with 100 nodes.
///
/// This is the full-scale test as specified in the requirements.
/// Marked as ignored by default due to resource requirements.
//= docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The default node count MUST be 100 nodes.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_100_nodes -- --ignored"]
async fn test_ring_convergence_100_nodes() -> Result<()> {
    let config = RingTestConfig::default();

    info!(
        node_count = config.node_count,
        "Starting 100-node ring test"
    );

    let mut ring = RingCtx::new(config).await?;

    ring.setup_team().await?;
    ring.sync_team_from_owner().await?;
    ring.configure_ring_topology().await?;
    ring.verify_topology()?;
    ring.verify_team_propagation().await?;

    ring.issue_test_command(0).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();
    ring.verify_bidirectional_propagation()?;

    info!("100-node ring convergence test completed successfully");
    Ok(())
}

/// Tests ring convergence with 70 nodes.
///
/// This is a large-scale test that exercises convergence behavior with
/// significant graph size while remaining somewhat lighter than the full
/// 100-node test.
/// Marked as ignored by default due to resource requirements.
//= docs/multi-daemon-convergence-test.md#conf-001
//= type=test
//# The test MUST support configuring the number of nodes in the ring.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
#[ignore = "Long-running test - run with: cargo test --test ring_convergence test_ring_convergence_70_nodes -- --ignored"]
async fn test_ring_convergence_70_nodes() -> Result<()> {
    let config = RingTestConfig::builder()
        .node_count(70)
        .max_duration(std::time::Duration::from_secs(600))
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 70-node ring test"
    );

    let mut ring = RingCtx::new(config).await?;

    ring.setup_team().await?;
    ring.sync_team_from_owner().await?;
    ring.configure_ring_topology().await?;
    ring.verify_topology()?;
    ring.verify_team_propagation().await?;

    ring.issue_test_command(0).await?;
    ring.wait_for_convergence().await?;
    ring.report_metrics();
    ring.verify_bidirectional_propagation()?;

    info!("70-node ring convergence test completed successfully");
    Ok(())
}

/// Tests that invalid configurations are rejected.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_ring_config_validation() -> Result<()> {
    // Test that < 3 nodes is rejected
    let result = RingTestConfig::builder().node_count(2).build();
    assert!(result.is_err(), "Should reject node_count < 3");

    let result = RingTestConfig::builder().node_count(1).build();
    assert!(result.is_err(), "Should reject node_count < 3");

    // Test that >= 3 nodes is accepted
    let result = RingTestConfig::builder().node_count(3).build();
    assert!(result.is_ok(), "Should accept node_count >= 3");

    Ok(())
}
