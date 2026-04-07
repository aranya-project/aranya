//! Ring topology convergence tests.
//!
//! These tests validate Aranya daemon convergence behavior with nodes arranged
//! in a bidirectional ring topology, as specified in the multi-daemon convergence
//! test specification.

#![cfg(false)] // TODO(mtls): Update to mtls.
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

use crate::scale::{dual_ring_bridge_topology, NodeIndex, SyncMode, TestConfig, TestCtx, Topology};

// ---------------------------------------------------------------------------
// Helper: run a convergence test with the given config
// ---------------------------------------------------------------------------

async fn run_convergence(config: TestConfig) -> Result<()> {
    let mut ctx = TestCtx::new(config).await?;

    ctx.setup_team().await?;
    ctx.sync_team_from_owner().await?;
    ctx.configure_topology().await?;
    ctx.verify_team_propagation().await?;

    ctx.issue_test_command(NodeIndex(0)).await?;
    let result = ctx.wait_for_convergence().await;
    ctx.tracker.report_metrics();
    result
}

/// Tests convergence with 10 nodes arranged in two 5-node rings connected
/// by a single bidirectional bridge, using poll sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_dual_ring_bridge_10_nodes() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("dual_bridge_10n_poll")
        .node_count(10)
        .sync_mode(SyncMode::Poll {
            interval: Duration::from_secs(1),
        })
        .max_duration(Duration::from_secs(120))
        .topology(Topology::Custom {
            connect: dual_ring_bridge_topology,
        })
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 10-node dual ring bridge test (poll mode)"
    );
    run_convergence(config).await?;
    info!("10-node dual ring bridge convergence test (poll mode) completed successfully");
    Ok(())
}

/// Tests convergence with 10 nodes arranged in two 5-node rings connected
/// by a single bidirectional bridge, using hello sync mode.
#[test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_dual_ring_bridge_10_nodes_hello() -> Result<()> {
    let config = TestConfig::builder()
        .test_name("dual_bridge_10n_hello")
        .node_count(10)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(120))
        .topology(Topology::Custom {
            connect: dual_ring_bridge_topology,
        })
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 10-node dual ring bridge test (hello mode)"
    );
    run_convergence(config).await?;
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
        .test_name("ring_3n_poll")
        .node_count(3)
        .sync_mode(SyncMode::poll_default())
        .max_duration(Duration::from_secs(60))
        .topology(Topology::Ring)
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 3-node ring test (poll mode)"
    );
    run_convergence(config).await?;
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
        .test_name("ring_3n_hello")
        .node_count(3)
        .sync_mode(SyncMode::Hello {
            debounce: Duration::from_millis(100),
            subscription_duration: Duration::from_secs(600),
        })
        .max_duration(Duration::from_secs(60))
        .topology(Topology::Ring)
        .build()?;

    info!(
        node_count = config.node_count,
        "Starting 3-node ring test (hello mode)"
    );
    run_convergence(config).await?;
    info!("3-node ring convergence test (hello mode) completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Macro: generate poll + hello ring convergence test pairs
// ---------------------------------------------------------------------------

/// Generates poll + hello ring convergence test pairs for a given node count.
///
/// Each invocation produces two async test functions: one for poll sync mode
/// and one for hello sync mode. The caller passes both function names
/// explicitly to avoid needing the `paste` crate.
macro_rules! ring_convergence_tests {
    (
        $poll_fn:ident, $hello_fn:ident,
        nodes: $n:literal, max_duration_secs: $secs:literal
        $(, ignore: $reason:literal)?
    ) => {
        #[test(tokio::test(flavor = "multi_thread"))]
        #[serial]
        $(#[ignore = $reason])?
        async fn $poll_fn() -> Result<()> {
            let config = TestConfig::builder()
                .test_name(concat!("ring_", stringify!($n), "n_poll"))
                .node_count($n)
                .sync_mode(SyncMode::poll_default())
                .max_duration(Duration::from_secs($secs))
                .topology(Topology::Ring)
                .build()?;
            info!(node_count = $n, "Starting ring convergence test (poll mode)");
            run_convergence(config).await?;
            info!(node_count = $n, "Ring convergence test (poll mode) completed");
            Ok(())
        }

        #[test(tokio::test(flavor = "multi_thread"))]
        #[serial]
        $(#[ignore = $reason])?
        async fn $hello_fn() -> Result<()> {
            let config = TestConfig::builder()
                .test_name(concat!("ring_", stringify!($n), "n_hello"))
                .node_count($n)
                .sync_mode(SyncMode::Hello {
                    debounce: Duration::from_millis(100),
                    subscription_duration: Duration::from_secs(600),
                })
                .max_duration(Duration::from_secs($secs))
                .topology(Topology::Ring)
                .build()?;
            info!(node_count = $n, "Starting ring convergence test (hello mode)");
            run_convergence(config).await?;
            info!(node_count = $n, "Ring convergence test (hello mode) completed");
            Ok(())
        }
    };
}

// ---------------------------------------------------------------------------
// 10-100 node ring tests
// ---------------------------------------------------------------------------

// CI-friendly (not ignored)
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-001
//= type=test
//# The test MUST support configuring the number of nodes.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-008
//= type=test
//# The test MUST support configuring the sync mode (poll or hello).
ring_convergence_tests!(
    test_ring_convergence_10_nodes, test_ring_convergence_10_nodes_hello,
    nodes: 10, max_duration_secs: 120
);

// Scaling tests (ignored by default)
ring_convergence_tests!(
    test_ring_convergence_20_nodes, test_ring_convergence_20_nodes_hello,
    nodes: 20, max_duration_secs: 200, ignore: "Long-running scaling test"
);
ring_convergence_tests!(
    test_ring_convergence_30_nodes, test_ring_convergence_30_nodes_hello,
    nodes: 30, max_duration_secs: 300, ignore: "Long-running scaling test"
);
ring_convergence_tests!(
    test_ring_convergence_40_nodes, test_ring_convergence_40_nodes_hello,
    nodes: 40, max_duration_secs: 400, ignore: "Long-running scaling test"
);
ring_convergence_tests!(
    test_ring_convergence_50_nodes, test_ring_convergence_50_nodes_hello,
    nodes: 50, max_duration_secs: 400, ignore: "Long-running scaling test"
);
ring_convergence_tests!(
    test_ring_convergence_60_nodes, test_ring_convergence_60_nodes_hello,
    nodes: 60, max_duration_secs: 600, ignore: "Long-running scaling test"
);
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The test MUST scale to at least 70 nodes without failure.
ring_convergence_tests!(
    test_ring_convergence_70_nodes, test_ring_convergence_70_nodes_hello,
    nodes: 70, max_duration_secs: 600, ignore: "Long-running scaling test"
);
ring_convergence_tests!(
    test_ring_convergence_80_nodes, test_ring_convergence_80_nodes_hello,
    nodes: 80, max_duration_secs: 600, ignore: "Long-running scaling test"
);
ring_convergence_tests!(
    test_ring_convergence_90_nodes, test_ring_convergence_90_nodes_hello,
    nodes: 90, max_duration_secs: 600, ignore: "Long-running scaling test"
);
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#conf-002
//= type=test
//# The test MUST scale to at least 70 nodes without failure.
ring_convergence_tests!(
    test_ring_convergence_100_nodes, test_ring_convergence_100_nodes_hello,
    nodes: 100, max_duration_secs: 600, ignore: "Long-running scaling test"
);

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
