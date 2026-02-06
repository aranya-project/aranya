//! Ring topology configuration for scale convergence tests.

use std::collections::VecDeque;

use anyhow::{bail, Context, Result};
use aranya_client::{HelloSubscriptionConfig, SyncPeerConfig};
use tracing::{debug, info, instrument};

use crate::scale::{SyncMode, TestCtx};

impl TestCtx {
    /// Configures the bidirectional ring topology.
    ///
    /// Each node is connected to its clockwise and counter-clockwise neighbors,
    /// forming a ring where data can propagate in both directions.
    //= docs/multi-daemon-convergence-test.md#topo-001
    //# In the ring topology, each node MUST connect to exactly two other nodes: its clockwise neighbor and its counter-clockwise neighbor.
    #[instrument(skip(self))]
    pub async fn configure_ring_topology(&mut self) -> Result<()> {
        let team_id = self.team_id.context("Team not created")?;
        let n = self.nodes.len();

        info!(
            node_count = n,
            sync_mode = ?self.sync_mode,
            "Configuring bidirectional ring topology"
        );

        // Build SyncPeerConfig based on the sync mode
        //= docs/multi-daemon-convergence-test.md#sync-002
        //# Sync peer configuration MUST specify the sync interval.
        let peer_config = match &self.sync_mode {
            SyncMode::Poll { interval } => SyncPeerConfig::builder().interval(*interval).build()?,
            SyncMode::Hello { .. } => SyncPeerConfig::builder().sync_on_hello(true).build()?,
        };

        // Build HelloSubscriptionConfig if in hello mode
        let hello_config = match &self.sync_mode {
            SyncMode::Hello {
                debounce,
                subscription_duration,
            } => Some(
                HelloSubscriptionConfig::builder()
                    .graph_change_debounce(*debounce)
                    .expiration(*subscription_duration)
                    .build()?,
            ),
            SyncMode::Poll { .. } => None,
        };

        // Configure each node's peers
        for i in 0..n {
            //= docs/multi-daemon-convergence-test.md#topo-002
            //# In the ring topology, sync peers MUST be configured bidirectionally, meaning if node A syncs with node B, node B MUST also sync with node A.
            let clockwise = (i + 1) % n;
            let counter_clockwise = (i + n - 1) % n;

            //= docs/multi-daemon-convergence-test.md#sync-003
            //# The sync peer address MUST be obtained from the neighbor node's local address.
            let cw_addr = self.nodes[clockwise].aranya_local_addr().await?;
            let ccw_addr = self.nodes[counter_clockwise].aranya_local_addr().await?;

            //= docs/multi-daemon-convergence-test.md#sync-001
            //# Each node MUST add its two ring neighbors as sync peers.
            let node_team = self.nodes[i].client.team(team_id);
            node_team
                .add_sync_peer(cw_addr, peer_config.clone())
                .await
                .with_context(|| format!("node {i} unable to add clockwise peer {clockwise}"))?;

            node_team
                .add_sync_peer(ccw_addr, peer_config.clone())
                .await
                .with_context(|| {
                    format!("node {i} unable to add counter-clockwise peer {counter_clockwise}")
                })?;

            // In hello mode, subscribe to hello notifications from each peer
            //= docs/multi-daemon-convergence-test.md#sync-006
            //# In hello sync mode, each node MUST subscribe to hello notifications from its sync peers.
            if let Some(ref hello_cfg) = hello_config {
                node_team
                    .sync_hello_subscribe(cw_addr, hello_cfg.clone())
                    .await
                    .with_context(|| {
                        format!("node {i} unable to subscribe to hello from peer {clockwise}")
                    })?;

                node_team
                    .sync_hello_subscribe(ccw_addr, hello_cfg.clone())
                    .await
                    .with_context(|| {
                        format!(
                            "node {i} unable to subscribe to hello from peer {counter_clockwise}"
                        )
                    })?;
            }

            //= docs/multi-daemon-convergence-test.md#topo-004
            //# In the ring topology, no node MUST have more than 2 sync peers.
            self.nodes[i].peers = vec![clockwise, counter_clockwise];

            debug!(
                node = i,
                clockwise, counter_clockwise, "Configured sync peers"
            );
        }

        //= docs/multi-daemon-convergence-test.md#sync-004
        //# Sync peer configuration MUST complete before the convergence test phase.
        // Give a small delay for sync configuration to settle
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        info!("Ring topology configured");
        Ok(())
    }

    /// Verifies the ring topology is correctly configured.
    ///
    /// Checks that:
    /// 1. Each node has exactly 2 peers
    /// 2. Peers are bidirectional (if A peers with B, B peers with A)
    /// 3. The graph forms a single connected component
    //= docs/multi-daemon-convergence-test.md#topo-002
    //# In the ring topology, sync peers MUST be configured bidirectionally, meaning if node A syncs with node B, node B MUST also sync with node A.

    //= docs/multi-daemon-convergence-test.md#topo-003
    //# The ring topology MUST form a single connected ring with no partitions.
    #[instrument(skip(self))]
    pub fn verify_ring_topology(&self) -> Result<()> {
        let n = self.nodes.len();

        info!(node_count = n, "Verifying ring topology");

        // Check each node has correct peers
        for i in 0..n {
            let expected_cw = (i + 1) % n;
            let expected_ccw = (i + n - 1) % n;

            if self.nodes[i].peers.len() != 2 {
                bail!(
                    "Node {} has {} peers, expected 2",
                    i,
                    self.nodes[i].peers.len()
                );
            }

            if !self.nodes[i].peers.contains(&expected_cw) {
                bail!(
                    "Node {} missing clockwise peer {} (has {:?})",
                    i,
                    expected_cw,
                    self.nodes[i].peers
                );
            }

            if !self.nodes[i].peers.contains(&expected_ccw) {
                bail!(
                    "Node {} missing counter-clockwise peer {} (has {:?})",
                    i,
                    expected_ccw,
                    self.nodes[i].peers
                );
            }

            // Verify bidirectional connections
            for &peer in &self.nodes[i].peers {
                if !self.nodes[peer].peers.contains(&i) {
                    bail!(
                        "Node {} peers with {}, but {} does not peer with {}",
                        i,
                        peer,
                        peer,
                        i
                    );
                }
            }
        }

        // Verify single connected component using BFS
        let mut visited = vec![false; n];
        let mut queue = VecDeque::new();
        queue.push_back(0);
        visited[0] = true;
        let mut visited_count = 1;

        while let Some(node) = queue.pop_front() {
            for &peer in &self.nodes[node].peers {
                if !visited[peer] {
                    visited[peer] = true;
                    visited_count += 1;
                    queue.push_back(peer);
                }
            }
        }

        if visited_count != n {
            let unvisited: Vec<_> = visited
                .iter()
                .enumerate()
                .filter(|(_, &v)| !v)
                .map(|(i, _)| i)
                .collect();
            bail!(
                "Ring topology is partitioned: {} nodes reachable, {} unreachable {:?}",
                visited_count,
                n - visited_count,
                unvisited
            );
        }

        info!("Ring topology verified");
        Ok(())
    }
}
