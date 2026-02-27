//! Ring topology configuration for scale convergence tests.

use anyhow::{Context, Result};
use aranya_client::{HelloSubscriptionConfig, SyncPeerConfig};
use tracing::{debug, info, instrument};

use crate::scale::{NodeIndex, SyncMode, TestCtx};

impl TestCtx {
    /// Configures the bidirectional ring topology.
    ///
    /// Each node is connected to its clockwise and counter-clockwise neighbors,
    /// forming a ring where data can propagate in both directions.
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#ring-001
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
        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-002
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
        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-004
        //# Sync peer configuration MUST complete before the convergence test phase.
        for i in 0..n {
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#ring-001
            //# In the ring topology, each node MUST connect to exactly two other nodes: its clockwise neighbor and its counter-clockwise neighbor.

            // Modular arithmetic guarantees a single cycle: 0->1->...->n-1->0.
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#ring-002
            //# The ring topology MUST form a single connected ring (each node's two peers link to form one cycle covering all nodes).
            let clockwise = (i + 1) % n;
            let counter_clockwise = (i + n - 1) % n;

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-003
            //# The sync peer address MUST be obtained from the neighbor node's local address.
            let cw_addr = self.nodes[clockwise].aranya_local_addr().await?;
            let ccw_addr = self.nodes[counter_clockwise].aranya_local_addr().await?;

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-001
            //# Each node MUST add sync peers according to the configured topology.
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
            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#sync-006
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

            //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#ring-001
            //# In the ring topology, each node MUST connect to exactly two other nodes: its clockwise neighbor and its counter-clockwise neighbor.
            self.nodes[i].peers = vec![NodeIndex(clockwise), NodeIndex(counter_clockwise)];

            debug!(
                node = i,
                clockwise, counter_clockwise, "Configured sync peers"
            );
        }

        info!("Ring topology configured");
        Ok(())
    }
}
