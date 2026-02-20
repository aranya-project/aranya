//! Topology configuration dispatcher for scale convergence tests.

use anyhow::Result;
use tracing::info;

use crate::scale::{NodeIndex, TestCtx, Topology};

impl TestCtx {
    /// Configures the topology based on `self.topology` and verifies correctness.
    ///
    /// If `self.topology` is `None`, no topology is configured (the caller is
    /// expected to use `add_sync_peer` / `remove_sync_peer` manually).
    ///
    /// If `Some`, each topology in the list is applied sequentially.
    pub async fn configure_topology(&mut self) -> Result<()> {
        let topos = match self.topology.take() {
            Some(t) => t,
            None => return Ok(()),
        };

        //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#topo-004
        //# When multiple topologies are configured, the test MUST apply them sequentially, each topology adding its peers on top of any previously configured peers.
        for topo in &topos {
            match topo {
                //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#topo-001
                //# The test MUST support the Ring topology.
                Topology::Ring => {
                    self.configure_ring_topology().await?;
                }
                //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#topo-002
                //# The test MUST support the Custom topology.
                Topology::Custom { connect } => {
                    let n = self.nodes.len();
                    let peer_map = connect(n);

                    info!(
                        node_count = n,
                        edges = peer_map.iter().map(|p| p.len()).sum::<usize>(),
                        "Applying custom topology"
                    );

                    for (i, peers) in peer_map.iter().enumerate() {
                        let from = NodeIndex(i);
                        for &to in peers {
                            self.add_sync_peer(from, to).await?;
                        }
                    }
                }
            }
        }

        self.topology = Some(topos);
        Ok(())
    }
}
