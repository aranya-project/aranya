//! Topology types and configuration dispatcher for scale convergence tests.

use anyhow::Result;
use tracing::info;

use crate::scale::{NodeIndex, TestCtx};

/// A function that takes the total node count and returns the peer list
/// for each node. `peers[i]` contains the `NodeIndex`s of node `i`'s sync peers.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#cust-001
//# The Custom topology MUST accept a topology connect function (`TopologyConnectFn`) that takes the total node count and returns the peer list for each node.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#cust-002
//# The topology connect function MUST return a peer list of length equal to the node count, where each entry contains the `NodeIndex`s of that node's sync peers.
pub type TopologyConnectFn = fn(usize) -> Vec<Vec<NodeIndex>>;

/// The topology used to connect nodes.
///
/// The enum is expected to grow as additional topologies (star, mesh, etc.)
/// are added in future extensions.
//= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#topo-003
//# The initial implementation MUST include at least the Ring and Custom topologies.
#[derive(Clone)]
#[allow(dead_code)]
pub enum Topology {
    Ring,
    //= https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md#cust-003
    //# The Custom topology MUST allow defining arbitrary peer relationships between nodes, including topologies such as star, mesh, and hierarchical.
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
pub fn dual_ring_bridge_topology(n: usize) -> Vec<Vec<NodeIndex>> {
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
