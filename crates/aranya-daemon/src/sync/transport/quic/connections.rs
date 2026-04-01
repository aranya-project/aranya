use std::{collections::BTreeMap, sync::Arc};

use s2n_quic::connection::{Handle, StreamAcceptor};
use tokio::sync::{mpsc, Mutex};

use aranya_daemon_api::DeviceId;

use crate::sync::SyncPeer;

type SharedConnectionMap = Arc<Mutex<BTreeMap<SyncPeer, Handle>>>;
type ConnectionUpdate = (SyncPeer, StreamAcceptor);

/// Shared state for coordinating QUIC connections between connector and listener.
pub(crate) struct ConnectionPool {
    conns: SharedConnectionMap,
    local_device_id: DeviceId,
    tx: mpsc::Sender<ConnectionUpdate>,
    rx: mpsc::Receiver<ConnectionUpdate>,
}

impl ConnectionPool {
    pub fn new(buffer: usize, local_device_id: DeviceId) -> Self {
        let (tx, rx) = mpsc::channel(buffer);
        Self {
            conns: Arc::default(),
            local_device_id,
            tx,
            rx,
        }
    }

    pub fn split(self) -> (ConnectorPool, ListenerPool) {
        (
            ConnectorPool {
                conns: Arc::clone(&self.conns),
                local_device_id: self.local_device_id,
                tx: self.tx,
            },
            ListenerPool {
                conns: self.conns,
                local_device_id: self.local_device_id,
                rx: self.rx,
            },
        )
    }
}

#[derive(Debug)]
pub(crate) struct ConnectorPool {
    pub(super) conns: SharedConnectionMap,
    pub(super) local_device_id: DeviceId,
    pub(super) tx: mpsc::Sender<ConnectionUpdate>,
}

#[derive(Debug)]
pub(crate) struct ListenerPool {
    pub(super) conns: SharedConnectionMap,
    pub(super) local_device_id: DeviceId,
    pub(super) rx: mpsc::Receiver<ConnectionUpdate>,
}

/// Determines whether the outbound (connector-initiated) connection should win
/// during tie-breaking when both peers have simultaneous connections.
///
/// The peer with the lower device ID keeps its outbound connection. Both peers
/// evaluate this independently and arrive at the same conclusion.
pub(super) fn outbound_wins_tiebreak(
    local_device_id: DeviceId,
    remote_device_id: DeviceId,
) -> bool {
    local_device_id < remote_device_id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_id(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 32])
    }

    #[test]
    fn tiebreak_local_lower_wins_outbound() {
        assert!(outbound_wins_tiebreak(device_id(1), device_id(2)));
    }

    #[test]
    fn tiebreak_local_higher_loses_outbound() {
        assert!(!outbound_wins_tiebreak(device_id(2), device_id(1)));
    }

    #[test]
    fn tiebreak_equal_ids_loses_outbound() {
        // Equal device IDs shouldn't happen in practice — outbound does not win.
        assert!(!outbound_wins_tiebreak(device_id(1), device_id(1)));
    }

    #[test]
    fn tiebreak_both_peers_agree() {
        // Simulate simultaneous connections between peer A (id=1) and peer B (id=2).
        let peer_a = device_id(1);
        let peer_b = device_id(2);

        // Peer A's connector: A has lower ID, so A's outbound wins.
        assert!(outbound_wins_tiebreak(peer_a, peer_b));

        // Peer B's connector: B has higher ID, so B's outbound loses.
        assert!(!outbound_wins_tiebreak(peer_b, peer_a));

        // Both peers keep the same connection (A's outbound = B's inbound).
    }

    /// Regression test: address-based tie-breaking fails behind NAT.
    ///
    /// When two peers are behind the same NAT gateway, the listener sees
    /// the NAT's public IP for both. Address ordering depends on NAT port
    /// assignment, which peers don't control. Device ID tie-breaking is
    /// deterministic regardless of network topology.
    #[test]
    fn tiebreak_works_behind_nat() {
        use crate::sync::Addr;
        use std::net::Ipv4Addr;

        let nat_ip = Ipv4Addr::new(203, 0, 113, 1);
        let peer_a_id = device_id(0xAA);
        let peer_b_id = device_id(0xBB);

        // Address-based result flips when NAT port assignment changes.
        let addr_a = Addr::from((nat_ip, 40000));
        let addr_b = Addr::from((nat_ip, 40001));
        let addr_based = addr_a < addr_b;

        let addr_a_swapped = Addr::from((nat_ip, 40001));
        let addr_b_swapped = Addr::from((nat_ip, 40000));
        let addr_based_swapped = addr_a_swapped < addr_b_swapped;

        assert_ne!(addr_based, addr_based_swapped);

        // Device ID result is stable regardless of port assignment.
        assert!(outbound_wins_tiebreak(peer_a_id, peer_b_id));
        assert!(outbound_wins_tiebreak(peer_a_id, peer_b_id));
    }
}
