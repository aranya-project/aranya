use anyhow::Result;

use super::UdpTransport;
use crate::is_transport;

#[test]
fn test_udp_socket_implements_transport() -> Result<()> {
    is_transport::<UdpTransport>();

    Ok(())
}
