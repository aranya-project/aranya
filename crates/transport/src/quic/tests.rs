use anyhow::Result;

use super::QuicTransport;
use crate::is_transport;

#[test]
fn test_quic_server_implements_transport() -> Result<()> {
    is_transport::<QuicTransport>();

    Ok(())
}
