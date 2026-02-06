//! Topology configuration dispatcher for scale convergence tests.

use anyhow::Result;

use crate::scale::TestCtx;

impl TestCtx {
    /// Configures the topology based on `self.topology` and verifies correctness.
    pub async fn configure_topology(&mut self) -> Result<()> {
        match self.topology {
            super::Topology::Ring => {
                self.configure_ring_topology().await?;
                self.verify_ring_topology()?;
            }
        }
        Ok(())
    }
}
