//! Integration tests for unstable APIS in the user library.

use anyhow::{bail, Result};
use test_log::test;
use tracing::info;

use crate::common::DevicesCtx;

mod common;

/// Tests parallel finalize commands
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_parallel_finalize() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_parallel_finalize").await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = devices.create_and_add_team().await?;

    // Grab the shorthand for our address.
    let owner_addr = devices.owner.aranya_local_addr().await?;
    let membera_addr = devices.membera.aranya_local_addr().await?;

    // Add the devices to the team.
    info!("adding devices to team");
    devices.add_all_device_roles(team_id).await?;

    // Grab the shorthand for the teams we need to operate on.
    let owner = devices.owner.client.team(team_id);
    let membera = devices.membera.client.team(team_id);

    // Assign the finalize permission to this device.
    // Note: The device that created the team has this permission by default.
    owner.assign_finalize_perm(devices.membera.id).await?;

    membera.sync_now(owner_addr.into(), None).await?;

    // Ok. Sync with peer between finalize commands
    {
        owner.finalize_team().await?;
        membera.sync_now(owner_addr.into(), None).await?;

        membera.finalize_team().await?;
        owner.sync_now(membera_addr.into(), None).await?;
    }

    // Not Ok.
    {
        owner.finalize_team().await?;
        membera.finalize_team().await?;

        let sync_result = membera.sync_now(owner_addr.into(), None).await;

        match sync_result {
            Ok(()) => bail!("Expected syncing to fail"),
            Err(aranya_client::Error::Aranya(err)) => {
                assert!(err.is_parallel_finalize());
            }
            Err(_) => bail!("Unexpected error"),
        }
    }

    Ok(())
}
