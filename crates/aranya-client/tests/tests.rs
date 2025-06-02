//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

use anyhow::{bail, Context, Result};
use aranya_client::TeamConfig;
use aranya_daemon_api::Role;
use test_log::test;
use tracing::{debug, info};

mod common;
use common::{sleep, TeamCtx, SLEEP_INTERVAL};

/// Tests sync_now() by showing that an admin cannot assign any roles until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_sync_now", work_dir).await?;

    // Create the initial team, and get our TeamId and PSK.
    let (team_id, maybe_psk) = {
        let cfg = TeamConfig::builder().build()?;
        team.owner
            .client
            .create_team(cfg)
            .await
            .expect("expected to create team")
    };
    info!(?team_id);

    if let Some(psk) = maybe_psk {
        let cfg = {
            let idenitity = psk.idenitity();
            let secret = psk.raw_secret_bytes();
            TeamConfig::builder().psk(idenitity, secret).build()?
        };

        team.admin.client.add_team(team_id, cfg.clone()).await?;
        team.operator.client.add_team(team_id, cfg.clone()).await?;
        team.membera.client.add_team(team_id, cfg.clone()).await?;
        team.memberb.client.add_team(team_id, cfg).await?;
    }

    // Grab the shorthand for our address.
    let owner_addr = team.owner.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut owner = team.owner.client.team(team_id);
    let mut admin = team.admin.client.team(team_id);

    // Add the admin as a new device, but don't give it a role.
    info!("adding admin to team");
    owner.add_device_to_team(team.admin.pk.clone()).await?;

    // Add the operator as a new device, but don't give it a role.
    info!("adding operator to team");
    owner.add_device_to_team(team.operator.pk.clone()).await?;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner.assign_role(team.admin.id, Role::Admin).await?;

    // Now, we try to assign a role using the admin, which is expected to fail.
    match admin.assign_role(team.operator.id, Role::Operator).await {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin.sync_now(owner_addr.into(), None).await?;
    sleep(SLEEP_INTERVAL).await;

    // Now we should be able to successfully assign a role.
    admin.assign_role(team.operator.id, Role::Operator).await?;

    Ok(())
}

/// Tests functionality to make sure that we can query the fact database for various things.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_functions() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    // Create the initial team, and get our TeamId and PSK.
    let (team_id, maybe_psk) = {
        let cfg = TeamConfig::builder().build()?;
        team.owner
            .client
            .create_team(cfg)
            .await
            .expect("expected to create team")
    };
    info!(?team_id);

    if let Some(psk) = maybe_psk {
        let cfg = {
            let idenitity = psk.idenitity();
            let secret = psk.raw_secret_bytes();
            TeamConfig::builder().psk(idenitity, secret).build()?
        };

        team.admin.client.add_team(team_id, cfg.clone()).await?;
        team.operator.client.add_team(team_id, cfg.clone()).await?;
        team.membera.client.add_team(team_id, cfg.clone()).await?;
        team.memberb.client.add_team(team_id, cfg).await?;
    }

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Test all our fact database queries.
    let mut queries = team.membera.client.queries(team_id);

    // First, let's check how many devices are on the team.
    let devices = queries.devices_on_team().await?;
    assert_eq!(devices.iter().count(), 5);
    debug!("membera devices on team: {:?}", devices.iter().count());

    // Check the specific role(s) a device has.
    let role = queries.device_role(team.membera.id).await?;
    assert_eq!(role, Role::Member);
    debug!("membera role: {:?}", role);

    // Make sure that we have the correct keybundle.
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    debug!("membera keybundle: {:?}", keybundle);

    // TODO(nikki): device_label_assignments, label_exists, labels

    // TODO(nikki): if cfg!(feature = "aqc") { aqc_net_identifier } and have aqc on by default.

    Ok(())
}

/// Tests add_team() by demonstrating that syncing can only occur after
/// a peer calls the add_team() API
#[ignore] // FIXME
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_team() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_add_team", work_dir).await?;

    // Create the initial team, and get our TeamId and PSK.
    let (team_id, maybe_psk) = {
        let cfg = TeamConfig::builder().build()?;
        team.owner
            .client
            .create_team(cfg)
            .await
            .expect("expected to create team")
    };
    info!(?team_id);

    if let Some(psk) = maybe_psk {
        let cfg = {
            let idenitity = psk.idenitity();
            let secret = psk.raw_secret_bytes();
            TeamConfig::builder().psk(idenitity, secret).build()?
        };

        // Grab the shorthand for our address.
        let owner_addr = team.owner.aranya_local_addr().await?;

        // Grab the shorthand for the teams we need to operate on.
        let mut owner = team.owner.client.team(team_id);
        let mut admin = team.admin.client.team(team_id);

        // Add the admin as a new device.
        info!("adding admin to team");
        owner.add_device_to_team(team.admin.pk.clone()).await?;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner.add_device_to_team(team.operator.pk.clone()).await?;

        // Give the admin its role.
        owner.assign_role(team.admin.id, Role::Admin).await?;

        // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
        admin.sync_now(owner_addr.into(), None).await?;
        sleep(SLEEP_INTERVAL).await;

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin.assign_role(team.operator.id, Role::Operator).await {
            Ok(_) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }

        admin.add_team(cfg.clone()).await?;
        sleep(SLEEP_INTERVAL).await;
        admin.sync_now(owner_addr.into(), None).await?;
        sleep(SLEEP_INTERVAL).await;

        // Now we should be able to successfully assign a role.
        admin
            .assign_role(team.operator.id, Role::Operator)
            .await
            .context("Assigning a role should not fail here!")?;

        return Ok(());
    }

    panic!("Handle other syncer types")
}
