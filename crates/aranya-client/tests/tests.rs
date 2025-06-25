//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

use std::time::Duration;

use anyhow::{bail, Context, Result};
use aranya_client::{QuicSyncConfig, TeamConfig};
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

    // Create the initial team, and get our TeamId and seed.
    let team_id = team.create_and_add_team().await?;

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

/// Tests that devices can be removed from the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_devices() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let team_id = team
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Remove devices from the team while checking that the device count decreases each time a device is removed.
    {
        let mut queries = team.owner.client.queries(team_id);
        assert_eq!(queries.devices_on_team().await?.iter().count(), 5);
    }
    {
        let mut owner = team.owner.client.team(team_id);
        owner.remove_device_from_team(team.membera.id).await?;
    }
    {
        let mut queries = team.owner.client.queries(team_id);
        assert_eq!(queries.devices_on_team().await?.iter().count(), 4);
    }
    {
        let mut owner = team.owner.client.team(team_id);
        owner.remove_device_from_team(team.memberb.id).await?;
    }
    {
        let mut queries = team.owner.client.queries(team_id);
        assert_eq!(queries.devices_on_team().await?.iter().count(), 3);
    }
    {
        let mut owner = team.owner.client.team(team_id);
        owner.revoke_role(team.operator.id, Role::Operator).await?;
        owner.remove_device_from_team(team.operator.id).await?;
    }
    {
        let mut queries = team.owner.client.queries(team_id);
        assert_eq!(queries.devices_on_team().await?.iter().count(), 2);
    }
    {
        let mut owner = team.owner.client.team(team_id);
        owner.revoke_role(team.admin.id, Role::Admin).await?;
        owner.remove_device_from_team(team.admin.id).await?;
    }
    {
        let mut queries = team.owner.client.queries(team_id);
        assert_eq!(queries.devices_on_team().await?.iter().count(), 1);
    }
    {
        let mut owner = team.owner.client.team(team_id);
        owner.revoke_role(team.owner.id, Role::Owner).await?;
        owner
            .remove_device_from_team(team.owner.id)
            .await
            .expect_err("owner should not be able to remove itself from team");
    }

    Ok(())
}

/// Tests functionality to make sure that we can query the fact database for various things.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_functions() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = team.create_and_add_team().await?;

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
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_team() -> Result<()> {
    const TLS_HANDSHAKE_DURATION: Duration = Duration::from_secs(10);

    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_add_team", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let team_id = team
        .owner
        .client
        .create_team({
            TeamConfig::builder()
                .quic_sync(QuicSyncConfig::builder().build()?)
                .build()?
        })
        .await
        .expect("expected to create team");
    info!(?team_id);

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
    sleep(TLS_HANDSHAKE_DURATION).await;

    // Now, we try to assign a role using the admin, which is expected to fail.
    match admin.assign_role(team.operator.id, Role::Operator).await {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    let admin_seed = owner
        .encrypt_psk_seed_for_peer(&team.admin.pk.encoding)
        .await?;
    admin
        .add_team({
            TeamConfig::builder()
                .quic_sync(
                    QuicSyncConfig::builder()
                        .wrapped_seed_from_bytes(&admin_seed)?
                        .build()?,
                )
                .build()?
        })
        .await?;
    admin.sync_now(owner_addr.into(), None).await?;
    sleep(SLEEP_INTERVAL).await;

    // Now we should be able to successfully assign a role.
    admin
        .assign_role(team.operator.id, Role::Operator)
        .await
        .context("Assigning a role should not fail here!")?;

    return Ok(());
}

/// Tests that devices can be removed from the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_team() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_remove_team", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let team_id = team
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    team.add_all_sync_peers(team_id).await?;

    let mut owner = team.owner.client.team(team_id);
    let mut admin = team.admin.client.team(team_id);

    // Add the operator as a new device.
    info!("adding operator to team");
    owner.add_device_to_team(team.operator.pk.clone()).await?;

    // Add the admin as a new device.
    owner.add_device_to_team(team.admin.pk.clone()).await?;

    // Give the admin its role.
    owner.assign_role(team.admin.id, Role::Admin).await?;

    sleep(SLEEP_INTERVAL).await;

    // We should be able to successfully assign a role.
    admin.assign_role(team.operator.id, Role::Operator).await?;

    // Remove the team from the admin's local storage
    admin.remove_team().await?;

    sleep(SLEEP_INTERVAL).await;

    // Role assignment should fail
    match admin.assign_role(team.operator.id, Role::Member).await {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    Ok(())
}

/// Tests that devices can be removed from the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_multi_team_sync() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team1 = TeamCtx::new("test_multi_team_sync_1", work_dir.join("team1")).await?;
    let mut team2 = TeamCtx::new("test_multi_team_sync_2", work_dir.join("team2")).await?;

    // Create the first team, and get our TeamId.
    let team_id_1 = team1
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id_1);

    // Create the second team, and get our TeamId.
    let team_id_2 = team2
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id_2);

    // Tell all peers to sync with one another, and assign their roles.
    team1.add_all_sync_peers(team_id_1).await?;
    team1.add_all_device_roles(team_id_1).await?;

    team2.add_all_sync_peers(team_id_2).await?;
    team2.add_all_device_roles(team_id_2).await?;

    // Admin2 syncs on team 1
    {
        let admin2_device = &mut team2.admin;
        let owner1_addr = team1.owner.aranya_local_addr().await?;
        let mut owner1 = team1.owner.client.team(team_id_1);

        let mut admin2 = admin2_device.client.team(team_id_1);

        let admin_keys = admin2_device.pk.clone();
        owner1.add_device_to_team(admin_keys).await?;

        // Assign Admin2 the Admin role on team 1.
        owner1.assign_role(admin2_device.id, Role::Admin).await?;
        sleep(SLEEP_INTERVAL).await;

        // Create a wrapped seed for Admin2
        let admin_seed = owner1
            .encrypt_psk_seed_for_peer(&admin2_device.pk.encoding)
            .await?;

        // Admin2 adds team1 to it's local storage using the wrapped seed
        admin2
            .add_team({
                TeamConfig::builder()
                    .quic_sync(
                        QuicSyncConfig::builder()
                            .wrapped_seed_from_bytes(&admin_seed)?
                            .build()?,
                    )
                    .build()?
            })
            .await?;
        admin2.sync_now(owner1_addr.into(), None).await?;

        sleep(SLEEP_INTERVAL).await;
        admin2.assign_role(team1.membera.id, Role::Operator).await?;
    }

    // Admin2 syncs on team 2
    {
        let owner2_addr = team2.owner.aranya_local_addr().await?;
        let mut admin2 = team2.admin.client.team(team_id_2);

        admin2.sync_now(owner2_addr.into(), None).await?;

        sleep(SLEEP_INTERVAL).await;
        admin2.assign_role(team2.membera.id, Role::Operator).await?;
    }

    Ok(())
}
