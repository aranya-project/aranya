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
use aranya_client::{
    config::CreateTeamConfig, AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
use aranya_daemon_api::{text, ChanOp, Role};
use test_log::test;
use tokio_util::time::FutureExt as _;
use tracing::info;

mod common;
use common::{sleep, TeamCtx, SLEEP_INTERVAL};

use crate::common::SYNC_INTERVAL;

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
    let owner = team.owner.client.team(team_id);
    let admin = team.admin.client.team(team_id);

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
    let owner = team.owner.client.team(team_id);
    let queries = owner.queries();

    assert_eq!(queries.devices_on_team().await?.iter().count(), 5);

    owner.remove_device_from_team(team.membera.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 4);

    owner.remove_device_from_team(team.memberb.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 3);

    owner.revoke_role(team.operator.id, Role::Operator).await?;
    owner.remove_device_from_team(team.operator.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 2);

    owner.revoke_role(team.admin.id, Role::Admin).await?;
    owner.remove_device_from_team(team.admin.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 1);

    owner.revoke_role(team.owner.id, Role::Owner).await?;
    owner
        .remove_device_from_team(team.owner.id)
        .await
        .expect_err("owner should not be able to remove itself from team");

    Ok(())
}

/// Tests functionality to make sure that we can query the fact database for various things.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_functions() -> Result<()> {
    let timeout = SYNC_INTERVAL * 2;

    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = team.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Assign AQC net identifier to membera.
    let operator_team = team.operator.client.team(team_id);
    let membera = team.membera;
    let expected_net_identifier = membera.aqc_net_id();
    operator_team
        .assign_aqc_net_identifier(membera.id, expected_net_identifier.clone())
        .await?;

    // Create label and assign it to membera.
    let label1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team.assign_label(membera.id, label1, op).await?;

    // Test all our fact database queries.
    let memberb = team.memberb.client.team(team_id);
    let queries = memberb.queries();

    // TODO: #404 invoke sync_now() before queries when long-polling is supported

    // First, let's check how many devices are on the team.
    async {
        loop {
            if let Ok(devices) = queries.devices_on_team().await {
                if devices.iter().count() == 5 {
                    break;
                }
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected 5 devices on team");

    // Check the specific role(s) a device has.
    async {
        loop {
            if let Ok(Role::Member) = queries.device_role(membera.id).await {
                break;
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected membera to have member role");

    // Query key bundle.
    async {
        let keybundle = membera
            .client
            .get_key_bundle()
            .await
            .expect("expected keybundle");
        loop {
            if let Ok(queried_keybundle) = queries.device_keybundle(membera.id).await {
                if keybundle == queried_keybundle {
                    break;
                }
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected queried keybundle to match device keybundle");

    // Query AQC net identifier.
    async {
        loop {
            if let Ok(Some(got_net_identifier)) = queries.aqc_net_identifier(membera.id).await {
                if expected_net_identifier == got_net_identifier {
                    break;
                }
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected AQC network identifier");

    // Query label exists.
    async {
        loop {
            if let Ok(true) = queries.label_exists(label1).await {
                break;
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected label to exist");

    // Query labels.
    async {
        loop {
            if let Ok(labels) = queries.labels().await {
                if labels.iter().count() == 1 {
                    break;
                }
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected 1 label");

    // Query assigned labels.
    async {
        loop {
            if let Ok(labels) = queries.device_label_assignments(membera.id).await {
                if labels.iter().count() == 1 {
                    break;
                }
            }
            sleep(SYNC_INTERVAL).await;
        }
    }
    .timeout(timeout)
    .await
    .expect("expected 1 assigned label");

    Ok(())
}

/// Tests add_team() by demonstrating that syncing can only occur after
/// a peer calls the add_team() API
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_team() -> Result<()> {
    const TLS_HANDSHAKE_DURATION: Duration = Duration::from_secs(10);

    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let team = TeamCtx::new("test_add_team", work_dir).await?;

    // Grab the shorthand for our address.
    let owner_addr = team.owner.aranya_local_addr().await?;

    // Create the initial team, and get our TeamId.
    let owner = team
        .owner
        .client
        .create_team({
            CreateTeamConfig::builder()
                .quic_sync(CreateTeamQuicSyncConfig::builder().build()?)
                .build()?
        })
        .await
        .expect("expected to create team");
    let team_id = owner.team_id();
    info!(?team_id);

    // Add the admin as a new device.
    info!("adding admin to team");
    owner.add_device_to_team(team.admin.pk.clone()).await?;

    // Add the operator as a new device.
    info!("adding operator to team");
    owner.add_device_to_team(team.operator.pk.clone()).await?;

    // Give the admin its role.
    owner.assign_role(team.admin.id, Role::Admin).await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = team.admin.client.team(team_id);
        admin.sync_now(owner_addr.into(), None).await?;
        sleep(TLS_HANDSHAKE_DURATION).await;

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin.assign_role(team.operator.id, Role::Operator).await {
            Ok(_) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
    }

    let admin_seed = owner
        .encrypt_psk_seed_for_peer(&team.admin.pk.encoding)
        .await?;
    team.admin
        .client
        .add_team({
            AddTeamConfig::builder()
                .team_id(team_id)
                .quic_sync(
                    AddTeamQuicSyncConfig::builder()
                        .wrapped_seed(&admin_seed)?
                        .build()?,
                )
                .build()?
        })
        .await?;
    {
        let admin = team.admin.client.team(team_id);
        admin.sync_now(owner_addr.into(), None).await?;
        sleep(SLEEP_INTERVAL).await;

        // Now we should be able to successfully assign a role.
        admin
            .assign_role(team.operator.id, Role::Operator)
            .await
            .context("Assigning a role should not fail here!")?;
    }

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

    {
        let owner = team.owner.client.team(team_id);
        let admin = team.admin.client.team(team_id);

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
    }

    // Remove the team from the admin's local storage
    team.admin.client.remove_team(team_id).await?;

    sleep(SLEEP_INTERVAL).await;

    {
        let admin = team.admin.client.team(team_id);

        // Role assignment should fail
        match admin.assign_role(team.operator.id, Role::Member).await {
            Ok(_) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
    }

    Ok(())
}

/// Tests that devices can sync to multiple teams.
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
        let owner1_addr = team1.owner.aranya_local_addr().await?;
        let owner1 = team1.owner.client.team(team_id_1);

        let admin_seed = {
            let admin2_device = &mut team2.admin;

            let admin_keys = admin2_device.pk.clone();
            owner1.add_device_to_team(admin_keys).await?;

            // Assign Admin2 the Admin role on team 1.
            owner1.assign_role(admin2_device.id, Role::Admin).await?;
            sleep(SLEEP_INTERVAL).await;

            // Create a wrapped seed for Admin2
            owner1
                .encrypt_psk_seed_for_peer(&admin2_device.pk.encoding)
                .await?
        };

        // Admin2 adds team1 to it's local storage using the wrapped seed
        team2
            .admin
            .client
            .add_team({
                AddTeamConfig::builder()
                    .quic_sync(
                        AddTeamQuicSyncConfig::builder()
                            .wrapped_seed(&admin_seed)?
                            .build()?,
                    )
                    .team_id(team_id_1)
                    .build()?
            })
            .await?;
        {
            let admin2 = team2.admin.client.team(team_id_1);
            admin2.sync_now(owner1_addr.into(), None).await?;

            sleep(SLEEP_INTERVAL).await;
            admin2.assign_role(team1.membera.id, Role::Operator).await?;
        }
    }

    // Admin2 syncs on team 2
    {
        let owner2_addr = team2.owner.aranya_local_addr().await?;
        let admin2 = team2.admin.client.team(team_id_2);

        admin2.sync_now(owner2_addr.into(), None).await?;

        sleep(SLEEP_INTERVAL).await;
        admin2.assign_role(team2.membera.id, Role::Operator).await?;
    }

    Ok(())
}
