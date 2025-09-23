//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

mod common;

use anyhow::{bail, Context, Result};
use aranya_client::{
    config::CreateTeamConfig, AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
use aranya_daemon_api::Role;
use test_log::test;
use tracing::{debug, info};

use crate::common::DevicesCtx;

/// Tests sync_now() by showing that an admin cannot assign any roles until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_sync_now").await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = devices.create_and_add_team().await?;

    // Grab the shorthand for our address.
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let owner = devices.owner.client.team(team_id);
    let admin = devices.admin.client.team(team_id);

    // Add the admin as a new device, but don't give it a role.
    info!("adding admin to team");
    owner.add_device_to_team(devices.admin.pk.clone()).await?;

    // Add the operator as a new device, but don't give it a role.
    info!("adding operator to team");
    owner
        .add_device_to_team(devices.operator.pk.clone())
        .await?;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner.assign_role(devices.admin.id, Role::Admin).await?;

    // Now, we try to assign a role using the admin, which is expected to fail.
    match admin.assign_role(devices.operator.id, Role::Operator).await {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin.sync_now(owner_addr.into(), None).await?;

    // Now we should be able to successfully assign a role.
    admin
        .assign_role(devices.operator.id, Role::Operator)
        .await?;

    Ok(())
}

/// Tests that devices can be removed from the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_devices() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_remove_devices").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    // Remove devices from the team while checking that the device count decreases each time a device is removed.
    let owner = devices.owner.client.team(team_id);
    let queries = owner.queries();

    assert_eq!(queries.devices_on_team().await?.iter().count(), 5);

    owner.remove_device_from_team(devices.membera.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 4);

    owner.remove_device_from_team(devices.memberb.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 3);

    owner
        .revoke_role(devices.operator.id, Role::Operator)
        .await?;
    owner.remove_device_from_team(devices.operator.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 2);

    owner.revoke_role(devices.admin.id, Role::Admin).await?;
    owner.remove_device_from_team(devices.admin.id).await?;
    assert_eq!(queries.devices_on_team().await?.iter().count(), 1);

    owner.revoke_role(devices.owner.id, Role::Owner).await?;
    owner
        .remove_device_from_team(devices.owner.id)
        .await
        .expect_err("owner should not be able to remove itself from team");

    Ok(())
}

/// Tests functionality to make sure that we can query the fact database for various things.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_functions() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_query_functions").await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    // Test all our fact database queries.
    let memberb = devices.membera.client.team(team_id);
    let queries = memberb.queries();

    // First, let's check how many devices are on the team.
    let devices_query = queries.devices_on_team().await?;
    assert_eq!(devices_query.iter().count(), 5);
    debug!(
        "membera devices on team: {:?}",
        devices_query.iter().count()
    );

    // Check the specific role(s) a device has.
    let role = queries.device_role(devices.membera.id).await?;
    assert_eq!(role, Role::Member);
    debug!("membera role: {:?}", role);

    // Make sure that we have the correct keybundle.
    let keybundle = queries.device_keybundle(devices.membera.id).await?;
    debug!("membera keybundle: {:?}", keybundle);

    // TODO(nikki): device_label_assignments, label_exists, labels

    // TODO(nikki): if cfg!(feature = "aqc") { aqc_net_identifier } and have aqc on by default.

    Ok(())
}

/// Tests add_team() by demonstrating that syncing can only occur after
/// a peer calls the add_team() API
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_team() -> Result<()> {
    // Set up our team context so we can run the test.
    let devices = DevicesCtx::new("test_add_team").await?;

    // Grab the shorthand for our address.
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Create the initial team, and get our TeamId.
    let owner = devices
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
    owner.add_device_to_team(devices.admin.pk.clone()).await?;

    // Add the operator as a new device.
    info!("adding operator to team");
    owner
        .add_device_to_team(devices.operator.pk.clone())
        .await?;

    // Give the admin its role.
    owner.assign_role(devices.admin.id, Role::Admin).await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id);
        match admin.sync_now(owner_addr.into(), None).await {
            Ok(()) => bail!("expected syncing to fail"),
            // TODO(#299): This should fail "immediately" with an `Aranya(_)` sync error,
            // but currently the handshake timeout races with the tarpc timeout.
            Err(aranya_client::Error::Aranya(_) | aranya_client::Error::Ipc(_)) => {}
            Err(err) => return Err(err).context("unexpected error while syncing"),
        }

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin.assign_role(devices.operator.id, Role::Operator).await {
            Ok(()) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
    }

    let admin_seed = owner
        .encrypt_psk_seed_for_peer(&devices.admin.pk.encoding)
        .await?;
    devices
        .admin
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
        let admin = devices.admin.client.team(team_id);
        admin.sync_now(owner_addr.into(), None).await?;

        // Now we should be able to successfully assign a role.
        admin
            .assign_role(devices.operator.id, Role::Operator)
            .await
            .context("Assigning a role should not fail here!")?;
    }

    return Ok(());
}

/// Tests that devices can be removed from the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_team() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_remove_team").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    {
        let owner = devices.owner.client.team(team_id);
        let admin = devices.admin.client.team(team_id);

        // Add the operator as a new device.
        info!("adding operator to team");
        owner
            .add_device_to_team(devices.operator.pk.clone())
            .await?;

        // Add the admin as a new device.
        owner.add_device_to_team(devices.admin.pk.clone()).await?;

        // Give the admin its role.
        owner.assign_role(devices.admin.id, Role::Admin).await?;

        admin
            .sync_now(devices.owner.aranya_local_addr().await?.into(), None)
            .await?;

        // We should be able to successfully assign a role.
        admin
            .assign_role(devices.operator.id, Role::Operator)
            .await?;
    }

    // Remove the team from the admin's local storage
    devices.admin.client.remove_team(team_id).await?;

    {
        let admin = devices.admin.client.team(team_id);

        // Role assignment should fail
        match admin.assign_role(devices.operator.id, Role::Member).await {
            Ok(_) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
    }

    Ok(())
}

/// Tests that a device can create multiple teams and receive sync requests for each team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_multi_team_sync() -> Result<()> {
    // Set up our team context so we can run the test.
    let devices = DevicesCtx::new("test_multi_team_sync").await?;

    // Grab the shorthand for our address.
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Create the initial team, and get our TeamId.
    let team1 = devices
        .owner
        .client
        .create_team({
            CreateTeamConfig::builder()
                .quic_sync(CreateTeamQuicSyncConfig::builder().build()?)
                .build()?
        })
        .await
        .expect("expected to create team1");
    let team_id1 = team1.team_id();
    info!(?team_id1);

    // Create the second team, and get our TeamId.
    let team2 = devices
        .owner
        .client
        .create_team({
            CreateTeamConfig::builder()
                .quic_sync(CreateTeamQuicSyncConfig::builder().build()?)
                .build()?
        })
        .await
        .expect("expected to create team2");
    let team_id2 = team2.team_id();
    info!(?team_id2);

    // Add the admin as a new device.
    info!("adding admin to team1");
    team1.add_device_to_team(devices.admin.pk.clone()).await?;

    // Add the operator as a new device.
    info!("adding operator to team1");
    team1
        .add_device_to_team(devices.operator.pk.clone())
        .await?;

    // Give the admin its role.
    team1.assign_role(devices.admin.id, Role::Admin).await?;

    // Add the admin as a new device.
    info!("adding admin to team2");
    team2.add_device_to_team(devices.admin.pk.clone()).await?;

    // Add the operator as a new device.
    info!("adding operator to team2");
    team2
        .add_device_to_team(devices.operator.pk.clone())
        .await?;

    // Give the admin its role.
    team2.assign_role(devices.admin.id, Role::Admin).await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id1);
        match admin.sync_now(owner_addr.into(), None).await {
            Ok(()) => bail!("expected syncing to fail"),
            // TODO(#299): This should fail "immediately" with an `Aranya(_)` sync error,
            // but currently the handshake timeout races with the tarpc timeout.
            Err(aranya_client::Error::Aranya(_) | aranya_client::Error::Ipc(_)) => {}
            Err(err) => return Err(err).context("unexpected error while syncing"),
        }

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin.assign_role(devices.operator.id, Role::Operator).await {
            Ok(()) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
    }

    let admin_seed1 = team1
        .encrypt_psk_seed_for_peer(&devices.admin.pk.encoding)
        .await?;
    devices
        .admin
        .client
        .add_team({
            AddTeamConfig::builder()
                .team_id(team_id1)
                .quic_sync(
                    AddTeamQuicSyncConfig::builder()
                        .wrapped_seed(&admin_seed1)?
                        .build()?,
                )
                .build()?
        })
        .await?;

    let admin1 = devices.admin.client.team(team_id1);
    admin1.sync_now(owner_addr.into(), None).await?;

    // Now we should be able to successfully assign a role.
    admin1
        .assign_role(devices.operator.id, Role::Operator)
        .await
        .context("Assigning a role should not fail here!")?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id2);
        match admin.sync_now(owner_addr.into(), None).await {
            Ok(()) => bail!("expected syncing to fail"),
            // TODO(#299): This should fail "immediately" with an `Aranya(_)` sync error,
            // but currently the handshake timeout races with the tarpc timeout.
            Err(aranya_client::Error::Aranya(_) | aranya_client::Error::Ipc(_)) => {}
            Err(err) => return Err(err).context("unexpected error while syncing"),
        }

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin.assign_role(devices.operator.id, Role::Operator).await {
            Ok(()) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
    }

    let admin_seed2 = team2
        .encrypt_psk_seed_for_peer(&devices.admin.pk.encoding)
        .await?;
    devices
        .admin
        .client
        .add_team({
            AddTeamConfig::builder()
                .team_id(team_id2)
                .quic_sync(
                    AddTeamQuicSyncConfig::builder()
                        .wrapped_seed(&admin_seed2)?
                        .build()?,
                )
                .build()?
        })
        .await?;

    let admin2 = devices.admin.client.team(team_id2);
    admin2.sync_now(owner_addr.into(), None).await?;

    // Now we should be able to successfully assign a role.
    admin2
        .assign_role(devices.operator.id, Role::Operator)
        .await
        .context("Assigning a role should not fail here!")?;

    Ok(())
}
