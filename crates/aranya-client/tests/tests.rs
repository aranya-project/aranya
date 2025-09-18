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

use std::time::Duration;

use anyhow::{bail, Context, Result};
use aranya_client::{
    client::RoleId, config::CreateTeamConfig, AddTeamConfig, AddTeamQuicSyncConfig,
    CreateTeamQuicSyncConfig,
};
use test_log::test;
use tracing::{debug, info};

use crate::common::{sleep, DefaultRoles, DevicesCtx, RolesExt, SLEEP_INTERVAL};

/// Tests sync_now() by showing that an admin cannot assign any roles until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_sync_now").await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = devices.create_and_add_team().await?;

    let roles = devices
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    let owner_addr = devices.owner.aranya_local_addr().await?;

    let owner = devices.owner.client.team(team_id);
    let admin = devices.admin.client.team(team_id);

    // Add the admin as a new device, but don't give it a role.
    owner
        .add_device(devices.admin.pk.clone(), None)
        .await
        .context("owner unable to add admin to team")?;

    // Add the operator as a new device, but don't give it a role.
    owner
        .add_device(devices.operator.pk.clone(), None)
        .await
        .context("owner unable to add operator to team")?;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner
        .assign_role(devices.admin.id, roles.admin().id)
        .await
        .context("owner unable to assign admin role")?;

    // Now, we try to assign a role using the admin, which is expected to fail.
    match admin
        .assign_role(devices.operator.id, roles.operator().id)
        .await
    {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin
        .sync_now(owner_addr.into(), None)
        .await
        .context("admin unable to sync with owner")?;

    sleep(SLEEP_INTERVAL).await;

    // Now we should be able to successfully assign a role.
    admin
        .assign_role(devices.operator.id, roles.operator().id)
        .await
        .context("admin unable to assign role to operator")?;

    Ok(())
}

/// Tests that devices can be added to the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_devices() -> Result<()> {
    let mut team = DevicesCtx::new("test_add_devices").await?;

    let team_id = team
        .create_and_add_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    let owner = team.owner.client.team(team_id);
    let admin = team.admin.client.team(team_id);
    let operator = team.operator.client.team(team_id);

    team.add_all_sync_peers(team_id)
        .await
        .context("unable to add all sync peers")?;

    // There are now three more roles in addition to the original
    // owner role:
    // - admin
    // - operator
    // - member
    // The owner role manages all of those roles.
    let roles = team
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    // Add the initial admin who should be allowed to add
    // devices.
    owner
        .add_device(team.admin.pk.clone(), Some(roles.admin().id))
        .await
        .context("owner should be able to add admin to team")?;

    sleep(SLEEP_INTERVAL).await;

    admin
        .add_device(team.operator.pk.clone(), Some(roles.operator().id))
        .await
        .context("owner should be able to add operator to team")?;

    sleep(SLEEP_INTERVAL).await;

    for (name, kb) in [
        ("membera", team.membera.pk.clone()),
        ("memberb", team.memberb.pk.clone()),
    ] {
        admin
            .add_device(kb, None)
            .await
            .with_context(|| format!("admin should be able to add `{name}` to team"))?;
        sleep(SLEEP_INTERVAL).await;
        operator
            .assign_role(team.membera.id, roles.member().id)
            .await
            .with_context(|| {
                format!("operator should be able to assign member role to `{name}`")
            })?;
    }

    sleep(SLEEP_INTERVAL).await;

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

    assert_eq!(owner.devices().await?.iter().count(), 5);

    owner.remove_device(devices.membera.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 4);

    owner.remove_device(devices.memberb.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 3);

    // TODO: Implement role revocation with proper RoleId system
    owner.remove_device(devices.operator.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 2);

    owner.remove_device(devices.admin.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 1);

    // TODO: Implement role revocation with proper RoleId system
    owner
        .remove_device(devices.owner.id)
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

    // Set up the default roles first
    let roles = devices
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    // Test all our fact database queries.
    let memberb = devices.membera.client.team(team_id);

    // First, let's check how many devices are on the team.
    let devices_query = memberb.devices().await?;
    assert_eq!(devices_query.iter().count(), 5);
    debug!(
        "membera devices on team: {:?}",
        devices_query.iter().count()
    );

    // Check the specific role(s) a device has.
    let dev_role = memberb.device(devices.membera.id).role().await?;
    assert_eq!(dev_role.as_ref().map(|r| r.id), Some(roles.member().id));
    debug!("membera role: {:?}", dev_role);

    // Make sure that we have the correct keybundle.
    let keybundle = memberb.device(devices.membera.id).keybundle().await?;
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

    let owner_role_id = owner.roles().await?.try_into_owner_role()?.id;
    let roles = owner
        .setup_default_roles(owner_role_id)
        .await?
        .try_into_default_roles()?;

    // Add the admin as a new device.
    info!("adding admin to team");
    owner.add_device(devices.admin.pk.clone(), None).await?;

    // Add the operator as a new device.
    info!("adding operator to team");
    owner.add_device(devices.operator.pk.clone(), None).await?;

    // Give the admin its role.
    owner
        .assign_role(devices.admin.id, roles.admin().id)
        .await?;

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
        match admin
            .assign_role(devices.operator.id, roles.operator().id)
            .await
        {
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
            .assign_role(devices.operator.id, roles.operator().id)
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

    let owner = devices.owner.client.team(team_id);
    let owner_role_id = owner.roles().await?.try_into_owner_role()?.id;
    let roles = owner
        .setup_default_roles(owner_role_id)
        .await?
        .try_into_default_roles()?;

    {
        let admin = devices.admin.client.team(team_id);

        // Add the operator as a new device.
        info!("adding operator to team");
        owner.add_device(devices.operator.pk.clone(), None).await?;

        // Add the admin as a new device.
        owner.add_device(devices.admin.pk.clone(), None).await?;

        // Give the admin its role.
        owner
            .assign_role(devices.admin.id, roles.admin().id)
            .await?;

        admin
            .sync_now(devices.owner.aranya_local_addr().await?.into(), None)
            .await?;

        // We should be able to successfully assign a role.
        admin
            .assign_role(devices.operator.id, roles.operator().id)
            .await?;
    }

    // Remove the team from the admin's local storage
    devices.admin.client.remove_team(team_id).await?;

    {
        let admin = devices.admin.client.team(team_id);

        // Role assignment should fail
        match admin
            .assign_role(devices.operator.id, roles.member().id)
            .await
        {
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
    let devices = DevicesCtx::new("test_multi_team").await?;

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

    // Set up roles for team1
    let owner_role_id1 = team1.roles().await?.try_into_owner_role()?.id;
    let roles1 = team1
        .setup_default_roles(owner_role_id1)
        .await?
        .try_into_default_roles()?;

    // Set up roles for team2
    let owner_role_id2 = team2.roles().await?.try_into_owner_role()?.id;
    let roles2 = team2
        .setup_default_roles(owner_role_id2)
        .await?
        .try_into_default_roles()?;

    // Add the admin as a new device.
    info!("adding admin to team1");
    team1.add_device(devices.admin.pk.clone(), None).await?;

    // Add the operator as a new device.
    info!("adding operator to team1");
    team1.add_device(devices.operator.pk.clone(), None).await?;

    // Give the admin its role.
    team1
        .assign_role(devices.admin.id, roles1.admin().id)
        .await?;

    // Add the admin as a new device.
    info!("adding admin to team2");
    team2.add_device(devices.admin.pk.clone(), None).await?;

    // Add the operator as a new device.
    info!("adding operator to team2");
    team2.add_device(devices.operator.pk.clone(), None).await?;

    // Give the admin its role.
    team2
        .assign_role(devices.admin.id, roles2.admin().id)
        .await?;

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
        match admin
            .assign_role(devices.operator.id, roles1.operator().id)
            .await
        {
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
        .assign_role(devices.operator.id, roles1.operator().id)
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
        match admin
            .assign_role(devices.operator.id, roles2.operator().id)
            .await
        {
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
        .assign_role(devices.operator.id, roles2.operator().id)
        .await
        .context("Assigning a role should not fail here!")?;

    Ok(())
}
