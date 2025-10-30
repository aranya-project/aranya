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
    client::{ChanOp, RoleId},
    config::CreateTeamConfig,
    AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
use aranya_daemon_api::text;
use test_log::test;
use tracing::{debug, info};

use crate::common::{sleep, DevicesCtx, SLEEP_INTERVAL};

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

    // Now we should be able to successfully assign a role.
    admin
        .assign_role(devices.operator.id, roles.operator().id)
        .await
        .context("admin unable to assign role to operator")?;

    Ok(())
}

/// Tests adding sync peers.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_sync_peers() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_sync_peers").await?;
    let team_id = devices
        .create_and_add_team()
        .await
        .expect("expected to create team");

    // create default roles
    let roles = devices.setup_default_roles(team_id).await?;

    devices
        .add_all_sync_peers(team_id)
        .await
        .context("unable to add all sync peers")?;

    // TODO: if this is removed the label queries have a seal error.
    devices.add_all_device_roles(team_id, &roles).await?;

    // Add a command to graph by having the owner create a label.
    let owner_team = devices.owner.client.team(team_id);
    owner_team
        .create_label(text!("label1"), roles.owner().id)
        .await?;

    // Wait for syncing.
    sleep(SLEEP_INTERVAL).await;

    // Verify peers automatically sync command with sync peer.
    // They should receive the label that was created.
    let owner_team_labels = owner_team.labels().await?;
    assert_eq!(owner_team_labels.iter().count(), 1);

    let membera_team = devices.membera.client.team(team_id);
    let membera_team_labels = membera_team.labels().await?;
    assert_eq!(membera_team_labels.iter().count(), 1);

    let memberb_team = devices.memberb.client.team(team_id);
    let memberb_team_labels = memberb_team.labels().await?;
    assert_eq!(memberb_team_labels.iter().count(), 1);

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

    admin
        .sync_now(team.owner.aranya_local_addr().await?.into(), None)
        .await
        .context("admin unable to sync with owner")?;

    admin
        .add_device(team.operator.pk.clone(), Some(roles.operator().id))
        .await
        .context("admin should be able to add operator to team")?;

    operator
        .sync_now(team.admin.aranya_local_addr().await?.into(), None)
        .await
        .context("operator unable to sync with admin")?;

    for (name, kb, device_id) in [
        ("membera", team.membera.pk.clone(), team.membera.id),
        ("memberb", team.memberb.pk.clone(), team.memberb.id),
    ] {
        admin
            .add_device(kb, None)
            .await
            .with_context(|| format!("admin should be able to add `{name}` to team"))?;
        operator
            .sync_now(team.admin.aranya_local_addr().await?.into(), None)
            .await
            .context("operator unable to sync with admin")?;
        operator
            .assign_role(device_id, roles.member().id)
            .await
            .with_context(|| {
                format!("operator should be able to assign member role to `{name}`")
            })?;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_device_with_initial_role_requires_delegation() -> Result<()> {
    let mut devices =
        DevicesCtx::new("test_add_device_with_initial_role_requires_delegation").await?;

    let team_id = devices.create_and_add_team().await?;

    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await
        .context("unable to setup default roles")?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    owner_team
        .add_device(devices.admin.pk.clone(), Some(roles.admin().id))
        .await
        .context("owner should be able to add admin to team")?;

    admin_team
        .sync_now(devices.owner.aranya_local_addr().await?.into(), None)
        .await
        .context("admin unable to sync with owner")?;

    match admin_team
        .add_device(devices.membera.pk.clone(), Some(roles.member().id))
        .await
    {
        Ok(_) => bail!("expected delegated add_device to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error: {err:?}"),
    }

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

    // Setup default roles and ensure delegations exist for helper routines.
    let roles = devices
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id, &roles).await?;

    // Remove devices from the team while checking that the device count decreases each time a device is removed.
    let owner = devices.owner.client.team(team_id);

    assert_eq!(owner.devices().await?.iter().count(), 5);

    owner.remove_device(devices.membera.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 4);

    owner.remove_device(devices.memberb.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 3);

    owner.remove_device(devices.operator.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 2);

    owner.remove_device(devices.admin.id).await?;
    assert_eq!(owner.devices().await?.iter().count(), 1);

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
    devices.add_all_device_roles(team_id, &roles).await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label(text!("label1"), roles.owner().id)
        .await?;

    // Assigning labels to devices with the "member" role should succeed since it does not have `CanUseAfc` permission.
    let op = ChanOp::SendRecv;
    owner_team
        .device(devices.membera.id)
        .assign_label(label_id, op)
        .await?;
    owner_team
        .device(devices.memberb.id)
        .assign_label(label_id, op)
        .await?;

    // wait for syncing.
    let owner_addr = devices.owner.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(owner_addr, None)
        .await?;

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

    // Make sure membera can query labels assigned to it.
    let membera_labels = memberb
        .device(devices.membera.id)
        .label_assignments()
        .await?;
    assert_eq!(membera_labels.iter().count(), 1);

    // Make sure owner can query labels created on the team.
    let team_labels = owner_team.labels().await?;
    assert_eq!(team_labels.iter().count(), 1);

    // Make sure owner can query whether certain labels exist on the team.
    assert!(owner_team.label(label_id).await?.is_some());

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

    let roles = devices.setup_default_roles(team_id).await?;

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
        .encrypt_psk_seed_for_peer(&devices.admin.pk.encryption)
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
    let roles = devices.setup_default_roles(team_id).await?;

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

    // Set up roles for team1
    let roles1 = devices.setup_default_roles(team_id1).await?;

    // Set up roles for team2
    let roles2 = devices.setup_default_roles(team_id2).await?;

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
        .encrypt_psk_seed_for_peer(&devices.admin.pk.encryption)
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
        .encrypt_psk_seed_for_peer(&devices.admin.pk.encryption)
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

/// Enforces that default roles can only be seeded once per team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_setup_default_roles_single_use() -> Result<()> {
    let mut devices = DevicesCtx::new("test_setup_default_roles_single_use").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await
        .context("unable to setup default roles without delegation")?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team.setup_default_roles(roles.owner().id).await {
        Ok(_) => bail!("expected replayed setup_default_roles to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error re-running setup_default_roles: {err:?}"),
    }

    Ok(())
}

/// Verifies that the managing role supplied to setup_default_roles must exist.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_setup_default_roles_rejects_unknown_owner() -> Result<()> {
    let mut devices = DevicesCtx::new("test_setup_default_roles_rejects_unknown_owner").await?;

    let team_id = devices.create_and_add_team().await?;
    let owner_team = devices.owner.client.team(team_id);
    let bogus_role = RoleId::from([0x55; 32]);

    match owner_team.setup_default_roles(bogus_role).await {
        Ok(_) => bail!("expected setup_default_roles to reject unknown owner role"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error when using bogus owner role: {err:?}"),
    }

    Ok(())
}

/// Prevents devices from assigning roles to themselves.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_assign_role_self_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_assign_role_self_rejected").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team
        .assign_role(devices.owner.id, roles.owner().id)
        .await
    {
        Ok(_) => bail!("expected assigning role to self to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected assign_role error: {err:?}"),
    }

    Ok(())
}

/// Prevents the sole owner from revoking its own owner role.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_owner_cannot_revoke_owner_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_owner_cannot_revoke_owner_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team
        .revoke_role(devices.owner.id, roles.owner().id)
        .await
    {
        Ok(_) => bail!("expected revoking owner role from self to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected revoke_role error: {err:?}"),
    }

    Ok(())
}

/// Requires role management delegation before assigning a role.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_assign_role_requires_delegation() -> Result<()> {
    let mut devices = DevicesCtx::new("test_assign_role_requires_delegation").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    owner_team
        .add_device(devices.admin.pk.clone(), Some(roles.admin().id))
        .await?;
    owner_team
        .add_device(devices.membera.pk.clone(), None)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?.into();
    admin_team.sync_now(owner_addr, None).await?;

    match admin_team
        .assign_role(devices.membera.id, roles.member().id)
        .await
    {
        Ok(_) => bail!("expected assigning role without delegation to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected assign_role error: {err:?}"),
    }

    Ok(())
}

/// Role management changes require the caller to own the role.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_assign_role_management_permission_requires_ownership() -> Result<()> {
    let mut devices =
        DevicesCtx::new("test_assign_role_management_permission_requires_ownership").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    owner_team
        .add_device(devices.admin.pk.clone(), Some(roles.admin().id))
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?.into();
    admin_team.sync_now(owner_addr, None).await?;

    match admin_team
        .assign_role_management_permission(
            roles.member().id,
            roles.operator().id,
            text!("CanAssignRole"),
        )
        .await
    {
        Ok(_) => bail!("expected assigning management perm without ownership to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected assign_role_management_permission error: {err:?}"),
    }

    Ok(())
}

/// Test that role management permissions can be assigned and revoked correctly.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_assign_and_revoke_role_management_permission() -> Result<()> {
    let mut devices = DevicesCtx::new("test_assign_and_revoke_role_management_permission").await?;

    let team_id = devices.create_and_add_team().await?;
    // Use setup without delegations so owner owns all roles without conflicts
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);

    // First, assign the permission
    owner_team
        .assign_role_management_permission(
            roles.operator().id,
            roles.admin().id,
            text!("CanAssignRole"),
        )
        .await
        .context("Failed to assign role management permission")?;

    // Add admin and operator devices
    owner_team
        .add_device(devices.admin.pk.clone(), Some(roles.admin().id))
        .await?;
    owner_team
        .add_device(devices.operator.pk.clone(), None)
        .await?;
    owner_team
        .add_device(devices.membera.pk.clone(), None)
        .await?;

    // Sync admin with owner
    let admin_team = devices.admin.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?.into();
    admin_team.sync_now(owner_addr, None).await?;

    // Try to assign operator role as admin - should succeed with the permission
    admin_team
        .assign_role(devices.operator.id, roles.operator().id)
        .await
        .context("Admin should be able to assign operator role with CanAssignRole permission")?;

    // Now revoke the permission
    owner_team
        .revoke_role_management_permission(
            roles.operator().id,
            roles.admin().id,
            text!("CanAssignRole"),
        )
        .await
        .context("Failed to revoke role management permission")?;

    // Sync admin with owner again to get the revocation
    admin_team.sync_now(owner_addr, None).await?;

    // Try to assign operator role again as admin - should fail now
    match admin_team
        .assign_role(devices.membera.id, roles.operator().id)
        .await
    {
        Ok(_) => bail!("Admin should NOT be able to assign operator role after revocation"),
        Err(aranya_client::Error::Aranya(_)) => {} // Expected failure
        Err(err) => bail!("Unexpected error when trying to assign after revocation: {err:?}"),
    }

    Ok(())
}

/// Test that a role cannot be assigned if a role is already assigned.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_cannot_assign_role_twice() -> Result<()> {
    let mut devices = DevicesCtx::new("test_cannot_assign_role_twice").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    let owner_team = devices.owner.client.team(team_id);

    let r = owner_team
        .assign_role(devices.membera.id, roles.operator().id)
        .await;

    assert!(matches!(r, Err(aranya_client::Error::Aranya(_))));

    Ok(())
}

/// Deleting a label requires `DeleteLabel` and label management rights.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_delete_label_requires_permission() -> Result<()> {
    let mut devices = DevicesCtx::new("test_delete_label_requires_permission").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    let owner_team = devices.owner.client.team(team_id);
    let operator_team = devices.operator.client.team(team_id);

    let label = owner_team
        .create_label(text!("delete-label-guard"), roles.owner().id)
        .await?;

    operator_team
        .sync_now(devices.owner.aranya_local_addr().await?.into(), None)
        .await
        .context("operator unable to sync owner state")?;

    match operator_team.delete_label(label).await {
        Ok(_) => bail!("expected delete_label without permission to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected delete_label error: {err:?}"),
    }

    Ok(())
}

/// Devices cannot assign labels to themselves.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_assign_label_to_device_self_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_assign_label_to_device_self_rejected").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_id = devices.owner.id;
    let owner_team = devices.owner.client.team(team_id);

    let label = owner_team
        .create_label(text!("device-self-label"), roles.owner().id)
        .await?;

    match owner_team
        .device(owner_id)
        .assign_label(label, ChanOp::SendRecv)
        .await
    {
        Ok(_) => bail!("expected assigning label to self to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected assign_label error: {err:?}"),
    }

    Ok(())
}

/// Ensures the last owner cannot be removed by another device.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_admin_cannot_remove_last_owner() -> Result<()> {
    let mut devices = DevicesCtx::new("test_admin_cannot_remove_last_owner").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    let admin_team = devices.admin.client.team(team_id);
    match admin_team.remove_device(devices.owner.id).await {
        Ok(_) => bail!("expected removing the final owner to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected remove_device error: {err:?}"),
    }

    Ok(())
}

/// Confirms that managing-role changes require an explicit permission grant.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_role_owner_change_requires_permission() -> Result<()> {
    let mut devices = DevicesCtx::new("test_role_owner_change_requires_permission").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    let owner_team = devices.owner.client.team(team_id);
    owner_team
        .add_role_owner(roles.member().id, roles.admin().id)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?.into();
    let admin_team = devices.admin.client.team(team_id);
    admin_team.sync_now(owner_addr, None).await?;

    match admin_team
        .add_role_owner(roles.member().id, roles.operator().id)
        .await
    {
        Ok(_) => bail!("expected add_role_owner to require additional permission"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected add_role_owner error: {err:?}"),
    }

    Ok(())
}

/// Duplicate role-owner entries must be rejected before attempting storage writes.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_role_owner_duplicate_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_role_owner_duplicate_rejected").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    owner_team
        .add_role_owner(roles.member().id, roles.admin().id)
        .await?;

    match owner_team
        .add_role_owner(roles.member().id, roles.admin().id)
        .await
    {
        Ok(_) => bail!("expected duplicate role owner addition to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected add_role_owner duplicate error: {err:?}"),
    }

    Ok(())
}

/// Removing a non-existent owning role should produce a policy failure, not a runtime error.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_role_owner_missing_entry() -> Result<()> {
    let mut devices = DevicesCtx::new("test_remove_role_owner_missing_entry").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team
        .remove_role_owner(roles.member().id, roles.operator().id)
        .await
    {
        Ok(_) => bail!("expected removing absent role owner to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected remove_role_owner error: {err:?}"),
    }

    Ok(())
}

/// Tests that role_owners returns the correct owning roles.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_role_owners_query() -> Result<()> {
    let mut devices = DevicesCtx::new("test_role_owners_query").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    let owner_team = devices.owner.client.team(team_id);

    // Initially, member role should have owner role as its owner (from setup_default_roles)
    let initial_owners = owner_team.role_owners(roles.member().id).await?;
    let initial_owners_vec: Vec<_> = initial_owners.iter().collect();
    assert_eq!(
        initial_owners_vec.len(),
        1,
        "member role should initially have one owner from setup"
    );
    assert_eq!(
        initial_owners_vec[0].id,
        roles.owner().id,
        "owner role should initially own member role"
    );

    // Add admin as owner of member role
    owner_team
        .add_role_owner(roles.member().id, roles.admin().id)
        .await?;

    // Query owners again - should now show both owner and admin roles
    let owners_after_add = owner_team.role_owners(roles.member().id).await?;
    let owners_after_add_vec: Vec<_> = owners_after_add.iter().collect();
    assert_eq!(
        owners_after_add_vec.len(),
        2,
        "member role should have two owners after adding admin"
    );

    // Check both owners are present (order not guaranteed)
    let owner_ids_after_add: Vec<_> = owners_after_add_vec.iter().map(|r| r.id).collect();
    assert!(
        owner_ids_after_add.contains(&roles.owner().id),
        "owner should still be owner"
    );
    assert!(
        owner_ids_after_add.contains(&roles.admin().id),
        "admin should now be owner"
    );

    // Add operator as another owner of member role
    owner_team
        .add_role_owner(roles.member().id, roles.operator().id)
        .await?;

    // Query owners again - should now show all three: owner, admin, and operator
    let owners_after_second_add = owner_team.role_owners(roles.member().id).await?;
    let owners_after_second_add_vec: Vec<_> = owners_after_second_add.iter().collect();
    assert_eq!(
        owners_after_second_add_vec.len(),
        3,
        "member role should have three owners"
    );

    // Check all owners are present (order not guaranteed)
    let owner_ids: Vec<_> = owners_after_second_add_vec.iter().map(|r| r.id).collect();
    assert!(
        owner_ids.contains(&roles.owner().id),
        "owner should still be owner"
    );
    assert!(
        owner_ids.contains(&roles.admin().id),
        "admin should still be owner"
    );
    assert!(
        owner_ids.contains(&roles.operator().id),
        "operator should now be owner"
    );

    // Remove admin as owner
    owner_team
        .remove_role_owner(roles.member().id, roles.admin().id)
        .await?;

    // Query owners again - should now show owner and operator
    let owners_after_remove = owner_team.role_owners(roles.member().id).await?;
    let owners_after_remove_vec: Vec<_> = owners_after_remove.iter().collect();
    assert_eq!(
        owners_after_remove_vec.len(),
        2,
        "member role should have two owners after removing admin"
    );

    let owner_ids_after_remove: Vec<_> = owners_after_remove_vec.iter().map(|r| r.id).collect();
    assert!(
        owner_ids_after_remove.contains(&roles.owner().id),
        "owner should still be owner"
    );
    assert!(
        owner_ids_after_remove.contains(&roles.operator().id),
        "operator should still be owner"
    );
    assert!(
        !owner_ids_after_remove.contains(&roles.admin().id),
        "admin should no longer be owner"
    );

    // Verify other clients can also query role owners after sync
    let owner_addr = devices.owner.aranya_local_addr().await?.into();
    let admin_team = devices.admin.client.team(team_id);
    admin_team.sync_now(owner_addr, None).await?;

    let admin_view_owners = admin_team.role_owners(roles.member().id).await?;
    let admin_view_owners_vec: Vec<_> = admin_view_owners.iter().collect();
    assert_eq!(
        admin_view_owners_vec.len(),
        2,
        "admin client should see two owners"
    );

    let admin_view_owner_ids: Vec<_> = admin_view_owners_vec.iter().map(|r| r.id).collect();
    assert!(
        admin_view_owner_ids.contains(&roles.owner().id),
        "admin client should see owner as owner"
    );
    assert!(
        admin_view_owner_ids.contains(&roles.operator().id),
        "admin client should see operator as owner"
    );

    Ok(())
}
