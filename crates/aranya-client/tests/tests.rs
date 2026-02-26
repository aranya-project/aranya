//! Integration tests for the user library.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

mod common;

use std::{ptr, time::Duration};

use anyhow::{bail, Context, Result};
use aranya_client::{
    client::{ChanOp, Permission, RoleId, RoleManagementPermission},
    config::{CreateTeamConfig, HelloSubscriptionConfig, SyncPeerConfig},
    AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
use aranya_daemon_api::text;
use test_log::test;
use tracing::{debug, info};

use crate::common::{sleep, DeviceCtx, DevicesCtx, SLEEP_INTERVAL};

/// Tests getting keybundle and device ID.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_get_keybundle_device_id() -> Result<()> {
    let devices = DevicesCtx::new("test_get_keybundle_device_id").await?;

    // Note: get_device_id() and get_key_bundle() are already invoked in `DevicesCtx::new()`.
    // This test makes sure we don't accidentally break the API from a backward compatibility standpoint.
    assert_eq!(
        devices.owner.client.get_device_id().await?,
        devices.owner.id
    );
    assert_eq!(
        devices.owner.client.get_public_key_bundle().await?,
        devices.owner.pk
    );

    Ok(())
}

/// Tests generating random numbers with the aranya client.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_client_rand() -> Result<()> {
    let devices = DevicesCtx::new("test_get_keybundle_device_id").await?;

    let mut buf1 = vec![0u8; 100];
    devices.owner.client.rand(&mut buf1).await;
    let mut buf2 = vec![0u8; 100];
    devices.owner.client.rand(&mut buf2).await;

    // Randomly generated numbers should never match.
    assert_ne!(buf1, buf2);

    Ok(())
}

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
        .device(devices.admin.id)
        .assign_role(roles.admin().id)
        .await
        .context("owner unable to assign admin role")?;

    // Now, we try to assign a role using the admin, which is expected to fail.
    let err = admin
        .device(devices.operator.id)
        .assign_role(roles.operator().id)
        .await
        .expect_err("admin has not synced yet, role assignment should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

    // Let's sync immediately, which will propagate the role change.
    admin
        .sync_now(owner_addr, None)
        .await
        .context("admin unable to sync with owner")?;

    // Now we should be able to successfully assign a role.
    admin
        .device(devices.operator.id)
        .assign_role(roles.operator().id)
        .await
        .context("admin unable to assign role to operator")?;

    Ok(())
}

/// Tests adding/removing sync peers.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_remove_sync_peers() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_remove_sync_peers").await?;
    let team_id = devices
        .create_and_add_team()
        .await
        .expect("expected to create team");

    // create default roles
    let roles = devices.setup_default_roles(team_id).await?;

    // add all sync peers with sync intervals.
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
    // We're sleeping here rather than syncing via `sync_now()` to test periodic sync functionality.
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

    // Remove sync peers.
    for device in devices.devices() {
        for peer in devices.devices() {
            if ptr::eq(device, peer) {
                continue;
            }
            device
                .client
                .team(team_id)
                .remove_sync_peer(peer.aranya_local_addr().await?)
                .await?;
        }
    }

    let owner_addr = devices.owner.aranya_local_addr().await?;
    membera_team.remove_sync_peer(owner_addr).await?;
    let membera_addr = devices.membera.aranya_local_addr().await?;
    owner_team.remove_sync_peer(membera_addr).await?;

    // Create another label.
    owner_team
        .create_label(text!("label2"), roles.owner().id)
        .await?;

    // Wait for syncing.
    sleep(SLEEP_INTERVAL).await;

    // Verify device doesn't see label after sync peer is removed.
    let labels_after_removing_sync_peer = membera_team.labels().await?;
    assert_eq!(labels_after_removing_sync_peer.iter().count(), 1);

    Ok(())
}

/// Tests creating/assigning/revoking a role.
/// Verifies query indicates correct role assignment status.
/// Verifies device is only allowed to perform operation when role with permission is assigned to it.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_role_create_assign_revoke() -> Result<()> {
    // Set up our team context so we can run the test.
    let devices = DevicesCtx::new("test_role_create_assign_revoke").await?;

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
    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Query to show admin role exists.
    let roles_on_team = owner_team.roles().await?;
    assert_eq!(roles_on_team.iter().count(), 4);
    let _admin_role = roles_on_team
        .iter()
        .find(|r| r.name == "admin")
        .ok_or_else(|| anyhow::anyhow!("no admin role"))?
        .clone();

    // Show that admin cannot create a label.
    admin_team
        .create_label(text!("label1"), roles.admin().id)
        .await
        .expect_err("expected label creation to fail");

    // Add the admin as a new device.
    info!("adding admin to team");
    owner.add_device(devices.admin.pk.clone(), None).await?;

    // Add team to admin device.
    let admin_seed = owner
        .encrypt_psk_seed_for_peer(devices.admin.pk.encryption())
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

    // Admin sync with owner.
    admin_team
        .sync_now(owner_addr, None)
        .await
        .context("admin unable to sync with owner")?;

    // Show that admin cannot create a label.
    admin_team
        .create_label(text!("label1"), roles.admin().id)
        .await
        .expect_err("expected label creation to fail");

    // Give the admin its role.
    owner
        .device(devices.admin.id)
        .assign_role(roles.admin().id)
        .await?;

    // Admin sync with owner.
    admin_team
        .sync_now(owner_addr, None)
        .await
        .context("admin unable to sync with owner")?;

    // Query to show admin role is assigned to admin device.
    let admin_role = admin_team
        .device(devices.admin.id)
        .role()
        .await?
        .expect("expected admin device to have role assigned to it");
    assert_eq!(admin_role.name, text!("admin"));

    // Create label.
    let label1 = admin_team
        .create_label(text!("label1"), roles.admin().id)
        .await
        .expect("expected admin to create label");

    // Confirm there is 1 label on team.
    assert_eq!(admin_team.labels().await?.iter().count(), 1);

    // Confirm created label exists.
    assert!(admin_team.label(label1).await?.is_some());

    // Revoke role.
    owner
        .device(devices.admin.id)
        .revoke_role(roles.admin().id)
        .await?;

    // Admin sync with owner.
    admin_team
        .sync_now(owner_addr, None)
        .await
        .context("admin unable to sync with owner")?;

    // Query to show admin role is no longer assigned to admin device.
    if admin_team.device(devices.admin.id).role().await?.is_some() {
        bail!("did not expect role to be assigned to admin device");
    }

    // Show that admin cannot create a label.
    admin_team
        .create_label(text!("label1"), roles.admin().id)
        .await
        .expect_err("expected label creation to fail");

    // TODO: issue#575 show operation fails after delete_role() (after it is added to the API).

    Ok(())
}

/// Tests that a role can be changed after it has been assigned to a device.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_role_change() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_role_change").await?;

    // Create the initial team, and get our TeamId and seed.
    let team_id = devices.create_and_add_team().await?;

    let roles = devices
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;
    devices.add_all_device_roles(team_id, &roles).await?;

    let owner = devices.owner.client.team(team_id);

    // Assign operator role to membera.
    owner
        .device(devices.membera.id)
        .change_role(roles.member().id, roles.operator().id)
        .await
        .expect("expected to change role from member to operator");

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
        .sync_now(team.owner.aranya_local_addr().await?, None)
        .await
        .context("admin unable to sync with owner")?;

    admin
        .add_device(team.operator.pk.clone(), Some(roles.operator().id))
        .await
        .context("admin should be able to add operator to team")?;

    operator
        .sync_now(team.admin.aranya_local_addr().await?, None)
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
            .sync_now(team.admin.aranya_local_addr().await?, None)
            .await
            .context("operator unable to sync with admin")?;
        operator
            .device(device_id)
            .assign_role(roles.member().id)
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
        .sync_now(devices.owner.aranya_local_addr().await?, None)
        .await
        .context("admin unable to sync with owner")?;

    let err = admin_team
        .add_device(devices.membera.pk.clone(), Some(roles.member().id))
        .await
        .expect_err("add_device with initial role requires delegation");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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

    owner.device(devices.membera.id).remove_from_team().await?;
    assert_eq!(owner.devices().await?.iter().count(), 4);

    owner.device(devices.memberb.id).remove_from_team().await?;
    assert_eq!(owner.devices().await?.iter().count(), 3);

    owner.device(devices.operator.id).remove_from_team().await?;
    assert_eq!(owner.devices().await?.iter().count(), 2);

    owner.device(devices.admin.id).remove_from_team().await?;
    assert_eq!(owner.devices().await?.iter().count(), 1);

    owner
        .device(devices.owner.id)
        .remove_from_team()
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
    let owner_addr = devices.owner.aranya_local_addr().await?;
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
    let keybundle = memberb
        .device(devices.membera.id)
        .public_key_bundle()
        .await?;
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

    // Query role assigned to a device.
    assert_eq!(
        roles.member().id,
        memberb
            .device(devices.memberb.id)
            .role()
            .await?
            .expect("expected role")
            .id
    );

    // Query all the roles on the team.
    let membera_team = devices.membera.client.team(team_id);
    assert_eq!(membera_team.roles().await?.iter().count(), 4);

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
        .device(devices.admin.id)
        .assign_role(roles.admin().id)
        .await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id);
        let err = admin
            .sync_now(owner_addr, None)
            .await
            .expect_err("syncing should fail before add_team()");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

        // Now, we try to assign a role using the admin, which is expected to fail.
        let err = admin
            .device(devices.operator.id)
            .assign_role(roles.operator().id)
            .await
            .expect_err("role assignment should fail before add_team()");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");
    }

    let admin_seed = owner
        .encrypt_psk_seed_for_peer(devices.admin.pk.encryption())
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
        admin.sync_now(owner_addr, None).await?;

        // Now we should be able to successfully assign a role.
        admin
            .device(devices.operator.id)
            .assign_role(roles.operator().id)
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
            .device(devices.admin.id)
            .assign_role(roles.admin().id)
            .await?;

        admin
            .sync_now(devices.owner.aranya_local_addr().await?, None)
            .await?;

        // We should be able to successfully assign a role.
        admin
            .device(devices.operator.id)
            .assign_role(roles.operator().id)
            .await?;
    }

    // Remove the team from the admin's local storage
    devices.admin.client.remove_team(team_id).await?;

    {
        let admin = devices.admin.client.team(team_id);

        // Role assignment should fail
        let err = admin
            .device(devices.operator.id)
            .assign_role(roles.member().id)
            .await
            .expect_err("role assignment should fail after team removal");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");
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
        .device(devices.admin.id)
        .assign_role(roles1.admin().id)
        .await?;

    // Add the admin as a new device.
    info!("adding admin to team2");
    team2.add_device(devices.admin.pk.clone(), None).await?;

    // Add the operator as a new device.
    info!("adding operator to team2");
    team2.add_device(devices.operator.pk.clone(), None).await?;

    // Give the admin its role.
    team2
        .device(devices.admin.id)
        .assign_role(roles2.admin().id)
        .await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id1);
        let err = admin
            .sync_now(owner_addr, None)
            .await
            .expect_err("syncing team1 should fail before add_team()");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

        // Now, we try to assign a role using the admin, which is expected to fail.
        let err = admin
            .device(devices.operator.id)
            .assign_role(roles1.operator().id)
            .await
            .expect_err("role assignment on team1 should fail before add_team()");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");
    }

    let admin_seed1 = team1
        .encrypt_psk_seed_for_peer(devices.admin.pk.encryption())
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
    admin1.sync_now(owner_addr, None).await?;

    // Now we should be able to successfully assign a role.
    admin1
        .device(devices.operator.id)
        .assign_role(roles1.operator().id)
        .await
        .context("Assigning a role should not fail here!")?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id2);
        let err = admin
            .sync_now(owner_addr, None)
            .await
            .expect_err("syncing team2 should fail before add_team()");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

        // Now, we try to assign a role using the admin, which is expected to fail.
        let err = admin
            .device(devices.operator.id)
            .assign_role(roles2.operator().id)
            .await
            .expect_err("role assignment on team2 should fail before add_team()");
        assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");
    }

    let admin_seed2 = team2
        .encrypt_psk_seed_for_peer(devices.admin.pk.encryption())
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
    admin2.sync_now(owner_addr, None).await?;

    // Now we should be able to successfully assign a role.
    admin2
        .device(devices.operator.id)
        .assign_role(roles2.operator().id)
        .await
        .context("Assigning a role should not fail here!")?;

    Ok(())
}

/// Tests hello subscription functionality by demonstrating that devices can subscribe
/// to hello notifications from peers and automatically sync when receiving notifications.
#[test(tokio::test(flavor = "multi_thread"))]
#[cfg(feature = "preview")]
async fn test_hello_subscription() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_hello_subscription").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices.create_and_add_team().await?;

    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    // Grab addresses for testing
    let admin_addr = devices.admin.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let membera_team = devices.membera.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    let sync_config = SyncPeerConfig::builder()
        .sync_now(false)
        .sync_on_hello(true)
        .build()?;

    membera_team.add_sync_peer(admin_addr, sync_config).await?;
    info!("membera added admin as sync peer with sync_on_hello=true");

    // MemberA subscribes to hello notifications from Admin
    // Use a long periodic_interval to ensure sync is triggered by graph change, not periodic send
    membera_team
        .sync_hello_subscribe(
            admin_addr,
            HelloSubscriptionConfig::builder()
                .periodic_interval(Duration::from_secs(60))
                .build()?,
        )
        .await?;
    info!("membera subscribed to hello notifications from admin");

    // Before the action, verify that MemberA doesn't know about any labels created by admin
    // (This will be our way to test if sync worked)
    info!("verifying initial state - membera should not see any labels created by admin");
    let initial_labels = membera_team.labels().await?;
    let initial_label_count = initial_labels.iter().count();
    info!(
        "initial label count as seen by membera: {}",
        initial_label_count
    );

    // Admin performs an action that will update their graph - create a label
    // (admin has permission to create labels)
    info!("admin creating a test label");
    let test_label = admin_team
        .create_label(
            aranya_daemon_api::text!("sync_hello_test_label"),
            roles.admin().id,
        )
        .await?;
    info!("admin created test label: {:?}", test_label);

    // Wait for hello message to be sent and sync to be triggered
    // The hello message should be sent, membera should receive it,
    // check that the command doesn't exist locally, and trigger a sync
    info!("waiting for hello message and automatic sync...");

    // Poll every 100ms for up to 10 seconds for the label count to increase
    let poll_start = std::time::Instant::now();
    let poll_timeout = Duration::from_millis(10_000);
    let poll_interval = Duration::from_millis(100);

    let final_labels = loop {
        let current_labels = membera_team.labels().await?;
        let current_count = current_labels.iter().count();

        if current_count > initial_label_count {
            info!(
                "sync detected - label count increased from {} to {} after {:?}",
                initial_label_count,
                current_count,
                poll_start.elapsed()
            );
            break current_labels;
        }

        if poll_start.elapsed() >= poll_timeout {
            bail!(
                "Sync on hello failed: timeout after {:?} - expected label count to increase from {} but it remained at {}",
                poll_timeout,
                initial_label_count,
                current_count
            );
        }

        sleep(poll_interval).await;
    };

    // Verify that the specific label created by admin is visible
    let label_exists = final_labels
        .iter()
        .any(|label| label.name.as_str() == "sync_hello_test_label");

    if !label_exists {
        bail!("Sync on hello failed: the test label created by admin is not visible to membera");
    }

    info!("sync_on_hello test succeeded - membera automatically synced after receiving hello notification");

    // Test basic subscription/unsubscription functionality for completeness
    info!("testing basic subscription functionality");

    let owner_addr = devices.owner.aranya_local_addr().await?;
    let operator_team = devices.operator.client.team(team_id);

    // Admin subscribes to hello notifications from Owner
    admin_team
        .sync_hello_subscribe(owner_addr, HelloSubscriptionConfig::default())
        .await?;
    info!("admin subscribed to hello notifications from owner");

    // Test multiple subscriptions
    operator_team
        .sync_hello_subscribe(owner_addr, HelloSubscriptionConfig::default())
        .await?;
    operator_team
        .sync_hello_subscribe(admin_addr, HelloSubscriptionConfig::default())
        .await?;
    info!("operator subscribed to both owner and admin");

    // Test unsubscribing
    admin_team.sync_hello_unsubscribe(owner_addr).await?;
    operator_team.sync_hello_unsubscribe(owner_addr).await?;
    operator_team.sync_hello_unsubscribe(admin_addr).await?;
    membera_team.sync_hello_unsubscribe(admin_addr).await?;
    info!("all devices unsubscribed");

    // Test edge cases
    admin_team
        .sync_hello_subscribe(owner_addr, HelloSubscriptionConfig::default())
        .await?;
    admin_team.sync_hello_unsubscribe(owner_addr).await?;
    info!("tested immediate subscribe/unsubscribe");

    // Test unsubscribing from non-subscribed peer
    let memberb_addr = devices.memberb.aranya_local_addr().await?;
    admin_team.sync_hello_unsubscribe(memberb_addr).await?;
    info!("tested unsubscribing from non-subscribed peer");

    Ok(())
}

/// Tests that schedule_delay parameter in sync_hello_subscribe works correctly.
/// Verifies that with high schedule_delay, only graph-change-triggered notifications occur,
/// while with low schedule_delay, scheduled periodic sends pick up all pending changes.
#[test(tokio::test(flavor = "multi_thread"))]
#[cfg(feature = "preview")]
async fn test_hello_subscription_schedule_delay() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_hello_subscription_schedule_delay").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices.create_and_add_team().await?;

    let roles = devices.setup_default_roles(team_id).await?;
    devices.add_all_device_roles(team_id, &roles).await?;

    // Grab addresses for testing
    let admin_addr = devices.admin.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let membera_team = devices.membera.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    let sync_config = SyncPeerConfig::builder()
        .sync_now(false)
        .sync_on_hello(true)
        .build()?;

    membera_team.add_sync_peer(admin_addr, sync_config).await?;
    info!("membera added admin as sync peer with sync_on_hello=true");

    // Phase 1: Test with high schedule_delay (60s) - should only see first graph change
    info!("Phase 1: Testing with high schedule_delay (60s) and high graph_change_debounce (60s)");
    membera_team
        .sync_hello_subscribe(
            admin_addr,
            HelloSubscriptionConfig::builder()
                .graph_change_debounce(Duration::from_secs(60))
                .periodic_interval(Duration::from_secs(60))
                .build()?,
        )
        .await?;
    info!("membera subscribed to hello notifications from admin with high schedule_delay");

    // Before the action, verify that MemberA doesn't know about any labels created by admin
    info!("verifying initial state - membera should not see any labels created by admin");
    let initial_labels = membera_team.labels().await?;
    let initial_label_count = initial_labels.iter().count();
    info!(
        "initial label count as seen by membera: {}",
        initial_label_count
    );

    // Admin creates first label
    info!("admin creating first test label");
    let test_label_1 = admin_team
        .create_label(
            aranya_daemon_api::text!("schedule_test_label_1"),
            roles.admin().id,
        )
        .await?;
    info!("admin created first test label: {:?}", test_label_1);

    // Wait for first label to be seen (should be sent via graph change notification)
    info!("waiting for first label to be seen via graph change notification...");
    let poll_start = std::time::Instant::now();
    let poll_timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(100);

    let first_label_seen = loop {
        let current_labels = membera_team.labels().await?;
        let current_count = current_labels.iter().count();

        if current_count > initial_label_count {
            let label_exists = current_labels
                .iter()
                .any(|label| label.name.as_str() == "schedule_test_label_1");
            if label_exists {
                info!(
                    "first label seen after {:?} - label count increased from {} to {}",
                    poll_start.elapsed(),
                    initial_label_count,
                    current_count
                );
                break true;
            }
        }

        if poll_start.elapsed() >= poll_timeout {
            bail!(
                "First label not seen: timeout after {:?} - expected label count to increase from {} but it remained at {}",
                poll_timeout,
                initial_label_count,
                current_count
            );
        }

        sleep(poll_interval).await;
    };

    assert!(first_label_seen, "First label should have been seen");

    // Admin creates second label
    info!("admin creating second test label");
    let test_label_2 = admin_team
        .create_label(
            aranya_daemon_api::text!("schedule_test_label_2"),
            roles.admin().id,
        )
        .await?;
    info!("admin created second test label: {:?}", test_label_2);

    // Wait a short time and verify second label is NOT seen (rate-limited and schedule hasn't fired)
    info!("waiting briefly to confirm second label is not seen (rate-limited)...");
    sleep(Duration::from_secs(2)).await;

    let current_labels = membera_team.labels().await?;
    let current_count = current_labels.iter().count();
    let second_label_exists = current_labels
        .iter()
        .any(|label| label.name.as_str() == "schedule_test_label_2");

    if second_label_exists {
        bail!(
            "Second label should not have been seen yet (rate-limited) - found {} labels, expected {}",
            current_count,
            initial_label_count + 1
        );
    }

    info!("confirmed second label not seen - rate limiting working");

    // Phase 2: Test with low schedule_delay (10ms) - should see all labels
    info!("Phase 2: Testing with low schedule_delay (10ms)");
    membera_team.sync_hello_unsubscribe(admin_addr).await?;
    info!("membera unsubscribed from admin");

    membera_team
        .sync_hello_subscribe(
            admin_addr,
            HelloSubscriptionConfig::builder()
                .graph_change_debounce(Duration::from_secs(60))
                .periodic_interval(Duration::from_millis(10))
                .build()?,
        )
        .await?;
    info!("membera subscribed to hello notifications from admin with low periodic_interval");

    // Wait for both labels to be seen (scheduled send should pick up pending changes)
    info!("waiting for both labels to be seen via scheduled periodic send...");
    let poll_start = std::time::Instant::now();
    let poll_timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(100);

    let both_labels_seen = loop {
        let current_labels = membera_team.labels().await?;
        let current_count = current_labels.iter().count();

        if current_count >= initial_label_count + 2 {
            let label1_exists = current_labels
                .iter()
                .any(|label| label.name.as_str() == "schedule_test_label_1");
            let label2_exists = current_labels
                .iter()
                .any(|label| label.name.as_str() == "schedule_test_label_2");

            if label1_exists && label2_exists {
                info!(
                    "both labels seen after {:?} - label count: {} (expected at least {})",
                    poll_start.elapsed(),
                    current_count,
                    initial_label_count + 2
                );
                break true;
            }
        }

        if poll_start.elapsed() >= poll_timeout {
            let current_labels = membera_team.labels().await?;
            let label1_exists = current_labels
                .iter()
                .any(|label| label.name.as_str() == "schedule_test_label_1");
            let label2_exists = current_labels
                .iter()
                .any(|label| label.name.as_str() == "schedule_test_label_2");

            bail!(
                "Both labels not seen: timeout after {:?} - label1: {}, label2: {}, count: {} (expected at least {})",
                poll_timeout,
                label1_exists,
                label2_exists,
                current_labels.iter().count(),
                initial_label_count + 2
            );
        }

        sleep(poll_interval).await;
    };

    assert!(both_labels_seen, "Both labels should have been seen");

    // Cleanup
    membera_team.sync_hello_unsubscribe(admin_addr).await?;
    info!("cleanup: unsubscribed membera from admin");

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
    let err = owner_team
        .setup_default_roles(roles.owner().id)
        .await
        .expect_err("setup_default_roles should only succeed once");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

    Ok(())
}

/// Verifies that the managing role supplied to setup_default_roles must exist.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_setup_default_roles_rejects_unknown_owner() -> Result<()> {
    let mut devices = DevicesCtx::new("test_setup_default_roles_rejects_unknown_owner").await?;

    let team_id = devices.create_and_add_team().await?;
    let owner_team = devices.owner.client.team(team_id);
    let bogus_role = RoleId::from([0x55; 32]);

    let err = owner_team
        .setup_default_roles(bogus_role)
        .await
        .expect_err("setup_default_roles should reject unknown owner role");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

    Ok(())
}

/// Tests that role creation works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_create_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_create_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let owner_role = owner_team
        .roles()
        .await?
        .into_iter()
        .find(|r| r.name == "owner")
        .expect("no owner role!?");

    let test_role = owner_team
        .create_role(text!("test_role"), owner_role.id)
        .await
        .expect("expected to create role");

    owner_team
        .roles()
        .await?
        .into_iter()
        .find(|r| r.name == "test_role")
        .expect("no test role found");

    // Set up another device, sync it, and make sure they can see the
    // role.
    owner_team
        .add_device(devices.admin.pk.clone(), Some(roles.admin().id))
        .await?;
    let admin_team = devices.admin.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    let test_role2 = admin_team
        .roles()
        .await?
        .into_iter()
        .find(|r| r.name == "test_role")
        .expect("no test role found");
    assert_eq!(test_role, test_role2);

    Ok(())
}

/// Tests that role creation works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_perm_to_created_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_perm_to_created_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let owner_team = devices.owner.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;
    let owner_role = owner_team
        .roles()
        .await?
        .into_iter()
        .find(|r| r.name == "owner")
        .expect("no owner role!?");

    // Create a custom admin type role
    let admin_role = owner_team
        .create_role(text!("admin"), owner_role.id)
        .await?;
    owner_team
        .add_perm_to_role(admin_role.id, Permission::AddDevice)
        .await
        .expect("expected to assign AddDevice to admin");

    // Add our admin with this role
    owner_team
        .add_device(devices.admin.pk, Some(admin_role.id))
        .await
        .expect("expected to add admin with role");

    // Sync the admin and test that they can add the operator
    let admin_team = devices.admin.client.team(team_id);
    admin_team.sync_now(owner_addr, None).await?;

    admin_team
        .add_device(devices.operator.pk, None)
        .await
        .expect("admin should be able to add operator");

    Ok(())
}

/// Tests that privilege escalation attempt is rejected.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_privilege_escalation_rejected() -> Result<()> {
    let team_name = "test_privilege_escalation_rejected";
    let mut devices = DevicesCtx::new(team_name).await?;

    // Owner creates the team.
    let team_id = devices.create_and_add_team().await?;
    let owner_team = devices.owner.client.team(team_id);
    let owner_role = owner_team
        .roles()
        .await?
        .into_iter()
        .find(|r| r.name == "owner")
        .ok_or_else(|| anyhow::anyhow!("no owner role!?"))?;

    // Initialize malicious device on team.
    let work_dir = tempfile::tempdir()?;
    let work_dir_path = work_dir.path();
    let device = DeviceCtx::new(team_name, "malicious", work_dir_path.join("malicious")).await?;
    owner_team.add_device(device.pk.clone(), None).await?;
    let device_seed = owner_team
        .encrypt_psk_seed_for_peer(device.pk.encryption())
        .await?;
    device
        .client
        .add_team({
            AddTeamConfig::builder()
                .team_id(team_id)
                .quic_sync(
                    AddTeamQuicSyncConfig::builder()
                        .wrapped_seed(&device_seed)?
                        .build()?,
                )
                .build()?
        })
        .await?;

    // Owner creates malicious role on team:
    let role = owner_team
        .create_role(text!("malicious_role"), owner_role.id)
        .await
        .expect("expected to create malicious role");

    // Owner only allows role to create new roles.
    owner_team
        .add_perm_to_role(role.id, Permission::CreateRole)
        .await?;

    // Owner assigns role to malicious device.
    owner_team.device(device.id).assign_role(role.id).await?;

    // Malicious device syncs with owner.
    let device_team = device.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;
    device_team.sync_now(owner_addr, None).await?;

    // Malicious device creates a new target role (which it maintains control of).
    let target_role = device_team
        .create_role(text!("target_role"), role.id)
        .await
        .expect("unable to create target role");

    // Malicious device attempts to grant target role a permission it does not have: e.g. CanUseAfc
    // This should be rejected, which indicates a privilege escalation attempt will be rejected.
    device_team
        .add_perm_to_role(target_role.id, Permission::CanUseAfc)
        .await
        .expect_err("expected privilege escalation attempt to fail");

    Ok(())
}

/// Tests that role creation works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_perm_from_default_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_perm_to_created_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Add admin with admin role
    owner_team
        .add_device(devices.admin.pk, Some(roles.admin().id))
        .await
        .expect("expected to add admin with role");

    owner_team
        .remove_perm_from_role(roles.admin().id, Permission::AddDevice)
        .await
        .expect("expected to remove AddDevice from admin");

    // Sync the admin
    let admin_team = devices.admin.client.team(team_id);
    admin_team.sync_now(owner_addr, None).await?;

    // Admin cannot add operator
    admin_team
        .add_device(devices.operator.pk, None)
        .await
        .expect_err("admin should not be able to add operator");

    Ok(())
}

/// Tests that role deletion works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_delete_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_delete_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices
        .setup_default_roles_without_delegation(team_id)
        .await?;

    let owner_team = devices.owner.client.team(team_id);
    owner_team
        .delete_role(roles.member().id)
        .await
        .expect("expected to delete role");

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
    let err = owner_team
        .device(devices.owner.id)
        .assign_role(roles.owner().id)
        .await
        .expect_err("assigning role to self should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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
    let err = owner_team
        .device(devices.owner.id)
        .revoke_role(roles.owner().id)
        .await
        .expect_err("sole owner cannot revoke its own role");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    let err = admin_team
        .device(devices.membera.id)
        .assign_role(roles.member().id)
        .await
        .expect_err("assigning role without delegation should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    let err = admin_team
        .assign_role_management_permission(
            roles.member().id,
            roles.operator().id,
            RoleManagementPermission::CanAssignRole,
        )
        .await
        .expect_err("assigning management perm without ownership should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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
            RoleManagementPermission::CanAssignRole,
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
    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    // Try to assign operator role as admin - should succeed with the permission
    admin_team
        .device(devices.operator.id)
        .assign_role(roles.operator().id)
        .await
        .context("Admin should be able to assign operator role with CanAssignRole permission")?;

    // Now revoke the permission
    owner_team
        .revoke_role_management_permission(
            roles.operator().id,
            roles.admin().id,
            RoleManagementPermission::CanAssignRole,
        )
        .await
        .context("Failed to revoke role management permission")?;

    // Sync admin with owner again to get the revocation
    admin_team.sync_now(owner_addr, None).await?;

    // Try to assign operator role again as admin - should fail now
    let err = admin_team
        .device(devices.membera.id)
        .assign_role(roles.operator().id)
        .await
        .expect_err("admin should not be able to assign role after revocation");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

    Ok(())
}

/// Confirms that role can no longer manage another role after it is removed as a role owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_role_owner_removed_permissions_revoked() -> Result<()> {
    let mut devices = DevicesCtx::new("test_role_owner_removed_permissions_revoked").await?;

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
            RoleManagementPermission::CanAssignRole,
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

    // Sync admin with owner
    let admin_team = devices.admin.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    // Try to assign operator role as admin - should succeed with the permission
    admin_team
        .device(devices.operator.id)
        .assign_role(roles.operator().id)
        .await
        .context("Admin should be able to assign operator role with CanAssignRole permission")?;

    // Add a new owner role to operator so we can remove the owner role.
    // Note: this is because there must be at least one owning role.
    owner_team
        .add_role_owner(roles.operator().id, roles.member().id)
        .await?;

    // Now remove the owner as a role owner of operator.
    owner_team
        .remove_role_owner(roles.operator().id, roles.owner().id)
        .await
        .context("Failed to remove owner as role owner from operator")?;

    // Verify owner can no longer change role management permissions of operator role.
    owner_team
        .assign_role_management_permission(
            roles.operator().id,
            roles.admin().id,
            RoleManagementPermission::CanRevokeRole,
        )
        .await
        .expect_err("expected owner role management to fail after owner role was removed");

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
        .device(devices.membera.id)
        .assign_role(roles.operator().id)
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
        .sync_now(devices.owner.aranya_local_addr().await?, None)
        .await
        .context("operator unable to sync owner state")?;

    let err = operator_team
        .delete_label(label)
        .await
        .expect_err("delete_label without permission should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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

    let err = owner_team
        .device(owner_id)
        .assign_label(label, ChanOp::SendRecv)
        .await
        .expect_err("assigning label to self should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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
    let err = admin_team
        .device(devices.owner.id)
        .remove_from_team()
        .await
        .expect_err("removing the final owner should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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

    let owner_addr = devices.owner.aranya_local_addr().await?;
    let admin_team = devices.admin.client.team(team_id);
    admin_team.sync_now(owner_addr, None).await?;

    let err = admin_team
        .add_role_owner(roles.member().id, roles.operator().id)
        .await
        .expect_err("role owner change requires permission");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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

    let err = owner_team
        .add_role_owner(roles.member().id, roles.admin().id)
        .await
        .expect_err("duplicate role owner addition should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

    Ok(())
}

/// Removing a non-existent owning role should produce a policy failure, not a runtime error.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_role_owner_missing_entry() -> Result<()> {
    let mut devices = DevicesCtx::new("test_remove_role_owner_missing_entry").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let err = owner_team
        .remove_role_owner(roles.member().id, roles.operator().id)
        .await
        .expect_err("removing absent role owner should fail");
    assert!(matches!(err, aranya_client::Error::Aranya(_)), "{err:?}");

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
    let owner_addr = devices.owner.aranya_local_addr().await?;
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
