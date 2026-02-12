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

use std::{ptr, time::Duration};

use anyhow::{bail, Context, Result};
use aranya_client::{
    client::{ChanOp, Permission},
    config::{CreateTeamConfig, HelloSubscriptionConfig, SyncPeerConfig},
    AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig, ObjectId,
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
        devices.owner.client.get_key_bundle().await?,
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

/// Tests sync_now() by showing that an admin cannot perform operations until it syncs with the owner.
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
        .add_device_with_rank(devices.admin.pk.clone(), None, 799.into())
        .await
        .context("owner unable to add admin to team")?;

    // Add the operator as a new device, but don't give it a role.
    owner
        .add_device_with_rank(devices.operator.pk.clone(), None, 699.into())
        .await
        .context("owner unable to add operator to team")?;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner
        .device(devices.admin.id)
        .assign_role(roles.admin().id)
        .await
        .context("owner unable to assign admin role")?;

    // Now, we try to assign a role using the admin, which is expected to fail
    // because the admin hasn't synced yet and doesn't know about its role.
    match admin
        .device(devices.operator.id)
        .assign_role(roles.operator().id)
        .await
    {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin
        .sync_now(owner_addr, None)
        .await
        .context("admin unable to sync with owner")?;

    // Now we should be able to successfully create a label (admin has CreateLabel perm).
    admin
        .create_label_with_rank(text!("test_label"), 500.into())
        .await
        .context("admin unable to create label after sync")?;

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
        .create_label_with_rank(text!("label1"), 500.into())
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
        .create_label_with_rank(text!("label2"), 500.into())
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
    roles_on_team
        .iter()
        .find(|r| r.name == "admin")
        .ok_or_else(|| anyhow::anyhow!("no admin role"))?;

    // Show that admin cannot create a label.
    admin_team
        .create_label_with_rank(text!("label1"), 500.into())
        .await
        .expect_err("expected label creation to fail");

    // Add the admin as a new device.
    info!("adding admin to team");
    owner
        .add_device_with_rank(devices.admin.pk.clone(), None, 799.into())
        .await?;

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
        .create_label_with_rank(text!("label1"), 500.into())
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
        .create_label_with_rank(text!("label1"), 500.into())
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
        .create_label_with_rank(text!("label1"), 500.into())
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
        .add_device_with_rank(team.admin.pk.clone(), Some(roles.admin().id), 799.into())
        .await
        .context("owner should be able to add admin to team")?;

    admin
        .sync_now(team.owner.aranya_local_addr().await?, None)
        .await
        .context("admin unable to sync with owner")?;

    // Admin adds operator without initial role (admin has AddDevice but not AssignRole).
    admin
        .add_device_with_rank(team.operator.pk.clone(), None, 699.into())
        .await
        .context("admin should be able to add operator to team")?;

    // Owner assigns operator role (owner has AssignRole).
    owner
        .sync_now(team.admin.aranya_local_addr().await?, None)
        .await
        .context("owner unable to sync with admin")?;
    owner
        .device(team.operator.id)
        .assign_role(roles.operator().id)
        .await
        .context("owner should be able to assign operator role")?;

    operator
        .sync_now(team.owner.aranya_local_addr().await?, None)
        .await
        .context("operator unable to sync with owner")?;

    for (name, kb, device_id) in [
        ("membera", team.membera.pk.clone(), team.membera.id),
        ("memberb", team.memberb.pk.clone(), team.memberb.id),
    ] {
        // Admin adds members without role (admin has AddDevice but not AssignRole).
        admin
            .add_device_with_rank(kb, None, 500.into())
            .await
            .with_context(|| format!("admin should be able to add `{name}` to team"))?;
        // Operator syncs to see newly added device, then assigns member role (operator has AssignRole).
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
async fn test_add_device_with_initial_role_requires_outranking() -> Result<()> {
    let mut devices =
        DevicesCtx::new("test_add_device_with_initial_role_requires_outranking").await?;

    let team_id = devices.create_and_add_team().await?;

    let roles = devices
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Give admin the AssignRole permission so it can add devices with initial roles.
    owner_team
        .add_perm_to_role(roles.admin().id, Permission::AssignRole)
        .await
        .context("owner should be able to add AssignRole to admin")?;

    // Add admin with rank 799 (outranks member role at rank 600).
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 799.into())
        .await
        .context("owner should be able to add admin to team")?;

    admin_team
        .sync_now(devices.owner.aranya_local_addr().await?, None)
        .await
        .context("admin unable to sync with owner")?;

    // Admin (rank 799) should succeed at adding membera with member role
    // because admin outranks the member role and has both AddDevice and AssignRole perms.
    admin_team
        .add_device_with_rank(
            devices.membera.pk.clone(),
            Some(roles.member().id),
            599.into(),
        )
        .await
        .context("admin should be able to add device with member role (admin outranks member)")?;

    // Admin (rank 799) should fail when trying to add a device with the owner role
    // because admin does not outrank the owner role.
    match admin_team
        .add_device_with_rank(
            devices.memberb.pk.clone(),
            Some(roles.owner().id),
            900.into(),
        )
        .await
    {
        Ok(_) => {
            bail!("expected add_device with owner role to fail (admin does not outrank owner)")
        }
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
        .create_label_with_rank(text!("label1"), 500.into())
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
    owner
        .add_device_with_rank(devices.admin.pk.clone(), None, 799.into())
        .await?;

    // Add the operator as a new device.
    info!("adding operator to team");
    owner
        .add_device_with_rank(devices.operator.pk.clone(), None, 699.into())
        .await?;

    // Give the admin its role.
    owner
        .device(devices.admin.id)
        .assign_role(roles.admin().id)
        .await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id);
        match admin.sync_now(owner_addr, None).await {
            Ok(()) => bail!("expected syncing to fail"),
            // TODO(#299): This should fail "immediately" with an `Aranya(_)` sync error,
            // but currently the handshake timeout races with the tarpc timeout.
            Err(aranya_client::Error::Aranya(_) | aranya_client::Error::Ipc(_)) => {}
            Err(err) => return Err(err).context("unexpected error while syncing"),
        }

        // Now, we try to assign a role using the admin, which is expected to fail
        // because the admin hasn't called add_team() yet.
        match admin
            .device(devices.operator.id)
            .assign_role(roles.operator().id)
            .await
        {
            Ok(()) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
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

        // Now we should be able to successfully create a label (admin has CreateLabel perm).
        admin
            .create_label_with_rank(text!("test_label"), 500.into())
            .await
            .context("Creating a label should not fail here!")?;
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
        owner
            .add_device_with_rank(devices.operator.pk.clone(), None, 699.into())
            .await?;

        // Add the admin as a new device.
        owner
            .add_device_with_rank(devices.admin.pk.clone(), None, 799.into())
            .await?;

        // Give the admin its role.
        owner
            .device(devices.admin.id)
            .assign_role(roles.admin().id)
            .await?;

        admin
            .sync_now(devices.owner.aranya_local_addr().await?, None)
            .await?;

        // We should be able to successfully create a label (admin has CreateLabel perm).
        admin
            .create_label_with_rank(text!("test_label"), 500.into())
            .await?;
    }

    // Remove the team from the admin's local storage
    devices.admin.client.remove_team(team_id).await?;

    {
        let admin = devices.admin.client.team(team_id);

        // Label creation should fail after team removal.
        match admin
            .create_label_with_rank(text!("test_label2"), 500.into())
            .await
        {
            Ok(_) => bail!("Expected label creation to fail"),
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
    team1
        .add_device_with_rank(devices.admin.pk.clone(), None, 799.into())
        .await?;

    // Add the operator as a new device.
    info!("adding operator to team1");
    team1
        .add_device_with_rank(devices.operator.pk.clone(), None, 699.into())
        .await?;

    // Give the admin its role.
    team1
        .device(devices.admin.id)
        .assign_role(roles1.admin().id)
        .await?;

    // Add the admin as a new device.
    info!("adding admin to team2");
    team2
        .add_device_with_rank(devices.admin.pk.clone(), None, 799.into())
        .await?;

    // Add the operator as a new device.
    info!("adding operator to team2");
    team2
        .add_device_with_rank(devices.operator.pk.clone(), None, 699.into())
        .await?;

    // Give the admin its role.
    team2
        .device(devices.admin.id)
        .assign_role(roles2.admin().id)
        .await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id1);
        match admin.sync_now(owner_addr, None).await {
            Ok(()) => bail!("expected syncing to fail"),
            // TODO(#299): This should fail "immediately" with an `Aranya(_)` sync error,
            // but currently the handshake timeout races with the tarpc timeout.
            Err(aranya_client::Error::Aranya(_) | aranya_client::Error::Ipc(_)) => {}
            Err(err) => return Err(err).context("unexpected error while syncing"),
        }

        // Now, we try to assign a role using the admin, which is expected to fail
        // because add_team() hasn't been called yet.
        match admin
            .device(devices.operator.id)
            .assign_role(roles1.operator().id)
            .await
        {
            Ok(()) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
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

    // Now we should be able to successfully create a label (admin has CreateLabel perm).
    admin1
        .create_label_with_rank(text!("team1_label"), 500.into())
        .await
        .context("Creating a label should not fail here!")?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = devices.admin.client.team(team_id2);
        match admin.sync_now(owner_addr, None).await {
            Ok(()) => bail!("expected syncing to fail"),
            // TODO(#299): This should fail "immediately" with an `Aranya(_)` sync error,
            // but currently the handshake timeout races with the tarpc timeout.
            Err(aranya_client::Error::Aranya(_) | aranya_client::Error::Ipc(_)) => {}
            Err(err) => return Err(err).context("unexpected error while syncing"),
        }

        // Now, we try to assign a role using the admin, which is expected to fail
        // because add_team() hasn't been called for team2 yet.
        match admin
            .device(devices.operator.id)
            .assign_role(roles2.operator().id)
            .await
        {
            Ok(()) => bail!("Expected role assignment to fail"),
            Err(aranya_client::Error::Aranya(_)) => {}
            Err(_) => bail!("Unexpected error"),
        }
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

    // Now we should be able to successfully create a label (admin has CreateLabel perm).
    admin2
        .create_label_with_rank(text!("team2_label"), 500.into())
        .await
        .context("Creating a label should not fail here!")?;

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
        .create_label_with_rank(
            aranya_daemon_api::text!("sync_hello_test_label"),
            500.into(),
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
        .create_label_with_rank(
            aranya_daemon_api::text!("schedule_test_label_1"),
            500.into(),
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
        .create_label_with_rank(
            aranya_daemon_api::text!("schedule_test_label_2"),
            500.into(),
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
    devices
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team.setup_default_roles().await {
        Ok(_) => bail!("expected replayed setup_default_roles to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error re-running setup_default_roles: {err:?}"),
    }

    Ok(())
}

/// Tests that role creation works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_create_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_create_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    let test_role = owner_team
        .create_role(text!("test_role"), 50.into())
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
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 799.into())
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
    assert_eq!(test_role.id, test_role2.id);
    assert_eq!(test_role.name, test_role2.name);

    Ok(())
}

/// Tests that role creation works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_perm_to_created_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_perm_to_created_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let owner_team = devices.owner.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Create a custom admin type role
    let admin_role = owner_team.create_role(text!("admin"), 500.into()).await?;
    owner_team
        .add_perm_to_role(admin_role.id, Permission::AddDevice)
        .await
        .expect("expected to assign AddDevice to admin");

    // Add our admin with this role
    owner_team
        .add_device_with_rank(devices.admin.pk, Some(admin_role.id), 499.into())
        .await
        .expect("expected to add admin with role");

    // Sync the admin and test that they can add the operator
    let admin_team = devices.admin.client.team(team_id);
    admin_team.sync_now(owner_addr, None).await?;

    admin_team
        .add_device_with_rank(devices.operator.pk, None, 400.into())
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

    // Initialize malicious device on team.
    let work_dir = tempfile::tempdir()?;
    let work_dir_path = work_dir.path();
    let device = DeviceCtx::new(team_name, "malicious", work_dir_path.join("malicious")).await?;
    owner_team
        .add_device_with_rank(device.pk.clone(), None, 399.into())
        .await?;
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
        .create_role(text!("malicious_role"), 400.into())
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
        .create_role(text!("target_role"), 300.into())
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
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Add admin with admin role
    owner_team
        .add_device_with_rank(devices.admin.pk, Some(roles.admin().id), 799.into())
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
        .add_device_with_rank(devices.operator.pk, None, 500.into())
        .await
        .expect_err("admin should not be able to add operator");

    Ok(())
}

/// Tests that role deletion works.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_delete_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_delete_role").await?;

    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

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
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team
        .device(devices.owner.id)
        .assign_role(roles.owner().id)
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
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    match owner_team
        .device(devices.owner.id)
        .revoke_role(roles.owner().id)
        .await
    {
        Ok(_) => bail!("expected revoking owner role from self to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected revoke_role error: {err:?}"),
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

    match owner_team
        .device(devices.membera.id)
        .assign_role(roles.operator().id)
        .await
    {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

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
        .create_label_with_rank(text!("delete-label-guard"), 500.into())
        .await?;

    operator_team
        .sync_now(devices.owner.aranya_local_addr().await?, None)
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
    devices.setup_default_roles(team_id).await?;

    let owner_id = devices.owner.id;
    let owner_team = devices.owner.client.team(team_id);

    let label = owner_team
        .create_label_with_rank(text!("device-self-label"), 500.into())
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
    match admin_team.device(devices.owner.id).remove_from_team().await {
        Ok(_) => bail!("expected removing the final owner to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected remove_device error: {err:?}"),
    }

    Ok(())
}

// ========================================================================
// Rank-based tests
// ========================================================================

/// Tests that a role can be created with a specific rank and that the rank
/// can be queried back.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_create_role_with_rank() -> Result<()> {
    let mut devices = DevicesCtx::new("test_create_role_with_rank").await?;
    let team_id = devices.create_and_add_team().await?;
    devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let expected_rank = 50.into();
    let role = owner_team
        .create_role(text!("ranked_role"), expected_rank)
        .await?;

    let role_obj: ObjectId = ObjectId::transmute(role.id);
    let rank = owner_team.query_rank(role_obj).await?;
    assert_eq!(rank, expected_rank);

    Ok(())
}

/// Tests that a label can be created with a specific rank and that the rank
/// can be queried back.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_create_label_with_rank() -> Result<()> {
    let mut devices = DevicesCtx::new("test_create_label_with_rank").await?;
    let team_id = devices.create_and_add_team().await?;
    devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let expected_rank = 50.into();
    let label_id = owner_team
        .create_label_with_rank(text!("ranked_label"), expected_rank)
        .await?;

    let label_obj: ObjectId = ObjectId::transmute(label_id);
    let rank = owner_team.query_rank(label_obj).await?;
    assert_eq!(rank, expected_rank);

    Ok(())
}

/// Tests that the rank of an object can be changed with a valid old_rank.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_rank() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_rank").await?;
    let team_id = devices.create_and_add_team().await?;
    devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let initial_rank = 50.into();
    let updated_rank = 75.into();
    let role = owner_team
        .create_role(text!("mutable_role"), initial_rank)
        .await?;

    let role_obj: ObjectId = ObjectId::transmute(role.id);

    owner_team
        .change_rank(role_obj, initial_rank, updated_rank)
        .await?;

    let new_rank = owner_team.query_rank(role_obj).await?;
    assert_eq!(new_rank, updated_rank);

    Ok(())
}

/// Tests that a lower-ranked device cannot change the rank of a higher-ranked
/// object (author_rank must be > target_rank).
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_rank_requires_sufficient_author_rank() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_rank_requires_sufficient_author_rank").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let operator_team = devices.operator.client.team(team_id);

    // Create a role with rank higher than the operator device rank
    let high_role_rank = 750.into();
    let operator_device_rank = 699.into();
    let high_role = owner_team
        .create_role(text!("high_role"), high_role_rank)
        .await?;

    // Add operator device and sync
    owner_team
        .add_device_with_rank(
            devices.operator.pk.clone(),
            Some(roles.operator().id),
            operator_device_rank,
        )
        .await?;

    // Give operator ChangeRank permission
    owner_team
        .add_perm_to_role(roles.operator().id, Permission::ChangeRank)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    operator_team.sync_now(owner_addr, None).await?;

    let role_obj: ObjectId = ObjectId::transmute(high_role.id);

    // Operator tries to change rank of object ranked above it -- should fail
    match operator_team
        .change_rank(role_obj, high_role_rank, 600.into())
        .await
    {
        Ok(_) => bail!("expected change_rank to fail when author rank < object rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected change_rank error: {err:?}"),
    }

    Ok(())
}

/// Tests that an admin cannot create a role with a rank higher than the
/// admin's own rank.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_create_role_rank_too_high_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_create_role_rank_too_high_rejected").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Add admin with rank 799 (admin default role already has CreateRole)
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 799.into())
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    // Admin (rank 799) tries to create role with rank 900 -- should fail
    match admin_team.create_role(text!("too_high"), 900.into()).await {
        Ok(_) => bail!("expected create_role to fail when rank > author rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected create_role error: {err:?}"),
    }

    Ok(())
}

/// Tests that adding a device with a rank higher than its assigned role's rank
/// is rejected (role_rank >= device_rank must hold).
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_add_device_rank_higher_than_role_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_add_device_rank_higher_than_role_rejected").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    // Try to add device with rank 700 and member role (rank 600)
    // Should fail: role_rank (600) >= device_rank (700) is false
    match owner_team
        .add_device_with_rank(
            devices.admin.pk.clone(),
            Some(roles.member().id),
            700.into(),
        )
        .await
    {
        Ok(_) => bail!("expected add_device to fail when device rank > role rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected add_device error: {err:?}"),
    }

    Ok(())
}

/// Tests that changing a device rank above its role's rank is rejected.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_rank_above_role_rank_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_rank_above_role_rank_rejected").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    // Add admin with member role and device rank below the role rank
    let device_rank = 599.into();
    owner_team
        .add_device_with_rank(
            devices.admin.pk.clone(),
            Some(roles.member().id),
            device_rank,
        )
        .await?;

    let device_obj: ObjectId = ObjectId::transmute(devices.admin.id);

    // Try to change device rank above its role rank -- should fail
    match owner_team
        .change_rank(device_obj, device_rank, 700.into())
        .await
    {
        Ok(_) => bail!("expected change_rank to fail when new rank > role rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected change_rank error: {err:?}"),
    }

    Ok(())
}

/// Tests that a role's rank can be demoted below a device that holds it.
///
/// This should normally not be done, but the policy cannot prevent it because
/// enforcing `role_rank >= device_rank` on demotion would require iterating
/// over all devices assigned to the role, which the policy language does not
/// support. See the "Role Rank Changes and the Device-Role Invariant" section
/// in policy.md for more details.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_role_rank_below_device_rank_allowed() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_role_rank_below_device_rank_allowed").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    // Add admin device with rank just below the member role rank (600)
    let device_rank = 599.into();
    owner_team
        .add_device_with_rank(
            devices.admin.pk.clone(),
            Some(roles.member().id),
            device_rank,
        )
        .await?;

    let role_obj: ObjectId = ObjectId::transmute(roles.member().id);
    let role_rank = 600.into();

    // Demote the member role rank below the device's rank
    let demoted_role_rank = 500.into();
    owner_team
        .change_rank(role_obj, role_rank, demoted_role_rank)
        .await
        .context("demoting role rank below device rank should succeed")?;

    // Verify the role rank is now below the device rank
    let current_role_rank = owner_team.query_rank(role_obj).await?;
    assert_eq!(current_role_rank, demoted_role_rank);

    let device_obj: ObjectId = ObjectId::transmute(devices.admin.id);
    let current_device_rank = owner_team.query_rank(device_obj).await?;
    assert!(
        current_device_rank > current_role_rank,
        "device rank ({current_device_rank}) should now exceed role rank ({current_role_rank})"
    );

    Ok(())
}

/// Tests that a lower-ranked device cannot operate on higher-ranked objects:
/// removing devices, deleting roles, or deleting labels.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_insufficient_rank_cannot_operate_on_objects() -> Result<()> {
    let mut devices = DevicesCtx::new("test_insufficient_rank_cannot_operate_on_objects").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let operator_team = devices.operator.client.team(team_id);

    // Add admin (rank 799) and operator (rank 699)
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 799.into())
        .await?;
    owner_team
        .add_device_with_rank(
            devices.operator.pk.clone(),
            Some(roles.operator().id),
            699.into(),
        )
        .await?;

    // Create a high-rank label
    let high_label = owner_team
        .create_label_with_rank(text!("high_label"), 800.into())
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    operator_team.sync_now(owner_addr, None).await?;

    // Operator (rank 699) tries to remove admin (rank 799) -- should fail
    match operator_team
        .device(devices.admin.id)
        .remove_from_team()
        .await
    {
        Ok(_) => bail!("expected removing higher-ranked device to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected remove_device error: {err:?}"),
    }

    // Operator (rank 699) tries to delete admin role (rank 800) -- should fail
    match operator_team.delete_role(roles.admin().id).await {
        Ok(_) => bail!("expected deleting higher-ranked role to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected delete_role error: {err:?}"),
    }

    // Operator (rank 699) tries to delete high-rank label (rank 800) -- should fail
    match operator_team.delete_label(high_label).await {
        Ok(_) => bail!("expected deleting higher-ranked label to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected delete_label error: {err:?}"),
    }

    Ok(())
}

/// Tests that change_rank fails when the new_rank exceeds the author's own rank.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_rank_new_rank_above_author_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_rank_new_rank_above_author_rejected").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let operator_team = devices.operator.client.team(team_id);

    let low_role_rank = 50.into();
    let operator_device_rank = 699.into();

    // Owner creates a role at low rank
    let role = owner_team
        .create_role(text!("low_role"), low_role_rank)
        .await?;

    // Add operator with ChangeRank perm
    owner_team
        .add_device_with_rank(
            devices.operator.pk.clone(),
            Some(roles.operator().id),
            operator_device_rank,
        )
        .await?;
    owner_team
        .add_perm_to_role(roles.operator().id, Permission::ChangeRank)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    operator_team.sync_now(owner_addr, None).await?;

    let role_obj: ObjectId = ObjectId::transmute(role.id);

    // Operator tries to change role rank to above operator's rank -- should fail
    match operator_team
        .change_rank(role_obj, low_role_rank, 800.into())
        .await
    {
        Ok(_) => bail!("expected change_rank to fail when new_rank > author_rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected change_rank error: {err:?}"),
    }

    Ok(())
}

/// Tests that change_rank fails when the provided old_rank does not match the
/// object's current rank (stale old_rank).
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_rank_stale_old_rank_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_rank_stale_old_rank_rejected").await?;
    let team_id = devices.create_and_add_team().await?;
    devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    let initial_rank = 50.into();
    let updated_rank = 75.into();
    let role = owner_team
        .create_role(text!("versioned_role"), initial_rank)
        .await?;
    let role_obj: ObjectId = ObjectId::transmute(role.id);

    // Change rank from initial to updated
    owner_team
        .change_rank(role_obj, initial_rank, updated_rank)
        .await?;

    // Try to change rank using stale old_rank (initial instead of current updated)
    match owner_team
        .change_rank(role_obj, initial_rank, 100.into())
        .await
    {
        Ok(_) => bail!("expected change_rank to fail with stale old_rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected change_rank error: {err:?}"),
    }

    Ok(())
}

/// Tests that a device can demote its own rank (self-demotion is allowed with
/// just the ChangeRank permission).
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_change_rank_self_demotion() -> Result<()> {
    let mut devices = DevicesCtx::new("test_change_rank_self_demotion").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Add admin -- admin default role already has ChangeRank
    let admin_rank = 799.into();
    let demoted_rank = 500.into();
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), admin_rank)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    let device_obj: ObjectId = ObjectId::transmute(devices.admin.id);

    // Admin demotes itself
    admin_team
        .change_rank(device_obj, admin_rank, demoted_rank)
        .await
        .context("device should be able to demote its own rank")?;

    // Verify the rank actually changed
    // Need to sync owner to see the change
    owner_team
        .sync_now(devices.admin.aranya_local_addr().await?, None)
        .await?;
    let new_rank = owner_team.query_rank(device_obj).await?;
    assert_eq!(new_rank, demoted_rank);

    Ok(())
}

/// Tests that a device at the same rank as another cannot operate on it
/// (strict > is required, not >=).
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_equal_rank_cannot_operate() -> Result<()> {
    let mut devices = DevicesCtx::new("test_equal_rank_cannot_operate").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Add admin and operator both at rank 699
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 699.into())
        .await?;
    owner_team
        .add_device_with_rank(
            devices.operator.pk.clone(),
            Some(roles.operator().id),
            699.into(),
        )
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    // Admin (rank 699) tries to remove operator (rank 699) -- should fail (strict >)
    match admin_team
        .device(devices.operator.id)
        .remove_from_team()
        .await
    {
        Ok(_) => bail!("expected removing equal-ranked device to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected remove_device error: {err:?}"),
    }

    Ok(())
}

/// Tests that assigning a role requires the author to outrank both the role
/// and the target device.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_assign_role_requires_outranking_both_role_and_device() -> Result<()> {
    let mut devices = DevicesCtx::new("test_assign_role_requires_outranking_both").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Add admin at rank 699 (below operator role rank 700)
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 699.into())
        .await?;
    // Add operator without role at rank 500
    owner_team
        .add_device_with_rank(devices.operator.pk.clone(), None, 500.into())
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    // Admin (rank 699) tries to assign operator role (rank 700) to operator device (rank 500)
    // Admin outranks the device (699 > 500) but NOT the role (699 < 700)
    // Should fail because author must outrank both targets
    match admin_team
        .device(devices.operator.id)
        .assign_role(roles.operator().id)
        .await
    {
        Ok(_) => bail!("expected assign_role to fail when author doesn't outrank the role"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected assign_role error: {err:?}"),
    }

    Ok(())
}

/// Tests that creating a label with a rank higher than the author's rank is
/// rejected.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_create_label_rank_too_high_rejected() -> Result<()> {
    let mut devices = DevicesCtx::new("test_create_label_rank_too_high_rejected").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);

    // Add admin with rank 799
    owner_team
        .add_device_with_rank(devices.admin.pk.clone(), Some(roles.admin().id), 799.into())
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    admin_team.sync_now(owner_addr, None).await?;

    // Admin (rank 799) tries to create label with rank 900 -- should fail
    match admin_team
        .create_label_with_rank(text!("too_high_label"), 900.into())
        .await
    {
        Ok(_) => bail!("expected create_label to fail when rank > author rank"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected create_label error: {err:?}"),
    }

    Ok(())
}

/// Tests that adding a permission to a role requires the author to outrank
/// that role.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_perm_change_requires_outranking_role() -> Result<()> {
    let mut devices = DevicesCtx::new("test_perm_change_requires_outranking_role").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let operator_team = devices.operator.client.team(team_id);

    // Add operator (rank 699) with ChangeRolePerms permission
    owner_team
        .add_device_with_rank(
            devices.operator.pk.clone(),
            Some(roles.operator().id),
            699.into(),
        )
        .await?;
    owner_team
        .add_perm_to_role(roles.operator().id, Permission::ChangeRolePerms)
        .await?;

    let owner_addr = devices.owner.aranya_local_addr().await?;
    operator_team.sync_now(owner_addr, None).await?;

    // Operator (rank 699) tries to add permission to admin role (rank 800) -- should fail
    match operator_team
        .add_perm_to_role(roles.admin().id, Permission::CreateRole)
        .await
    {
        Ok(_) => bail!("expected add_perm_to_role to fail when author doesn't outrank role"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected add_perm_to_role error: {err:?}"),
    }

    Ok(())
}

// ========================================================================
// Deprecated API coverage tests
// ========================================================================

/// Tests the deprecated add_device API still works and assigns a default rank.
#[allow(deprecated)]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_deprecated_add_device() -> Result<()> {
    let mut devices = DevicesCtx::new("test_deprecated_add_device").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    // Use deprecated add_device API
    owner_team
        .add_device(devices.admin.pk.clone(), Some(roles.admin().id))
        .await?;

    // Verify device was added
    let team_devices = owner_team.devices().await?;
    assert!(team_devices.iter().any(|d| *d == devices.admin.id));

    // Verify default rank is role_rank - 1 (admin role rank 800 - 1 = 799)
    let device_obj: ObjectId = ObjectId::transmute(devices.admin.id);
    let rank = owner_team.query_rank(device_obj).await?;
    assert_eq!(
        rank,
        799.into(),
        "deprecated add_device should default to role_rank - 1"
    );

    Ok(())
}

/// Tests the deprecated setup_default_roles API that takes an owning_role
/// parameter (which is ignored).
#[allow(deprecated)]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_deprecated_setup_default_roles() -> Result<()> {
    let mut devices = DevicesCtx::new("test_deprecated_setup_default_roles").await?;
    let team_id = devices.create_and_add_team().await?;

    let owner_team = devices.owner.client.team(team_id);
    let owner_role = owner_team
        .roles()
        .await?
        .into_iter()
        .find(|r| r.name == "owner" && r.default)
        .expect("owner role should exist");

    // Use deprecated setup_default_roles_deprecated API with owning_role parameter
    let setup_roles = owner_team
        .setup_default_roles_deprecated(owner_role.id)
        .await?;
    assert_eq!(
        setup_roles.iter().count(),
        3,
        "should create admin, operator, member"
    );

    Ok(())
}

/// Tests the deprecated create_label API that takes a managing_role_id
/// parameter (which is ignored).
#[allow(deprecated)]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_deprecated_create_label() -> Result<()> {
    let mut devices = DevicesCtx::new("test_deprecated_create_label").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);

    // Use deprecated create_label API
    let label_id = owner_team
        .create_label(text!("deprecated_label"), roles.owner().id)
        .await?;

    // Verify label was created
    let label = owner_team.label(label_id).await?;
    assert!(label.is_some(), "label should exist");

    // Verify default rank is author_rank - 1 (owner device rank 1000000 - 1 = 999999)
    let label_obj: ObjectId = ObjectId::transmute(label_id);
    let rank = owner_team.query_rank(label_obj).await?;
    assert_eq!(
        rank,
        999999.into(),
        "deprecated create_label should default to author_rank - 1"
    );

    Ok(())
}

/// Tests the deprecated role_owners API always returns an empty list.
#[allow(deprecated)]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_deprecated_role_owners_returns_empty() -> Result<()> {
    let mut devices = DevicesCtx::new("test_deprecated_role_owners_returns_empty").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let owners = owner_team.role_owners(roles.admin().id).await?;
    assert_eq!(
        owners.iter().count(),
        0,
        "deprecated role_owners should always return empty"
    );

    Ok(())
}

/// Tests the deprecated add_label_managing_role API succeeds as a no-op.
#[allow(deprecated)]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_deprecated_add_label_managing_role_noop() -> Result<()> {
    let mut devices = DevicesCtx::new("test_deprecated_add_label_managing_role_noop").await?;
    let team_id = devices.create_and_add_team().await?;
    let roles = devices.setup_default_roles(team_id).await?;

    let owner_team = devices.owner.client.team(team_id);
    let label_id = owner_team
        .create_label_with_rank(text!("test_label"), 500.into())
        .await?;

    // Use deprecated add_label_managing_role API -- should succeed as no-op
    owner_team
        .add_label_managing_role(label_id, roles.admin().id)
        .await
        .context("deprecated add_label_managing_role should succeed as no-op")?;

    Ok(())
}
