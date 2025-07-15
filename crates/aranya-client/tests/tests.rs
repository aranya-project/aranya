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
use test_log::test;
use tracing::{debug, info};

mod common;
use common::{sleep, RolesExt, TeamCtx, SLEEP_INTERVAL};

/// Tests sync_now() by showing that an admin cannot assign any roles until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_sync_now", work_dir).await?;

    let team_id = team.create_and_add_team().await?;
    info!(?team_id);

    let roles = team
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    let owner_addr = team.owner.aranya_local_addr().await?;

    let mut owner = team.owner.client.team(team_id);
    let mut admin = team.admin.client.team(team_id);

    // Add the admin as a new device, but don't give it a role.
    owner
        .add_device(team.admin.pk.clone(), None)
        .await
        .context("owner unable to add admin to team")?;

    // Add the operator as a new device, but don't give it a role.
    owner
        .add_device(team.operator.pk.clone(), None)
        .await
        .context("owner unable to add operator to team")?;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner
        .assign_role(team.admin.id, roles.admin().id)
        .await
        .context("owner unable to assign admin role")?;

    // Now, we try to assign a role using the admin, which is expected to fail.
    match admin
        .assign_role(team.operator.id, roles.operator().id)
        .await
    {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(err) => bail!("Unexpected error: {err}"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin
        .sync_now(owner_addr.into(), None)
        .await
        .context("admin unable to sync with owner")?;

    sleep(SLEEP_INTERVAL).await;

    // Now we should be able to successfully assign a role.
    admin
        .assign_role(team.operator.id, roles.operator().id)
        .await
        .context("admin unable to assign role to operator")?;

    Ok(())
}

/// Tests that devices can be removed from the team.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_remove_devices() -> Result<()> {
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let team = TeamCtx::new("test_query_functions", work_dir).await?;

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

    // Add the initial admin.
    //
    // We have to do this before we set up the default roles
    // since `setup_default_roles` removes the owner's ability to
    // add devices to the team.
    owner
        .add_device(team.admin.pk.clone(), None)
        .await
        .context("owner should be able to add admin to team")?;

    // There are now three more roles:
    // - admin
    // - operator
    // - member
    // The owner role manages all of those roles.
    let roles = team
        .setup_default_roles(team_id)
        .await
        .context("unable to setup default roles")?;

    // The owner assigns the admin role to the admin.
    owner.assign_role(team.admin.id, roles.admin().id).await?;

    owner
        .assign_role_management_permission(roles.admin().id, roles.operator().id, todo!())
        .await
        .context("owner should be able to change admin role to operator")?;

    sleep(SLEEP_INTERVAL).await;

    admin
        .add_device(team.operator.pk.clone(), None)
        .await
        .context("admin should be able to add operator to team")?;
    admin
        .add_device(team.membera.pk.clone(), None)
        .await
        .context("admin should be able to add membera to team")?;
    admin
        .add_device(team.memberb.pk.clone(), None)
        .await
        .context("admin should be able to add memberb to team")?;

    //assert_eq!(owner.queries().devices_on_team().await?.iter().count(), 5);

    Ok(())
}

/// TODO
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_roles() -> Result<()> {
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    let team_id = team.create_and_add_team().await?;

    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    let owner_role_id = team
        .owner
        .client
        .team(team_id)
        .roles()
        .await?
        .try_into_owner_role()?
        .id;
    let roles = team
        .owner
        .client
        .team(team_id)
        .setup_default_roles(owner_role_id)
        .await?
        .try_into_default_roles()?;

    let mut membera = team.membera.client.team(team_id);

    let devices = membera.devices().await?;
    assert_eq!(devices.iter().count(), 5);
    debug!(
        count = %devices.iter().count(),
        "`membera` devices on team",
    );

    // Check the specific role a device has.
    let dev_role = membera
        .device(team.membera.id)
        .role()
        .await?;
    assert_eq!(dev_role.map(|r| r.id), Some(roles.member().id));

    // Make sure that we have the correct keybundle.
    let keybundle = membera.device(team.membera.id).keybundle().await?;
    debug!("membera keybundle: {:?}", keybundle);

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
            TeamConfig::builder()
                .quic_sync(QuicSyncConfig::builder().build()?)
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
    owner
        .add_device(team.admin.pk.clone(), None)
        .await?;

    // Add the operator as a new device.
    info!("adding operator to team");
    owner
        .add_device(team.operator.pk.clone(), None)
        .await?;

    // Give the admin its role.
    owner.assign_role(team.admin.id, roles.admin().id).await?;

    // Let's sync immediately. The role change will not propogate since add_team() hasn't been called.
    {
        let admin = team.admin.client.team(team_id);
        admin.sync_now(owner_addr.into(), None).await?;
        sleep(TLS_HANDSHAKE_DURATION).await;

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin
            .assign_role(team.operator.id, roles.operator().id)
            .await
        {
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
        .add_team(team_id, {
            TeamConfig::builder()
                .quic_sync(
                    QuicSyncConfig::builder()
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
            .assign_role(team.operator.id, roles.operator().id)
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

        let owner_role_id = owner.roles().await?.try_into_owner_role()?.id;
        let roles = owner
            .setup_default_roles(owner_role_id)
            .await?
            .try_into_default_roles()?;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner
            .add_device(team.operator.pk.clone(), None)
            .await?;

        // Add the admin as a new device.
        owner
            .add_device(team.admin.pk.clone(), None)
            .await?;

        // Give the admin its role.
        owner.assign_role(team.admin.id, roles.admin().id).await?;

        sleep(SLEEP_INTERVAL).await;

        // We should be able to successfully assign a role.
        admin
            .assign_role(team.operator.id, roles.operator().id)
            .await?;
    }

    // Remove the team from the admin's local storage
    team.admin.client.remove_team(team_id).await?;

    sleep(SLEEP_INTERVAL).await;

    {
        let admin = team.admin.client.team(team_id);

        // Role assignment should fail
        let owner_role_id = admin.roles().await?.try_into_owner_role()?.id;
        let roles = admin
            .setup_default_roles(owner_role_id)
            .await?
            .try_into_default_roles()?;
        match admin.assign_role(team.operator.id, roles.member().id).await {
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

        let owner_role_id = owner1.roles().await?.try_into_owner_role()?.id;
        let roles = owner1
            .setup_default_roles(owner_role_id)
            .await?
            .try_into_default_roles()?;

        let admin_seed = {
            let admin2_device = &mut team2.admin;

            let admin_keys = admin2_device.pk.clone();
            owner1.add_device(admin_keys, None).await?;

            // Assign Admin2 the Admin role on team 1.
            owner1
                .assign_role(admin2_device.id, roles.admin().id)
                .await?;
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
            .add_team(team_id_1, {
                TeamConfig::builder()
                    .quic_sync(
                        QuicSyncConfig::builder()
                            .wrapped_seed(&admin_seed)?
                            .build()?,
                    )
                    .build()?
            })
            .await?;
        {
            let admin2 = team2.admin.client.team(team_id_1);
            admin2.sync_now(owner1_addr.into(), None).await?;

            sleep(SLEEP_INTERVAL).await;
            admin2
                .assign_role(team1.membera.id, roles.operator().id)
                .await?;
        }
    }

    // Admin2 syncs on team 2
    {
        let owner2_addr = team2.owner.aranya_local_addr().await?;
        let admin2 = team2.admin.client.team(team_id_2);

        let owner_role_id = admin2.roles().await?.try_into_owner_role()?.id;
        let roles = admin2
            .setup_default_roles(owner_role_id)
            .await?
            .try_into_default_roles()?;

        admin2.sync_now(owner2_addr.into(), None).await?;

        sleep(SLEEP_INTERVAL).await;
        admin2
            .assign_role(team2.membera.id, roles.operator().id)
            .await?;
    }

    Ok(())
}
