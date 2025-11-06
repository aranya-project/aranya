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
    client::Role,
    config::{CreateTeamConfig, SyncPeerConfig},
    AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
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
    admin.sync_now(owner_addr, None).await?;

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
        match admin.sync_now(owner_addr, None).await {
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
            .sync_now(devices.owner.aranya_local_addr().await?, None)
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
        match admin.sync_now(owner_addr, None).await {
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
        .assign_role(devices.operator.id, Role::Operator)
        .await
        .context("Assigning a role should not fail here!")?;

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

        // Now, we try to assign a role using the admin, which is expected to fail.
        match admin.assign_role(devices.operator.id, Role::Operator).await {
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

    // Now we should be able to successfully assign a role.
    admin2
        .assign_role(devices.operator.id, Role::Operator)
        .await
        .context("Assigning a role should not fail here!")?;

    Ok(())
}

/// Tests hello subscription functionality by demonstrating that devices can subscribe
/// to hello notifications from peers and automatically sync when receiving notifications.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_hello_subscription() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_hello_subscription").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

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
    membera_team
        .sync_hello_subscribe(
            admin_addr,
            Duration::from_millis(100),
            Duration::from_millis(1000),
            Duration::from_secs(60), // Schedule delay for periodic sends
        ) // Short delay for faster testing
        .await?;
    info!("membera subscribed to hello notifications from admin");

    // Before the action, verify that MemberA doesn't know about any labels created by admin
    // (This will be our way to test if sync worked)
    info!("verifying initial state - membera should not see any labels created by admin");
    let queries = membera_team.queries();
    let initial_labels = queries.labels().await?;
    let initial_label_count = initial_labels.iter().count();
    info!(
        "initial label count as seen by membera: {}",
        initial_label_count
    );

    // Admin performs an action that will update their graph - create a label
    // (admin has permission to create labels)
    info!("admin creating a test label");
    let test_label = admin_team
        .create_label(aranya_daemon_api::text!("sync_hello_test_label"))
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
        let current_labels = queries.labels().await?;
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

        common::sleep(poll_interval).await;
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
        .sync_hello_subscribe(
            owner_addr,
            Duration::from_millis(1000),
            Duration::from_millis(1000),
            Duration::from_secs(60), // Schedule delay for periodic sends
        )
        .await?;
    info!("admin subscribed to hello notifications from owner");

    // Test multiple subscriptions
    operator_team
        .sync_hello_subscribe(
            owner_addr,
            Duration::from_millis(2000),
            Duration::from_millis(1000),
            Duration::from_secs(60), // Schedule delay for periodic sends
        )
        .await?;
    operator_team
        .sync_hello_subscribe(
            admin_addr,
            Duration::from_millis(1500),
            Duration::from_millis(1000),
            Duration::from_secs(60), // Schedule delay for periodic sends
        )
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
        .sync_hello_subscribe(
            owner_addr,
            Duration::from_millis(100),
            Duration::from_millis(1000),
            Duration::from_secs(60), // Schedule delay for periodic sends
        )
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
async fn test_hello_subscription_schedule_delay() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_hello_subscription_schedule_delay").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

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
    info!("Phase 1: Testing with high schedule_delay (60s) and high graph_change_delay (60s)");
    membera_team
        .sync_hello_subscribe(
            admin_addr,
            Duration::from_secs(60),  // graph_change_delay
            Duration::from_secs(120), // duration
            Duration::from_secs(60),  // schedule_delay - high
        )
        .await?;
    info!("membera subscribed to hello notifications from admin with high schedule_delay");

    // Before the action, verify that MemberA doesn't know about any labels created by admin
    info!("verifying initial state - membera should not see any labels created by admin");
    let queries = membera_team.queries();
    let initial_labels = queries.labels().await?;
    let initial_label_count = initial_labels.iter().count();
    info!(
        "initial label count as seen by membera: {}",
        initial_label_count
    );

    // Admin creates first label
    info!("admin creating first test label");
    let test_label_1 = admin_team
        .create_label(aranya_daemon_api::text!("schedule_test_label_1"))
        .await?;
    info!("admin created first test label: {:?}", test_label_1);

    // Wait for first label to be seen (should be sent via graph change notification)
    info!("waiting for first label to be seen via graph change notification...");
    let poll_start = std::time::Instant::now();
    let poll_timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(100);

    let first_label_seen = loop {
        let current_labels = queries.labels().await?;
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

        common::sleep(poll_interval).await;
    };

    assert!(first_label_seen, "First label should have been seen");

    // Admin creates second label
    info!("admin creating second test label");
    let test_label_2 = admin_team
        .create_label(aranya_daemon_api::text!("schedule_test_label_2"))
        .await?;
    info!("admin created second test label: {:?}", test_label_2);

    // Wait a short time and verify second label is NOT seen (rate-limited and schedule hasn't fired)
    info!("waiting briefly to confirm second label is not seen (rate-limited)...");
    common::sleep(Duration::from_secs(2)).await;

    let current_labels = queries.labels().await?;
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
            Duration::from_secs(60),   // graph_change_delay
            Duration::from_secs(120),  // duration
            Duration::from_millis(10), // schedule_delay - low
        )
        .await?;
    info!("membera subscribed to hello notifications from admin with low schedule_delay");

    // Wait for both labels to be seen (scheduled send should pick up pending changes)
    info!("waiting for both labels to be seen via scheduled periodic send...");
    let poll_start = std::time::Instant::now();
    let poll_timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(100);

    let both_labels_seen = loop {
        let current_labels = queries.labels().await?;
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
            let current_labels = queries.labels().await?;
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

        common::sleep(poll_interval).await;
    };

    assert!(both_labels_seen, "Both labels should have been seen");

    // Cleanup
    membera_team.sync_hello_unsubscribe(admin_addr).await?;
    info!("cleanup: unsubscribed membera from admin");

    Ok(())
}
