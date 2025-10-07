//! Integration tests for push sync functionality.

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

use anyhow::{bail, Result};
use aranya_daemon_api::Address;
use test_log::test;
use tracing::info;

use crate::common::DevicesCtx;

/// Tests push sync functionality by demonstrating that devices can subscribe
/// to push notifications from peers and automatically receive updates to the graph.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_push_sync() -> Result<()> {
    // Set up our team context so we can run the test.
    let mut devices = DevicesCtx::new("test_push_sync").await?;

    // Create the initial team, and get our TeamId.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    // Grab addresses for testing
    let admin_addr = devices.admin.aranya_local_addr().await?;
    let owner_addr = devices.owner.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let membera_team = devices.membera.client.team(team_id);
    let admin_team = devices.admin.client.team(team_id);
    let owner_team = devices.owner.client.team(team_id);

    // Add sync peers with sync_on_hello disabled to avoid interference
    let sync_config = aranya_client::config::SyncPeerConfig::builder()
        .interval(Duration::from_secs(24 * 60 * 60))? // Long interval
        .sync_now(false)
        .sync_on_hello(false)
        .build()?;

    membera_team
        .add_sync_peer(admin_addr, sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(owner_addr, sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(owner_addr, sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(admin_addr, sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(
            devices.membera.aranya_local_addr().await?,
            sync_config.clone(),
        )
        .await?;
    info!("added sync peers with sync_on_hello=false");

    // Before the action, verify that MemberA doesn't know about any labels created by admin
    // (This will be our way to test if push sync worked)
    info!("verifying initial state - membera should not see any labels created by admin");
    let queries = membera_team.queries();
    let initial_labels = queries.labels().await?;
    let initial_label_count = initial_labels.iter().count();
    info!(
        "initial label count as seen by membera: {}",
        initial_label_count
    );

    // For push sync, we need to provide sample commands (graph heads).
    // For simplicity in this test, we'll use an empty vector.
    let commands: Vec<Address> = Vec::new();

    // MemberA subscribes to push notifications from Admin
    membera_team
        .sync_push_subscribe(
            admin_addr, 30,     // remain_open: 30 seconds
            102400, // max_bytes: 100KB
            commands,
        )
        .await?;
    info!("membera subscribed to push notifications from admin");

    // Wait a moment to ensure the subscription is active
    common::sleep(Duration::from_millis(200)).await;

    // Admin performs an action that will update their graph - create a label
    // (admin has permission to create labels)
    info!("admin creating a test label");
    let test_label = admin_team
        .create_label(aranya_daemon_api::text!("push_sync_test_label"))
        .await?;
    info!("admin created test label: {:?}", test_label);

    // Wait for push notification to be sent and processed
    // The push notification should be sent, membera should receive it,
    // check that the command doesn't exist locally, and add it to their graph
    info!("waiting for push notification and automatic sync...");

    // Poll every 100ms for up to 10 seconds for the label count to increase
    let poll_start = std::time::Instant::now();
    let poll_timeout = Duration::from_millis(10_000);
    let poll_interval = Duration::from_millis(100);

    let final_labels = loop {
        let current_labels = queries.labels().await?;
        let current_count = current_labels.iter().count();

        if current_count > initial_label_count {
            info!(
                "push sync detected - label count increased from {} to {} after {:?}",
                initial_label_count,
                current_count,
                poll_start.elapsed()
            );
            break current_labels;
        }

        if poll_start.elapsed() >= poll_timeout {
            bail!(
                "Push sync failed: timeout after {:?} - expected label count to increase from {} but it remained at {}",
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
        .any(|label| label.name.as_str() == "push_sync_test_label");

    if !label_exists {
        bail!("Push sync failed: the test label created by admin is not visible to membera");
    }

    info!("push sync test succeeded - membera automatically received updates after subscribing");

    // Test basic subscription/unsubscription functionality for completeness
    info!("testing basic subscription functionality");

    // Test multiple subscriptions
    owner_team
        .sync_push_subscribe(
            admin_addr,
            60,         // remain_open: 60 seconds
            204800,     // max_bytes: 200KB
            Vec::new(), // empty commands for simplicity
        )
        .await?;
    info!("owner subscribed to push notifications from admin");

    // Test unsubscribing
    membera_team.sync_push_unsubscribe(admin_addr).await?;
    owner_team.sync_push_unsubscribe(admin_addr).await?;
    info!("all devices unsubscribed from push notifications");

    // Test edge cases
    membera_team
        .sync_push_subscribe(
            admin_addr,
            10,    // remain_open: 10 seconds
            51200, // max_bytes: 50KB
            Vec::new(),
        )
        .await?;
    membera_team.sync_push_unsubscribe(admin_addr).await?;
    info!("tested immediate subscribe/unsubscribe");

    // Test unsubscribing from non-subscribed peer
    let memberb_addr = devices.memberb.aranya_local_addr().await?;
    membera_team.sync_push_unsubscribe(memberb_addr).await?;
    info!("tested unsubscribing from non-subscribed peer");

    Ok(())
}
