//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

#[cfg(feature = "afc")]
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
#[cfg(feature = "afc")]
use aranya_client::SyncPeerConfig;
use aranya_client::{Client, SyncPeerConfig, TeamConfig};
use aranya_crypto::{hash::Hash as _, rust::Sha256};
use aranya_daemon::{
    config::{AfcConfig, Config},
    Daemon,
};
#[cfg(feature = "afc")]
use aranya_daemon_api::ChanOp;
#[cfg(feature = "afc")]
use aranya_daemon_api::NetIdentifier;
use aranya_daemon_api::{DeviceId, KeyBundle, Role, TeamId};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use spideroak_base58::ToBase58 as _;
use tempfile::tempdir;
use test_log::test;
use tracing::{debug, info};

mod common;
use common::{sleep, TeamCtx, SLEEP_INTERVAL}; // Import from common

#[cfg(any())]
mod afc_imports {
    pub(super) use std::path::Path;

    pub(super) use aranya_client::afc::{Label, Message};
    pub(super) use aranya_daemon_api::NetIdentifier;
    pub(super) use aranya_fast_channels::Seq;
    pub(super) use buggy::BugExt as _;
}
#[cfg(any())]
use afc_imports::*;

/// Trim up to `width` trailing zeros from `d`.
fn trim(mut d: u128, mut width: usize) -> (u128, usize) {
    while width > 0 {
        if d % 10 != 0 {
            break;
        }
        d /= 10;
        width -= 1;
    }
    (d, width)
}

/// Repeatedly calls `poll_data`, followed by `handle_data`, until all of the clients are pending.
// TODO(nikki): alternative to select!{} to resolve lifetime issues
#[cfg(any())]
macro_rules! do_afc_poll {
    ($($client:expr),*) => {
        debug!(
            clients = stringify!($($client),*),
            "start `do_afc_poll`",
        );

        // Make sure any changes before now get synced before we try polling.
        sleep(SLEEP_INTERVAL).await;

        loop {
            let mut afcs = [ $($client.afc()),* ];
            let mut afcs = afcs.iter_mut();
            tokio::select! {
                biased;
                $(data = afcs.next().assume("macro enforces client count")?.poll_data() => {
                    $client.afc().handle_data(data?).await?
                },)*
                _ = async {} => break,
            }
        }

        debug!(
            clients = stringify!($($client),*),
            "finish `do_afc_poll`",
        );
    };
}

/// Tests sync_now() by showing that an admin cannot assign any roles until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_sync_now", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // TODO(geoff): implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another.
    team.add_all_sync_peers(team_id).await?;

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
        Err(aranya_client::Error::Daemon(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin.sync_now(owner_addr.into(), None).await?;
    sleep(SLEEP_INTERVAL).await;

    // Now we should be able to successfully assign a role.
    admin.assign_role(team.operator.id, Role::Operator).await?;

    Ok(())
}

/// Tests functionality to make sure that we can query the fact database for various things.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_functions() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

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

    // Now let's test any AFC-specific features. TODO(nikki): `if cfg!(feature = "afc") {`
    #[cfg(any())]
    {
        // TODO(nikki): device_afc_label_assignments

        // Grab the shorthand for the teams we need to operate on.
        let mut operator = team.operator.client.team(team_id);

        // Grab the shorthand for the AFC address.
        let membera_afc_addr = team.membera.afc_local_addr().await?;

        // Assign a Network Identifier so that we can query for it.
        operator
            .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
            .await?;

        // Check that it's the Network Identifier we expected.
        let afc_net_identifier = queries
            .afc_net_identifier(team.membera.id)
            .await?
            .expect("expected net identifier");
        assert_eq!(
            afc_net_identifier,
            NetIdentifier(membera_afc_addr.to_string())
        );
        debug!("membera afc_net_identifer: {:?}", afc_net_identifier);

        // Assign a temporary label to these devices.
        let label1 = Label::new(1);
        operator.create_afc_label(label1).await?;

        // Check that the label we created actually exists.
        let label_exists = queries.afc_label_exists(label1).await?;
        assert!(label_exists);
        debug!("membera label1 exists?: {:?}", label_exists);
    }

    // TODO(nikki): if cfg!(feature = "aqc") { aqc_net_identifier } and have aqc on by default.

    Ok(())
}

// Tests to make sure that a single device can receive messages from more than one channel.
#[cfg(any())]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_one_way_two_chans() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_afc_one_way_two_chans", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut operator = team.operator.client.team(team_id);

    // Grab the shorthand for the AFC addresses.
    let membera_afc_addr = team.membera.afc_local_addr().await?;
    let memberb_afc_addr = team.memberb.afc_local_addr().await?;

    /* The operator is responsible for assigning labels for AFC channels */
    // Create the first label so we can use it to open a channel.
    let label1 = Label::new(1);
    operator.create_afc_label(label1).await?;
    operator.assign_afc_label(team.membera.id, label1).await?;
    operator.assign_afc_label(team.memberb.id, label1).await?;

    // Create the second label so we can use it to open a channel.
    let label2 = Label::new(2);
    operator.create_afc_label(label2).await?;
    operator.assign_afc_label(team.membera.id, label2).await?;
    operator.assign_afc_label(team.memberb.id, label2).await?;

    // Assign Network Identifiers so peers are able to find each other.
    operator
        .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator
        .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;

    // Make sure they see those changes.
    sleep(SLEEP_INTERVAL).await;

    // Create Channel 1 from Member A to Member B
    let afc_id1 = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
        .await?;

    // Create Channel 2 from Member A to Member B
    let afc_id2 = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label2)
        .await?;

    // Make sure both clients are polling for AFC data.
    do_afc_poll!(team.membera.client, team.memberb.client);

    let msgs = ["hello world label1", "hello world label2"];

    // Send a message from Member A on the first channel.
    team.membera
        .client
        .afc()
        .send_data(afc_id1, msgs[0].as_bytes())
        .await?;
    debug!(msg = msgs[0], "sent message");

    // Send another message from Member A on the second channel.
    team.membera
        .client
        .afc()
        .send_data(afc_id2, msgs[1].as_bytes())
        .await?;
    debug!(msg = msgs[1], "sent message");

    // Make sure that Member B receives both messages.
    do_afc_poll!(team.membera.client, team.memberb.client);

    // Check that the first message arrived.
    let got = team
        .memberb
        .client
        .afc()
        .try_recv_data()
        .expect("should have a message");
    let want = Message {
        data: msgs[0].as_bytes().to_vec(),
        // TODO(nikki): We don't currently expose the address of outgoing connections, so assume
        // `got.address` is correct here.
        address: got.address,
        channel: afc_id1,
        label: label1,
        seq: Seq::ZERO,
    };
    assert_eq!(got, want);

    // Check that the second message arrived.
    let got = team
        .memberb
        .client
        .afc()
        .try_recv_data()
        .expect("should have a message");
    let want = Message {
        data: msgs[1].as_bytes().to_vec(),
        // TODO(nikki): We don't currently expose the address of outgoing connections, so assume
        // `got.address` is correct here.
        address: got.address,
        channel: afc_id2,
        label: label2,
        seq: Seq::ZERO,
    };
    assert_eq!(got, want);

    Ok(())
}

/// Tests to make sure that devices can talk to each other both ways across an AFC channel.
#[cfg(any())]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_two_way_one_chan() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_afc_two_way_one_chan", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut operator = team.operator.client.team(team_id);

    // Grab the shorthand for the AFC addresses.
    let membera_afc_addr = team.membera.afc_local_addr().await?;
    let memberb_afc_addr = team.memberb.afc_local_addr().await?;

    /* The operator is responsible for assigning labels for AFC channels */
    // Create a label so we're able to open a channel between members.
    let label1 = Label::new(1);
    operator.create_afc_label(label1).await?;
    operator.assign_afc_label(team.membera.id, label1).await?;
    operator.assign_afc_label(team.memberb.id, label1).await?;

    // Assign Network Identifiers so peers are able to find each other.
    operator
        .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator
        .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;

    // Make sure they see those changes.
    sleep(SLEEP_INTERVAL).await;

    // Create a bidirectional channel between Member A <-> Member B.
    let afc_id1 = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
        .await?;

    // Try sending a message from Member A.
    let msg = "a to b";
    team.membera
        .client
        .afc()
        .send_data(afc_id1, msg.as_bytes())
        .await?;
    debug!(msg = msg, "sent message");

    // Make sure both peers are polling so Member B can receive the message and respond.
    do_afc_poll!(team.membera.client, team.memberb.client);

    // Try to receive the message from Member A.
    let got = team
        .memberb
        .client
        .afc()
        .try_recv_data()
        .expect("should have a message");
    let want = Message {
        data: msg.as_bytes().to_vec(),
        // TODO(nikki): We don't currently expose the address of outgoing connections, so assume
        // `got.address` is correct here.
        address: got.address,
        channel: afc_id1,
        label: label1,
        seq: Seq::ZERO,
    };
    assert_eq!(got, want, "a->b");

    // Try responding to Member A.
    let msg = "b to a";
    team.memberb
        .client
        .afc()
        .send_data(afc_id1, msg.as_bytes())
        .await?;
    debug!(msg, "sent message");

    // Sleep and make sure we're polling so we can receive the message back.
    do_afc_poll!(team.membera.client, team.memberb.client);

    // Check that we actually got the message.
    let want = Message {
        data: msg.as_bytes().to_vec(),
        address: memberb_afc_addr,
        channel: afc_id1,
        label: label1,
        seq: Seq::ZERO,
    };
    let got = team
        .membera
        .client
        .afc()
        .try_recv_data()
        .expect("should have a message");
    assert_eq!(got, want, "b->a");

    Ok(())
}

/// A positive test that sequence numbers are monotonic.
#[cfg(any())]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_monotonic_seq() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_afc_monotonic_seq", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut operator = team.operator.client.team(team_id);

    // Grab the shorthand for the AFC addresses.
    let membera_afc_addr = team.membera.afc_local_addr().await?;
    let memberb_afc_addr = team.memberb.afc_local_addr().await?;

    // Create a label so our two peers can talk to each other.
    let label1 = Label::new(1);
    operator.create_afc_label(label1).await?;
    operator.assign_afc_label(team.membera.id, label1).await?;
    operator.assign_afc_label(team.memberb.id, label1).await?;

    // Assign Network Identifiers so they're able to find each other.
    operator
        .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator
        .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;

    // Make sure they see those changes.
    sleep(SLEEP_INTERVAL).await;

    // Create a bidirectional channel between Member A <-> Member B.
    let afc_id1 = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
        .await?;

    // Now let's try sending a number of messages to see if the sequence number gets iterated.
    for i in 0..10u64 {
        let seq = Seq::new(i);

        // Try sending a message to Member B.
        let msg = format!("ping {i}");
        team.membera
            .client
            .afc()
            .send_data(afc_id1, msg.as_bytes())
            .await?;
        debug!(msg = msg, "sent message");

        // Sleep and make sure that both peers are polling so we can receive the message.
        do_afc_poll!(team.membera.client, team.memberb.client);

        // Check that we got a message, and make sure it has the correct sequence number.
        let got = team
            .memberb
            .client
            .afc()
            .try_recv_data()
            .expect("should have a message");
        let want = Message {
            data: msg.into(),
            // TODO(nikki): We don't currently expose the address of outgoing connections, so assume
            // `got.address` is correct here.
            address: got.address,
            channel: afc_id1,
            label: label1,
            seq,
        };
        assert_eq!(got, want, "a->b");

        // Reply back from Member B.
        let msg = format!("pong {i}");
        team.memberb
            .client
            .afc()
            .send_data(afc_id1, msg.as_bytes())
            .await?;
        debug!(msg, "sent message");

        // Sleep and make sure that both peers are polling so we can receive the message.
        do_afc_poll!(team.membera.client, team.memberb.client);

        // Make sure we get back the message we expect, and that it has the right sequence number.
        let want = Message {
            data: msg.into(),
            address: memberb_afc_addr,
            channel: afc_id1,
            label: label1,
            seq,
        };
        let got = team
            .membera
            .client
            .afc()
            .try_recv_data()
            .expect("should have a message");
        assert_eq!(got, want, "b->a");
    }

    Ok(())
}

/// Tests to make sure that if a daemon gets killed and reboots, it can recover all parameters
/// needed to talk between channels.
#[cfg(any())]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_reboot() -> Result<()> {
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_afc_reboot", work_dir.clone()).await?;

    // Create the initial team, and get our TeamId.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut operator = team.operator.client.team(team_id);

    // Grab the shorthand for the AFC addresses.
    let membera_afc_addr = team.membera.afc_local_addr().await?;
    let memberb_afc_addr = team.memberb.afc_local_addr().await?;

    // Create a label so our two peers can talk to each other.
    let label = Label::new(1);
    operator.create_afc_label(label).await?;
    operator.assign_afc_label(team.membera.id, label).await?;
    operator.assign_afc_label(team.memberb.id, label).await?;

    // Assign Network Identifiers so they're able to find each other.
    operator
        .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator
        .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;

    // Make sure they see those changes.
    sleep(SLEEP_INTERVAL).await;

    // Now, let's try killing the two daemons to simulate e.g. a crash, and reboot them.
    drop(team.membera);
    team.membera = DeviceCtx::new("test_afc_reboot", "membera", work_dir.join("membera")).await?;
    drop(team.memberb);
    team.memberb = DeviceCtx::new("test_afc_reboot", "memberb", work_dir.join("memberb")).await?;

    // Try creating a new channel. This should fail if we haven't reloaded the necessary info.
    let afc_id = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label)
        .await?;

    // Try sending a message from Member A.
    let msg = "a to b";
    team.membera
        .client
        .afc()
        .send_data(afc_id, msg.as_bytes())
        .await?;
    debug!(msg = msg, "sent message");

    // Sleep and make sure we're polling so we can receive the message back.
    do_afc_poll!(team.membera.client, team.memberb.client);

    // Make sure Member B gets the correct message.
    let got = team
        .memberb
        .client
        .afc()
        .try_recv_data()
        .expect("should have a message");
    let want = Message {
        data: msg.as_bytes().to_vec(),
        // We don't know the address of outgoing connections, so
        // assume `got.addr` is correct here.
        address: got.address,
        channel: afc_id,
        label,
        seq: Seq::ZERO,
    };
    assert_eq!(got, want, "a->b");

    // Try responding to Member A.
    let msg = "b to a";
    team.memberb
        .client
        .afc()
        .send_data(afc_id, msg.as_bytes())
        .await?;
    debug!(msg, "sent message");

    // Sleep and make sure we're polling so we can receive the message back.
    do_afc_poll!(team.membera.client, team.memberb.client);

    // Check that we actually got the response back.
    let want = Message {
        data: msg.as_bytes().to_vec(),
        address: memberb_afc_addr,
        channel: afc_id,
        label,
        seq: Seq::ZERO,
    };
    let got = team
        .membera
        .client
        .afc()
        .try_recv_data()
        .expect("should have a message");
    assert_eq!(got, want, "b->a");

    Ok(())
}

// TODO(nikki): aqc testing variants.
