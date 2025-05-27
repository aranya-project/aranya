#![allow(clippy::panic)]

use std::time::Duration;

mod common;
use anyhow::Result;
use aranya_client::{aqc::AqcPeerChannel, TeamConfig};
use aranya_crypto::csprng::rand;
use aranya_daemon_api::{ChanOp, NetIdentifier};
use buggy::BugExt;
use bytes::{Bytes, BytesMut};
use common::{sleep, TeamCtx};
use futures_util::future::try_join;
use tempfile::tempdir;
use tracing::info;

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_aqc_chans", work_dir).await?;

    let cfg = TeamConfig::builder().build()?;
    // create team.
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    let mut operator_team = team.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(
            team.membera.id,
            NetIdentifier(team.membera.client.aqc().server_addr()?.to_string()),
        )
        .await?;
    operator_team
        .assign_aqc_net_identifier(
            team.memberb.id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
        )
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    let label1 = operator_team.create_label("label1".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label("label2".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label2, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            team.membera.client.aqc().create_bidi_channel(
                team_id,
                NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
                label1,
            ),
            team.memberb.client.aqc().receive_channel(),
        )
        .await
        .expect("can create and receive channel");

        let mut bidi_chan2 = match peer_channel {
            AqcPeerChannel::Bidi(channel) => channel,
            _ => buggy::bug!("Expected a bidirectional channel on memberb"),
        };

        let mut send1_1 = bidi_chan1.create_uni_stream().await?;

        // Test sending streams

        // Send from 1 to 2 with a unidirectional stream
        let msg1 = Bytes::from_static(b"hello");
        send1_1.send(msg1.clone()).await?;
        // Receive a unidirectional stream from peer 1
        let mut recv2_1 = bidi_chan2
            .receive_stream()
            .await
            .unwrap()
            .into_receive()
            .ok()
            .unwrap();
        let bytes = recv2_1.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg1);

        let mut bidi1_2 = bidi_chan1.create_bidi_stream().await?;
        // Send from 1 to 2 with a bidirectional stream
        let msg2 = Bytes::from_static(b"hello2");
        bidi1_2.send(msg2.clone()).await?;
        let mut bidi2_2 = bidi_chan2
            .receive_stream()
            .await
            .unwrap()
            .into_bidi()
            .ok()
            .unwrap();
        let bytes = bidi2_2.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg2);
        // Send from 2 to 1 with a bidirectional stream
        let msg3 = Bytes::from_static(b"hello3");
        bidi2_2.send(msg3.clone()).await?;
        let bytes = bidi1_2.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg3);

        // Test sending a large message
        let big_data = {
            let mut rng = rand::thread_rng();
            let mut data = vec![0u8; 1024 * 1024 * 3 / 2];
            rand::Rng::fill(&mut rng, &mut data[..]);
            Bytes::from(data)
        };
        bidi1_2.send(big_data.clone()).await?;
        let mut dest_bytes = BytesMut::new();
        // Send stream should return the message in pieces
        while let Some(bytes) = bidi2_2.receive().await? {
            dest_bytes.extend_from_slice(&bytes);
            if dest_bytes.len() >= big_data.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(dest_bytes.freeze(), big_data);

        team.membera
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan1)
            .await?;
        team.memberb
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan2)
            .await?;
    }

    {
        // membera creates aqc uni channel with memberb concurrently
        let (mut uni_chan1, peer_channel) = try_join(
            team.membera.client.aqc().create_uni_channel(
                team_id,
                NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
                label1,
            ),
            team.memberb.client.aqc().receive_channel(),
        )
        .await
        .expect("can create uni channel");

        let mut uni_chan2 = match peer_channel {
            AqcPeerChannel::Receive(receiver) => receiver,
            _ => panic!("Expected a unidirectional channel"),
        };

        let mut send1_1 = uni_chan1.create_uni_stream().await?;

        // Test sending streams

        // Send from 1 to 2 with a unidirectional stream
        let msg1 = Bytes::from_static(b"hello");
        send1_1.send(msg1.clone()).await?;

        let mut recv2_1 = uni_chan2.receive_uni_stream().await?;

        let bytes = recv2_1.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg1);
    }

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            team.membera.client.aqc().create_bidi_channel(
                team_id,
                NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
                label2,
            ),
            async {
                Ok(loop {
                    let peer_channel_result = team.memberb.client.aqc().try_receive_channel();
                    if let Ok(peer_channel) = peer_channel_result {
                        break peer_channel;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                })
            },
        )
        .await
        .expect("can create and receive with try_receive_channel");

        let mut bidi_chan2 = match peer_channel {
            AqcPeerChannel::Bidi(channel) => channel,
            _ => buggy::bug!("Expected a bidirectional channel on memberb"),
        };

        let mut send1_1 = bidi_chan1.create_uni_stream().await?;

        // Test sending streams

        // Send from 1 to 2 with a unidirectional stream
        let msg1 = Bytes::from_static(b"hello");
        send1_1.send(msg1.clone()).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Receive a unidirectional stream from peer 1
        let (maybe_send2_1, mut recv2_1) = bidi_chan2
            .try_receive_stream()
            .assume("stream not received")?;
        assert!(maybe_send2_1.is_none(), "Expected unidirectional stream");
        let bytes = recv2_1.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg1);
    }

    Ok(())
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_not_auth_label_sender() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_aqc_chans_not_auth_label_sender", work_dir).await?;

    let cfg = TeamConfig::builder().build()?;
    // create team.
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    let mut operator_team = team.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(
            team.membera.id,
            NetIdentifier(team.membera.client.aqc().server_addr()?.to_string()),
        )
        .await?;
    operator_team
        .assign_aqc_net_identifier(
            team.memberb.id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
        )
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    let label1 = operator_team.create_label("label1".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label("label2".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label2, op)
        .await?;

    let label3 = operator_team.create_label("label3".to_string()).await?;
    let op = ChanOp::SendRecv;
    // assign label 3 to only the receiver, we are testing if the sender can create
    // a channel without the label assignment
    operator_team
        .assign_label(team.memberb.id, label3, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    try_join(
        team.membera.client.aqc().create_bidi_channel(
            team_id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
            label3,
        ),
        team.memberb.client.aqc().receive_channel(),
    )
    .await
    .expect_err("can not create and receive channel");

    Ok(())
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_not_auth_label_recvr() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_aqc_chans_not_auth_label_recvr", work_dir).await?;

    let cfg = TeamConfig::builder().build()?;
    // create team.
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    let mut operator_team = team.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(
            team.membera.id,
            NetIdentifier(team.membera.client.aqc().server_addr()?.to_string()),
        )
        .await?;
    operator_team
        .assign_aqc_net_identifier(
            team.memberb.id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
        )
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    let label1 = operator_team.create_label("label1".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label("label2".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label2, op)
        .await?;

    let label3 = operator_team.create_label("label3".to_string()).await?;
    let op = ChanOp::SendRecv;
    // assign label 3 to only the sender, we are testing if the receiver can receive
    // a channel without the label assignment
    operator_team
        .assign_label(team.membera.id, label3, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    try_join(
        team.membera.client.aqc().create_bidi_channel(
            team_id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
            label3,
        ),
        team.memberb.client.aqc().receive_channel(),
    )
    .await
    .expect_err("can not receive channel");

    Ok(())
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_close_sender_stream() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_aqc_chans_close_sender_stream", work_dir).await?;

    let cfg = TeamConfig::builder().build()?;
    // create team.
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    let mut operator_team = team.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(
            team.membera.id,
            NetIdentifier(team.membera.client.aqc().server_addr()?.to_string()),
        )
        .await?;
    operator_team
        .assign_aqc_net_identifier(
            team.memberb.id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
        )
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    let label1 = operator_team.create_label("label1".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label("label2".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label2, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            team.membera.client.aqc().create_bidi_channel(
                team_id,
                NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
                label1,
            ),
            team.memberb.client.aqc().receive_channel(),
        )
        .await
        .expect("can create and receive channel");

        let mut bidi_chan2 = match peer_channel {
            AqcPeerChannel::Bidi(channel) => channel,
            _ => buggy::bug!("Expected a bidirectional channel on memberb"),
        };

        let mut send1_1 = bidi_chan1.create_uni_stream().await?;

        // Test sending streams

        // Send from 1 to 2 with a unidirectional stream
        let msg1 = Bytes::from_static(b"hello");
        send1_1.send(msg1.clone()).await?;
        // Receive a unidirectional stream from peer 1
        let mut recv2_1 = bidi_chan2
            .receive_stream()
            .await
            .unwrap()
            .into_receive()
            .ok()
            .unwrap();
        let bytes = recv2_1.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg1);

        let mut bidi1_2 = bidi_chan1.create_bidi_stream().await?;
        // Send from 1 to 2 with a bidirectional stream
        let msg2 = Bytes::from_static(b"hello2");
        bidi1_2.send(msg2.clone()).await?;
        let mut bidi2_2 = bidi_chan2
            .receive_stream()
            .await
            .unwrap()
            .into_bidi()
            .ok()
            .unwrap();
        let bytes = bidi2_2.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg2);

        // close the bidi2_2 stream, then try to send on it
        // we are still able to enqueue data to send, but the receiver
        // should get None to indicate the stream is closed.
        bidi2_2.close().await?;

        sleep(Duration::from_millis(100)).await;

        // Send from 2 to 1 with a bidirectional stream
        let msg3 = Bytes::from_static(b"hello3");
        bidi2_2.send(msg3.clone()).await?;
        // we expect the result of bidi1_2 to be none, as the stream is closed. (per s2n docs)
        assert!(bidi1_2.receive().await?.is_none());

        team.membera
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan1)
            .await?;
        team.memberb
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan2)
            .await?;
    }

    Ok(())
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_delete_chan() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_aqc_chans_delete_chan", work_dir).await?;

    let cfg = TeamConfig::builder().build()?;
    // create team.
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    let mut operator_team = team.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(
            team.membera.id,
            NetIdentifier(team.membera.client.aqc().server_addr()?.to_string()),
        )
        .await?;
    operator_team
        .assign_aqc_net_identifier(
            team.memberb.id,
            NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
        )
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    let label1 = operator_team.create_label("label1".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label("label2".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label2, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            team.membera.client.aqc().create_bidi_channel(
                team_id,
                NetIdentifier(team.memberb.client.aqc().server_addr()?.to_string()),
                label1,
            ),
            team.memberb.client.aqc().receive_channel(),
        )
        .await
        .expect("can create and receive channel");

        let mut bidi_chan2 = match peer_channel {
            AqcPeerChannel::Bidi(channel) => channel,
            _ => buggy::bug!("Expected a bidirectional channel on memberb"),
        };

        let mut send1_1 = bidi_chan1.create_uni_stream().await?;

        // Test sending streams

        // Send from 1 to 2 with a unidirectional stream
        let msg1 = Bytes::from_static(b"hello");
        send1_1.send(msg1.clone()).await?;
        // Receive a unidirectional stream from peer 1
        let mut recv2_1 = bidi_chan2
            .receive_stream()
            .await
            .unwrap()
            .into_receive()
            .ok()
            .unwrap();
        let bytes = recv2_1.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg1);

        let mut bidi1_2 = bidi_chan1.create_bidi_stream().await?;
        // Send from 1 to 2 with a bidirectional stream
        let msg2 = Bytes::from_static(b"hello2");
        bidi1_2.send(msg2.clone()).await?;
        let mut bidi2_2 = bidi_chan2
            .receive_stream()
            .await
            .unwrap()
            .into_bidi()
            .ok()
            .unwrap();
        let bytes = bidi2_2.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg2);
        // Send from 2 to 1 with a bidirectional stream
        let msg3 = Bytes::from_static(b"hello3");
        bidi2_2.send(msg3.clone()).await?;
        let bytes = bidi1_2.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg3);

        team.membera
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan1)
            .await?;
        team.memberb
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan2)
            .await?;

        // wait for ctrl message to be sent.
        sleep(Duration::from_millis(100)).await;

        // try sending after channels are closed
        let msg2 = Bytes::from_static(b"hello2");
        bidi1_2
            .send(msg2.clone())
            .await
            .expect_err("expected to fail sending");
    }

    Ok(())
}
