#![allow(clippy::panic)]

use std::time::Duration;

mod common;

use anyhow::{Context as _, Result};
use aranya_client::aqc::AqcPeerChannel;
use aranya_crypto::dangerous::spideroak_crypto::csprng::rand;
use aranya_daemon_api::{text, ChanOp};
use backon::{ConstantBuilder, Retryable as _};
use buggy::BugExt;
use bytes::{Bytes, BytesMut};
use futures_util::{future::try_join, FutureExt};
use tempfile::tempdir;

use crate::common::{sleep, DevicesCtx};

/// Demonstrate nominal usage of AQC channels.
/// 1. Create bidirectional and unidirectional AQC channels.
/// 2. Send and receive data via AQC channels.
/// 3. Delete AQC channels.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut devices = DevicesCtx::new("test_aqc_chans", work_dir).await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label2, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            devices.membera.client.aqc().create_bidi_channel(
                team_id,
                devices.memberb.aqc_net_id(),
                label1,
            ),
            devices.memberb.client.aqc().receive_channel(),
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
        }
        assert_eq!(dest_bytes.freeze(), big_data);

        devices
            .membera
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan1)
            .await?;
        devices
            .memberb
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan2)
            .await?;
    }

    {
        // membera creates aqc uni channel with memberb concurrently
        let (mut uni_chan1, peer_channel) = try_join(
            devices.membera.client.aqc().create_uni_channel(
                team_id,
                devices.memberb.aqc_net_id(),
                label1,
            ),
            devices.memberb.client.aqc().receive_channel(),
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
            devices
                .membera
                .client
                .aqc()
                .create_bidi_channel(team_id, devices.memberb.aqc_net_id(), label2)
                .map(|r| r.context("member-a creating channel")),
            (|| {
                std::future::ready(
                    devices
                        .memberb
                        .client
                        .aqc()
                        .try_receive_channel()
                        .context("member-b receiving channel"),
                )
            })
            .retry(
                ConstantBuilder::new()
                    .with_delay(Duration::from_millis(10))
                    .with_max_times(10),
            ),
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
        // Receive a unidirectional stream from peer 1
        let mut recv2_1 = (|| std::future::ready(bidi_chan2.try_receive_stream()))
            .retry(
                ConstantBuilder::new()
                    .with_delay(Duration::from_millis(10))
                    .with_max_times(10),
            )
            .await
            .assume("stream not received")?
            .into_receive()
            .ok()
            .assume("is recv stream")?;
        let bytes = recv2_1.receive().await?.assume("no data received")?;
        assert_eq!(bytes, msg1);
    }

    Ok(())
}

/// Demonstrate that a device cannot create an AQC channel with a label that is not assigned to it.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_not_auth_label_sender() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut devices = DevicesCtx::new("test_aqc_chans_not_auth_label_sender", work_dir).await?;
    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label2, op)
        .await?;

    let label3 = operator_team.create_label(text!("label3")).await?;
    let op = ChanOp::SendRecv;
    // assign label 3 to only the receiver, we are testing if the sender can create
    // a channel without the label assignment
    operator_team
        .assign_label(devices.memberb.id, label3, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let err = try_join(
        devices.membera.client.aqc().create_bidi_channel(
            team_id,
            devices.memberb.aqc_net_id(),
            label3,
        ),
        devices.memberb.client.aqc().receive_channel(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, aranya_client::error::Error::Aranya(_)));

    Ok(())
}

/// Demonstrate that a device cannot receive an AQC channel with a label that is not assigned to the device.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_not_auth_label_recvr() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut devices = DevicesCtx::new("test_aqc_chans_not_auth_label_recvr", work_dir).await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label2, op)
        .await?;

    let label3 = operator_team.create_label(text!("label3")).await?;
    let op = ChanOp::SendRecv;
    // assign label 3 to only the sender, we are testing if the receiver can receive
    // a channel without the label assignment
    operator_team
        .assign_label(devices.membera.id, label3, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    let err = try_join(
        devices.membera.client.aqc().create_bidi_channel(
            team_id,
            devices.memberb.aqc_net_id(),
            label3,
        ),
        devices.memberb.client.aqc().receive_channel(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, aranya_client::error::Error::Aranya(_)));

    Ok(())
}

/// Demonstrate that data cannot be received on a closed AQC QUIC stream.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_close_sender_stream() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut devices = DevicesCtx::new("test_aqc_chans_close_sender_stream", work_dir).await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label2, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            devices.membera.client.aqc().create_bidi_channel(
                team_id,
                devices.memberb.aqc_net_id(),
                label1,
            ),
            devices.memberb.client.aqc().receive_channel(),
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

        devices
            .membera
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan1)
            .await?;
        devices
            .memberb
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan2)
            .await?;
    }

    Ok(())
}

/// Demonstrate that data cannot be sent or received on a deleted AQC channel.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans_delete_chan_send_recv() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut devices = DevicesCtx::new("test_aqc_chans_delete_chan_send", work_dir).await?;

    // create team.
    let team_id = devices.create_and_add_team().await?;

    // Tell all peers to sync with one another, and assign their roles.
    devices.add_all_device_roles(team_id).await?;

    let operator_team = devices.operator.client.team(team_id);
    operator_team
        .assign_aqc_net_identifier(devices.membera.id, devices.membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(devices.memberb.id, devices.memberb.aqc_net_id())
        .await?;

    let label1 = operator_team.create_label(text!("label1")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label1, op)
        .await?;

    let label2 = operator_team.create_label(text!("label2")).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(devices.membera.id, label2, op)
        .await?;
    operator_team
        .assign_label(devices.memberb.id, label2, op)
        .await?;

    // wait for syncing.
    let operator_addr = devices.operator.aranya_local_addr().await?.into();
    devices
        .membera
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;
    devices
        .memberb
        .client
        .team(team_id)
        .sync_now(operator_addr, None)
        .await?;

    {
        let (mut bidi_chan1, peer_channel) = try_join(
            devices.membera.client.aqc().create_bidi_channel(
                team_id,
                devices.memberb.aqc_net_id(),
                label1,
            ),
            devices.memberb.client.aqc().receive_channel(),
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

        devices
            .membera
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan1)
            .await?;
        devices
            .memberb
            .client
            .aqc()
            .delete_bidi_channel(bidi_chan2)
            .await?;

        // wait for ctrl message to be sent.
        sleep(Duration::from_millis(100)).await;

        // try sending after channels are closed
        let msg2 = Bytes::from_static(b"hello2");
        let err = bidi1_2.send(msg2.clone()).await.err().unwrap();
        assert!(matches!(
            err,
            aranya_client::error::AqcError::StreamError(_)
        ));

        // try receiving after channels are closed.
        let err = bidi1_2.receive().await.err().unwrap();
        assert!(matches!(
            err,
            aranya_client::error::AqcError::StreamError(_)
        ));
    }

    Ok(())
}
