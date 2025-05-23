use std::time::Duration;

mod common;
use anyhow::Result;
use aranya_client::{aqc::AqcPeerChannel, TeamConfig};
use aranya_crypto::csprng::rand;
use aranya_daemon_api::ChanOp;
use buggy::BugExt;
use bytes::{Bytes, BytesMut};
use common::{sleep, TeamCtx};
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
        .assign_aqc_net_identifier(team.membera.id, team.membera.aqc_addr.clone())
        .await?;
    operator_team
        .assign_aqc_net_identifier(team.memberb.id, team.memberb.aqc_addr.clone())
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

    let mut membera = team.membera;
    let memberb_aqc_addr = team.memberb.aqc_addr.clone();

    let create_handle = tokio::spawn(async move {
        let channel_result = membera
            .client
            .aqc()
            .create_bidi_channel(team_id, memberb_aqc_addr, label1)
            .await;
        (channel_result, membera)
    });

    let channel_type_result = team.memberb.client.aqc().receive_channel().await;

    let (bidi_chan1_result, membera) = create_handle
        .await
        .expect("Task panicked (channel creation)");

    team.membera = membera;
    let mut bidi_chan1 = bidi_chan1_result?;

    let channel_type = channel_type_result.assume("channel must exist on memberb")?;
    let mut bidi_chan2 = match channel_type {
        AqcPeerChannel::Bidirectional(channel) => channel,
        _ => buggy::bug!("Expected a bidirectional channel on memberb"),
    };

    let mut send1_1 = bidi_chan1.create_uni_stream().await?;

    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;
    // Receive a unidirectional stream from peer 1
    let (maybe_send2_1, mut recv2_1) = bidi_chan2
        .receive_stream()
        .await
        .assume("stream not received")?;
    assert!(maybe_send2_1.is_none(), "Expected unidirectional stream");
    let bytes = recv2_1.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg1);

    let (mut send1_2, mut recv1_2) = bidi_chan1.create_bidi_stream().await?;
    // Send from 1 to 2 with a bidirectional stream
    let msg2 = Bytes::from("hello2");
    send1_2.send(&msg2).await?;
    let (maybe_send2_2, mut recv2_2) = bidi_chan2
        .receive_stream()
        .await
        .assume("stream not received")?;
    let mut send2_2 = maybe_send2_2.expect("Expected bidirectional stream");
    let bytes = recv2_2.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg2);
    // Send from 2 to 1 with a bidirectional stream
    let msg3 = Bytes::from("hello3");
    send2_2.send(&msg3).await?;
    let bytes = recv1_2.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg3);

    // Test sending a large message
    let big_data = {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1024 * 1024 * 3 / 2];
        rand::Rng::fill(&mut rng, &mut data[..]);
        Bytes::from(data)
    };
    send1_2.send(&big_data).await?;
    let mut dest_bytes = BytesMut::new();
    // Send stream should return the message in pieces
    while let Some(bytes) = recv2_2.receive().await? {
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

    // membera creates aqc uni channel with memberb concurrently
    let mut membera = team.membera;
    let memberb_aqc_addr = team.memberb.aqc_addr.clone();

    let create_uni_handle = tokio::spawn(async move {
        let channel_result = membera
            .client
            .aqc()
            .create_uni_channel(team_id, memberb_aqc_addr, label1)
            .await;
        (channel_result, membera)
    });

    let channel_type_result = team.memberb.client.aqc().receive_channel().await;

    let (uni_chan1_result, membera) = create_uni_handle // Get back owned membera
        .await
        .expect("Task panicked (uni channel creation)");

    team.membera = membera;
    let mut uni_chan1 = uni_chan1_result?;

    let channel_type = channel_type_result.assume("uni channel must exist on memberb")?;
    let mut uni_chan2 = match channel_type {
        AqcPeerChannel::Receiver(receiver) => receiver,
        _ => {
            buggy::bug!("Expected a unidirectional channel")
        }
    };

    let mut send1_1 = uni_chan1.create_uni_stream().await?;

    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;

    let mut recv2_1 = uni_chan2.receive_uni_stream().await?;

    let bytes = recv2_1.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg1);

    let mut membera = team.membera;
    let memberb_aqc_addr = team.memberb.aqc_addr.clone();
    let create_handle = tokio::spawn(async move {
        let channel_result = membera
            .client
            .aqc()
            .create_bidi_channel(team_id, memberb_aqc_addr, label2)
            .await;
        (channel_result, membera)
    });

    let channel_type = loop {
        let channel_type_result = team.memberb.client.aqc().try_receive_channel();
        if let Ok(channel_type) = channel_type_result {
            break channel_type;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let (bidi_chan1_result, membera) = create_handle
        .await
        .expect("Task panicked (channel creation)");

    team.membera = membera;
    let mut bidi_chan1 = bidi_chan1_result?;

    let mut bidi_chan2 = match channel_type {
        AqcPeerChannel::Bidirectional(channel) => channel,
        _ => buggy::bug!("Expected a bidirectional channel on memberb"),
    };

    let mut send1_1 = bidi_chan1.create_uni_stream().await?;

    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Receive a unidirectional stream from peer 1
    let (maybe_send2_1, mut recv2_1) = bidi_chan2
        .try_receive_stream()
        .assume("stream not received")?;
    assert!(maybe_send2_1.is_none(), "Expected unidirectional stream");
    let bytes = recv2_1.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg1);
    Ok(())
}
