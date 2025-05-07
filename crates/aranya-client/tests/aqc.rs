use std::time::Duration;

mod common;
use anyhow::Result;
use aranya_client::{aqc::net::AqcChannelType, TeamConfig};
use aranya_crypto::csprng::rand;
use aranya_daemon_api::ChanOp;
use buggy::BugExt;
use bytes::Bytes;
use common::{sleep, TeamCtx};
use tempfile::tempdir;
use tracing::info;

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("../src/aqc/cert.pem");
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("../src/aqc/key.pem");

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

    // wait for syncing.
    sleep(sleep_interval).await;

    // membera creates aqc bidi channel with memberb
    let mut bidi_chan1 = team
        .membera
        .client
        .aqc()
        .create_bidi_channel(team_id, team.memberb.aqc_addr.clone(), label1)
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let channel_type = team
        .memberb
        .client
        .aqc()
        .receive_channel()
        .await
        .assume("channel must exist")?;
    let mut bidi_chan2 = match channel_type {
        AqcChannelType::Bidirectional { channel } => channel,
        _ => {
            buggy::bug!("Expected a bidirectional channel")
        }
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut send1_1 = bidi_chan1.create_uni_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Receive a unidirectional stream from peer 1
    let (maybe_send2_1, mut recv2_1) = bidi_chan2
        .receive_stream()
        .await
        .assume("stream not received")?;
    assert!(maybe_send2_1.is_none(), "Expected unidirectional stream");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_1
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello");

    let (mut send1_2, mut recv1_2) = bidi_chan1.create_bidi_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Send from 1 to 2 with a bidirectional stream
    let msg2 = Bytes::from("hello2");
    send1_2.send(&msg2).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (maybe_send2_2, mut recv2_2) = bidi_chan2
        .receive_stream()
        .await
        .assume("stream not received")?;
    let mut send2_2 = maybe_send2_2.expect("Expected bidirectional stream");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_2
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello2");
    // Send from 2 to 1 with a bidirectional stream
    let msg3 = Bytes::from("hello3");
    send2_2.send(&msg3).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv1_2
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello3");

    // Test sending a large message
    let big_data = {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1024 * 1024 * 3 / 2];
        rand::Rng::fill(&mut rng, &mut data[..]);
        Bytes::from(data)
    };

    send1_2.send(&big_data).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut total_len: usize = 0;
    let mut total_pieces: i32 = 0;
    // Send stream should return the message in pieces
    while let Some(len) = recv2_2.receive(&mut target[total_len..]).await? {
        total_pieces = total_pieces.checked_add(1).expect("Pieces overflow");
        total_len = total_len.checked_add(len).expect("Length overflow");
        if total_len >= big_data.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(total_pieces > 1);
    assert_eq!(total_len, big_data.len());
    assert_eq!(&target[..total_len], &big_data[..]);

    bidi_chan1.close()?;
    bidi_chan2.close()?;
    // membera creates aqc uni channel with memberb
    let mut uni_chan1 = team
        .membera
        .client
        .aqc()
        .create_uni_channel(team_id, team.memberb.aqc_addr.clone(), label1)
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let channel_type = team
        .memberb
        .client
        .aqc()
        .try_receive_channel()
        .expect("channel must exist");
    let mut uni_chan2 = match channel_type {
        AqcChannelType::Receiver { receiver } => receiver,
        _ => {
            buggy::bug!("Expected a unidirectional channel")
        }
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut send1_1 = uni_chan1.create_uni_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut recv2_1 = uni_chan2
        .receive_uni_stream()
        .await
        .assume("stream not received")?
        .assume("stream not received")?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_1
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello");
    Ok(())
}
