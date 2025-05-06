use std::time::Duration;

mod common;
use anyhow::Result;
use aranya_client::{aqc::net::AqcChannelType, TeamConfig};
use aranya_daemon_api::ChanOp;
use bytes::Bytes;
use common::{sleep, TeamCtx};
use tempfile::tempdir;
use tokio::task::JoinSet;
use tracing::info;

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("../src/aqc/cert.pem");
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("../src/aqc/key.pem");

// Test AQC channels.
//
// Have each member device do the following in parallel:
// 1. Create a bidirectional channel with each peer.
// 2. Create a unidirectional channel with each peer.
// 3. Send data over each channel that supports sending data.
// 4. Receive data over each channel that supports receiving data.
// 5. Delete all the channels that were created by the device.
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
    operator_team
        .assign_aqc_net_identifier(team.memberc.id, team.memberc.aqc_addr.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    const NUM_DEVICES: i8 = 3;
    const LABELS_PER_DEVICE: i8 = 4;
    const NUM_LABELS: i8 = NUM_DEVICES * LABELS_PER_DEVICE;
    let mut labels = Vec::new();
    for i in 0..NUM_LABELS {
        let label = operator_team
            .create_label(format!("label{}", i).to_string())
            .await?;
        labels.push(label);
    }
    // TODO: test with different ops.
    let op = ChanOp::SendRecv;

    // wait for syncing.
    sleep(sleep_interval).await;

    let membera_peers = [team.memberb.aqc_addr.clone(), team.memberc.aqc_addr.clone()];
    let memberb_peers = [team.membera.aqc_addr.clone(), team.memberc.aqc_addr.clone()];
    let memberc_peers = [team.membera.aqc_addr.clone(), team.memberb.aqc_addr.clone()];
    let peers = [membera_peers, memberb_peers, memberc_peers];
    let mut devices = Vec::new();
    devices.push(team.membera);
    devices.push(team.memberb);
    devices.push(team.memberc);

    // Assign labels to all devices.
    // TODO: only assign labels to devices that use them.
    for device in &devices {
        for label in &labels {
            operator_team.assign_label(device.id, *label, op).await?;
        }
    }
    // wait for syncing.
    sleep(sleep_interval).await;

    // Run AQC channel tests in parallel.
    let mut set = JoinSet::new();
    for i in 0..devices.len() {
        let mut device = devices.pop().expect("expected a device");
        let peers = peers[i].clone();
        let mut l = Vec::new();
        for _i in 0..LABELS_PER_DEVICE {
            l.push(labels.pop().expect("expected label"));
        }
        set.spawn(async move {
            let mut bidi_chans = Vec::new();
            let mut uni_chans = Vec::new();
            for peer in peers {
                // create bidirectional channels with each peer.
                let bidi = device
                    .client
                    .aqc()
                    .create_bidi_channel(team_id, peer.clone(), l.pop().expect("expected label"))
                    .await
                    .expect("expected to create bidi chan");
                bidi_chans.push(bidi);

                // create unidirectional channels with each peer.
                let uni = device
                    .client
                    .aqc()
                    .create_uni_channel(team_id, peer, l.pop().expect("expected label"))
                    .await
                    .expect("expected to create bidi chan");
                uni_chans.push(uni);
            }
            // Receive any channels that were created.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut recv_chans = Vec::new();
            while let Some(recv_chan) = device.client.aqc().receive_channel().await {
                recv_chans.push(recv_chan);
            }

            // Send data over all created channels that support send.
            // TODO: test create_bidirectional_stream()
            for bidi in &mut bidi_chans {
                let mut send = bidi
                    .create_unidirectional_stream()
                    .await
                    .expect("expected to create uni stream");
                let msg = Bytes::from("hello");
                send.send(&msg).await.expect("expected to send data");
            }
            for uni in &mut uni_chans {
                let mut send = uni
                    .create_unidirectional_stream()
                    .await
                    .expect("expected to create uni stream");
                let msg = Bytes::from("hello");
                send.send(&msg).await.expect("expected to send data");
            }

            // Send data over all received channels that support send.
            // TODO: test sending larger messages.
            // TODO: send different data over each channel.
            for uni in &mut recv_chans {
                let mut send = match uni {
                    AqcChannelType::Sender { ref mut sender } => sender
                        .create_unidirectional_stream()
                        .await
                        .expect("expected to create uni stream"),
                    AqcChannelType::Receiver { .. } => continue,
                    AqcChannelType::Bidirectional { ref mut channel } => channel
                        .create_unidirectional_stream()
                        .await
                        .expect("expected to create uni stream"),
                };
                let msg = Bytes::from("hello");
                send.send(&msg).await.expect("expected to send data");
            }

            // Receive data over all created and received channels that support receiving data.
            tokio::time::sleep(Duration::from_millis(100)).await;
            for bidi in &mut bidi_chans {
                while let Some((_send, mut recv)) = bidi.receive_stream().await {
                    let mut buf = vec![0u8; 1024 * 1024 * 2];
                    let len = recv
                        .receive(buf.as_mut_slice())
                        .await
                        .expect("expected to receive data")
                        .expect("no data received");
                    assert_eq!(&buf[..len], b"hello");
                }
            }
            for uni in &mut recv_chans {
                let mut streams = Vec::new();
                match uni {
                    AqcChannelType::Sender { .. } => continue,
                    AqcChannelType::Receiver { ref mut receiver } => {
                        while let Some(recv) = receiver
                            .receive_unidirectional_stream()
                            .await
                            .expect("expected no error")
                        {
                            streams.push(recv);
                        }
                    }
                    AqcChannelType::Bidirectional { ref mut channel } => {
                        while let Some((_send, recv)) = channel.receive_stream().await {
                            streams.push(recv);
                        }
                    }
                };
                for mut recv in streams {
                    let mut buf = vec![0u8; 1024 * 1024 * 2];
                    let len = recv
                        .receive(buf.as_mut_slice())
                        .await
                        .expect("expected to receive data")
                        .expect("no data received");
                    assert_eq!(&buf[..len], b"hello");
                }
            }

            // Delete all channels created by the device.
            for bidi in &mut bidi_chans {
                bidi.close().expect("expected to close bidi channel");
            }
            for uni in &mut uni_chans {
                uni.close().expect("expected to close uni chan");
            }

            // TODO: verify total messages send/received.

            // TODO: optimize this delay.
            tokio::time::sleep(Duration::from_millis(1000)).await;
        });
    }
    set.join_all().await;

    Ok(())
}
