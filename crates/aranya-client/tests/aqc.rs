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

    // TODO: add memberc back.
    let membera_peers = vec![team.memberb.aqc_addr.clone(), team.memberc.aqc_addr.clone()];
    let memberb_peers = vec![team.membera.aqc_addr.clone(), team.memberc.aqc_addr.clone()];
    let memberc_peers = vec![team.membera.aqc_addr.clone(), team.memberb.aqc_addr.clone()];
    let peers = [membera_peers, memberb_peers, memberc_peers];
    let mut devices = Vec::new();
    devices.push(team.memberc);
    devices.push(team.memberb);
    devices.push(team.membera);

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
            info!(?device.id, ?device.aqc_addr, peer_len=?peers.len());
            let mut bidi_chans = Vec::new();
            let mut uni_chans = Vec::new();
            for peer in peers {
                // create bidirectional channels with each peer.
                info!(?device.id, ?device.aqc_addr, ?peer, "creating bidi channel");
                let bidi = device
                    .client
                    .aqc()
                    .create_bidi_channel(team_id, peer.clone(), l.pop().expect("expected label"))
                    .await
                    .expect("expected to create bidi chan");
                bidi_chans.push(bidi);

                // create unidirectional channels with each peer.
                info!(?device.aqc_addr, ?peer, "creating uni channel");
                let uni = device
                    .client
                    .aqc()
                    .create_uni_channel(team_id, peer, l.pop().expect("expected label"))
                    .await
                    .expect("expected to create bidi chan");
                uni_chans.push(uni);
            }
            assert_eq!(bidi_chans.len(), 2);
            info!(?device.id, "created all bidi channels");
            //assert_eq!(uni_chans.len(), 2);
            //info!(?device.id, "created all uni channels");

            // Receive any channels that were created.
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let mut recv_chans = Vec::new();
            // TODO: receive specific number of channels when ctrl messages are more reliable.
            //loop {
                while let Ok(recv_chan) = device.client.aqc().try_receive_channel() {
                    info!(?device.id, "received channel");
                    recv_chans.push(recv_chan);
                };
                /*
                if recv_chans.len() >= 2 {
                    break;
                }
                */
            //}
            // TODO: verify number of channel received.
            //assert_eq!(recv_chans.len(), 2);
            info!(?device.id, "received all channels");

            // Create a unidirectional stream for each channel.
            // TODO: test create_bidirectional_stream()
            let mut send_streams = Vec::new();
            for bidi in &mut bidi_chans {
                info!(?device.id, "creating unidirectional stream");
                if let Ok(send) = bidi
                    .create_uni_stream()
                    .await {
                        info!(?device.id, "created unidirectional stream");
                        send_streams.push(send);
                    }
            }
            // TODO: verify number of send streams
            //assert_eq!(send_streams.len(), 2);
            
            for uni in &mut uni_chans {
                if let Ok(send) = uni
                    .create_uni_stream()
                    .await {
                        send_streams.push(send);
                    }
            }
            // TODO: verify number of send streams
            //assert_eq!(send_streams.len(), 4);

            // Send data over all send streams.
            for send in &mut send_streams {
                info!(?device.id, "sending chan data");
                let msg = Bytes::from("hello");
                send.send(&msg).await.expect("expected to send data");
                info!(?device.id, "sent chan data");
            }

            // Send data over all received channels that support send.
            // TODO: test sending larger messages.
            // TODO: send different data over each channel.
            // TODO: create_uni_stream should never fail.
            for uni in &mut recv_chans {
                let mut send = match uni {
                    AqcChannelType::Sender { ref mut sender } => {
                      let Ok(recv_chan) = sender
                        .create_uni_stream()
                        .await else {
                            continue;
                        };
                        recv_chan
                    },
                    AqcChannelType::Receiver { .. } => continue,
                    AqcChannelType::Bidirectional { ref mut channel } =>  {
                        let Ok(recv_chan) = channel
                        .create_uni_stream()
                        .await else {
                            continue;
                        };
                        recv_chan
                    },
                };
                info!(?device.id, "sending chan data for received channel");
                let msg = Bytes::from("hello");
                send.send(&msg).await.expect("expected to send data");
            }

            // Receive data over all created bidi channels.
            tokio::time::sleep(Duration::from_millis(100)).await;
            for bidi in &mut bidi_chans {
                while let Ok((_send, mut recv)) = bidi.try_receive_stream() {
                    let mut buf = vec![0u8; 1024 * 1024 * 2];
                    let len = recv
                        .receive(buf.as_mut_slice())
                        .await
                        .expect("expected to receive data")
                        .expect("no data received");
                    assert_eq!(&buf[..len], b"hello");
                    info!(?device.id, "received chan data for created bidi chan");
                }
            }
            // Receive data over all received streams.
            let mut recv_streams = Vec::new();
            for uni in &mut recv_chans {
                match uni {
                    AqcChannelType::Sender { .. } => continue,
                    AqcChannelType::Receiver { ref mut receiver } => {
                        while let Ok(recv) = receiver
                            .try_receive_uni_stream()
                        {
                            recv_streams.push(recv);
                        }
                    }
                    AqcChannelType::Bidirectional { ref mut channel } => {
                        while let Ok((_send, recv)) = channel.try_receive_stream() {
                            recv_streams.push(recv);
                        }
                    }
                };
            }
            for recv in &mut recv_streams {
                let mut buf = vec![0u8; 1024 * 1024 * 2];
                let len = recv
                    .receive(buf.as_mut_slice())
                    .await
                    .expect("expected to receive data")
                    .expect("no data received");
                assert_eq!(&buf[..len], b"hello");
                info!(?device.id, "received chan data for received stream");
            }

            // TODO: verify total messages sent/received.

            // TODO: optimize this delay.
            tokio::time::sleep(Duration::from_millis(1000)).await;

            // Delete all channels created by the device.
            info!(?device.id, "closing channels");
            for bidi in &mut bidi_chans {
                bidi.close().expect("expected to close bidi channel");
            }
            for uni in &mut uni_chans {
                uni.close().expect("expected to close uni chan");
            }

            info!(?device.id, "done");
        });
    }
    set.join_all().await;

    Ok(())
}
