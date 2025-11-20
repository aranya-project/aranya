//! Member B device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{afc::Channels, AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_example_multi_node::{
    env::EnvVars,
    get_member_peer,
    onboarding::{DeviceInfo, Onboard, TeamInfo, SLEEP_INTERVAL, SYNC_INTERVAL},
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tokio::time::sleep;
use tracing::info;

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon UDS socket path.
    #[arg(long)]
    uds_sock: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing(module_path!());
    info!("starting aranya-example-multi-node-memberb");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Start TCP server.
    info!("memberb: starting onboarding server");
    let onboard = Onboard::new(env.memberb.tcp_addr, env.passphrase).await?;
    info!("memberb: started onboarding server");

    // Initialize client.
    info!("memberb: initializing client");
    let client = (|| {
        Client::builder()
            .with_daemon_uds_path(&args.uds_sock)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("memberb: initialized client");

    // Get team info from owner.
    let team_info: TeamInfo = onboard.recv().await?;
    info!("memberb: received team info from owner");

    // Add team.
    let add_team_cfg = {
        let qs_cfg = AddTeamQuicSyncConfig::builder()
            .seed_ikm(team_info.seed_ikm)
            .build()?;
        AddTeamConfig::builder()
            .quic_sync(qs_cfg)
            .team_id(team_info.team_id)
            .build()?
    };
    let team = client
        .add_team(add_team_cfg.clone())
        .await
        .expect("expected to add team");
    info!("memberb: added team");

    // Send device info to owner.
    info!("memberb: sending device info to owner");
    let device_id = client.get_device_id().await?;
    let pk = client.get_key_bundle().await?;
    onboard
        .send(
            &DeviceInfo {
                name: env.memberb.name.clone(),
                device_id,
                pk: pk.clone(),
            },
            env.owner.tcp_addr,
        )
        .await?;
    info!("memberb: sent device info to owner");

    // Setup sync peers.
    let sync_cfg = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
    info!("memberb: adding operator sync peer");
    team.add_sync_peer(env.operator.sync_addr, sync_cfg.clone())
        .await
        .expect("expected to add sync peer");

    // wait for syncing.
    sleep(SLEEP_INTERVAL).await;

    // Wait for admin to create label.
    info!("memberb: waiting for admin to create label");
    loop {
        if let Ok(labels) = team.labels().await {
            if labels.iter().next().is_some() {
                break;
            }
        }
        sleep(SLEEP_INTERVAL).await;
    }

    // Loop until all devices have been added to the team.
    info!("memberb: waiting for all devices to be added to team");
    loop {
        if let Ok(devices) = team.devices().await {
            if devices.iter().count() == 5 {
                break;
            }
        }
        sleep(3 * SLEEP_INTERVAL).await;
    }
    info!("memberb: detected that all devices have been added to team");

    // Send device info to operator.
    info!("memberb: sending device info to operator");

    onboard
        .send(
            &DeviceInfo {
                name: env.memberb.name,
                device_id,
                pk,
            },
            env.operator.tcp_addr,
        )
        .await?;
    info!("memberb: sent device info to operator");

    // wait for syncing.
    sleep(SLEEP_INTERVAL).await;

    // Check that label has been assigned to memberb.
    loop {
        if let Ok(labels) = team.device(device_id).label_assignments().await {
            if labels.iter().count() == 1 {
                break;
            }
        }
        sleep(3 * SLEEP_INTERVAL).await;
    }

    // Remove operator sync peer.
    info!("memberb: removing operator sync peer");
    team.remove_sync_peer(env.operator.sync_addr).await?;

    let membera = get_member_peer(&client, team_info.team_id).await?;

    let receiver = TcpServer::bind(env.memberb.afc_addr).await?;
    let mut sender = TcpClient::new();

    info!("memberb: creating recv channel");
    let ctrl = receiver.recv().await?;
    let mut opener = client
        .afc()
        .accept_channel(team_info.team_id, ctrl.into_boxed_slice().into())
        .await?;

    info!("memberb: receiving AFC data");
    let resp = receiver.recv().await?;
    let mut msg_recv = vec![0u8; resp.len() - Channels::OVERHEAD];
    opener.open(&mut msg_recv, &resp)?;
    info!("memberb: received AFC data");

    info!("memberb: creating send channel");
    let (mut sealer, ctrl) = client
        .afc()
        .create_channel(team_info.team_id, membera, opener.label_id())
        .await?;
    sender.send(env.membera.afc_addr, ctrl.as_bytes()).await?;

    info!("memberb: sending AFC data");
    let msg_send = b"hello";
    let mut req = vec![0u8; msg_send.len() + Channels::OVERHEAD];
    sealer.seal(&mut req, msg_send)?;
    sender.send(env.membera.afc_addr, &req).await?;
    info!("memberb: sent AFC data");

    info!("memberb: complete");

    Ok(())
}
