//! Operator device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{client::ChanOp, AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_example_multi_node::{
    env::EnvVars,
    onboarding::{DeviceInfo, Onboard, TeamInfo, SLEEP_INTERVAL, SYNC_INTERVAL},
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
    info!("starting aranya-example-multi-node-operator");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Start TCP server.
    info!("operator: starting onboarding server");
    let onboard = Onboard::new(env.operator.tcp_addr, env.passphrase).await?;
    info!("operator: started onboarding server");

    // Initialize client.
    info!("operator: initializing client");
    let client = (|| {
        Client::builder()
            .with_daemon_uds_path(&args.uds_sock)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("operator: initialized client");

    // Get team info from owner.
    let team_info: TeamInfo = onboard.recv().await?;
    info!("operator: received team info from owner");

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
    let team = client.add_team(add_team_cfg.clone()).await?;
    info!("operator: added team");

    // Send device info to owner.
    info!("operator: sending device info to owner");
    let device_id = client.get_device_id().await?;
    let pk = client.get_key_bundle().await?;
    onboard
        .send(
            &DeviceInfo {
                name: env.operator.name,
                device_id,
                pk,
            },
            env.owner.tcp_addr,
        )
        .await?;
    info!("operator: sent device info to owner");

    // Setup sync peers.
    let sync_cfg = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
    info!("operator: adding admin sync peer");
    team.add_sync_peer(env.admin.sync_addr, sync_cfg.clone())
        .await?;

    // Wait to sync effects.
    sleep(SLEEP_INTERVAL).await;

    // Wait for admin to create label.
    let label1 = loop {
        if let Ok(labels) = team.labels().await {
            if let Some(label) = labels.iter().next() {
                break label.clone();
            }
        }
        sleep(SLEEP_INTERVAL).await;
    };

    // Loop until this device has the `Operator` role assigned to it.
    info!("operator: waiting for all devices to be added to team and operator role assignment");
    loop {
        if let Ok(devices) = team.devices().await {
            if devices.iter().count() == 5 {
                break;
            }
        }
        sleep(
            SLEEP_INTERVAL
                .checked_mul(3)
                .expect("sleep interval should not overflow"),
        )
        .await;
    }
    let operator_role = team
        .roles()
        .await?
        .iter()
        .find(|r| r.name == "operator")
        .ok_or_else(|| anyhow::anyhow!("no operator role"))?
        .clone();
    loop {
        if let Ok(Some(r)) = team.device(device_id).role().await {
            if r == operator_role {
                break;
            }
        }
        sleep(
            SLEEP_INTERVAL
                .checked_mul(3)
                .expect("sleep interval should not overflow"),
        )
        .await;
    }
    info!("operator: detected that all devices have been added to team and operator role has been assigned");

    // Remove admin sync peer.
    info!("operator: removing admin sync peer");
    team.remove_sync_peer(env.admin.sync_addr).await?;

    // Get device info from membera and memberb.
    // TODO: get human-readable name from owner or graph.
    let (membera, memberb) = {
        let info1: DeviceInfo = onboard.recv().await?;
        info!("operator: received device info from {}", info1.name);
        let info2: DeviceInfo = onboard.recv().await?;
        info!("operator: received device info from {}", info2.name);

        if info1.name == "membera" {
            (info1.device_id, info2.device_id)
        } else {
            (info2.device_id, info1.device_id)
        }
    };

    // Assign label to members.
    let op = ChanOp::SendRecv;
    info!("operator: assigning label to membera");
    team.device(membera).assign_label(label1.id, op).await?;
    info!("operator: assigned label to membera");
    info!("operator: assigning label to memberb");
    team.device(memberb).assign_label(label1.id, op).await?;
    info!("operator: assigned label to memberb");

    info!("operator: complete");

    Ok(())
}
