//! Operator device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{ChanOp, NetIdentifier, Role};
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
    init_tracing();
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
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&env.operator.aqc_addr)
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
    let queries = team.queries();
    let label1 = loop {
        if let Ok(labels) = queries.labels().await {
            if let Some(label1) = labels.iter().next() {
                break label1.id;
            }
        }
        sleep(SLEEP_INTERVAL).await;
    };

    // Loop until this device has the `Operator` role assigned to it.
    info!("operator: waiting for all devices to be added to team and operator role assignment");
    let queries = team.queries();
    loop {
        if let Ok(devices) = queries.devices_on_team().await {
            if devices.iter().count() == 5 {
                break;
            }
        }
        sleep(3 * SLEEP_INTERVAL).await;
    }
    loop {
        if let Ok(Role::Operator) = queries.device_role(device_id).await {
            break;
        }
        sleep(3 * SLEEP_INTERVAL).await;
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

    // Assign network identifiers for AQC.
    info!("operator: assigning network identifier to membera");
    team.assign_aqc_net_identifier(
        membera,
        NetIdentifier(
            env.membera
                .aqc_addr
                .to_string()
                .try_into()
                .expect("addr is valid text"),
        ),
    )
    .await
    .expect("expected to assign net identifier");
    info!("operator: assigned network identifier to membera");

    info!("operator: assigning network identifier to memberb");
    team.assign_aqc_net_identifier(
        memberb,
        NetIdentifier(
            env.memberb
                .aqc_addr
                .to_string()
                .try_into()
                .expect("addr is valid text"),
        ),
    )
    .await
    .expect("expected to assign net identifier");
    info!("operator: assigned network identifier to membera");

    // Assign label to members.
    let op = ChanOp::SendRecv;
    info!("operator: assigning label to membera");
    team.assign_label(membera, label1, op).await?;
    info!("operator: assigned label to membera");
    info!("operator: assigning label to memberb");
    team.assign_label(memberb, label1, op).await?;
    info!("operator: assigned label to memberb");

    info!("operator: complete");

    Ok(())
}
