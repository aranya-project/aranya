//! Admin device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{text, AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
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
    info!("starting aranya-example-multi-node-admin");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Start TCP server.
    info!("admin: starting onboarding server");
    let onboard = Onboard::new(env.admin.tcp_addr, env.passphrase).await?;
    info!("admin: started onboarding server");

    // Initialize client.
    info!("admin: initializing client");
    let client = (|| {
        Client::builder()
            .with_daemon_uds_path(&args.uds_sock)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("admin: initialized client");

    // Get team info from owner.
    let team_info: TeamInfo = onboard.recv().await?;
    info!("admin: received team info from owner");

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
    info!("admin: added team");

    // Send device info to owner.
    info!("admin: sending device info to owner");
    let device_id = client.get_device_id().await?;
    let pk = client.get_public_key_bundle().await?;
    onboard
        .send(
            &DeviceInfo {
                name: env.admin.name,
                device_id,
                pk,
            },
            env.owner.tcp_addr,
        )
        .await?;
    info!("admin: sent device info to owner");

    // Setup sync peers.
    info!("admin: adding owner sync peer");
    let sync_cfg = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
    team.add_sync_peer(env.owner.sync_addr, sync_cfg.clone())
        .await?;

    // Loop until this device has the `Admin` role assigned to it.
    info!("admin: finding admin role");
    let admin_role = loop {
        if let Ok(roles) = team.roles().await {
            if let Some(role) = roles.into_iter().find(|role| role.name == "admin") {
                break role;
            }
        }
        sleep(SLEEP_INTERVAL).await;
    };
    info!("admin: waiting for owner to assign admin role");
    loop {
        if let Ok(Some(r)) = team.device(device_id).role().await {
            if r == admin_role {
                break;
            }
        }
        sleep(SLEEP_INTERVAL).await;
    }
    info!("admin: detected that owner has assigned admin role");

    // Create label.
    info!("admin: creating label");
    let label1 = team.create_label(text!("label1"), admin_role.id).await?;
    info!("admin: created label");

    info!("admin: finding operator role");
    let operator_role = loop {
        if let Ok(roles) = team.roles().await {
            if let Some(role) = roles.into_iter().find(|role| role.name == "operator") {
                break role;
            }
        }
        sleep(SLEEP_INTERVAL).await;
    };

    info!("admin: assigning operator role to manage label1");
    team.add_label_managing_role(label1, operator_role.id)
        .await?;

    info!("admin: complete");

    Ok(())
}
