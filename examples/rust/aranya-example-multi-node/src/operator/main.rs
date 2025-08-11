//! Operator device.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{text, ChanOp, NetIdentifier, TeamId};
use aranya_example_multi_node::{
    config::create_config,
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tempfile::tempdir;
use tokio::time::sleep;
use tracing::{error, info};

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon executable path.
    #[arg(long)]
    daemon_path: PathBuf,
}

/// Name of the current Aranya device.
const DEVICE_NAME: &str = "operator";

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-operator");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Generate daemon config file.
    let tmp = tempdir()?;
    info!("operator: generating daemon config");
    let cfg = create_config(
        DEVICE_NAME.to_string(),
        env.operator.sync_addr,
        tmp.path().into(),
    )
    .await
    .expect("expected to generate daemon config file");

    // Start daemon.
    info!("operator: starting daemon");
    let mut child = Command::new(args.daemon_path)
        .arg("--config")
        .arg(cfg)
        .spawn()?;
    let uds_sock = tmp
        .path()
        .join(DEVICE_NAME)
        .join("daemon")
        .join("run")
        .join("uds.sock");
    // Wait for daemon to start.
    sleep(Duration::from_secs(1)).await;
    info!("operator: started daemon");

    if let Err(e) = run(&uds_sock, &env).await {
        error!(?e);
        // Stop the daemon.
        let _ = child.kill();
        return Err(e);
    };

    // Stop the daemon.
    let _ = child.kill();

    Ok(())
}

async fn run(uds_sock: &Path, env: &EnvVars) -> Result<()> {
    // Start TCP server.
    info!("operator: starting tcp server");
    let server = TcpServer::bind(env.operator.tcp_addr).await?;
    info!("operator: started tcp server");

    // Initialize client.
    info!("operator: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(uds_sock)
            .aqc_server_addr(&env.operator.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("operator: initialized client");

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&server.recv().await?)?;
    info!("operator: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&server.recv().await?)?;
    info!("operator: received seed ikm from owner");

    // Add team.
    let add_team_cfg = {
        let qs_cfg = AddTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        AddTeamConfig::builder()
            .quic_sync(qs_cfg)
            .team_id(team_id)
            .build()?
    };
    let team = client.add_team(add_team_cfg.clone()).await?;
    info!("operator: added team");

    // Send device ID to owner.
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&postcard::to_allocvec(&client.get_device_id().await?)?)
        .await?;

    // Send public keys to owner.
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&postcard::to_allocvec(&client.get_key_bundle().await?)?)
        .await?;

    // Setup sync peers.
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;
    info!("operator: adding admin sync peer");
    team.add_sync_peer(env.admin.sync_addr, sync_cfg.clone())
        .await?;

    // Wait to sync effects.
    sleep(sleep_interval).await;

    // Remove admin sync peer.
    info!("operator: removing admin sync peer");
    team.remove_sync_peer(env.admin.sync_addr).await?;

    // Get device info from membera and memberb.
    // TODO: get human-readable name from owner or graph.
    let (membera, memberb) = {
        let info1: DeviceInfo = postcard::from_bytes(&server.recv().await?)?;
        info!("operator: received device info from {}", info1.name);
        let info2: DeviceInfo = postcard::from_bytes(&server.recv().await?)?;
        info!("operator: received device info from {}", info2.name);

        if info1.name == "membera" {
            (info1.device_id, info2.device_id)
        } else {
            (info2.device_id, info1.device_id)
        }
    };

    // Assign network identifiers for AQC.
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

    // Create label.
    info!("operator: creating aqc label");
    let label1 = team.create_label(text!("label1")).await?;

    // Assign label to members.
    let op = ChanOp::SendRecv;
    info!("operator: assigning label to membera");
    team.assign_label(membera, label1, op).await?;
    info!("operator: assigning label to memberb");
    team.assign_label(memberb, label1, op).await?;

    // Allow peers to sync with added label commands.
    sleep(sleep_interval).await;

    info!("operator: complete");

    Ok(())
}
