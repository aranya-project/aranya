//! Operator device.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{text, ChanOp, NetIdentifier, Role, TeamId};
use aranya_example_multi_node::{
    age::AgeEncryptor,
    config::create_config,
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tempfile::tempdir;
use tokio::{process::Command, time::sleep};
use tracing::info;

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
    let _child = Command::new(args.daemon_path)
        .kill_on_drop(true)
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
    sleep(Duration::from_secs(2)).await;
    info!("operator: started daemon");

    // Start TCP server.
    info!("operator: starting tcp server");
    let server = TcpServer::bind(env.operator.tcp_addr).await?;
    info!("operator: started tcp server");

    // Initialize client.
    info!("operator: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&uds_sock)
            .aqc_server_addr(&env.operator.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("operator: initialized client");

    // Initialize `age` encryptor.
    let encryptor = AgeEncryptor::new(env.passphrase);

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
    info!("operator: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
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
    info!("operator: sending device ID to owner");
    let device_id = client.get_device_id().await?;
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&device_id)?)?)
        .await?;
    info!("operator: sent device ID to owner");

    // Send public keys to owner.
    info!("operator: sending public keys to owner");
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&client.get_key_bundle().await?)?)?)
        .await?;
    info!("operator: sent public keys to owner");

    // Setup sync peers.
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;
    info!("operator: adding admin sync peer");
    team.add_sync_peer(env.admin.sync_addr, sync_cfg.clone())
        .await?;

    // Wait to sync effects.
    sleep(sleep_interval).await;

    // Loop until this device has the `Operator` role assigned to it.
    info!("operator: waiting for all devices to be added to team and operator role assignment");
    let queries = team.queries();
    'outer: loop {
        if let Ok(devices) = queries.devices_on_team().await {
            if devices.iter().count() == 5 {
                for device in devices.iter() {
                    if let Ok(Role::Operator) = queries.device_role(*device).await {
                        break 'outer;
                    }
                }
            }
        }
        sleep(3 * sleep_interval).await;
    }
    info!("operator: detected that all devices have been added to team and operator role has been assigned");

    // Remove admin sync peer.
    info!("operator: removing admin sync peer");
    team.remove_sync_peer(env.admin.sync_addr).await?;

    // Get device info from membera and memberb.
    // TODO: get human-readable name from owner or graph.
    let (membera, memberb) = {
        let info1: DeviceInfo = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
        info!("operator: received device info from {}", info1.name);
        let info2: DeviceInfo = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
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

    // Create label.
    info!("operator: creating aqc label");
    let label1 = team.create_label(text!("label1")).await?;
    info!("operator: created aqc label");

    // Assign label to members.
    let op = ChanOp::SendRecv;
    info!("operator: assigning label to membera");
    team.assign_label(membera, label1, op).await?;
    info!("operator: assigned label to membera");
    info!("operator: assigning label to memberb");
    team.assign_label(memberb, label1, op).await?;
    info!("operator: assigned label to memberb");

    // Allow peers to sync with added label commands.
    sleep(3 * sleep_interval).await;

    info!("operator: complete");

    Ok(())
}
