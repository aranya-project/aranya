//! Admin device.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{Role, TeamId};
use aranya_example_multi_node::{
    age::AgeEncryptor,
    config::create_config,
    env::EnvVars,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tempfile::tempdir;
use tokio::{process::Command, time::sleep};
use tracing::info;

/// Name of the current Aranya device.
const DEVICE_NAME: &str = "admin";

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon executable path.
    #[arg(long)]
    daemon_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-admin");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Generate daemon config file.
    let tmp = tempdir()?;
    info!("admin: generating daemon config");
    let cfg = create_config(
        DEVICE_NAME.to_string(),
        env.admin.sync_addr,
        tmp.path().into(),
    )
    .await
    .expect("expected to generate daemon config file");

    // Start daemon.
    info!("admin: starting daemon");
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
    info!("admin: started daemon");

    // Start TCP server.
    info!("admin: starting tcp server");
    let server = TcpServer::bind(env.admin.tcp_addr).await?;
    info!("admin: started tcp server");

    // Initialize client.
    info!("admin: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&uds_sock)
            .aqc_server_addr(&env.admin.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("admin: initialized client");

    // Initialize `age` encryptor.
    let encryptor = AgeEncryptor::new(env.passphrase);

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
    info!("admin: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
    info!("admin: received seed ikm from owner");

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
    info!("admin: added team");

    // Send device ID to owner.
    info!("admin: sending device ID to owner");
    let device_id = client.get_device_id().await?;
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&device_id)?)?)
        .await?;
    info!("admin: sent device ID to owner");

    // Send public keys to owner.
    info!("admin: sending public keys to owner");
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&client.get_key_bundle().await?)?)?)
        .await?;
    info!("admin: sent public keys to owner");

    // Setup sync peers.
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    info!("admin: adding owner sync peer");
    team.add_sync_peer(env.owner.sync_addr, sync_cfg.clone())
        .await?;

    // Wait for syncing.
    sleep(sleep_interval).await;

    // Loop until this device has the `Admin` role assigned to it.
    let queries = team.queries();
    info!("admin: waiting for admin role assignment");
    loop {
        if let Ok(Role::Admin) = queries.device_role(device_id).await {
            break;
        }
        sleep(sleep_interval).await;
    }
    info!("admin: detected admin role assignment");

    info!("admin: waiting for all devices to be added to team and operator role assignment");
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
    info!("admin: detected that all devices have been added to team and operator role has been assigned");

    // Wait for syncing.
    sleep(sleep_interval).await;

    // Remove owner sync peer.
    info!("admin: removing owner sync peer");
    team.remove_sync_peer(env.owner.sync_addr).await?;
    info!("admin: removed owner sync peer");

    info!("admin: complete");

    Ok(())
}
