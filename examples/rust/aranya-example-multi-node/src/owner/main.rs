//! Owner device.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use aranya_client::{Client, CreateTeamConfig, CreateTeamQuicSyncConfig};
use aranya_daemon_api::{DeviceId, KeyBundle, Role};
use aranya_example_multi_node::{
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
const DEVICE_NAME: &str = "owner";

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
    info!("starting aranya-example-multi-node-owner");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Generate daemon config file.
    let tmp = tempdir()?;
    info!("owner: generating daemon config");
    let cfg = create_config(
        DEVICE_NAME.to_string(),
        env.owner.sync_addr,
        tmp.path().into(),
    )
    .await
    .expect("expected to generate daemon config file");

    // Start daemon.
    info!("owner: starting daemon");
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
    info!("owner: started daemon");

    // Start TCP server.
    info!("owner: starting tcp server");
    let server = TcpServer::bind(env.owner.tcp_addr).await?;
    info!("owner: started tcp server");

    // Initialize client.
    info!("owner: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&uds_sock)
            .aqc_server_addr(&env.owner.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("owner: initialized client");

    // Create team.
    info!("owner: creating team");
    let seed_ikm = {
        let mut buf = [0; 32];
        client.rand(&mut buf).await;
        buf
    };
    let cfg = {
        let qs_cfg = CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        CreateTeamConfig::builder().quic_sync(qs_cfg).build()?
    };
    let team = client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    let team_id = team.team_id();
    info!("owner: created team: {}", team_id);

    // Send team ID and IKM to each device except for itself.
    // Receive the device ID and public key bundle from each device.
    // Add each device to the team.
    // Assign the proper role to each device.
    for device in &env.devices {
        if device.name == DEVICE_NAME {
            continue;
        }

        // Send team ID to device.
        info!("owner: sending team ID to {}", device.name);
        TcpClient::connect(device.tcp_addr)
            .await?
            .send(&postcard::to_allocvec(&team_id)?)
            .await?;
        info!("owner: sent team ID to {}", device.name);

        // Send seed IKM to device.
        info!("owner: sending seed ikm to {}", device.name);
        TcpClient::connect(device.tcp_addr)
            .await?
            .send(&postcard::to_allocvec(&seed_ikm)?)
            .await?;
        info!("owner: sent seed ikm to {}", device.name);

        // Receive device ID from device.
        let id: DeviceId = postcard::from_bytes(&server.recv().await?)?;
        info!("owner: received device ID from {}", device.name);

        // Receive public keys from device.
        let pk: KeyBundle = postcard::from_bytes(&server.recv().await?)?;
        info!("owner: received public keys from {}", device.name);

        team.add_device_to_team(pk).await?;
        info!("owner: added device to team {}", device.name);

        // Devices are assigned the `Role::Member` role by default when added to the team. No need to assign it again.
        if device.role != Role::Member {
            // Assign role to device.
            info!(
                "owner: assigning role {:?} to device {}",
                device.role, device.name
            );
            team.assign_role(id, device.role)
                .await
                .expect("expected to assign role");
            info!(
                "owner: assigned role {:?} to device {}",
                device.role, device.name
            );
        }
    }

    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    sleep(sleep_interval).await;

    info!("owner: complete");

    Ok(())
}
