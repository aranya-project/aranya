//! Owner device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{Client, CreateTeamConfig, CreateTeamQuicSyncConfig};
use aranya_example_multi_node::{env::EnvVars, tcp::TcpClient, tracing::init_tracing};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tracing::info;

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon UDS socket path.
    #[arg(long)]
    uds_sock: PathBuf,
    /// AQC server address.
    #[arg(long)]
    aqc_addr: Addr,
    /// TCP server address for receiving team info from peers.
    #[arg(long)]
    tcp_addr: Addr,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-owner");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Initialize client.
    info!("owner: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&args.aqc_addr)
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
    for device in env.devices.get(1..).expect("expected devices") {
        info!("owner: sending team ID to {}", device.name);
        TcpClient::connect(device.tcp_addr)
            .await?
            .send(&postcard::to_allocvec(&team_id)?)
            .await?;
        info!("owner: sent team ID to {}", device.name);

        // Send seed IKM to admin.
        info!("owner: sending seed ikm to {}", device.name);
        TcpClient::connect(device.tcp_addr)
            .await?
            .send(&postcard::to_allocvec(&seed_ikm)?)
            .await?;
        info!("owner: sent seed ikm to {}", device.name);
    }

    Ok(())
}
