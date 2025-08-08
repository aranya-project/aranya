//! Member A device.

use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client};
use aranya_daemon_api::TeamId;
use aranya_example_multi_node::{env::EnvVars, tcp::TcpServer, tracing::init_tracing};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tracing::info;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon UDS socket path.
    #[arg(long)]
    uds_sock: PathBuf,
    /// AQC server address.
    #[arg(long)]
    aqc_addr: Addr,
    /// TCP server address for receiving team info from owner.
    #[arg(long)]
    tcp_addr: Addr,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-membera");

    // Parse input args.
    let args = Args::parse();
    let _env = EnvVars::load()?;

    // Start TCP server.
    info!("membera: starting tcp server");
    let server = TcpServer::bind(args.tcp_addr).await?;
    info!("membera: started tcp server");

    // Initialize client.
    info!("membera: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&args.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("membera: initialized client");

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&server.recv().await?)?;
    info!("membera: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&server.recv().await?)?;
    info!("membera: received seed ikm from owner");

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
    let _team = client.add_team(add_team_cfg.clone()).await?;
    info!("membera: added team");

    Ok(())
}
