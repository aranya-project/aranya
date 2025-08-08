use std::path::PathBuf;

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client};
use aranya_daemon_api::TeamId;
use aranya_example_multi_node::{env::EnvVars, tracing::init_tracing};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use tokio::{io::AsyncReadExt, net::TcpListener};
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
    info!("starting aranya-example-multi-node-admin");

    // Parse input args.
    let args = Args::parse();
    let _env = EnvVars::load()?;

    // Start TCP server.
    let listener = TcpListener::bind(args.tcp_addr.to_socket_addrs()).await?;

    // Initialize client.
    info!("admin: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&args.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("admin: initialized client");

    // Get team ID from owner.
    let mut buf = Vec::new();
    let (mut stream, _addr) = listener.accept().await?;
    let n = stream
        .read_to_end(&mut buf)
        .await
        .expect("expected to read_to_end on tcp stream");
    let team_id: TeamId = postcard::from_bytes(buf.get(0..n).expect("expected team id"))?;
    info!("admin: received team ID from owner");

    // Get seed IKM from owner.
    let (mut stream, _addr) = listener.accept().await?;
    let n = stream
        .read_to_end(&mut buf)
        .await
        .expect("expected to read_to_end on tcp stream");
    let seed_ikm = postcard::from_bytes(buf.get(0..n).expect("expected seed ikm"))?;
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
    let _team = client.add_team(add_team_cfg.clone()).await?;
    info!("admin: added team");

    Ok(())
}
