use std::{net::Ipv4Addr, path::PathBuf};

use anyhow::Result;
use aranya_client::{Client, CreateTeamConfig, CreateTeamQuicSyncConfig};
use aranya_example_multi_node::tracing::init_tracing;
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
    aqc_addr: Option<Addr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-owner");

    // Parse input args.
    let args = Args::parse();
    let aqc_addr = match args.aqc_addr {
        Some(aqc_addr) => aqc_addr,
        None => Addr::from((Ipv4Addr::LOCALHOST, 0)),
    };

    // Initialize client.
    info!("owner: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&aqc_addr)
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
    client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!("owner: created team");

    Ok(())
}
