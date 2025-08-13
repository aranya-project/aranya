//! Admin device.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::TeamId;
use aranya_example_multi_node::{
    age::AgeEncryptor,
    env::EnvVars,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-admin");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Start TCP server.
    info!("admin: starting tcp server");
    let server = TcpServer::bind(env.admin.tcp_addr).await?;
    info!("admin: started tcp server");

    // Initialize client.
    info!("admin: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
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
    info!("admin: adding owner sync peer");
    let sync_interval = Duration::from_millis(100);
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;
    team.add_sync_peer(env.owner.sync_addr, sync_cfg.clone())
        .await?;

    info!("admin: complete");

    Ok(())
}
