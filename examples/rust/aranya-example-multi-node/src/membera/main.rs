//! Member A device.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{NetIdentifier, TeamId};
use aranya_example_multi_node::{
    config::create_config,
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
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
const DEVICE_NAME: &str = "membera";

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!("starting aranya-example-multi-node-membera");

    // Parse input args.
    let args = Args::parse();
    let env = EnvVars::load()?;

    // Generate daemon config file.
    let tmp = tempdir()?;
    info!("membera: generating daemon config");
    let cfg = create_config(
        DEVICE_NAME.to_string(),
        env.membera.sync_addr,
        tmp.path().into(),
    )
    .await
    .expect("expected to generate daemon config file");

    // Start daemon.
    info!("membera: starting daemon");
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
    info!("membera: started daemon");

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
    info!("membera: starting tcp server");
    let server = TcpServer::bind(env.membera.tcp_addr).await?;
    info!("membera: started tcp server");

    // Initialize client.
    info!("membera: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(uds_sock)
            .aqc_server_addr(&env.membera.aqc_addr)
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
    let team = client
        .add_team(add_team_cfg.clone())
        .await
        .expect("expected to add team");
    info!("membera: added team");

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
    for device in &env.devices {
        if device.name == DEVICE_NAME {
            continue;
        }
        info!("membera: adding sync peer {}", device.name);
        team.add_sync_peer(device.sync_addr, sync_cfg.clone())
            .await
            .expect("expected to add sync peer");
    }

    // wait for syncing.
    sleep(sleep_interval).await;

    // Send device info to operator.
    TcpClient::connect(env.operator.tcp_addr)
        .await?
        .send(&postcard::to_allocvec(&DeviceInfo {
            name: DEVICE_NAME.to_string(),
            device_id: client.get_device_id().await?,
        })?)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Query the AQC label.
    let queries = team.queries();
    let label = loop {
        let labels = queries.labels().await?;
        if labels.iter().count() > 0 {
            break labels.iter().next().expect("expected label").clone();
        }
        sleep(sleep_interval).await;
    };

    // Create a bidi AQC channel.
    info!("membera: creating bidi channel");
    let mut chan = client
        .aqc()
        .create_bidi_channel(
            team_id,
            NetIdentifier(
                env.memberb
                    .aqc_addr
                    .to_string()
                    .try_into()
                    .expect("addr is valid text"),
            ),
            label.id,
        )
        .await
        .expect("expected to create bidi channel");

    // Create stream on bidi channel.
    info!("membera: creating bidi stream");
    let mut stream = chan
        .create_bidi_stream()
        .await
        .expect("expected to create bidi stream");

    // Send data.
    info!("membera: sending AQC data");
    let req = Bytes::from_static(b"hello");
    stream
        .send(req.clone())
        .await
        .expect("expected to send data");
    info!("membera: sent AQC data");

    // Receive data.
    info!("membera: receiving AQC data");
    let resp = stream.receive().await?.expect("expected to receive data");
    assert_eq!(req, resp);
    info!("membera: received AQC data");

    info!("membera: complete");

    Ok(())
}
