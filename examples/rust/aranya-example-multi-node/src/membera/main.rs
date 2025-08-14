//! Member A device.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use aranya_client::{AddTeamConfig, AddTeamQuicSyncConfig, Client, SyncPeerConfig};
use aranya_daemon_api::{NetIdentifier, Role, TeamId};
use aranya_example_multi_node::{
    age::AgeEncryptor,
    env::EnvVars,
    info::DeviceInfo,
    tcp::{TcpClient, TcpServer},
    tracing::init_tracing,
};
use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
use clap::Parser;
use tokio::time::sleep;
use tracing::info;

/// CLI args.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Daemon UDS socket path.
    #[arg(long)]
    uds_sock: PathBuf,
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

    // Start TCP server.
    info!("membera: starting tcp server");
    let server = TcpServer::bind(env.membera.tcp_addr).await?;
    info!("membera: started tcp server");

    // Initialize client.
    info!("membera: initializing client");
    let client = (|| {
        Client::builder()
            .daemon_uds_path(&args.uds_sock)
            .aqc_server_addr(&env.membera.aqc_addr)
            .connect()
    })
    .retry(ExponentialBuilder::default())
    .await
    .expect("expected to initialize client");
    info!("membera: initialized client");

    // Initialize `age` encryptor.
    let encryptor = AgeEncryptor::new(env.passphrase);

    // Get team ID from owner.
    let team_id: TeamId = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
    info!("membera: received team ID from owner");

    // Get seed IKM from owner.
    let seed_ikm = postcard::from_bytes(&encryptor.decrypt(&server.recv().await?)?)?;
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
    info!("membera: sending device ID to owner");
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&client.get_device_id().await?)?)?)
        .await?;
    info!("membera: sent device ID to owner");

    // Send public keys to owner.
    info!("membera: sending public keys to owner");
    TcpClient::connect(env.owner.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&client.get_key_bundle().await?)?)?)
        .await?;
    info!("membera: sent public keys to owner");

    // Setup sync peers.
    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;
    info!("membera: adding operator sync peer");
    team.add_sync_peer(env.operator.sync_addr, sync_cfg.clone())
        .await
        .expect("expected to add sync peer");

    // wait for syncing.
    sleep(sleep_interval).await;

    // Wait for admin to create label.
    info!("membera: waiting for admin to create label");
    let queries = team.queries();
    let label1 = loop {
        if let Ok(labels) = queries.labels().await {
            if let Some(label1) = labels.iter().next() {
                break label1.id;
            }
        }
        sleep(sleep_interval).await;
    };

    // Loop until this device has the `Operator` role assigned to it.
    info!("membera: waiting for all devices to be added to team and operator role assignment");
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
    info!("membera: detected that all devices have been added to team and operator role has been assigned");

    // Send device info to operator.
    info!("membera: sending device info to operator");
    TcpClient::connect(env.operator.tcp_addr)
        .await?
        .send(&encryptor.encrypt(&postcard::to_allocvec(&DeviceInfo {
            name: DEVICE_NAME.to_string(),
            device_id: client.get_device_id().await?,
        })?)?)
        .await?;
    info!("membera: sent device info to operator");

    // wait for syncing.
    sleep(sleep_interval).await;

    // Check that label has been assigned to membera and memberb.
    'outer: loop {
        if let Ok(devices) = queries.devices_on_team().await {
            let mut labels_assigned = 0;
            for device in devices.iter() {
                if let Ok(labels) = queries.device_label_assignments(*device).await {
                    if labels.iter().count() > 0 {
                        labels_assigned += 1;
                        if labels_assigned >= 2 {
                            break 'outer;
                        }
                    }
                }
            }
        }
        sleep(3 * sleep_interval).await;
    }

    // Remove operator sync peer.
    info!("membera: removing operator sync peer");
    team.remove_sync_peer(env.operator.sync_addr).await?;

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
            label1,
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
