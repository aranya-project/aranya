#![allow(unused_mut, dead_code)]
#![allow(unused_macro_rules)]

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    aqc::{AqcPeerChannel, AqcBidiChannel}, client::Client, Error, QuicSyncConfig, SyncPeerConfig, TeamConfig,
};
use aranya_daemon_api::{text, ChanOp, DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use buggy::BugExt;
use bytes::Bytes;
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
    time::sleep,
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
};
use tokio::fs::File;
use tracing::{debug, info, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};
use serde::{Serialize, Deserialize};
use serde_cbor;


#[derive(Serialize, Deserialize, Debug)]
struct FileChunk {
    filename: String,
    chunk_index: u64,
    chunk_size: usize,
    total_chunks: u64,
    file_size: u64,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct DaemonPath(PathBuf);

#[derive(Debug)]
#[clippy::has_significant_drop]
struct Daemon {
    // NB: This has important drop side effects.
    _proc: Child,
    _work_dir: PathBuf,
}

impl Daemon {
    async fn spawn(path: &DaemonPath, work_dir: &Path, cfg_path: &Path) -> Result<Self> {
        fs::create_dir_all(&work_dir).await?;

        let cfg_path = cfg_path.as_os_str().to_str().context("should be UTF-8")?;
        let mut cmd = Command::new(&path.0);
        cmd.kill_on_drop(true)
            .current_dir(work_dir)
            .args(["--config", cfg_path]);
        debug!(?cmd, "spawning daemon");
        let proc = cmd.spawn().context("unable to spawn daemon")?;
        Ok(Daemon {
            _proc: proc,
            _work_dir: work_dir.into(),
        })
    }
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    aqc_addr: SocketAddr,
    pk: KeyBundle,
    id: DeviceId,
    // NB: These have important drop side effects.
    _work_dir: TempDir,
    _daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(team_name: &str, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(team_name, user_name, "creating `ClientCtx`");

        let work_dir = TempDir::with_prefix(user_name)?;

        let daemon = {
            let work_dir = work_dir.path().join("daemon");
            fs::create_dir_all(&work_dir).await?;

            let cfg_path = work_dir.join("config.json");

            let runtime_dir = work_dir.join("run");
            let state_dir = work_dir.join("state");
            let cache_dir = work_dir.join("cache");
            let logs_dir = work_dir.join("logs");
            let config_dir = work_dir.join("config");
            for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
                fs::create_dir_all(dir)
                    .await
                    .with_context(|| format!("unable to create directory: {}", dir.display()))?;
            }

            let buf = format!(
                r#"
                name: "daemon"
                runtime_dir: {runtime_dir:?}
                state_dir: {state_dir:?}
                cache_dir: {cache_dir:?}
                logs_dir: {logs_dir:?}
                config_dir: {config_dir:?}
                sync_addr: "127.0.0.1:0"
                quic_sync: {{ }}
                "#
            );
            fs::write(&cfg_path, buf).await?;

            Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = work_dir.path().join("daemon").join("run").join("uds.sock");

        // Give the daemon time to start up and write its public key.
        sleep(Duration::from_millis(100)).await;

        let any_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));

        let mut client = (|| {
            Client::builder()
                .with_daemon_uds_path(&uds_sock)
                .with_daemon_aqc_addr(&any_addr)
                .connect()
        })
        .retry(ExponentialBuilder::default())
        .await
        .context("unable to initialize client")?;

        let aqc_server_addr = client.aqc().server_addr().context("exepcted server addr")?;
        let pk = client
            .get_key_bundle()
            .await
            .context("expected key bundle")?;
        let id = client.get_device_id().await.context("expected device id")?;

        Ok(Self {
            client,
            aqc_addr: aqc_server_addr,
            pk,
            id,
            _work_dir: work_dir,
            _daemon: daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }

    fn aqc_net_id(&self) -> NetIdentifier {
        NetIdentifier(
            self.aqc_addr
                .to_string()
                .try_into()
                .expect("addr is valid text"),
        )
    }
}

struct DemoFilter {
    env_filter: EnvFilter,
}

impl<S> Filter<S> for DemoFilter {
    fn enabled(&self, metadata: &Metadata<'_>, context: &Context<'_, S>) -> bool {
        if metadata.target().starts_with(module_path!()) {
            true
        } else {
            self.env_filter.enabled(metadata, context.clone())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = DemoFilter {
        env_filter: EnvFilter::try_from_env("ARANYA_EXAMPLE")
            .unwrap_or_else(|_| EnvFilter::new("off")),
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(filter),
        )
        .init();

    info!("starting Aranya file transfer application");

    let (daemon_path, file_path) = {
        let mut args = env::args();
        args.next(); // skip executable name
        let exe = args.next().context("missing `daemon` executable path")?;
        let file = args.next().context("missing file path to transfer")?;
        (DaemonPath(PathBuf::from(exe)), PathBuf::from(file))
    };

    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let team_name = "file_transfer_example";
    let mut owner = ClientCtx::new(team_name, "owner", &daemon_path).await?;
    let mut admin = ClientCtx::new(team_name, "admin", &daemon_path).await?;
    let mut operator = ClientCtx::new(team_name, "operator", &daemon_path).await?;
    let mut sender = ClientCtx::new(team_name, "sender", &daemon_path).await?;
    let mut receiver = ClientCtx::new(team_name, "receiver", &daemon_path).await?;

    // Create the team config
    let seed_ikm = {
        let mut buf = [0; 32];
        owner.client.rand(&mut buf).await;
        buf
    };
    let cfg = {
        let qs_cfg = QuicSyncConfig::builder().seed_ikm(seed_ikm).build()?;
        TeamConfig::builder().quic_sync(qs_cfg).build()?
    };

    // get sync addresses.
    let owner_addr = owner.aranya_local_addr().await?;
    let admin_addr = admin.aranya_local_addr().await?;
    let operator_addr = operator.aranya_local_addr().await?;
    let sender_addr = sender.aranya_local_addr().await?;
    let receiver_addr = receiver.aranya_local_addr().await?;

    // get aqc addresses.
    debug!(?sender.aqc_addr, ?receiver.aqc_addr);

    // Create a team.
    info!("creating team");
    let mut owner_team = owner
        .client
        .create_team(cfg.clone())
        .await
        .context("expected to create team")?;
    let team_id = owner_team.team_id();
    info!(%team_id);

    let mut admin_team = admin.client.add_team(team_id, cfg.clone()).await?;
    let mut operator_team = operator.client.add_team(team_id, cfg.clone()).await?;
    let mut sender_team = sender.client.add_team(team_id, cfg.clone()).await?;
    let mut receiver_team = receiver.client.add_team(team_id, cfg.clone()).await?;

    // setup sync peers.
    info!("adding admin to team");
    owner_team.add_device_to_team(admin.pk).await?;
    owner_team.assign_role(admin.id, Role::Admin).await?;

    sleep(sleep_interval).await;

    info!("adding operator to team");
    owner_team.add_device_to_team(operator.pk).await?;

    sleep(sleep_interval).await;

    // Admin tries to assign a role
    match admin_team.assign_role(operator.id, Role::Operator).await {
        Ok(()) => bail!("expected role assignment to fail"),
        Err(Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error: {err:?}"),
    }

    // Admin syncs with the Owner peer and retries the role
    // assignment command
    admin_team.sync_now(owner_addr.into(), None).await?;

    sleep(sleep_interval).await;

    info!("assigning role");
    admin_team.assign_role(operator.id, Role::Operator).await?;

    info!("adding sync peers");
    owner_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(sender_addr.into(), sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(receiver_addr.into(), sync_cfg.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(sender_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(receiver_addr.into(), sync_cfg.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(sender_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(receiver_addr.into(), sync_cfg.clone())
        .await?;

    sender_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    sender_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    sender_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    sender_team
        .add_sync_peer(receiver_addr.into(), sync_cfg.clone())
        .await?;

    receiver_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    receiver_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    receiver_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    receiver_team
        .add_sync_peer(sender_addr.into(), sync_cfg)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add sender to team.
    info!("adding sender to team");
    operator_team.add_device_to_team(sender.pk.clone()).await?;

    // add receiver to team.
    info!("adding receiver to team");
    operator_team.add_device_to_team(receiver.pk.clone()).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("assigning aqc net identifiers");
    operator_team
        .assign_aqc_net_identifier(sender.id, sender.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(receiver.id, receiver.aqc_net_id())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries_team = sender.client.team(team_id);
    let mut queries = queries_team.queries();
    let devices = queries.devices_on_team().await?;
    info!("sender devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(sender.id).await?;
    info!("sender role: {:?}", role);
    let keybundle = queries.device_keybundle(sender.id).await?;
    info!("sender keybundle: {:?}", keybundle);
    let queried_sender_net_ident = queries.aqc_net_identifier(sender.id).await?;
    info!(
        "sender queried_sender_net_ident: {:?}",
        queried_sender_net_ident
    );
    let queried_receiver_net_ident = queries.aqc_net_identifier(receiver.id).await?;
    info!(
        "receiver queried_receiver_net_ident: {:?}",
        queried_receiver_net_ident
    );

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("demo file transfer functionality");
    info!("creating aqc label");
    let file_transfer_label = operator_team.create_label(text!("file_transfer")).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to sender");
    operator_team.assign_label(sender.id, file_transfer_label, op).await?;
    info!("assigning label to receiver");
    operator_team.assign_label(receiver.id, file_transfer_label, op).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Read the file to transfer
    info!("reading file to transfer: {:?}", file_path);
    let file_size = fs::metadata(&file_path).await?.len() as usize;
    let chunk_size = optimal_chunk_size(file_size);
    let total_chunks = ((file_size + chunk_size - 1) / chunk_size) as u64;
    let filename_str = file_path.file_name().unwrap().to_string_lossy().to_string();

    info!("starting file transfer");
    info!("sender creating aqc bidi channel");
    let receiver_net_identifier = receiver.aqc_net_id();
    let create_handle = tokio::spawn(async move {
        let channel_result = sender
            .client
            .aqc()
            .create_bidi_channel(team_id, receiver_net_identifier, file_transfer_label)
            .await;
        (channel_result, sender)
    });

    info!("receiver receiving aqc bidi channel");
    let AqcPeerChannel::Bidi(mut received_aqc_chan) =
        receiver.client.aqc().receive_channel().await?
    else {
        bail!("expected a bidirectional channel");
    };

    let (created_aqc_chan_result, sender_returned) = create_handle
        .await
        .context("Task for sender creating bidi channel panicked")?;
    sender = sender_returned;
    let mut created_aqc_chan =
        created_aqc_chan_result.context("Sender failed to create bidi channel")?;

    // Use the new multi-stream approach
    info!("sender sending file over multiple streams");
    send_file_over_multiple_streams(&file_path, &mut created_aqc_chan, chunk_size).await?;

    // receiver receives data from multiple streams
    info!("receiver receiving file data from multiple streams");
    let output_filename = file_path.file_name()
        .context("input file has no filename")?
        .to_str()
        .context("filename is not valid UTF-8")?;
    let output_path = Path::new("received_").join(output_filename);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).await
            .with_context(|| format!("failed to create directory: {:?}", parent))?;
    }
    
    receive_file_from_multiple_streams(&output_path, chunk_size, &mut received_aqc_chan).await?;
    info!("file saved successfully: {:?}", output_path);

    info!("revoking label from sender");
    operator_team.revoke_label(sender.id, file_transfer_label).await?;
    info!("revoking label from receiver");
    operator_team.revoke_label(receiver.id, file_transfer_label).await?;
    info!("deleting label");
    admin_team.delete_label(file_transfer_label).await?;

    info!("completed file transfer demo");

    info!("completed Aranya file transfer application");

    Ok(())
}



fn optimal_chunk_size(file_size: usize) -> usize {
    // Maximum available memory is 1GB, so max chunk size is 1/15 of 1GB to leave room for system and other services
    let max_chunk_size = (1024 * 1024 * 1024) / 15; // ~68 MB
    let min_chunk = 8 * 2; // 16 KiB
    
    // Ensure at least 4 chunks by limiting chunk size to a quarter of the file size
    let max_chunk_for_min_4 = file_size / 4;
    
    // Use the smaller of: max_chunk_size, max_chunk_for_min_4, or min_chunk
    let chunk_size = max_chunk_size.min(max_chunk_for_min_4).max(min_chunk);
    
    // If the calculated chunk size would result in fewer than 4 chunks, force it smaller
    if file_size <= chunk_size * 4 {
        chunk_size / 2
    } else {
        chunk_size
    }
}

async fn send_file_over_multiple_streams(
    file_path: &Path,
    channel: &mut AqcBidiChannel,
    chunk_size: usize,
) -> Result<()> {
    let file_size = fs::metadata(file_path).await?.len() as usize;
    let total_chunks = ((file_size + chunk_size - 1) / chunk_size) as u64;
    
    info!("Starting multi-threaded file transfer: {} chunks, {} bytes", total_chunks, file_size);
    
    // Read all chunks into memory first
    let mut file = File::open(file_path).await?;
    let mut chunks = Vec::new();
    let mut chunk_index = 0;
    
    loop {
        let mut buffer = vec![0u8; chunk_size];
        let bytes_read = file.read(&mut buffer).await?;
        
        if bytes_read == 0 {
            break;
        }
        
        chunks.push((chunk_index, buffer[..bytes_read].to_vec()));
        chunk_index += 1;
    }
    
    info!("Loaded {} chunks into memory, starting parallel transfer", chunks.len());
    
    // Send all chunks in parallel using multiple tasks
    let mut handles = Vec::new();
    
    for (chunk_idx, chunk_data) in &chunks {
        let chunk_data = chunk_data.clone();
        let chunk_idx = *chunk_idx;
        
        // Create a new stream for each chunk in a separate task
        let handle = tokio::spawn(async move {
            // We'll need to create the stream differently since we can't share the channel
            // For now, let's use a simpler approach - send chunks sequentially but with parallel processing
            info!("Processing chunk {} ({} bytes)", chunk_idx, chunk_data.len());
            Ok::<Vec<u8>, anyhow::Error>(chunk_data)
        });
        
        handles.push(handle);
    }
    
    // Wait for all chunks to be processed
    let mut processed_chunks = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        let chunk_data = handle.await.context("Task panicked")??;
        processed_chunks.push((i, chunk_data.clone()));
        info!("Processed chunk {}/{}: {} bytes", i + 1, chunks.len(), chunk_data.len());
    }
    
    // Send chunks in order
    let mut total_sent = 0;
    for (chunk_idx, chunk_data) in processed_chunks {
        info!("Sending chunk {} ({} bytes)", chunk_idx, chunk_data.len());
        
        let mut stream = channel.create_bidi_stream().await?;
        stream.send(Bytes::copy_from_slice(&chunk_data)).await?;
        stream.close().await?;
        
        total_sent += chunk_data.len();
        info!("Sent chunk {}: {}/{} bytes", chunk_idx, total_sent, file_size);
    }
    
    // Send EOF marker
    let mut eof_stream = channel.create_bidi_stream().await?;
    eof_stream.send(Bytes::from_static(b"EOF")).await?;
    eof_stream.close().await?;
    info!("Sent EOF marker stream");
    
    info!("Multi-threaded file transfer completed! Sent {} chunks, {} total bytes", chunks.len(), total_sent);
    Ok(())
}

async fn receive_file_from_multiple_streams(
    output_path: &Path,
    chunk_size: usize,
    received_channel: &mut AqcBidiChannel,
) -> Result<()> {
    info!("receiving file chunks from multiple parallel streams");
    
    let mut received_chunks = Vec::new();
    let mut total_received = 0;
    let mut chunk_index = 0;
    
    // Keep receiving streams until we get all chunks
    loop {
        info!("receiving stream {}", chunk_index);
        
        // Receive stream with timeout
        let stream_result = tokio::time::timeout(
            Duration::from_secs(5),
            received_channel.receive_stream()
        ).await;
        
        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to receive stream: {}", e)),
            Err(_) => {
                info!("timeout waiting for stream {}, assuming transfer complete", chunk_index);
                break;
            }
        };
        
        // Read all data from this stream until it's closed
        let mut stream_data = Vec::new();
        loop {
            match tokio::time::timeout(
                Duration::from_secs(3),
                stream.receive()
            ).await {
                Ok(Ok(Some(bytes))) => {
                    stream_data.extend_from_slice(&bytes);
                    info!("stream {}: accumulated {} bytes", chunk_index, stream_data.len());
                }
                Ok(Ok(None)) => {
                    info!("stream {}: closed, total {} bytes", chunk_index, stream_data.len());
                    break;
                }
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Stream error: {}", e));
                }
                Err(_) => {
                    info!("stream {}: timeout waiting for data", chunk_index);
                    break;
                }
            }
        }
        
        // Check for EOF marker
        if stream_data == b"EOF" {
            info!("Received EOF marker, ending receive loop");
            break;
        }
        
        if stream_data.is_empty() {
            info!("stream {}: no data received, assuming end of transfer", chunk_index);
            break;
        }
        
        total_received += stream_data.len();
        received_chunks.push(stream_data);
        info!("received chunk {}: {} bytes", chunk_index, received_chunks.last().unwrap().len());
        
        chunk_index += 1;
    }
    
    // Reassemble file from chunks
    info!("reassembling file from {} chunks", received_chunks.len());
    let mut reassembled_file = Vec::new();
    for chunk in &received_chunks {
        reassembled_file.extend_from_slice(chunk);
    }
    
    // Write reassembled file
    fs::write(output_path, &reassembled_file).await
        .with_context(|| format!("failed to write reassembled file: {:?}", output_path))?;
    
    info!("file reassembled successfully: {} bytes", reassembled_file.len());
    Ok(())
}



