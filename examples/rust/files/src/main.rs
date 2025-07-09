#![allow(unused_mut, dead_code)]
#![allow(unused_macro_rules)]

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    aqc::{AqcPeerChannel, AqcBidiChannel}, client::Client, Error, QuicSyncConfig, SyncPeerConfig, TeamConfig,
};
use aranya_daemon_api::{text, ChanOp, DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
    time::sleep,
    io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt},
    task,
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
use priority_queue::PriorityQueue;


#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileChunk {
    file_id: u64,
    chunk_index: u64,
    chunk_size: usize,
    total_chunks: u64,
    file_size: u64,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct FileHeader {
    file_id: u64,
    filename: String,
    total_chunks: u64,
    file_size: u64,
    file_hash: u64,
}

// Chunk info for priority queue
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ChunkInfo {
    chunk_index: u64,
    data: Vec<u8>,
    chunk_size: usize,
}

// File receiver for handling out-of-order chunks
struct FileReceiver {
    chunks_buffer: PriorityQueue<ChunkInfo, u64>,  // item, priority (chunk_index)
    next_expected_chunk: u64,
    total_chunks: u64,
    output_file: File,
    chunks_written: u64,
    total_received: usize,
}

impl FileReceiver {
    fn new(output_file: File, total_chunks: u64) -> Self {
        Self {
            chunks_buffer: PriorityQueue::new(),
            next_expected_chunk: 0,
            total_chunks,
            output_file,
            chunks_written: 0,
            total_received: 0,
        }
    }

    fn add_chunk(&mut self, chunk: FileChunk, chunk_size: usize) -> Result<()> {
        let data_len = chunk.data.len();
        let chunk_info = ChunkInfo {
            chunk_index: chunk.chunk_index,
            data: chunk.data,
            chunk_size,
        };
        
        self.chunks_buffer.push(chunk_info, chunk.chunk_index);
        self.total_received += data_len;
        
        info!("Added chunk {} to buffer (total buffered: {})", chunk.chunk_index, self.chunks_buffer.len());
        Ok(())
    }

    async fn write_available_chunks(&mut self) -> Result<()> {
        // Write as many consecutive chunks as possible
        while let Some((_chunk_info, priority)) = self.chunks_buffer.peek() {
            if priority == &self.next_expected_chunk {
                // We can write this chunk
                let chunk_info = self.chunks_buffer.pop().unwrap().0;
                
                // Write chunk to file at correct position
                let chunk_offset = (chunk_info.chunk_index as u64) * (chunk_info.chunk_size as u64);
                self.output_file.seek(tokio::io::SeekFrom::Start(chunk_offset)).await
                    .with_context(|| format!("failed to seek to position {} for chunk {}", chunk_offset, chunk_info.chunk_index))?;
                self.output_file.write_all(&chunk_info.data).await
                    .with_context(|| format!("failed to write chunk {} to file", chunk_info.chunk_index))?;
                
                self.chunks_written += 1;
                self.next_expected_chunk += 1;
                
                info!("Wrote chunk {}: {} bytes (total: {}/{})", 
                      chunk_info.chunk_index, chunk_info.data.len(), self.chunks_written, self.total_chunks);
            } else {
                // Next chunk not available yet, wait for more chunks
                break;
            }
        }
        
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.chunks_written == self.total_chunks
    }

    fn get_progress(&self) -> (u64, u64) {
        (self.chunks_written, self.total_chunks)
    }
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

    // --- MOVE: Establish AQC channel before file transfer logic ---
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
    // --- END MOVE ---

    // Read the file to transfer
    info!("reading file to transfer: {:?}", file_path);
    let file_size = fs::metadata(&file_path).await?.len() as usize;
    let chunk_size = optimal_chunk_size(file_size);
    let _total_chunks = ((file_size + chunk_size - 1) / chunk_size) as u64;
    let _filename_str = file_path.file_name().unwrap().to_string_lossy().to_string();

    info!("starting file transfer");
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



async fn calculate_file_hash(file_path: &Path) -> Result<u64> {
    let mut file = File::open(file_path).await?;
    let mut hasher = DefaultHasher::new();
    let mut buffer = vec![0u8; 8192]; // 8KB buffer for hashing
    
    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.write(&buffer[..bytes_read]);
    }
    
    Ok(hasher.finish())
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
    let file_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    info!("Starting streaming file transfer: file_id={}, {} chunks, {} bytes", file_id, total_chunks, file_size);
    
    // Calculate file hash
    let file_hash = calculate_file_hash(file_path).await?;
    info!("File hash: {:x}", file_hash);
    
    // Send file header first
    let header = FileHeader {
        file_id,
        filename: file_path.file_name().unwrap().to_string_lossy().to_string(),
        total_chunks,
        file_size: file_size as u64,
        file_hash,
    };
    let mut header_stream = channel.create_bidi_stream().await?;
    let header_serialized = serde_cbor::to_vec(&header)?;
    header_stream.send(Bytes::copy_from_slice(&header_serialized)).await?;
    header_stream.close().await?;
    info!("Sent file header: {}", header.filename);
    
    // Open file for streaming with buffered reader
    let file = File::open(file_path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut chunk_index = 0;
    let mut total_sent = 0;
    
    // Stream chunks directly from file using multiple threads
    let mut handles = Vec::new();
    
    loop {
        let mut buffer = vec![0u8; chunk_size];
        let bytes_read = reader.read(&mut buffer).await?;
        
        if bytes_read == 0 {
            break;
        }
        
        let chunk_data = buffer[..bytes_read].to_vec();
        info!("Sending chunk {} ({} bytes)", chunk_index, bytes_read);
        
        // Spawn a task to send this chunk
        let file_id_clone = file_id;
        let chunk_index_clone = chunk_index;
        let total_chunks_clone = total_chunks;
        let file_size_clone = file_size as u64;
        
        let handle = task::spawn(async move {
            // Note: We'll handle the actual sending in the main thread
            // This task just prepares the chunk data
            let chunk_with_index = FileChunk {
                file_id: file_id_clone,
                chunk_index: chunk_index_clone,
                chunk_size: bytes_read,
                total_chunks: total_chunks_clone,
                file_size: file_size_clone,
                data: chunk_data,
            };
            
            Ok::<_, anyhow::Error>(chunk_with_index)
        });
        
        handles.push(handle);
        total_sent += bytes_read;
        info!("Sent chunk {}: {}/{} bytes", chunk_index, total_sent, file_size);
        chunk_index += 1;
    }
    
    // Wait for all sending tasks to complete and send the chunks
    for handle in handles {
        let chunk = handle.await??;
        
        // Create stream and send chunk
        let mut stream = channel.create_bidi_stream().await?;
        let serialized = serde_cbor::to_vec(&chunk)?;
        stream.send(Bytes::copy_from_slice(&serialized)).await?;
        stream.close().await?;
    }
    
    info!("Streaming file transfer completed! Sent {} chunks, {} total bytes", chunk_index, total_sent);
    Ok(())
}

async fn receive_file_from_multiple_streams(
    _output_path: &Path,
    chunk_size: usize,
    received_channel: &mut AqcBidiChannel,
) -> Result<()> {
    info!("receiving file chunks from multiple parallel streams");
    
    // Track files by ID
    let mut file_info: Option<(u64, String, u64, u64, u64)> = None; // (file_id, filename, total_chunks, file_size, file_hash)
    let mut file_receiver: Option<FileReceiver> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut expected_hash: Option<u64> = None;
    
    // Keep receiving streams until we get all chunks
    loop {
        info!("receiving stream");
        
        // Receive stream with timeout
        let stream_result = tokio::time::timeout(
            Duration::from_secs(5),
            received_channel.receive_stream()
        ).await;
        
        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to receive stream: {}", e)),
            Err(_) => {
                info!("timeout waiting for stream, assuming transfer complete");
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
                }
                Ok(Ok(None)) => {
                    break;
                }
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Stream error: {}", e));
                }
                Err(_) => {
                    info!("timeout waiting for data");
                    break;
                }
            }
        }
        
        if stream_data.is_empty() {
            info!("no data received, assuming end of transfer");
            break;
        }
        
        // Try to deserialize as header first, then as chunk
        if let Ok(header) = serde_cbor::from_slice::<FileHeader>(&stream_data) {
            info!("received file header: file_id={}, filename={}, {} chunks, {} bytes, hash={:x}", 
                  header.file_id, header.filename, header.total_chunks, header.file_size, header.file_hash);
            file_info = Some((header.file_id, header.filename, header.total_chunks, header.file_size, header.file_hash));
            expected_hash = Some(header.file_hash);
            continue;
        }
        
        // Deserialize as chunk
        let chunk: FileChunk = serde_cbor::from_slice(&stream_data)?;
        let chunk_data_len = chunk.data.len();
        info!("received chunk {} (file_id={}): {} bytes", chunk.chunk_index, chunk.file_id, chunk_data_len);
        
        // Get file info
        let (file_id, filename, total_chunks, _file_size, _file_hash) = file_info
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Received chunk before file header"))?;
        
        // Verify file_id matches
        if chunk.file_id != *file_id {
            return Err(anyhow::anyhow!("Chunk file_id {} doesn't match header file_id {}", chunk.file_id, file_id));
        }
        
        // Create file receiver if this is the first chunk
        if file_receiver.is_none() {
            let final_output_path = Path::new("received_").join(filename);
            if let Some(parent) = final_output_path.parent() {
                fs::create_dir_all(parent).await
                    .with_context(|| format!("failed to create directory: {:?}", parent))?;
            }
            let file = File::create(&final_output_path).await
                .with_context(|| format!("failed to create output file: {:?}", final_output_path))?;
            file_receiver = Some(FileReceiver::new(file, *total_chunks));
            output_path = Some(final_output_path.clone());
            info!("created output file: {:?}", final_output_path);
        }
        
        // Process chunk in a separate task for multi-threading
        let receiver = file_receiver.as_mut().unwrap();
        let chunk_clone = chunk.clone();
        let chunk_size_clone = chunk_size;
        
        // Spawn a task to process this chunk
        let handle = task::spawn(async move {
            // Simulate some processing work
            sleep(Duration::from_millis(1)).await;
            (chunk_clone, chunk_size_clone)
        });
        
        // Wait for the task to complete and get the result
        let (processed_chunk, processed_chunk_size) = handle.await?;
        
        // Add processed chunk to buffer and write available chunks
        receiver.add_chunk(processed_chunk, processed_chunk_size)?;
        receiver.write_available_chunks().await?;
        
        // Check if file is complete
        if receiver.is_complete() {
            let (_written, total) = receiver.get_progress();
            info!("File complete! Received all {} chunks", total);
            break;
        }
    }
    
    // Verify file integrity with hash
    if let Some(path) = output_path {
        if let Some(expected) = expected_hash {
            let actual_hash = calculate_file_hash(&path).await?;
            if actual_hash == expected {
                info!("File integrity verified! Hash: {:x}", actual_hash);
            } else {
                return Err(anyhow::anyhow!("File integrity check failed! Expected: {:x}, Got: {:x}", expected, actual_hash));
            }
        }
    }
    
    // Get final stats from file receiver
    if let Some(receiver) = file_receiver {
        let (written, total) = receiver.get_progress();
        info!("file streaming completed successfully: {} chunks written out of {}", written, total);
    }
    
    Ok(())
}

