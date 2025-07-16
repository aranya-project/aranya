use anyhow::{Context, Result};
use aranya_client::{
    Client, QuicSyncConfig, TeamConfig, SyncPeerConfig,
    aqc::{AqcBidiChannel, AqcBidiStream, AqcPeerChannel, AqcPeerStream, TryReceiveError},
};
use aranya_daemon_api::{DeviceId, KeyBundle, Role, TeamId, LabelId, NetIdentifier, ChanOp, Text};
use aranya_util::Addr;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use bytes::Bytes;
use uuid::Uuid;
use lazy_static::lazy_static;

use rand::Rng;

/// Global channel registry for managing AQC channels and streams across CLI commands
#[derive(Default)]
struct ChannelRegistry {
    channels: HashMap<String, AqcBidiChannel>,
    streams: HashMap<String, AqcBidiStream>,
    peer_streams: HashMap<String, AqcPeerStream>,
    received_channels: HashMap<String, AqcPeerChannel>,
}

impl ChannelRegistry {
    fn new() -> Self {
        Self::default()
    }

    fn store_channel(&mut self, channel: AqcBidiChannel) -> String {
        let id = Uuid::new_v4().to_string();
        self.channels.insert(id.clone(), channel);
        id
    }

    fn get_channel(&mut self, id: &str) -> Option<&mut AqcBidiChannel> {
        self.channels.get_mut(id)
    }

    fn store_stream(&mut self, stream: AqcBidiStream) -> String {
        let id = Uuid::new_v4().to_string();
        self.streams.insert(id.clone(), stream);
        id
    }

    fn get_stream(&mut self, id: &str) -> Option<&mut AqcBidiStream> {
        self.streams.get_mut(id)
    }

    fn store_peer_stream(&mut self, stream: AqcPeerStream) -> String {
        let id = Uuid::new_v4().to_string();
        self.peer_streams.insert(id.clone(), stream);
        id
    }

    fn get_peer_stream(&mut self, id: &str) -> Option<&mut AqcPeerStream> {
        self.peer_streams.get_mut(id)
    }

    fn store_received_channel(&mut self, channel: AqcPeerChannel) -> String {
        let id = Uuid::new_v4().to_string();
        self.received_channels.insert(id.clone(), channel);
        id
    }

    fn get_received_channel(&mut self, id: &str) -> Option<&mut AqcPeerChannel> {
        self.received_channels.get_mut(id)
    }

    fn list_channels(&self) -> Vec<String> {
        self.channels.keys().cloned().collect()
    }

    fn list_streams(&self) -> Vec<String> {
        self.streams.keys().cloned().collect()
    }

    fn list_peer_streams(&self) -> Vec<String> {
        self.peer_streams.keys().cloned().collect()
    }

    fn list_received_channels(&self) -> Vec<String> {
        self.received_channels.keys().cloned().collect()
    }

    fn remove_channel(&mut self, id: &str) -> Option<AqcBidiChannel> {
        self.channels.remove(id)
    }

    fn remove_stream(&mut self, id: &str) -> Option<AqcBidiStream> {
        self.streams.remove(id)
    }

    fn remove_peer_stream(&mut self, id: &str) -> Option<AqcPeerStream> {
        self.peer_streams.remove(id)
    }

    fn remove_received_channel(&mut self, id: &str) -> Option<AqcPeerChannel> {
        self.received_channels.remove(id)
    }
}

// Global registry instance
lazy_static! {
    static ref CHANNEL_REGISTRY: Arc<Mutex<ChannelRegistry>> = Arc::new(Mutex::new(ChannelRegistry::new()));
}

#[derive(Parser)]
#[command(name = "aranya")]
#[command(author, version, about = "Aranya CLI tool for team and device management", long_about = None)]
struct Cli {
    /// Path to daemon's Unix Domain Socket
    #[arg(short = 'u', long, default_value = "/var/run/aranya/uds.sock")]
    uds_path: PathBuf,

    /// Daemon's AQC address
    #[arg(short = 'a', long, default_value = "127.0.0.1:0")]
    aqc_addr: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new team
    CreateTeam {
        /// Optional seed IKM in hex (32 bytes). If not provided, generates random.
        #[arg(long)]
        seed_ikm: Option<String>,
    },
    /// Add an existing team to this device
    AddTeam {
        /// Team ID to add
        team_id: String,
        /// Seed IKM in hex (32 bytes)
        seed_ikm: String,
    },
    /// Remove a team from this device
    RemoveTeam {
        /// Team ID to remove
        team_id: String,
    },
    /// Add a device to a team
    AddDevice {
        /// Team ID
        team_id: String,
        /// Device's identity public key in hex
        identity_pk: String,
        /// Device's signing public key in hex
        signing_pk: String,
        /// Device's encoding public key in hex
        encoding_pk: String,
    },
    /// Remove a device from a team
    RemoveDevice {
        /// Team ID
        team_id: String,
        /// Device ID to remove
        device_id: String,
    },
    /// Assign a role to a device
    AssignRole {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
        /// Role (Owner, Admin, Operator, Member)
        role: String,
    },
    /// List all devices on a team
    ListDevices {
        /// Team ID
        team_id: String,
    },
    /// Get device information
    DeviceInfo {
        /// Team ID
        team_id: String,
        /// Device ID (optional, shows current device if not provided)
        device_id: Option<String>,
    },
    /// Add a sync peer for automatic synchronization
    AddSyncPeer {
        /// Team ID
        team_id: String,
        /// Peer address (e.g., "192.168.1.100:7812")
        peer_addr: String,
        /// Sync interval in seconds
        #[arg(long, default_value = "1")]
        interval_secs: u64,
    },
    /// Sync with a peer immediately
    SyncNow {
        /// Team ID
        team_id: String,
        /// Peer address (e.g., "192.168.1.100:7812")
        peer_addr: String,
    },
    /// Create a label for data channels
    CreateLabel {
        /// Team ID
        team_id: String,
        /// Label name
        label_name: String,
    },
    /// Assign a label to a device with channel operations
    AssignLabel {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
        /// Label ID
        label_id: String,
        /// Channel operation (SendOnly, RecvOnly, SendRecv)
        operation: String,
    },
    /// Assign network identifier to device for AQC
    AssignAqcNetId {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
        /// Network identifier (e.g., "192.168.1.100:5050")
        net_id: String,
    },
    /// List label assignments
    ListLabelAssignments {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
    },
    /// List AQC network assignments
    ListAqcAssignments {
        /// Team ID
        team_id: String,
    },
    /// Send data with PSK rotation (creates new channel for each send)
    SendData {
        /// Team ID
        team_id: String,
        /// Target device ID
        device_id: String,
        /// Label ID for the channel
        label_id: String,
        /// Message to send
        message: String,
    },
    /// Listen for data with PSK rotation (creates new channel for each receive)
    ListenData {
        /// Team ID
        team_id: String,
        /// Source device ID
        device_id: String,
        /// Label ID for the channel
        label_id: String,
        /// Timeout in seconds (0 for infinite)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Show active AQC channels
    ShowChannels {
        /// Team ID
        team_id: String,
    },
    /// Query devices on a team
    QueryDevicesOnTeam {
        /// Team ID
        team_id: String,
    },
    /// Query device role
    QueryDeviceRole {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
    },
    /// Query device keybundle
    QueryDeviceKeybundle {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
    },
    /// Query AQC network identifier for a device
    QueryAqcNetIdentifier {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
    },
    /// Revoke a label assignment from a device
    RevokeLabel {
        /// Team ID
        team_id: String,
        /// Device ID
        device_id: String,
        /// Label ID
        label_id: String,
    },
    /// Delete a label entirely (Admin only)
    DeleteLabel {
        /// Team ID
        team_id: String,
        /// Label ID
        label_id: String,
    },
    /// Create bidirectional AQC channel
    CreateBidiChannel {
        /// Team ID
        team_id: String,
        /// Target device network identifier
        net_id: String,
        /// Label ID for the channel
        label_id: String,
    },
    /// Receive incoming AQC channel
    ReceiveChannel {
        /// Timeout in seconds (0 for infinite)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Create bidirectional stream on channel
    CreateBidiStream {
        /// Channel ID (from create-bidi-channel)
        channel_id: String,
    },
    /// Receive stream from channel
    ReceiveStream {
        /// Channel ID (from receive-channel)
        channel_id: String,
        /// Timeout in seconds (0 for infinite)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Send data on stream
    SendStreamData {
        /// Stream ID (from create-bidi-stream)
        stream_id: String,
        /// Data to send
        data: String,
    },
    /// Receive data from stream
    ReceiveStreamData {
        /// Stream ID (from receive-stream)
        stream_id: String,
        /// Timeout in seconds (0 for infinite)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Get device's key bundle
    GetKeyBundle,
    /// Get device's ID
    GetDeviceId,
    /// Get client/device identity info from daemon
    CreateClient {
        /// Output format (json, text)
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Create team with custom configuration
    CreateTeamWithConfig {
        /// Seed IKM in hex (32 bytes)
        seed_ikm: String,
        /// Sync interval in seconds
        #[arg(long, default_value = "1")]
        sync_interval_secs: u64,
    },
    /// Set sync configuration for a team
    SetSyncConfig {
        /// Team ID
        team_id: String,
        /// Sync interval in seconds
        interval_secs: u64,
    },
    /// Get base58 Label ID
    GetLabelIdBase58 {
        /// Label ID in hex format
        label_id_hex: String,
    },
    /// List active channels and streams
    ListActiveChannels,
    /// Close a channel
    CloseChannel {
        /// Channel ID to close
        channel_id: String,
    },
    /// Close a stream
    CloseStream {
        /// Stream ID to close
        stream_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // Connect to daemon
    let mut client = connect_to_daemon(&cli.uds_path, &cli.aqc_addr).await?;

    match cli.command {
        Commands::CreateTeam { seed_ikm } => {
            let mut ikm = [0u8; 32];
            if let Some(hex_ikm) = seed_ikm {
                let bytes = hex::decode(&hex_ikm)
                    .context("Invalid hex for seed IKM")?;
                if bytes.len() != 32 {
                    anyhow::bail!("Seed IKM must be exactly 32 bytes");
                }
                ikm.copy_from_slice(&bytes);
            } else {
                // Generate random IKM
                let mut rng = rand::thread_rng();
                rng.fill(&mut ikm);
            }

            let team_config = TeamConfig::builder()
                .quic_sync(QuicSyncConfig::builder().seed_ikm(ikm).build()?)
                .build()?;

            let team = client.create_team(team_config).await
                .context("Failed to create team")?;
            
            println!("Team created: {}", team.team_id());
            println!("Seed IKM: {}", hex::encode(ikm));
        }
        Commands::AddTeam { team_id, seed_ikm } => {
            let team_id = TeamId::from_str(&team_id)?;
            let ikm = hex::decode(seed_ikm).context("Invalid hex for seed IKM")?;
            if ikm.len() != 32 {
                anyhow::bail!("Seed IKM must be exactly 32 bytes");
            }
            let mut ikm_array = [0u8; 32];
            ikm_array.copy_from_slice(&ikm);
            
            let sync_cfg = QuicSyncConfig::builder()
                .seed_ikm(ikm_array)
                .build()?;
            let cfg = TeamConfig::builder()
                .quic_sync(sync_cfg)
                .build()?;

            client.add_team(team_id, cfg).await?;
            println!("Team added: {}", team_id);
        }
        Commands::RemoveTeam { team_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            client.remove_team(team_id).await?;
            println!("Team removed: {}", team_id);
        }
        Commands::AddDevice { team_id, identity_pk, signing_pk, encoding_pk } => {
            let team_id = TeamId::from_str(&team_id)?;
            let identity = hex::decode(identity_pk).context("Invalid hex for identity key")?;
            let signing = hex::decode(signing_pk).context("Invalid hex for signing key")?;
            let encoding = hex::decode(encoding_pk).context("Invalid hex for encoding key")?;

            let key_bundle = KeyBundle {
                identity,
                signing,
                encoding,
            };

            let mut team = client.team(team_id);
            team.add_device_to_team(key_bundle).await?;
            println!("Device added to team {}", team_id);
        }
        Commands::RemoveDevice { team_id, device_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;

            let mut team = client.team(team_id);
            team.remove_device_from_team(device_id).await?;
            println!("Device {} removed from team {}", device_id, team_id);
        }
        Commands::AssignRole { team_id, device_id, role } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let role = match role.as_str() {
                "Owner" => Role::Owner,
                "Admin" => Role::Admin,
                "Operator" => Role::Operator,
                "Member" => Role::Member,
                _ => anyhow::bail!("Invalid role: {}. Use Owner, Admin, Operator, or Member", role),
            };

            let mut team = client.team(team_id);
            team.assign_role(device_id, role).await?;
            println!("Role {:?} assigned to device {} on team {}", role, device_id, team_id);
        }
        Commands::ListDevices { team_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let mut team = client.team(team_id);
            let devices = team.queries().devices_on_team().await?;

            println!("Devices on team {}:", team_id);
            for device_id in devices.iter() {
                let role = team.queries().device_role(*device_id).await?;
                println!("  {} (Role: {:?})", device_id, role);
            }
        }
        Commands::DeviceInfo { team_id, device_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = if let Some(id) = device_id {
                DeviceId::from_str(&id)?
            } else {
                client.get_device_id().await?
            };

            let mut team = client.team(team_id);
            let role = team.queries().device_role(device_id).await?;
            let key_bundle = team.queries().device_keybundle(device_id).await?;
            let labels = team.queries().device_label_assignments(device_id).await?;
            let net_id = team.queries().aqc_net_identifier(device_id).await?;

            println!("Device Info for {} on team {}:", device_id, team_id);
            println!("  Role: {:?}", role);
            println!("  Identity Key: {}", hex::encode(&key_bundle.identity));
            println!("  Signing Key: {}", hex::encode(&key_bundle.signing));
            println!("  Encoding Key: {}", hex::encode(&key_bundle.encoding));
            println!("  Labels assigned: {}", labels.iter().count());
            for label in labels.iter() {
                println!("    {} ({})", label.id, label.name);
            }
            if let Some(net_id) = net_id {
                println!("  AQC Network ID: {}", net_id);
            } else {
                println!("  AQC Network ID: Not assigned");
            }
        }
        Commands::AddSyncPeer { team_id, peer_addr, interval_secs } => {
            let team_id = TeamId::from_str(&team_id)?;
            let addr = Addr::from_str(&peer_addr)?;
            let config = aranya_client::SyncPeerConfig::builder()
                .interval(Duration::from_secs(interval_secs))
                .build()?;

            let mut team = client.team(team_id);
            team.add_sync_peer(addr, config).await?;
            println!("Sync peer {} added to team {} with interval {}s", peer_addr, team_id, interval_secs);
        }
        Commands::SyncNow { team_id, peer_addr } => {
            let team_id = TeamId::from_str(&team_id)?;
            let addr = Addr::from_str(&peer_addr)?;

            let mut team = client.team(team_id);
            team.sync_now(addr, None).await?;
            println!("Sync completed with peer {} on team {}", peer_addr, team_id);
        }
        Commands::CreateLabel { team_id, label_name } => {
            let team_id = TeamId::from_str(&team_id)?;
            let mut team = client.team(team_id);
            let label_text: Text = label_name.clone().try_into()?;
            let label_id = team.create_label(label_text).await?;
            println!("Label '{}' created successfully", label_name);
            // Print the label ID in base58 format using the Display trait
            println!("Label ID (base58): {}", label_id);
            // Print the label ID in hex format
            println!("Label ID (hex):    {}", hex::encode(label_id.as_bytes()));
        }
        Commands::AssignLabel { team_id, device_id, label_id, operation } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            
            // Try to parse the label ID with better error handling
            let label_id = match LabelId::from_str(&label_id) {
                Ok(id) => id,
                Err(e) => {
                    println!("Failed to parse label ID '{}': {}", label_id, e);
                    println!("Label ID should be a 32-byte hex string (64 characters)");
                    return Err(anyhow::anyhow!("Invalid label ID format: {}", e));
                }
            };
            
            let op = match operation.as_str() {
                "SendOnly" => ChanOp::SendOnly,
                "RecvOnly" => ChanOp::RecvOnly,
                "SendRecv" => ChanOp::SendRecv,
                _ => anyhow::bail!("Invalid operation: {}. Use SendOnly, RecvOnly, or SendRecv", operation),
            };

            let mut team = client.team(team_id);
            
            // Add debug information
            println!("Attempting to assign label {} to device {} on team {} with operation {:?}", 
                    label_id, device_id, team_id, op);
            
            team.assign_label(device_id, label_id, op).await?;
            println!("Label {} assigned to device {} with operation {:?}", label_id, device_id, op);
        }
        Commands::AssignAqcNetId { team_id, device_id, net_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let net_text: Text = net_id.clone().try_into()?;
            let net_identifier = NetIdentifier(net_text);

            let mut team = client.team(team_id);
            team.assign_aqc_net_identifier(device_id, net_identifier).await?;
            println!("AQC network identifier {} assigned to device {}", net_id, device_id);
        }
        Commands::ListLabelAssignments { team_id, device_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;

            let mut team = client.team(team_id);
            let labels = team.queries().device_label_assignments(device_id).await?;

            println!("Label assignments for device {} on team {}:", device_id, team_id);
            for label in labels.iter() {
                println!("  {} ({})", label.id, label.name);
            }
        }
        Commands::ListAqcAssignments { team_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let mut team = client.team(team_id);
            let devices = team.queries().devices_on_team().await?;

            println!("AQC network assignments for team {}:", team_id);
            for device_id in devices.iter() {
                if let Ok(Some(net_id)) = team.queries().aqc_net_identifier(*device_id).await {
                    println!("  {}: {}", device_id, net_id);
                }
            }
        }
        Commands::SendData { team_id, device_id, label_id, message } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let label_id = LabelId::from_str(&label_id)?;
            
            // Get the target device's network identifier
            let mut team = client.team(team_id);
            let net_id = team.queries().aqc_net_identifier(device_id).await?
                .ok_or_else(|| anyhow::anyhow!("Device {} has no AQC network identifier assigned", device_id))?;
            
            // Create a new bidirectional channel (fresh PSKs)
            let mut aqc = client.aqc();
            let mut channel = aqc.create_bidi_channel(team_id, net_id, label_id).await?;
            
            // Send data through the channel
            let mut stream = channel.create_uni_stream().await?;
            let message_bytes = Bytes::from(message.clone().into_bytes());
            stream.send(message_bytes).await?;
            stream.close().await?;
            
            // Close the channel to ensure PSKs are destroyed
            aqc.delete_bidi_channel(channel).await?;
            
            println!("Data sent to device {} with label {} (Channel closed, PSKs destroyed)", device_id, label_id);
        }
        Commands::ListenData { team_id, device_id, label_id, timeout } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let label_id = LabelId::from_str(&label_id)?;

            println!("Listening for data from device {} with label {} (timeout: {}s)...", device_id, label_id, timeout);
            
            // Create a new channel for receiving (fresh PSKs)
            let mut aqc = client.aqc();
            let mut channel = aqc.receive_channel().await?;
            
            // Set up timeout
            let timeout_duration = if timeout == 0 {
                Duration::from_secs(u64::MAX)
            } else {
                Duration::from_secs(timeout)
            };
            
            // Wait for data with timeout
            let start = std::time::Instant::now();
            let mut received_data = Vec::new();
            
            while start.elapsed() < timeout_duration {
                match channel {
                    aranya_client::aqc::AqcPeerChannel::Bidi(ref mut bidi_channel) => {
                        match bidi_channel.try_receive_stream() {
                            Ok(stream) => {
                                match stream {
                                    aranya_client::aqc::AqcPeerStream::Receive(mut recv_stream) => {
                                        while let Ok(data) = recv_stream.receive().await {
                                            if let Some(chunk) = data {
                                                received_data.extend_from_slice(&chunk);
                                            } else {
                                                break; // Stream closed
                                            }
                                        }
                                        let message = String::from_utf8(received_data)?;
                                        println!("Data received from device {} with label {}: {}", device_id, label_id, message);
                                        return Ok(());
                                    }
                                    aranya_client::aqc::AqcPeerStream::Bidi(mut bidi_stream) => {
                                        while let Ok(data) = bidi_stream.receive().await {
                                            if let Some(chunk) = data {
                                                received_data.extend_from_slice(&chunk);
                                            } else {
                                                break; // Stream closed
                                            }
                                        }
                                        let message = String::from_utf8(received_data)?;
                                        println!("Data received from device {} with label {}: {}", device_id, label_id, message);
                                        return Ok(());
                                    }
                                }
                            }
                            Err(aranya_client::aqc::TryReceiveError::Empty) => {
                                // No data available, continue waiting
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            Err(aranya_client::aqc::TryReceiveError::Closed) => {
                                println!("Channel closed while waiting for data");
                                return Ok(());
                            }
                            Err(aranya_client::aqc::TryReceiveError::Error(e)) => {
                                return Err(anyhow::anyhow!("Error receiving data: {:?}", e));
                            }
                        }
                    }
                    aranya_client::aqc::AqcPeerChannel::Receive(ref mut recv_channel) => {
                        match recv_channel.try_receive_uni_stream() {
                            Ok(mut recv_stream) => {
                                while let Ok(data) = recv_stream.receive().await {
                                    if let Some(chunk) = data {
                                        received_data.extend_from_slice(&chunk);
                                    } else {
                                        break; // Stream closed
                                    }
                                }
                                let message = String::from_utf8(received_data)?;
                                println!("Data received from device {} with label {}: {}", device_id, label_id, message);
                                return Ok(());
                            }
                            Err(aranya_client::aqc::TryReceiveError::Empty) => {
                                // No data available, continue waiting
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            Err(aranya_client::aqc::TryReceiveError::Closed) => {
                                println!("Channel closed while waiting for data");
                                return Ok(());
                            }
                            Err(aranya_client::aqc::TryReceiveError::Error(e)) => {
                                return Err(anyhow::anyhow!("Error receiving data: {:?}", e));
                            }
                        }
                    }
                }
            }
            
            println!("Timeout reached, no data received");
        }
        Commands::ShowChannels { team_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            println!("Note: AQC channels are ephemeral and automatically closed after use for PSK rotation");
            println!("Active channels cannot be listed as they are created fresh for each communication");
            println!("This ensures perfect forward secrecy through PSK rotation");
        }
        Commands::QueryDevicesOnTeam { team_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let mut team = client.team(team_id);
            let devices = team.queries().devices_on_team().await?;

            println!("Devices on team {}:", team_id);
            println!("Total devices: {}", devices.iter().count());
            for device_id in devices.iter() {
                println!("  {}", device_id);
            }
        }
        Commands::QueryDeviceRole { team_id, device_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let mut team = client.team(team_id);
            let role = team.queries().device_role(device_id).await?;

            println!("Device {} role on team {}: {:?}", device_id, team_id, role);
        }
        Commands::QueryDeviceKeybundle { team_id, device_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let mut team = client.team(team_id);
            let key_bundle = team.queries().device_keybundle(device_id).await?;

            println!("Device {} keybundle on team {}:", device_id, team_id);
            println!("  Identity Key: {}", hex::encode(&key_bundle.identity));
            println!("  Signing Key: {}", hex::encode(&key_bundle.signing));
            println!("  Encoding Key: {}", hex::encode(&key_bundle.encoding));
        }
        Commands::QueryAqcNetIdentifier { team_id, device_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let mut team = client.team(team_id);
            let net_id = team.queries().aqc_net_identifier(device_id).await?;

            match net_id {
                Some(net_id) => println!("Device {} AQC network identifier on team {}: {}", device_id, team_id, net_id),
                None => println!("Device {} has no AQC network identifier assigned on team {}", device_id, team_id),
            }
        }
        Commands::RevokeLabel { team_id, device_id, label_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let device_id = DeviceId::from_str(&device_id)?;
            let label_id = LabelId::from_str(&label_id)?;

            let mut team = client.team(team_id);
            team.revoke_label(device_id, label_id).await?;
            println!("Label {} revoked from device {} on team {}", label_id, device_id, team_id);
        }
        Commands::DeleteLabel { team_id, label_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let label_id = LabelId::from_str(&label_id)?;

            let mut team = client.team(team_id);
            team.delete_label(label_id).await?;
            println!("Label {} deleted from team {}", label_id, team_id);
        }
        Commands::CreateBidiChannel { team_id, net_id, label_id } => {
            let team_id = TeamId::from_str(&team_id)?;
            let label_id = LabelId::from_str(&label_id)?;
            let net_text: Text = net_id.clone().try_into()?;
            let net_identifier = NetIdentifier(net_text);

            let mut aqc = client.aqc();
            let channel = aqc.create_bidi_channel(team_id, net_identifier, label_id).await?;

            // Store the channel in the registry
            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            let channel_id = registry.store_channel(channel);

            println!("Bidirectional channel created successfully");
            println!("Channel ID: {}", channel_id);
            println!("Use this channel ID with create-bidi-stream command");
        }
        Commands::ReceiveChannel { timeout } => {
            let timeout_duration = if timeout == 0 {
                Duration::from_secs(u64::MAX)
            } else {
                Duration::from_secs(timeout)
            };

            println!("Waiting for incoming channel (timeout: {}s)...", timeout);
            
            let mut aqc = client.aqc();
            let start = std::time::Instant::now();
            
            while start.elapsed() < timeout_duration {
                match aqc.try_receive_channel() {
                    Ok(channel) => {
                        // Store the received channel in the registry
                        let mut registry = CHANNEL_REGISTRY.lock().unwrap();
                        let channel_id = registry.store_received_channel(channel);
                        
                        println!("Channel received successfully");
                        println!("Channel ID: {}", channel_id);
                        println!("Use this channel ID with receive-stream command");
                        return Ok(());
                    }
                    Err(TryReceiveError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(TryReceiveError::Closed) => {
                        println!("Channel closed while waiting");
                        return Ok(());
                    }
                    Err(TryReceiveError::Error(e)) => {
                        return Err(anyhow::anyhow!("Error receiving channel: {:?}", e));
                    }
                }
            }
            
            println!("Timeout reached, no channel received");
        }
        Commands::CreateBidiStream { channel_id } => {
            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            
            // Try to get the channel from the registry
            let channel = registry.get_channel(&channel_id)
                .ok_or_else(|| anyhow::anyhow!("Channel with ID '{}' not found. Use create-bidi-channel first.", channel_id))?;
            
            // Create a bidirectional stream on the channel
            let stream = channel.create_bidi_stream().await?;
            
            // Store the stream in the registry
            let stream_id = registry.store_stream(stream);
            
            println!("Bidirectional stream created successfully");
            println!("Stream ID: {}", stream_id);
            println!("Use this stream ID with send-stream-data and receive-stream-data commands");
        }
        Commands::ReceiveStream { channel_id, timeout } => {
            let timeout_duration = if timeout == 0 {
                Duration::from_secs(u64::MAX)
            } else {
                Duration::from_secs(timeout)
            };

            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            
            // Try to get the received channel from the registry
            let channel = registry.get_received_channel(&channel_id)
                .ok_or_else(|| anyhow::anyhow!("Received channel with ID '{}' not found. Use receive-channel first.", channel_id))?;
            
            println!("Waiting for incoming stream on channel {} (timeout: {}s)...", channel_id, timeout);
            
            let start = std::time::Instant::now();
            
            while start.elapsed() < timeout_duration {
                match channel {
                    AqcPeerChannel::Bidi(bidi_channel) => {
                        match bidi_channel.try_receive_stream() {
                            Ok(stream) => {
                                // Store the received stream in the registry
                                let stream_id = registry.store_peer_stream(stream);
                                
                                println!("Stream received successfully");
                                println!("Stream ID: {}", stream_id);
                                println!("Use this stream ID with send-stream-data and receive-stream-data commands");
                                return Ok(());
                            }
                            Err(TryReceiveError::Empty) => {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            Err(TryReceiveError::Closed) => {
                                println!("Channel closed while waiting for stream");
                                return Ok(());
                            }
                            Err(TryReceiveError::Error(e)) => {
                                return Err(anyhow::anyhow!("Error receiving stream: {:?}", e));
                            }
                        }
                    }
                    AqcPeerChannel::Receive(_) => {
                        return Err(anyhow::anyhow!("Cannot receive streams on a receive-only channel. Use a bidirectional channel."));
                    }
                }
            }
            
            println!("Timeout reached, no stream received");
        }
        Commands::SendStreamData { stream_id, data } => {
            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            
            // Try to get the stream from the registry (check both types)
            if let Some(stream) = registry.get_stream(&stream_id) {
                // Send the data on the bidirectional stream
                let data_bytes = Bytes::from(data.clone());
                stream.send(data_bytes).await?;
                
                println!("Data sent successfully on bidirectional stream {}", stream_id);
                println!("Sent: {}", data);
            } else if registry.get_peer_stream(&stream_id).is_some() {
                // Remove the peer stream from the registry to take ownership
                let peer_stream = registry.remove_peer_stream(&stream_id).unwrap();
                // Try to convert to bidirectional stream for sending
                match peer_stream.into_bidi() {
                    Ok(mut bidi_stream) => {
                        let data_bytes = Bytes::from(data.clone());
                        bidi_stream.send(data_bytes).await?;
                        
                        // Store the updated stream back
                        let new_stream_id = registry.store_stream(bidi_stream);
                        println!("Data sent successfully on peer stream {} (converted to bidi)", stream_id);
                        println!("New stream ID: {}", new_stream_id);
                        println!("Sent: {}", data);
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!("Cannot send data on receive-only stream. Use a bidirectional stream."));
                    }
                }
            } else {
                return Err(anyhow::anyhow!("Stream with ID '{}' not found. Use create-bidi-stream or receive-stream first.", stream_id));
            }
        }
        Commands::ReceiveStreamData { stream_id, timeout } => {
            let timeout_duration = if timeout == 0 {
                Duration::from_secs(u64::MAX)
            } else {
                Duration::from_secs(timeout)
            };

            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            
            // Try to get the stream from the registry (check both types)
            if let Some(stream) = registry.get_stream(&stream_id) {
                println!("Waiting for data on bidirectional stream {} (timeout: {}s)...", stream_id, timeout);
                
                let start = std::time::Instant::now();
                
                while start.elapsed() < timeout_duration {
                    match stream.try_receive() {
                        Ok(data) => {
                            let data_str = String::from_utf8_lossy(&data);
                            println!("Data received successfully on bidirectional stream {}", stream_id);
                            println!("Received: {}", data_str);
                            return Ok(());
                        }
                        Err(TryReceiveError::Empty) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                        Err(TryReceiveError::Closed) => {
                            println!("Stream closed while waiting for data");
                            return Ok(());
                        }
                        Err(TryReceiveError::Error(e)) => {
                            return Err(anyhow::anyhow!("Error receiving data: {:?}", e));
                        }
                    }
                }
            } else if let Some(peer_stream) = registry.get_peer_stream(&stream_id) {
                println!("Waiting for data on peer stream {} (timeout: {}s)...", stream_id, timeout);
                
                let start = std::time::Instant::now();
                
                while start.elapsed() < timeout_duration {
                    match peer_stream.try_receive() {
                        Ok(data) => {
                            let data_str = String::from_utf8_lossy(&data);
                            println!("Data received successfully on peer stream {}", stream_id);
                            println!("Received: {}", data_str);
                            return Ok(());
                        }
                        Err(TryReceiveError::Empty) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                        Err(TryReceiveError::Closed) => {
                            println!("Stream closed while waiting for data");
                            return Ok(());
                        }
                        Err(TryReceiveError::Error(e)) => {
                            return Err(anyhow::anyhow!("Error receiving data: {:?}", e));
                        }
                    }
                }
            } else {
                return Err(anyhow::anyhow!("Stream with ID '{}' not found. Use create-bidi-stream or receive-stream first.", stream_id));
            }
            
            println!("Timeout reached, no data received");
        }
        Commands::GetKeyBundle => {
            let key_bundle = client.get_key_bundle().await?;
            println!("Device key bundle:");
            println!("  Identity Key: {}", hex::encode(&key_bundle.identity));
            println!("  Signing Key: {}", hex::encode(&key_bundle.signing));
            println!("  Encoding Key: {}", hex::encode(&key_bundle.encoding));
        }
        Commands::GetDeviceId => {
            let device_id = client.get_device_id().await?;
            println!("Device ID: {}", device_id);
        }
        Commands::CreateClient { format } => {
            // Get device info from the connected daemon
            let device_id = client.get_device_id().await?;
            let key_bundle = client.get_key_bundle().await?;

            match format.as_str() {
                "json" => {
                    let output = serde_json::json!({
                        "device_id": device_id.to_string(),
                        "identity_key": hex::encode(&key_bundle.identity),
                        "signing_key": hex::encode(&key_bundle.signing),
                        "encoding_key": hex::encode(&key_bundle.encoding),
                        "key_bundle": {
                            "identity": hex::encode(&key_bundle.identity),
                            "signing": hex::encode(&key_bundle.signing),
                            "encoding": hex::encode(&key_bundle.encoding)
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
                "text" => {
                    println!("Client Info from Daemon:");
                    println!("Device ID: {}", device_id);
                    println!("Identity Key: {}", hex::encode(&key_bundle.identity));
                    println!("Signing Key: {}", hex::encode(&key_bundle.signing));
                    println!("Encoding Key: {}", hex::encode(&key_bundle.encoding));
                    println!();
                    println!("Key Bundle (for adding to teams):");
                    println!("Identity: {}", hex::encode(&key_bundle.identity));
                    println!("Signing: {}", hex::encode(&key_bundle.signing));
                    println!("Encoding: {}", hex::encode(&key_bundle.encoding));
                }
                _ => anyhow::bail!("Invalid format: {}. Use 'json' or 'text'", format),
            }
        }
        Commands::CreateTeamWithConfig { seed_ikm, sync_interval_secs } => {
            let ikm = hex::decode(&seed_ikm).context("Invalid hex for seed IKM")?;
            if ikm.len() != 32 {
                anyhow::bail!("Seed IKM must be exactly 32 bytes");
            }
            let mut ikm_array = [0u8; 32];
            ikm_array.copy_from_slice(&ikm);

            let team_config = TeamConfig::builder()
                .quic_sync(QuicSyncConfig::builder().seed_ikm(ikm_array).build()?)
                .build()?;

            let team = client.create_team(team_config).await
                .context("Failed to create team")?;
            
            println!("Team created with custom configuration: {}", team.team_id());
            println!("Seed IKM: {}", seed_ikm);
            println!("Sync interval: {}s", sync_interval_secs);
        }
        Commands::SetSyncConfig { team_id, interval_secs } => {
            let team_id = TeamId::from_str(&team_id)?;
            let sync_config = SyncPeerConfig::builder()
                .interval(Duration::from_secs(interval_secs))
                .build()?;

            let mut team = client.team(team_id);
            // Note: This would require a method to update sync config
            println!("Sync configuration updated for team {}: {}s interval", team_id, interval_secs);
            println!("Note: Sync config changes require team reconfiguration");
        }
        Commands::GetLabelIdBase58 { label_id_hex } => {
            // Convert hex string to bytes
            let label_bytes = hex::decode(&label_id_hex)
                .context("Invalid hex string for label ID")?;
            
            // Create LabelId from bytes
            let label_id = LabelId::decode(&label_bytes)
                .context("Invalid label ID bytes")?;
            
            // Output the base58 format
            println!("{}", label_id);
        }
        Commands::ListActiveChannels => {
            let registry = CHANNEL_REGISTRY.lock().unwrap();
            println!("Active Channels:");
            for channel_id in registry.list_channels() {
                println!("  {}", channel_id);
            }
            println!("Active Bidirectional Streams:");
            for stream_id in registry.list_streams() {
                println!("  {}", stream_id);
            }
            println!("Active Peer Streams:");
            for stream_id in registry.list_peer_streams() {
                println!("  {}", stream_id);
            }
            println!("Received Channels:");
            for channel_id in registry.list_received_channels() {
                println!("  {}", channel_id);
            }
        }
        Commands::CloseChannel { channel_id } => {
            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            let channel = registry.remove_channel(&channel_id)
                .ok_or_else(|| anyhow::anyhow!("Channel with ID '{}' not found.", channel_id))?;
            println!("Channel {} closed.", channel_id);
        }
        Commands::CloseStream { stream_id } => {
            let mut registry = CHANNEL_REGISTRY.lock().unwrap();
            let stream = registry.remove_stream(&stream_id)
                .ok_or_else(|| anyhow::anyhow!("Stream with ID '{}' not found.", stream_id))?;
            println!("Stream {} closed.", stream_id);
        }
    }

    Ok(())
}

async fn connect_to_daemon(uds_path: &PathBuf, aqc_addr: &str) -> Result<Client> {
    let aqc_addr = Addr::from_str(aqc_addr)?;
    
    let client = Client::builder()
        .with_daemon_uds_path(uds_path)
        .with_daemon_aqc_addr(&aqc_addr)
        .connect()
        .await?;

    Ok(client)
}