use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    iter,
    net::Ipv4Addr,
    path::PathBuf,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aranya_client::{
    client::{Client, DeviceId, KeyBundle, Role, RoleManagementPermission, TeamId},
    config::CreateTeamConfig,
    AddTeamConfig, AddTeamQuicSyncConfig, Addr, CreateTeamQuicSyncConfig, SyncPeerConfig,
};
use aranya_crypto::dangerous::spideroak_crypto::{hash::Hash, rust::Sha256};
use aranya_daemon::{
    config::{self as daemon_cfg, Config, Toggle},
    Daemon, DaemonHandle,
};
use aranya_daemon_api::SEED_IKM_SIZE;
use backon::{ExponentialBuilder, Retryable as _};
use futures_util::try_join;
use pcap::{Capture, Device, Savefile};
use spideroak_base58::ToBase58 as _;
use tempfile::TempDir;
use tokio::{fs, sync::Mutex, time};
use tracing::{info, instrument, trace};

#[allow(dead_code)]
const SYNC_INTERVAL: Duration = Duration::from_millis(100);
// Allow for one missed sync and a misaligned sync rate, while keeping run times low.
#[allow(dead_code)]
pub const SLEEP_INTERVAL: Duration = Duration::from_millis(250);

#[instrument(skip_all)]
pub async fn sleep(duration: Duration) {
    trace!(?duration, "sleeping");
    time::sleep(duration).await;
}

pub struct DevicesCtx {
    pub owner: DeviceCtx,
    pub admin: DeviceCtx,
    pub operator: DeviceCtx,
    pub membera: DeviceCtx,
    pub memberb: DeviceCtx,
    _work_dir: TempDir,
}

impl DevicesCtx {
    pub async fn new(name: &str) -> Result<Self> {
        let work_dir = tempfile::tempdir()?;
        let work_dir_path = work_dir.path();

        let (owner, admin, operator, membera, memberb) = try_join!(
            DeviceCtx::new(name, "owner", work_dir_path.join("owner")),
            DeviceCtx::new(name, "admin", work_dir_path.join("admin")),
            DeviceCtx::new(name, "operator", work_dir_path.join("operator")),
            DeviceCtx::new(name, "membera", work_dir_path.join("membera")),
            DeviceCtx::new(name, "memberb", work_dir_path.join("memberb")),
        )?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
            _work_dir: work_dir,
        })
    }

    pub async fn add_all_device_roles(
        &mut self,
        team_id: TeamId,
        roles: &DefaultRoles,
    ) -> Result<()> {
        // Shorthand for the teams we need to operate on.
        let owner_team = self.owner.client.team(team_id);
        let admin_team = self.admin.client.team(team_id);
        let operator_team = self.operator.client.team(team_id);
        let membera_team = self.membera.client.team(team_id);
        let memberb_team = self.memberb.client.team(team_id);

        // Add the admin as a new device, and assign its role.
        info!("adding admin to team");
        owner_team
            .add_device(self.admin.pk.clone(), Some(roles.admin().id))
            .await?;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner_team
            .add_device(self.operator.pk.clone(), Some(roles.operator().id))
            .await?;

        // Make sure it sees the configuration change.
        admin_team
            .sync_now(self.owner.aranya_local_addr().await?, None)
            .await?;

        // Make sure it sees the configuration change.
        operator_team
            .sync_now(self.admin.aranya_local_addr().await?, None)
            .await?;

        // Add member A as a new device.
        info!("adding membera to team");
        admin_team
            .add_device(self.membera.pk.clone(), Some(roles.member().id))
            .await?;

        // Add member B as a new device.
        info!("adding memberb to team");
        admin_team
            .add_device(self.memberb.pk.clone(), Some(roles.member().id))
            .await?;

        // Make sure all see the configuration change.
        let admin_addr = self.admin.aranya_local_addr().await?;
        owner_team.sync_now(admin_addr, None).await?;
        operator_team.sync_now(admin_addr, None).await?;
        membera_team.sync_now(admin_addr, None).await?;
        memberb_team.sync_now(admin_addr, None).await?;

        Ok(())
    }

    pub async fn create_and_add_team(&mut self) -> Result<TeamId> {
        // Create the initial team, and get our TeamId.
        let seed_ikm = {
            let mut buf = [0; SEED_IKM_SIZE];
            self.owner.client.rand(&mut buf).await;
            buf
        };
        let owner_cfg = {
            let qs_cfg = CreateTeamQuicSyncConfig::builder()
                .seed_ikm(seed_ikm)
                .build()?;
            CreateTeamConfig::builder().quic_sync(qs_cfg).build()?
        };

        let team = {
            self.owner
                .client
                .create_team(owner_cfg)
                .await
                .expect("expected to create team")
        };
        let team_id = team.team_id();
        info!(?team_id);

        let cfg = {
            let qs_cfg = AddTeamQuicSyncConfig::builder()
                .seed_ikm(seed_ikm)
                .build()?;
            AddTeamConfig::builder()
                .team_id(team_id)
                .quic_sync(qs_cfg)
                .build()?
        };

        // Owner has the team added due to calling `create_team`, now we assign it to all other peers
        self.admin.client.add_team(cfg.clone()).await?;
        self.operator.client.add_team(cfg.clone()).await?;
        self.membera.client.add_team(cfg.clone()).await?;
        self.memberb.client.add_team(cfg).await?;

        Ok(team_id)
    }

    pub(crate) fn devices(&self) -> [&DeviceCtx; 5] {
        [
            &self.owner,
            &self.admin,
            &self.operator,
            &self.membera,
            &self.memberb,
        ]
    }

    #[instrument(skip(self))]
    pub async fn add_all_sync_peers(&self, team_id: TeamId) -> Result<()> {
        let config = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
        for device in self.devices() {
            for peer in self.devices() {
                if ptr::eq(device, peer) {
                    continue;
                }
                device
                    .client
                    .team(team_id)
                    .add_sync_peer(peer.aranya_local_addr().await?, config.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// NB: This includes the owner role, which is not returned
    /// by [`Client::setup_default_roles`].
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self, team_id: TeamId) -> Result<DefaultRoles> {
        self.owner.setup_default_roles(team_id, true).await
    }

    /// Sets up default roles without creating any management delegations.
    #[instrument(skip(self))]
    pub async fn setup_default_roles_without_delegation(
        &self,
        team_id: TeamId,
    ) -> Result<DefaultRoles> {
        self.owner.setup_default_roles(team_id, false).await
    }
}

/// Context for managing a variable number of devices.
pub struct MultiDevicesCtx {
    pub devices: Vec<DeviceCtx>,
    pub device_names: Vec<String>,
    _work_dir: TempDir,
}

impl MultiDevicesCtx {
    /// Creates a new context with the specified number of devices.
    /// The first device is the owner, the rest are members.
    pub async fn new_with_count(name: &str, num_devices: usize) -> Result<Self> {
        assert!(num_devices >= 1, "must have at least 1 device (owner)");
        let work_dir = tempfile::tempdir()?;
        let work_dir_path = work_dir.path();

        let mut devices = Vec::with_capacity(num_devices);
        let mut device_names = Vec::with_capacity(num_devices);

        // Create owner first
        let owner_name = "owner";
        device_names.push(owner_name.to_string());
        let owner = DeviceCtx::new(name, owner_name, work_dir_path.join(owner_name)).await?;
        devices.push(owner);

        // Create member devices
        for i in 1..num_devices {
            let member_name = format!("member{}", i);
            device_names.push(member_name.clone());
            let member =
                DeviceCtx::new(name, &member_name, work_dir_path.join(&member_name)).await?;
            devices.push(member);
        }

        Ok(Self {
            devices,
            device_names,
            _work_dir: work_dir,
        })
    }

    /// Returns a reference to the owner device (first device).
    pub fn owner(&self) -> &DeviceCtx {
        &self.devices[0]
    }

    /// Returns a reference to all member devices (excluding owner).
    pub fn members(&self) -> &[DeviceCtx] {
        &self.devices[1..]
    }

    /// Returns all devices.
    pub fn all_devices(&self) -> &[DeviceCtx] {
        &self.devices
    }

    /// Returns the device name for a given index.
    pub fn device_name(&self, index: usize) -> &str {
        &self.device_names[index]
    }

    /// Creates a team with the owner and adds all member devices to it.
    pub async fn create_and_add_team(&mut self) -> Result<TeamId> {
        // Create the initial team, and get our TeamId.
        let seed_ikm = {
            let mut buf = [0; SEED_IKM_SIZE];
            self.owner().client.rand(&mut buf).await;
            buf
        };
        let owner_cfg = {
            let qs_cfg = CreateTeamQuicSyncConfig::builder()
                .seed_ikm(seed_ikm)
                .build()?;
            CreateTeamConfig::builder().quic_sync(qs_cfg).build()?
        };

        let team = {
            self.owner()
                .client
                .create_team(owner_cfg)
                .await
                .expect("expected to create team")
        };
        let team_id = team.team_id();
        info!(?team_id);

        let cfg = {
            let qs_cfg = AddTeamQuicSyncConfig::builder()
                .seed_ikm(seed_ikm)
                .build()?;
            AddTeamConfig::builder()
                .team_id(team_id)
                .quic_sync(qs_cfg)
                .build()?
        };

        // Owner has the team added due to calling `create_team`, now we assign it to all other peers
        for device in self.members() {
            device.client.add_team(cfg.clone()).await?;
        }

        Ok(team_id)
    }

    /// Sets up default roles using the owner device.
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self, team_id: TeamId) -> Result<DefaultRoles> {
        self.owner().setup_default_roles(team_id, true).await
    }

    /// Builds a map of Addr to device name for logging purposes.
    pub async fn build_addr_to_name_map(&self) -> Result<HashMap<Addr, String>> {
        let mut map: HashMap<Addr, String> = HashMap::new();
        for (i, device) in self.devices.iter().enumerate() {
            let addr = device.aranya_local_addr().await?;
            let name = self.device_name(i).to_string();
            map.insert(addr, name);
        }
        Ok(map)
    }
}

pub struct DeviceCtx {
    pub client: Client,
    pub pk: KeyBundle,
    pub id: DeviceId,
    #[expect(unused, reason = "manages tasks")]
    pub daemon: DaemonHandle,
}

impl DeviceCtx {
    pub(crate) async fn new(team_name: &str, name: &str, work_dir: PathBuf) -> Result<Self> {
        let addr_any = Addr::from((Ipv4Addr::LOCALHOST, 0));

        // TODO: only compile when 'afc' feature is enabled
        let afc_shm_path = {
            use aranya_daemon_api::shm;

            let path = Self::get_shm_path(format!("/{team_name}_{name}\0"));
            let path: Box<shm::Path> = path
                .as_str()
                .try_into()
                .context("unable to parse AFC shared memory path")?;
            let _ = shm::unlink(&path);
            path
        };

        // Setup daemon config.
        let cfg = Config {
            name: name.into(),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("log"),
            config_dir: work_dir.join("config"),
            afc: Toggle::Enabled(daemon_cfg::AfcConfig {
                shm_path: afc_shm_path,
                max_chans: 100,
            }),
            sync: daemon_cfg::SyncConfig {
                quic: Toggle::Enabled(daemon_cfg::QuicSyncConfig {
                    addr: addr_any,
                    client_addr: None,
                }),
            },
        };

        for dir in [
            &cfg.runtime_dir,
            &cfg.state_dir,
            &cfg.cache_dir,
            &cfg.logs_dir,
            &cfg.config_dir,
        ] {
            fs::create_dir_all(dir)
                .await
                .with_context(|| format!("unable to create directory: {}", dir.display()))?;
        }
        let uds_path = cfg.uds_api_sock();

        // Load and start daemon from config.
        let daemon = Daemon::load(cfg.clone())
            .await
            .context("unable to load daemon")?
            .spawn()
            .await
            .context("unable to start daemon")?;

        // Initialize the user library - the client will automatically load the daemon's public key.
        let client = (|| Client::builder().with_daemon_uds_path(&uds_path).connect())
            .retry(ExponentialBuilder::default())
            .await
            .context("unable to init client")?;

        // Get device id and key bundle.
        let pk = client.get_key_bundle().await.expect("expected key bundle");
        let id = client.get_device_id().await.expect("expected device id");

        Ok(Self {
            client,
            pk,
            id,
            daemon,
        })
    }

    pub async fn aranya_local_addr(&self) -> Result<Addr> {
        Ok(self.client.local_addr().await?)
    }

    fn get_shm_path(path: String) -> String {
        if cfg!(target_os = "macos") && path.len() > 31 {
            // Shrink the size of the team name down to 22 bytes to work within macOS's limits.
            let d = Sha256::hash(path.as_bytes());
            let t: [u8; 16] = d[..16].try_into().expect("expected shm path");
            return format!("/{}\0", t.to_base58());
        };
        path
    }

    #[instrument(skip(self, grant_delegations))]
    async fn setup_default_roles(
        &self,
        team_id: TeamId,
        grant_delegations: bool,
    ) -> Result<DefaultRoles> {
        let owner_role = self
            .client
            .team(team_id)
            .roles()
            .await?
            .try_into_owner_role()?;
        tracing::debug!(owner_role_id = %owner_role.id);

        let setup_roles = self
            .client
            .team(team_id)
            .setup_default_roles(owner_role.id)
            .await?;

        let roles = setup_roles
            .into_iter()
            .chain(iter::once(owner_role))
            .try_into_default_roles()
            .context("unable to parse `DefaultRoles`")?;
        tracing::debug!(?roles, "default roles set up");

        if grant_delegations {
            let mappings = [
                // admin -> operator
                ("admin -> operator", roles.admin().id, roles.operator().id),
                // admin -> member
                ("admin -> member", roles.admin().id, roles.member().id),
                // operator -> member
                ("operator -> member", roles.operator().id, roles.member().id),
            ];
            for (name, manager, role) in mappings {
                self.client
                    .team(team_id)
                    .assign_role_management_permission(
                        role,
                        manager,
                        RoleManagementPermission::CanAssignRole,
                    )
                    .await
                    .with_context(|| format!("{name}: unable to change managing role"))?;
            }
        }

        Ok(roles)
    }
}

/// Converts operations on [`Roles`].
pub trait RolesExt {
    /// Converts [`Roles`] into [`DefaultRoles`].
    fn try_into_default_roles(self) -> Result<DefaultRoles>;
    // Retrieves the owner role.
    fn try_into_owner_role(self) -> Result<Role>;
}

impl<I> RolesExt for I
where
    I: IntoIterator<Item = Role>,
{
    fn try_into_default_roles(self) -> Result<DefaultRoles> {
        DefaultRoles::try_from(self)
    }

    fn try_into_owner_role(self) -> Result<Role> {
        self.into_iter()
            .find(|role| role.name == "owner" && role.default)
            .context("unable to find owner role")
    }
}

/// The default roles for a team.
// NB: This assumes users cannot delete roles yet, which is true
// as of MVP.
#[derive(Clone, Debug)]
pub struct DefaultRoles {
    roles: HashMap<String, Role>,
}

impl DefaultRoles {
    /// Returns the 'owner' role.
    pub fn owner(&self) -> &Role {
        self.roles.get("owner").expect("owner role should exist")
    }

    /// Returns the 'admin' role.
    pub fn admin(&self) -> &Role {
        self.roles.get("admin").expect("admin role should exist")
    }

    /// Returns the 'operator' role.
    pub fn operator(&self) -> &Role {
        self.roles
            .get("operator")
            .expect("operator role should exist")
    }

    /// Returns the 'member' role.
    pub fn member(&self) -> &Role {
        self.roles.get("member").expect("member role should exist")
    }
}

impl DefaultRoles {
    fn try_from(roles: impl IntoIterator<Item = Role>) -> Result<Self> {
        let names = ["owner", "admin", "operator", "member"];
        let roles = roles
            .into_iter()
            .filter(|role| {
                // We only care about default roles.
                role.default
            })
            .fold(HashMap::new(), |mut acc, role| {
                if !names.contains(&role.name.as_str()) {
                    panic!("unexpected role: {}", role.name);
                }
                if acc.insert(role.name.to_string(), role.clone()).is_some() {
                    panic!("duplicate role: {}", role.name);
                }
                acc
            });
        for name in names {
            if !roles.contains_key(name) {
                return Err(anyhow!("missing default role: {name}"));
            }
        }
        Ok(Self { roles })
    }
}

/// Helper for logging network traffic using actual packet capture (pcap).
/// Captures UDP packets on the loopback interface and logs them in tcpdump format.
pub struct NetworkLogger {
    addr_to_name: Arc<Mutex<HashMap<Addr, String>>>,
    port_to_name: Arc<Mutex<HashMap<u16, String>>>,
    ephemeral_assignments: Arc<Mutex<HashSet<String>>>, // Track which members have ephemeral ports assigned
    start_time: std::time::Instant,
    log_file: RefCell<Option<std::fs::File>>,
    log_file_arc: Option<Arc<std::sync::Mutex<Option<std::fs::File>>>>, // Shared file handle for writing action logs
    running: Arc<AtomicBool>,
    capture_handle: Option<tokio::task::JoinHandle<()>>,
}

impl NetworkLogger {
    /// Creates a new network logger with address-to-name mapping.
    /// Starts packet capture in the background.
    pub fn new(addr_to_name: HashMap<Addr, String>) -> Result<Self> {
        Self::new_with_file(addr_to_name, None, None)
    }

    /// Creates a new network logger that also writes to a file.
    /// Starts packet capture in the background.
    ///
    /// # Arguments
    /// * `addr_to_name` - Mapping of addresses to device names
    /// * `file_path` - Optional path for text log file (tcpdump format)
    /// * `pcap_file_path` - Optional path for pcap file (raw packet capture)
    pub fn new_with_file(
        addr_to_name: HashMap<Addr, String>,
        file_path: Option<&str>,
        pcap_file_path: Option<&str>,
    ) -> Result<Self> {
        let log_file = if let Some(path) = file_path {
            let mut file = std::fs::File::create(path)
                .with_context(|| format!("unable to create log file: {}", path))?;
            // Write a header line to verify file handle works
            use std::io::Write;
            writeln!(file, "# Network traffic log - tcpdump format")
                .with_context(|| format!("unable to write header to log file: {}", path))?;
            file.flush()
                .with_context(|| format!("unable to flush log file: {}", path))?;
            Some(file)
        } else {
            None
        };

        // Build port-to-name mapping from address-to-name
        // Note: This maps listening ports. QUIC uses ephemeral source ports for outbound connections,
        // so we'll only be able to identify devices by their destination (listening) ports.
        let mut port_to_name = HashMap::new();
        for (addr, name) in &addr_to_name {
            if let Ok(sock_addr) = addr.to_string().parse::<std::net::SocketAddr>() {
                let port = sock_addr.port();
                port_to_name.insert(port, name.clone());
                eprintln!("Mapped port {} -> {}", port, name);
            } else {
                eprintln!(
                    "Warning: Could not parse address {} for device {}",
                    addr, name
                );
            }
        }
        eprintln!(
            "Built port-to-name mapping with {} entries",
            port_to_name.len()
        );

        let addr_to_name = Arc::new(Mutex::new(addr_to_name));
        let port_to_name = Arc::new(Mutex::new(port_to_name));
        let ephemeral_assignments = Arc::new(Mutex::new(HashSet::new()));
        // Use std::sync::Mutex for file since we're in blocking context
        let log_file = Arc::new(std::sync::Mutex::new(log_file));
        let running = Arc::new(AtomicBool::new(true));
        let start_time = std::time::Instant::now();

        // Set environment variable so daemon can use the same time reference
        // Convert Instant to SystemTime for serialization
        let start_time_system = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        std::env::set_var(
            "ARANYA_NETWORK_LOG_START_TIME",
            start_time_system.to_string(),
        );

        // Try to start packet capture
        let capture_handle = match Self::start_capture(
            Arc::clone(&addr_to_name),
            Arc::clone(&port_to_name),
            Arc::clone(&ephemeral_assignments),
            Arc::clone(&log_file),
            Arc::clone(&running),
            start_time,
            pcap_file_path,
        ) {
            Ok(handle) => {
                if let Some(ref path) = file_path {
                    eprintln!("Packet capture started successfully. Logging to: {}", path);
                    // Verify file exists and is writable
                    if let Ok(metadata) = std::fs::metadata(path) {
                        eprintln!("Log file exists, size: {} bytes", metadata.len());
                    } else {
                        eprintln!("Warning: Log file does not exist at: {}", path);
                    }
                }
                Some(handle)
            }
            Err(e) => {
                eprintln!("Warning: Could not start packet capture: {}. Network logs will not show actual packet sizes.", e);
                eprintln!("Note: Packet capture may require root privileges on some systems.");
                // Still create the file even if capture fails, so user knows it was attempted
                if let Some(path) = file_path {
                    if let Ok(mut file) = std::fs::File::create(path) {
                        use std::io::Write;
                        let _ = writeln!(file, "# Packet capture failed: {}", e);
                        let _ = writeln!(
                            file,
                            "# Note: Packet capture may require root privileges on some systems."
                        );
                    }
                }
                None
            }
        };

        Ok(Self {
            addr_to_name,
            port_to_name,
            ephemeral_assignments,
            start_time,
            log_file: RefCell::new(None), // Not used when file is passed to capture task
            log_file_arc: Some(Arc::clone(&log_file)), // Store reference for writing action logs
            running,
            capture_handle,
        })
    }

    /// Writes an action log message to the network log file.
    /// This helps correlate network traffic with test actions.
    pub fn log_action(&self, message: &str) -> Result<()> {
        if let Some(ref log_file_arc) = self.log_file_arc {
            let elapsed = self.start_time.elapsed();
            let secs = elapsed.as_secs();
            let micros = elapsed.subsec_micros();

            let log_line = format!(
                "# {:02}:{:02}:{:02}.{:06} ACTION: {}",
                (secs / 3600) % 24,
                (secs / 60) % 60,
                secs % 60,
                micros,
                message
            );

            let mut log_file_guard = log_file_arc
                .lock()
                .map_err(|e| anyhow!("Failed to lock log file: {}", e))?;

            if let Some(ref mut file) = *log_file_guard {
                use std::io::Write;
                writeln!(file, "{}", log_line).context("Failed to write action log to file")?;
                file.flush().context("Failed to flush action log to file")?;
            }
        }
        Ok(())
    }

    /// Starts packet capture in a background task.
    fn start_capture(
        addr_to_name: Arc<Mutex<HashMap<Addr, String>>>,
        port_to_name: Arc<Mutex<HashMap<u16, String>>>,
        ephemeral_assignments: Arc<Mutex<HashSet<String>>>,
        log_file: Arc<std::sync::Mutex<Option<std::fs::File>>>,
        running: Arc<AtomicBool>,
        start_time: std::time::Instant,
        pcap_file_path: Option<&str>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        // Find loopback interface
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == "lo0" || d.name == "lo" || d.name.contains("Loopback"))
            .ok_or_else(|| anyhow!("could not find loopback interface"))?;

        let mut capture = Capture::from_device(device)?
            .promisc(false)
            .immediate_mode(true)
            .open()?;

        // Set filter for UDP packets (QUIC uses UDP)
        capture.filter("udp", true)?;

        // Create pcap savefile if requested
        let mut savefile: Option<Savefile> = if let Some(pcap_path) = pcap_file_path {
            let sf = capture
                .savefile(pcap_path)
                .with_context(|| format!("unable to create pcap savefile: {}", pcap_path))?;
            eprintln!("Saving raw packets to pcap file: {}", pcap_path);
            Some(sf)
        } else {
            None
        };

        // Use spawn_blocking since next_packet() is a blocking call
        let handle = tokio::task::spawn_blocking(move || {
            let mut packet_count = 0u64;
            let mut processed_count = 0u64;
            eprintln!("Packet capture loop started");
            while running.load(Ordering::SeqCst) {
                match capture.next_packet() {
                    Ok(packet) => {
                        packet_count += 1;

                        // Save raw packet to pcap file if configured
                        if let Some(ref mut sf) = savefile {
                            sf.write(&packet);
                        }

                        // Process packet - we need async runtime
                        let addr_to_name_clone = Arc::clone(&addr_to_name);
                        let port_to_name_clone = Arc::clone(&port_to_name);
                        let ephemeral_assignments_clone = Arc::clone(&ephemeral_assignments);
                        let log_file_clone = Arc::clone(&log_file);
                        let start_time_clone = start_time;

                        // Process packet - use blocking runtime to handle async mutex
                        if let Ok(rt) = tokio::runtime::Handle::try_current() {
                            match rt.block_on(async {
                                Self::process_packet(
                                    &packet,
                                    &addr_to_name_clone,
                                    &port_to_name_clone,
                                    &ephemeral_assignments_clone,
                                    &log_file_clone,
                                    start_time_clone,
                                )
                                .await
                            }) {
                                Ok(()) => {
                                    processed_count += 1;
                                }
                                Err(e) => {
                                    eprintln!("Error processing packet: {}", e);
                                }
                            }
                        } else {
                            eprintln!(
                                "Warning: No tokio runtime available, skipping packet processing"
                            );
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Timeout is expected, continue
                        continue;
                    }
                    Err(e) => {
                        if running.load(Ordering::SeqCst) {
                            eprintln!("Error capturing packet: {}", e);
                        }
                        break;
                    }
                }
            }
            eprintln!(
                "Packet capture stopped. Captured {} packets, processed {} packets.",
                packet_count, processed_count
            );
        });

        Ok(handle)
    }

    /// Processes a captured packet and logs it.
    async fn process_packet<'a>(
        packet: &'a pcap::Packet<'a>,
        addr_to_name: &Arc<Mutex<HashMap<Addr, String>>>,
        port_to_name: &Arc<Mutex<HashMap<u16, String>>>,
        ephemeral_assignments: &Arc<Mutex<HashSet<String>>>,
        log_file: &Arc<std::sync::Mutex<Option<std::fs::File>>>,
        start_time: std::time::Instant,
    ) -> Result<()> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static PACKET_COUNT: AtomicU32 = AtomicU32::new(0);
        let count = PACKET_COUNT.fetch_add(1, Ordering::Relaxed);

        if count < 10 || count % 50 == 0 {
            eprintln!(
                "[process_packet] Packet #{}: data len={}",
                count,
                packet.data.len()
            );
            // Show first 32 bytes in hex for debugging
            if packet.data.len() > 0 {
                let hex_preview: String = packet
                    .data
                    .iter()
                    .take(32.min(packet.data.len()))
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                eprintln!(
                    "[process_packet] Packet #{}: First {} bytes: {}",
                    count,
                    32.min(packet.data.len()),
                    hex_preview
                );
            }
        }

        // packet.data may include Ethernet header (14 bytes) on some interfaces
        // Try to find IP header - check if it starts with Ethernet or IP
        let mut ip_offset = 0;

        // Check if there's an Ethernet header (first byte of IP would be 0x45 for IPv4)
        // Ethernet header is 14 bytes, but on loopback it might be different
        if packet.data.len() >= 14 {
            // Check if bytes 12-13 look like Ethernet type (0x0800 for IPv4)
            let eth_type = u16::from_be_bytes([packet.data[12], packet.data[13]]);
            if eth_type == 0x0800 {
                // Ethernet header present, skip it
                ip_offset = 14;
                if count < 10 {
                    eprintln!(
                        "[process_packet] Packet #{}: Found Ethernet header, ip_offset=14",
                        count
                    );
                }
            } else {
                // Might be loopback header or raw IP
                // On macOS loopback (lo0), there's a 4-byte header: AF_INET (2) + padding
                // The AF_INET value is stored in little-endian: 02 00 = 0x0002
                if packet.data.len() >= 4 {
                    let af_family = u16::from_le_bytes([packet.data[0], packet.data[1]]);
                    if count < 10 {
                        eprintln!(
                            "[process_packet] Packet #{}: Checking loopback header, bytes[0-1]={:04x} (AF_INET=0x0002)",
                            count, af_family
                        );
                    }
                    if af_family == 0x0002 {
                        // Loopback header present (4 bytes), skip it
                        ip_offset = 4;
                        if count < 10 {
                            eprintln!(
                                "[process_packet] Packet #{}: Found loopback header, ip_offset=4",
                                count
                            );
                        }
                    } else {
                        // Check if first byte looks like IP version
                        let version = (packet.data[0] >> 4) & 0x0F;
                        if version == 4 {
                            ip_offset = 0; // Raw IP, no Ethernet header
                            if count < 10 {
                                eprintln!(
                                    "[process_packet] Packet #{}: Raw IP, no Ethernet header",
                                    count
                                );
                            }
                        } else {
                            if count < 10 {
                                eprintln!(
                                    "[process_packet] Packet #{}: Unknown format, version={}, first_byte=0x{:02x}, af_family=0x{:04x}",
                                    count, version, packet.data[0], af_family
                                );
                            }
                            return Ok(()); // Unknown format
                        }
                    }
                } else {
                    // Check if first byte looks like IP version
                    let version = (packet.data[0] >> 4) & 0x0F;
                    if version == 4 {
                        ip_offset = 0; // Raw IP, no Ethernet header
                        if count < 10 {
                            eprintln!(
                                "[process_packet] Packet #{}: Raw IP (short packet), no Ethernet header",
                                count
                            );
                        }
                    } else {
                        if count < 10 {
                            eprintln!(
                                "[process_packet] Packet #{}: Unknown format (short), version={}, first_byte=0x{:02x}",
                                count, version, packet.data[0]
                            );
                        }
                        return Ok(()); // Unknown format
                    }
                }
            }
        } else if packet.data.len() < 20 {
            if count < 10 {
                eprintln!(
                    "[process_packet] Packet #{}: Too short ({} bytes)",
                    count,
                    packet.data.len()
                );
            }
            return Ok(()); // Too short
        }

        let ip_data = &packet.data[ip_offset..];
        if ip_data.len() < 20 {
            if count < 10 {
                eprintln!(
                    "[process_packet] Packet #{}: IP data too short ({} bytes)",
                    count,
                    ip_data.len()
                );
            }
            return Ok(()); // Too short to be a valid IP packet
        }

        // Check if IPv4 (version 4)
        let version = (ip_data[0] >> 4) & 0x0F;
        if version != 4 {
            if count < 10 {
                eprintln!(
                    "[process_packet] Packet #{}: Not IPv4, version={}",
                    count, version
                );
            }
            return Ok(()); // Not IPv4
        }

        // Get IP header length
        let ihl = (ip_data[0] & 0x0F) as usize * 4;
        if ip_data.len() < ihl + 8 {
            if count < 10 {
                eprintln!(
                    "[process_packet] Packet #{}: Too short for UDP header (ihl={}, len={})",
                    count,
                    ihl,
                    ip_data.len()
                );
            }
            return Ok(()); // Too short for UDP header
        }

        // Parse UDP header
        let src_port = u16::from_be_bytes([ip_data[ihl], ip_data[ihl + 1]]);
        let dst_port = u16::from_be_bytes([ip_data[ihl + 2], ip_data[ihl + 3]]);
        let udp_length = u16::from_be_bytes([ip_data[ihl + 4], ip_data[ihl + 5]]);

        // Filter out mDNS/Bonjour traffic (port 53533)
        const MDNS_PORT: u16 = 53533;
        if src_port == MDNS_PORT || dst_port == MDNS_PORT {
            return Ok(()); // Skip mDNS/Bonjour packets
        }

        if count < 10 {
            eprintln!(
                "[process_packet] Packet #{}: Parsed UDP - src_port={}, dst_port={}, udp_length={}",
                count, src_port, dst_port, udp_length
            );
        }

        // UDP length includes 8-byte UDP header, but tcpdump shows total UDP packet size
        // If length is 0 or seems wrong, use the actual packet data length
        let actual_length = if udp_length == 0 || udp_length < 8 {
            // Fallback: calculate from IP total length minus IP header
            let ip_total_length = u16::from_be_bytes([ip_data[2], ip_data[3]]) as usize;
            if ip_total_length > ihl {
                ip_total_length - ihl // Total IP packet minus IP header = UDP packet size
            } else {
                udp_length as usize // Use UDP length field even if 0
            }
        } else {
            udp_length as usize
        };

        // Get device names from port mapping (async mutex)
        // QUIC uses ephemeral source ports for outbound connections, so we track them dynamically
        if count < 10 {
            eprintln!(
                "[process_packet] Packet #{}: Locking port_to_name mutex",
                count
            );
        }
        let mut port_to_name_guard = port_to_name.lock().await;
        if count < 10 {
            eprintln!(
                "[process_packet] Packet #{}: Got port_to_name lock, src_port={}, dst_port={}",
                count, src_port, dst_port
            );
        }

        // Check if source port is known (listening port or previously tracked ephemeral port)
        let src_name = if let Some(name) = port_to_name_guard.get(&src_port) {
            // Source port is known, get the name
            name.as_str()
        } else {
            // Source port is unknown - might be an ephemeral port
            // Check destination to infer source device
            let dst_name = port_to_name_guard
                .get(&dst_port)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            if dst_name != "unknown" {
                // Get list of all member names from address mapping
                let addr_to_name_guard = addr_to_name.lock().await;
                let mut member_names: Vec<String> = addr_to_name_guard
                    .values()
                    .filter(|name| name.starts_with("member"))
                    .cloned()
                    .collect();
                member_names.sort(); // Sort for consistent assignment
                drop(addr_to_name_guard); // Release lock before modifying port_to_name_guard

                // Find which members already have ephemeral ports assigned
                let mut assigned_members = ephemeral_assignments.lock().await;

                // Find the first unassigned member
                let inferred_name = if dst_name == "owner" {
                    // Source is connecting to owner, so it's a member
                    member_names
                        .iter()
                        .find(|name| !assigned_members.contains(*name))
                        .cloned()
                        .unwrap_or_else(|| {
                            // All members assigned, use a fallback
                            if count < 10 {
                                eprintln!(
                                    "[process_packet] Packet #{}: All members assigned, using fallback",
                                    count
                                );
                            }
                            "member?".to_string()
                        })
                } else {
                    // If destination is a member, source might be owner or another member
                    // Check if owner is available
                    if !port_to_name_guard.values().any(|name| name == "owner") {
                        "owner".to_string()
                    } else {
                        // Try to find an unassigned member
                        member_names
                            .iter()
                            .find(|name| !assigned_members.contains(*name))
                            .cloned()
                            .unwrap_or_else(|| "device?".to_string())
                    }
                };

                // Mark this member as having an ephemeral port assigned
                assigned_members.insert(inferred_name.clone());
                drop(assigned_members); // Release lock before modifying port_to_name_guard

                // Track this ephemeral port for future packets from the same source
                port_to_name_guard.insert(src_port, inferred_name.clone());
                if count < 10 {
                    eprintln!(
                        "[process_packet] Packet #{}: Tracked ephemeral port {} -> {}",
                        count, src_port, inferred_name
                    );
                }
                // Get the reference from the HashMap (it's now owned by the HashMap)
                port_to_name_guard
                    .get(&src_port)
                    .expect("just inserted this port")
                    .as_str()
            } else {
                "unknown"
            }
        };

        // Get destination name (or "unknown")
        let dst_name = port_to_name_guard
            .get(&dst_port)
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        if count < 10 {
            eprintln!(
                "[process_packet] Packet #{}: src_name={}, dst_name={}",
                count, src_name, dst_name
            );
        }

        // Always log packets, even if ports are unknown (helps debug)
        // Debug: log if we're filtering out packets (both unknown)
        let _is_unknown = src_name == "unknown" && dst_name == "unknown";

        // Calculate timestamp relative to start
        let elapsed = start_time.elapsed();
        let secs = elapsed.as_secs();
        let micros = elapsed.subsec_micros();

        // Format log line in tcpdump format
        let log_line = format!(
            "{:02}:{:02}:{:02}.{:06} IP {}.{} > {}.{}: UDP, length {}",
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60,
            micros,
            src_name,
            src_port,
            dst_name,
            dst_port,
            actual_length
        );

        if count < 10 {
            eprintln!(
                "[process_packet] Packet #{}: Formatted log_line (len={}): {}",
                count,
                log_line.len(),
                log_line
            );
        }

        // Write to file if configured
        // We're in async context but called from spawn_blocking via block_on
        // Since block_on allows blocking operations, we can lock the blocking mutex directly
        // Use tokio::task::block_in_place to explicitly mark this as a blocking operation
        if count < 10 {
            eprintln!("[process_packet] Packet #{}: About to write to file", count);
        }
        tokio::task::block_in_place(|| {
            if count < 10 {
                eprintln!(
                    "[process_packet] Packet #{}: Inside block_in_place, locking file mutex",
                    count
                );
            }
            let mut log_file_guard = match log_file.lock() {
                Ok(guard) => {
                    if count < 10 {
                        eprintln!("[process_packet] Packet #{}: Got file mutex lock", count);
                    }
                    guard
                }
                Err(e) => {
                    eprintln!(
                        "[process_packet] Packet #{}: Error locking log file mutex: {}",
                        count, e
                    );
                    return;
                }
            };
            match *log_file_guard {
                Some(ref mut file) => {
                    if count < 10 {
                        eprintln!(
                            "[process_packet] Packet #{}: File handle is Some, writing...",
                            count
                        );
                    }
                    use std::io::Write;
                    if let Err(e) = writeln!(file, "{}", log_line) {
                        eprintln!(
                            "[process_packet] Packet #{}: Error writing to log file: {}",
                            count, e
                        );
                    } else {
                        if count < 10 {
                            eprintln!(
                                "[process_packet] Packet #{}: Write succeeded, flushing...",
                                count
                            );
                        }
                        // Always flush after each write to ensure data is written
                        if let Err(e) = file.flush() {
                            eprintln!(
                                "[process_packet] Packet #{}: Error flushing log file: {}",
                                count, e
                            );
                        } else {
                            if count < 10 {
                                eprintln!(
                                    "[process_packet] Packet #{}: Flush succeeded, syncing...",
                                    count
                                );
                            }
                            // Also sync to ensure data is on disk
                            if let Err(e) = file.sync_all() {
                                eprintln!(
                                    "[process_packet] Packet #{}: Error syncing log file: {}",
                                    count, e
                                );
                            } else if count < 10 {
                                eprintln!(
                                    "[process_packet] Packet #{}: Sync succeeded, write complete!",
                                    count
                                );
                            }
                        }
                    }
                }
                None => {
                    use std::sync::atomic::{AtomicU32, Ordering};
                    static WARN_COUNT: AtomicU32 = AtomicU32::new(0);
                    let warn_count = WARN_COUNT.fetch_add(1, Ordering::Relaxed);
                    if warn_count < 5 {
                        eprintln!(
                            "[process_packet] Packet #{}: Warning: log_file is None (warn_count: {}), file handle not available",
                            count, warn_count
                        );
                    }
                }
            }
        });
        if count < 10 {
            eprintln!("[process_packet] Packet #{}: Exiting process_packet", count);
        }

        Ok(())
    }

    /// Stops packet capture.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.capture_handle.take() {
            handle.abort();
        }
    }
}

impl Drop for NetworkLogger {
    fn drop(&mut self) {
        self.stop();
    }
}
