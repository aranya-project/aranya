use std::{
    collections::HashMap, iter, net::Ipv4Addr, path::PathBuf, ptr, sync::Arc, time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aranya_certgen::{CaCert, CertPaths, SaveOptions};
use aranya_client::{
    client::{Client, DeviceId, PublicKeyBundle, Role, RoleManagementPermission, TeamId},
    Addr, SyncPeerConfig,
};
// These deprecated types are only used in create_and_add_team for backward compatibility testing.
#[allow(deprecated)]
use aranya_client::{
    config::CreateTeamConfig, AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
use aranya_crypto::dangerous::spideroak_crypto::{hash::Hash, rust::Sha256};
use aranya_daemon::{
    config::{self as daemon_cfg, Config, Toggle},
    Daemon, DaemonHandle,
};
use backon::{ExponentialBuilder, Retryable as _};
use futures_util::try_join;
use spideroak_base58::ToBase58 as _;
use tempfile::TempDir;
use tokio::{fs, time};
use tracing::{info, instrument, trace};

/// Shared certificate authority for generating device certificates.
pub struct TestCertAuthority {
    ca: CaCert,
    root_certs_dir: PathBuf,
}

impl TestCertAuthority {
    /// Creates a new test CA in the given directory.
    pub fn new(dir: &std::path::Path) -> Result<Self> {
        let certs_dir = dir.join("certs");
        let root_certs_dir = certs_dir.join("root_certs");
        std::fs::create_dir_all(&root_certs_dir)?;

        let ca_paths = CertPaths::new(root_certs_dir.join("ca"));
        let ca = CaCert::new("Test CA", 365).context("failed to create CA cert")?;
        ca.save(&ca_paths, SaveOptions::default().create_parents())
            .context("failed to save CA cert")?;

        Ok(Self { ca, root_certs_dir })
    }

    /// Generates a device certificate.
    ///
    /// The certificate uses `127.0.0.1` as the CN, which certgen auto-detects as an
    /// IP address and creates an IP SAN for TLS connections.
    pub fn generate_device_cert(&self, device_dir: &std::path::Path) -> Result<CertPaths> {
        let certs_dir = device_dir.join("certs");
        std::fs::create_dir_all(&certs_dir)?;

        let device_paths = CertPaths::new(certs_dir.join("device"));
        let device_cert = self
            .ca
            .generate("127.0.0.1", 365)
            .context("failed to generate device cert")?;
        device_cert
            .save(&device_paths, SaveOptions::default().create_parents())
            .context("failed to save device cert")?;

        Ok(device_paths)
    }

    /// Returns the root certs directory.
    pub fn root_certs_dir(&self) -> &PathBuf {
        &self.root_certs_dir
    }
}

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
    #[allow(dead_code)] // Used in test_privilege_escalation_rejected
    pub ca: Arc<TestCertAuthority>,
    _work_dir: TempDir,
}

#[allow(dead_code)]
impl DevicesCtx {
    pub async fn new(name: &str) -> Result<Self> {
        let work_dir = tempfile::tempdir()?;
        let work_dir_path = work_dir.path();

        // Create shared CA for mTLS
        let ca = Arc::new(TestCertAuthority::new(work_dir_path)?);

        let (owner, admin, operator, membera, memberb) = try_join!(
            DeviceCtx::new(name, "owner", work_dir_path.join("owner"), ca.clone()),
            DeviceCtx::new(name, "admin", work_dir_path.join("admin"), ca.clone()),
            DeviceCtx::new(name, "operator", work_dir_path.join("operator"), ca.clone()),
            DeviceCtx::new(name, "membera", work_dir_path.join("membera"), ca.clone()),
            DeviceCtx::new(name, "memberb", work_dir_path.join("memberb"), ca.clone()),
        )?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
            ca,
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

    /// Creates a team and adds it to all devices using deprecated PSK-based APIs.
    ///
    /// This function uses deprecated `add_team()`, `CreateTeamQuicSyncConfig`, and
    /// `AddTeamQuicSyncConfig` APIs to test backward compatibility.
    #[allow(deprecated)]
    pub async fn create_and_add_team(&mut self) -> Result<TeamId> {
        // Create the initial team, and get our TeamId.
        let seed_ikm = {
            let mut buf = [0; _];
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

pub struct DeviceCtx {
    pub client: Client,
    pub pk: PublicKeyBundle,
    pub id: DeviceId,
    #[expect(unused, reason = "manages tasks")]
    pub daemon: DaemonHandle,
}

impl DeviceCtx {
    pub(crate) async fn new(
        team_name: &str,
        name: &str,
        work_dir: PathBuf,
        ca: Arc<TestCertAuthority>,
    ) -> Result<Self> {
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

        // Generate device certificate for mTLS
        let device_paths = ca.generate_device_cert(&work_dir)?;

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
                    root_certs_dir: ca.root_certs_dir().clone(),
                    device_cert: device_paths.cert().to_path_buf(),
                    device_key: device_paths.key().to_path_buf(),
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
        let pk = client
            .get_public_key_bundle()
            .await
            .expect("expected key bundle");
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
