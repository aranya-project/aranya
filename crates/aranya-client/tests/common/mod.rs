use std::{
    collections::HashMap,
    iter,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    ptr,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aranya_client::{
    client::{Client, DeviceId, NetIdentifier, Role, TeamId},
    config::CreateTeamConfig,
    text, SyncPeerConfig, AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamQuicSyncConfig,
};
use aranya_daemon::{
    config::{self as daemon_cfg, Config, Toggle},
    Daemon, DaemonHandle,
};
use aranya_daemon_api::{KeyBundle, SEED_IKM_SIZE};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use futures_util::try_join;
use tempfile::TempDir;
use tokio::{fs, time};
use tracing::{debug, info, instrument, trace};

const SYNC_INTERVAL: Duration = Duration::from_millis(100);
// Allow for one missed sync and a misaligned sync rate, while keeping run times low.
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

    pub async fn add_all_device_roles(&mut self, team_id: TeamId) -> Result<()> {
        // Shorthand for the teams we need to operate on.
        let owner_team = self.owner.client.team(team_id);
        let admin_team = self.admin.client.team(team_id);
        let operator_team = self.operator.client.team(team_id);
        let membera_team = self.membera.client.team(team_id);
        let memberb_team = self.memberb.client.team(team_id);

        // Add the admin as a new device, and assign its role.
        info!("adding admin to team");
        owner_team.add_device(self.admin.pk.clone(), None).await?;
        // TODO: Need to create roles first or use predefined role IDs
        // owner_team.assign_role(self.admin.id, Role::Admin).await?;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner_team
            .add_device(self.operator.pk.clone(), None)
            .await?;

        // Make sure it sees the configuration change.
        admin_team
            .sync_now(self.owner.aranya_local_addr().await?.into(), None)
            .await?;

        // Assign the operator its role.
        // TODO: Need to create roles first or use predefined role IDs
        // admin_team
        //     .assign_role(self.operator.id, Role::Operator)
        //     .await?;

        // Make sure it sees the configuration change.
        operator_team
            .sync_now(self.admin.aranya_local_addr().await?.into(), None)
            .await?;

        // Add member A as a new device.
        info!("adding membera to team");
        operator_team
            .add_device(self.membera.pk.clone(), None)
            .await?;

        // Add member B as a new device.
        info!("adding memberb to team");
        operator_team
            .add_device(self.memberb.pk.clone(), None)
            .await?;

        // Make sure all see the configuration change.
        let operator_addr = self.operator.aranya_local_addr().await?.into();
        for team in [owner_team, admin_team, membera_team, memberb_team] {
            team.sync_now(operator_addr, None).await?;
        }

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

    fn devices(&self) -> [&DeviceCtx; 5] {
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
                    .add_sync_peer(peer.aranya_local_addr().await?.into(), config.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// NB: This includes the owner role, which is not returned
    /// by [`Client::setup_default_roles`].
    #[instrument(skip(self))]
    pub async fn setup_default_roles(&self, team_id: TeamId) -> Result<DefaultRoles> {
        let owner_role = self
            .owner
            .client
            .team(team_id)
            .roles()
            .await?
            .try_into_owner_role()?;
        tracing::debug!(owner_role_id = %owner_role.id);

        let roles = self
            .owner
            .client
            .team(team_id)
            .setup_default_roles(owner_role.id)
            .await?
            .into_iter()
            .chain(iter::once(owner_role))
            .try_into_default_roles()
            .context("unable to parse `DefaultRoles`")?;
        tracing::debug!(?roles, "default roles set up");

        let mappings = [
            // admin -> operator
            ("admin -> operator", roles.operator().id, roles.admin().id),
            // admin -> member
            ("admin -> member", roles.member().id, roles.admin().id),
        ];
        for (name, role, manager) in mappings {
            self.owner
                .client
                .team(team_id)
                .assign_role_management_permission(role, manager, text!("CanAssignRole"))
                .await
                .with_context(|| format!("{name}: unable to change managing role"))?;
        }

        Ok(roles)
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
    async fn new(_team_name: &str, name: &str, work_dir: PathBuf) -> Result<Self> {
        let addr_any = Addr::from((Ipv4Addr::LOCALHOST, 0));

        // Setup daemon config.
        let cfg = Config {
            name: name.into(),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("log"),
            config_dir: work_dir.join("config"),
            aqc: Toggle::Enabled(daemon_cfg::AqcConfig {}),
            sync: daemon_cfg::SyncConfig {
                quic: Toggle::Enabled(daemon_cfg::QuicSyncConfig { addr: addr_any }),
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
            .context("unanble to start daemon")?;

        // Initialize the user library - the client will automatically load the daemon's public key.
        let client = (|| {
            Client::builder()
                .with_daemon_uds_path(&uds_path)
                .with_daemon_aqc_addr(&addr_any)
                .connect()
        })
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

    pub async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }

    #[allow(unused, reason = "module compiled for each test file")]
    pub fn aqc_net_id(&mut self) -> NetIdentifier {
        NetIdentifier::try_from(self.client.aqc().server_addr().to_string())
            .expect("socket addr is valid text")
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
    /// Returns the 'owner role.
    pub fn owner(&self) -> &Role {
        self.roles.get("owner").unwrap()
    }

    /// Returns the 'admin' role.
    pub fn admin(&self) -> &Role {
        self.roles.get("admin").unwrap()
    }

    /// Returns the 'operator' role.
    pub fn operator(&self) -> &Role {
        self.roles.get("operator").unwrap()
    }

    /// Returns the 'member' role.
    pub fn member(&self) -> &Role {
        self.roles.get("member").unwrap()
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
                    unreachable!("unexpected role: {}", role.name);
                }
                if acc.insert(role.name.to_string(), role.clone()).is_some() {
                    unreachable!("duplicate role: {}", role.name);
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
