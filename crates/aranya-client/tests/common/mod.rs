use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aranya_client::{
    client::Client, DeviceId, NetIdentifier, QuicSyncConfig, Role, Roles, SyncPeerConfig,
    TeamConfig, TeamId,
};
use aranya_daemon::{Config, Daemon, DaemonHandle};
use aranya_daemon_api::{KeyBundle, SEED_IKM_SIZE};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use tokio::{fs, time};
use tracing::{info, instrument, trace};

const SYNC_INTERVAL: Duration = Duration::from_millis(100);
// Allow for one missed sync and a misaligned sync rate, while keeping run times low.
pub const SLEEP_INTERVAL: Duration = Duration::from_millis(250);

#[instrument(skip_all)]
pub async fn sleep(duration: Duration) {
    trace!(?duration, "sleeping");
    time::sleep(duration).await;
}

pub struct TeamCtx {
    pub owner: DeviceCtx,
    pub admin: DeviceCtx,
    pub operator: DeviceCtx,
    pub membera: DeviceCtx,
    pub memberb: DeviceCtx,
}

impl TeamCtx {
    pub async fn new(name: &str, work_dir: PathBuf) -> Result<Self> {
        let owner = DeviceCtx::new(name, "owner", work_dir.join("owner")).await?;
        let admin = DeviceCtx::new(name, "admin", work_dir.join("admin")).await?;
        let operator = DeviceCtx::new(name, "operator", work_dir.join("operator")).await?;
        let membera = DeviceCtx::new(name, "membera", work_dir.join("membera")).await?;
        let memberb = DeviceCtx::new(name, "memberb", work_dir.join("memberb")).await?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
        })
    }

    pub(super) fn devices(&mut self) -> [&mut DeviceCtx; 5] {
        [
            &mut self.owner,
            &mut self.admin,
            &mut self.operator,
            &mut self.membera,
            &mut self.memberb,
        ]
    }

    #[instrument(skip(self))]
    pub async fn add_all_sync_peers(&mut self, team_id: TeamId) -> Result<()> {
        let config = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
        let mut devices = self.devices();
        for i in 0..devices.len() {
            let (device, peers) = devices[i..].split_first_mut().expect("expected device");
            for peer in peers {
                device
                    .client
                    .team(team_id)
                    .add_sync_peer(peer.aranya_local_addr().await?.into(), config.clone())
                    .await?;
                peer.client
                    .team(team_id)
                    .add_sync_peer(device.aranya_local_addr().await?.into(), config.clone())
                    .await?;
            }
        }
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn setup_default_roles(&mut self, team_id: TeamId) -> Result<DefaultRoles> {
        let owner_role_id = self
            .owner
            .client
            .team(team_id)
            .roles()
            .await?
            .try_into_owner_role()?
            .id;
        self.owner
            .client
            .team(team_id)
            .setup_default_roles(owner_role_id)
            .await?
            .try_into_default_roles()
    }

    #[instrument(skip(self))]
    pub async fn add_all_device_roles(&mut self, team_id: TeamId) -> Result<()> {
        // Shorthand for the teams we need to operate on.
        let mut owner_team = self.owner.client.team(team_id);
        let mut admin_team = self.admin.client.team(team_id);
        let mut operator_team = self.operator.client.team(team_id);

        let roles = owner_team
            .roles()
            .await
            .context("failed to get roles")?
            .try_into_default_roles()
            .context("failed to convert roles")?;

        // Add the admin as a new device and assign its role in
        // one step.
        info!("adding admin to team");
        owner_team
            .add_device_to_team(self.admin.pk.clone(), Some(roles.admin().id))
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Add the operator as a new device and then have the
        // admin assign its role.
        info!("adding operator to team");
        owner_team
            .add_device_to_team(self.operator.pk.clone(), None)
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Assign the operator its role.
        admin_team
            .assign_role(self.operator.id, roles.operator().id)
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Add member A as a new device.
        info!("adding membera to team");
        operator_team
            .add_device_to_team(self.membera.pk.clone(), None)
            .await?;

        // Add member A as a new device.
        info!("adding memberb to team");
        operator_team
            .add_device_to_team(self.memberb.pk.clone(), None)
            .await?;

        // Make sure they see the configuration change.
        sleep(SLEEP_INTERVAL).await;

        Ok(())
    }

    pub async fn create_and_add_team(&mut self) -> Result<TeamId> {
        // Create the initial team, and get our TeamId.
        let seed_ikm = {
            let mut buf = [0; SEED_IKM_SIZE];
            self.owner.client.rand(&mut buf).await;
            buf
        };
        let cfg = {
            let qs_cfg = QuicSyncConfig::builder().seed_ikm(seed_ikm).build()?;
            TeamConfig::builder().quic_sync(qs_cfg).build()?
        };

        let team = {
            self.owner
                .client
                .create_team(cfg.clone())
                .await
                .expect("expected to create team")
        };
        let team_id = team.team_id();
        info!(?team_id);

        // Owner has the team added due to calling `create_team`, now we assign it to all other peers
        self.admin.client.add_team(team_id, cfg.clone()).await?;
        self.operator.client.add_team(team_id, cfg.clone()).await?;
        self.membera.client.add_team(team_id, cfg.clone()).await?;
        self.memberb.client.add_team(team_id, cfg).await?;

        Ok(team_id)
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
        let quic_sync = Some(aranya_daemon::QuicSyncConfig {});

        let cfg = Config {
            name: name.into(),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("log"),
            config_dir: work_dir.join("config"),
            sync_addr: addr_any,
            afc: None,
            aqc: None,
            quic_sync,
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
            .context("unable to init daemon")?
            .spawn();

        // give daemon time to setup UDS API and write the public key.
        sleep(SLEEP_INTERVAL).await;

        // Initialize the user library - the client will automatically load the daemon's public key.
        let mut client = (|| {
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
        self.client
            .aqc()
            .server_addr()
            .expect("can get server addr")
            .to_string()
            .try_into()
            .expect("`SocketAddr` is a valid `NetIdentifier`")
    }
}

/// Converts operations on [`Roles`].
pub trait RolesExt {
    /// Converts [`Roles`] into [`DefaultRoles`].
    fn try_into_default_roles(self) -> Result<DefaultRoles>;
    // Retrieves the owner role.
    fn try_into_owner_role(self) -> Result<Role>;
}

impl RolesExt for Roles {
    fn try_into_default_roles(self) -> Result<DefaultRoles> {
        DefaultRoles::try_from(self)
    }

    fn try_into_owner_role(self) -> Result<Role> {
        println!("roles = {}", self.clone().into_iter().count());
        self.into_iter()
            .find(|role| {
                println!("role = {role:?}");
                let ok = role.name == "owner" && role.default;
                println!("ok = {ok}");
                ok
            })
            .context("unable to find owner role")
    }
}

/// The default roles for a team.
// NB: This assumes users cannot delete roles yet, which is true
// as of MVP.
#[derive(Clone, Debug)]
pub struct DefaultRoles {
    owner: Role,
    admin: Role,
    operator: Role,
    member: Role,
}

impl DefaultRoles {
    /// Returns the 'owner' role.
    pub fn owner(&self) -> &Role {
        &self.owner
    }

    /// Returns the 'owner' role.
    pub fn admin(&self) -> &Role {
        &self.admin
    }

    /// Returns the 'owner' role.
    pub fn operator(&self) -> &Role {
        &self.operator
    }

    /// Returns the 'owner' role.
    pub fn member(&self) -> &Role {
        &self.member
    }
}

impl TryFrom<Roles> for DefaultRoles {
    type Error = anyhow::Error;

    fn try_from(roles: Roles) -> Result<Self> {
        #[derive(Clone, Default, Debug)]
        struct S {
            owner: Option<Role>,
            admin: Option<Role>,
            operator: Option<Role>,
            member: Option<Role>,
        }
        let S {
            owner,
            admin,
            operator,
            member,
        } = roles
            .iter()
            .cloned()
            .try_fold(S::default(), |mut acc, role| {
                let name = role.name.as_str();
                let dst = match name {
                    "owner" => &mut acc.owner,
                    "admin" => &mut acc.admin,
                    "operator" => &mut acc.operator,
                    "member" => &mut acc.member,
                    name => unreachable!("unexpected role: {name}"),
                };
                match dst {
                    Some(_) => {
                        // Each of the default roles has a unique
                        // name.
                        Err(anyhow!("duplicate role name: {name}"))
                    }
                    None => {
                        *dst = Some(role);
                        Ok(acc)
                    }
                }
            })?;
        Ok(Self {
            owner: owner.context("missing owner role")?,
            admin: admin.context("missing admin role")?,
            operator: operator.context("missing operator role")?,
            member: member.context("missing member role")?,
        })
    }
}
