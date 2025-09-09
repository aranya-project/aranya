use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use aranya_client::{
    client::Client, config::CreateTeamConfig, AddTeamConfig, AddTeamQuicSyncConfig,
    CreateTeamQuicSyncConfig,
};
use aranya_crypto::{
    dangerous::spideroak_crypto::{hash::Hash, rust::Sha256},
    id::ToBase58,
};
use aranya_daemon::{
    config::{self as daemon_cfg, Config, Toggle},
    Daemon, DaemonHandle,
};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier, Role, TeamId, SEED_IKM_SIZE};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use futures_util::try_join;
use tempfile::TempDir;
use tokio::{fs, time};
use tracing::{info, instrument, trace};

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
        owner_team.add_device_to_team(self.admin.pk.clone()).await?;
        owner_team.assign_role(self.admin.id, Role::Admin).await?;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner_team
            .add_device_to_team(self.operator.pk.clone())
            .await?;

        // Make sure it sees the configuration change.
        admin_team
            .sync_now(self.owner.aranya_local_addr().await?.into(), None)
            .await?;

        // Assign the operator its role.
        admin_team
            .assign_role(self.operator.id, Role::Operator)
            .await?;

        // Make sure it sees the configuration change.
        operator_team
            .sync_now(self.admin.aranya_local_addr().await?.into(), None)
            .await?;

        // Add member A as a new device.
        info!("adding membera to team");
        operator_team
            .add_device_to_team(self.membera.pk.clone())
            .await?;

        // Add member A as a new device.
        info!("adding memberb to team");
        operator_team
            .add_device_to_team(self.memberb.pk.clone())
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
}

pub struct DeviceCtx {
    pub client: Client,
    pub pk: KeyBundle,
    pub id: DeviceId,
    #[expect(unused, reason = "manages tasks")]
    pub daemon: DaemonHandle,
}

impl DeviceCtx {
    async fn new(team_name: &str, name: &str, work_dir: PathBuf) -> Result<Self> {
        let addr_any = Addr::from((Ipv4Addr::LOCALHOST, 0));

        let afc_shm_path = get_shm_path(format!("/{team_name}_{name}"));

        // Setup daemon config.
        let cfg = Config {
            name: name.into(),
            runtime_dir: work_dir.join("run"),
            state_dir: work_dir.join("state"),
            cache_dir: work_dir.join("cache"),
            logs_dir: work_dir.join("log"),
            config_dir: work_dir.join("config"),
            aqc: Toggle::Enabled(daemon_cfg::AqcConfig {}),
            afc: Toggle::Enabled(daemon_cfg::AfcConfig {
                shm_path: afc_shm_path.clone(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans: 100,
            }),
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
            .context("unable to start daemon")?;

        // Initialize the user library - the client will automatically load the daemon's public key.
        let client = (|| {
            Client::builder()
                .daemon_uds_path(&uds_path)
                .aqc_server_addr(&addr_any)
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
        NetIdentifier(
            self.client
                .aqc()
                .server_addr()
                .to_string()
                .try_into()
                .expect("socket addr is valid text"),
        )
    }
}

fn get_shm_path(path: String) -> String {
    if cfg!(target_os = "macos") && path.len() > 31 {
        // Shrink the size of the team name down to 22 bytes to work within macOS's limits.
        let d = Sha256::hash(path.as_bytes());
        let t: [u8; 16] = d[..16].try_into().expect("expected shm path");
        return format!("/{}", t.to_base58());
    };
    path
}
