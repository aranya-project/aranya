use std::{
    env,
    fmt::Display,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use aranya_client::{text, Addr, Client, DeviceId, KeyBundle};
use backon::{ExponentialBuilder, Retryable};
use tempfile::TempDir;
use tokio::{fs, process::Command};
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Clone, Debug)]
struct DaemonPath(PathBuf);

#[derive(Debug)]
#[clippy::has_significant_drop]
struct Daemon {
    #[allow(unused, reason = "drop side effects")]
    proc: tokio::process::Child,
}

impl Daemon {
    async fn spawn(path: &DaemonPath, work_dir: &Path, cfg_path: &Path) -> Result<Self> {
        let mut cmd = Command::new(&path.0);
        cmd.kill_on_drop(true)
            .current_dir(work_dir)
            .args(["--config".as_ref(), cfg_path.as_os_str()]);
        debug!(?cmd, "spawning daemon");
        let proc = cmd.spawn().context("unable to spawn daemon")?;
        Ok(Daemon { proc })
    }
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
    state_dir: PathBuf,
    #[allow(unused, reason = "drop side effects")]
    temp: TempDir,
    #[allow(unused, reason = "drop side effects")]
    daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(root: &Path, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(user_name, "creating `ClientCtx`");

        let daemon_dir = root.join(user_name);
        let temp = TempDir::new()?;

        let runtime_dir = temp.path().join("run");
        let state_dir = daemon_dir.join("state");

        let daemon = {
            let cache_dir = temp.path().join("cache");
            let logs_dir = temp.path().join("logs");
            let config_dir = temp.path().join("config");
            let cfg_path = config_dir.join("config.toml");

            for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
                fs::create_dir_all(dir)
                    .await
                    .with_context(|| format!("unable to create directory: {}", dir.display()))?;
            }

            let buf = format!(
                r#"
                name = {user_name:?}
                runtime_dir = {runtime_dir:?}
                state_dir = {state_dir:?}
                cache_dir = {cache_dir:?}
                logs_dir = {logs_dir:?}
                config_dir = {config_dir:?}

                [afc]
                enable = true
                shm_path = "/{user_name}"
                max_chans = 100

                [sync.quic]
                enable = true
                addr = "127.0.0.1:0"
                "#
            );
            fs::write(&cfg_path, buf).await.context("writing config")?;

            Daemon::spawn(daemon_path, &daemon_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = runtime_dir.join("uds.sock");

        let client = (|| Client::builder().with_daemon_uds_path(&uds_sock).connect())
            .retry(ExponentialBuilder::default())
            .await
            .context("unable to initialize client")?;

        let pk = client
            .get_key_bundle()
            .await
            .context("expected key bundle")?;
        let id = client.get_device_id().await.context("expected device id")?;

        let this = Self {
            client,
            pk,
            id,
            state_dir,
            temp,
            daemon,
        };

        Ok(this)
    }

    async fn aranya_local_addr(&self) -> Result<Addr> {
        Ok(self.client.local_addr().await?)
    }

    async fn write(&self, filename: &str, value: impl Display) -> Result<()> {
        Ok(fs::write(self.state_dir.join(filename), value.to_string()).await?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(filter),
        )
        .init();

    info!("starting provisioning");

    let daemon_path = {
        let mut args = env::args();
        args.next(); // skip executable name
        let exe = args.next().context("missing `daemon` executable path")?;
        DaemonPath(PathBuf::from(exe))
    };

    let root = env::current_dir()?.join("daemons");
    let owner = ClientCtx::new(&root, "owner", &daemon_path).await?;
    let admin = ClientCtx::new(&root, "admin", &daemon_path).await?;
    let operator = ClientCtx::new(&root, "operator", &daemon_path).await?;
    let membera = ClientCtx::new(&root, "member-a", &daemon_path).await?;
    let memberb = ClientCtx::new(&root, "member-b", &daemon_path).await?;

    for user in [&operator, &membera, &memberb] {
        user.write("member-a.id", membera.id).await?;
        user.write("member-b.id", memberb.id).await?;
    }

    // Create the team config
    let seed_ikm = {
        let mut buf = [0; 32];
        owner.client.rand(&mut buf).await;
        buf
    };
    let create_team_cfg = {
        let qs_cfg = aranya_client::CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        aranya_client::CreateTeamConfig::builder()
            .quic_sync(qs_cfg)
            .build()?
    };

    // get sync addresses.
    let owner_addr = owner.aranya_local_addr().await?;
    let admin_addr = admin.aranya_local_addr().await?;
    let operator_addr = operator.aranya_local_addr().await?;

    info!("creating team");
    let owner_team = owner
        .client
        .create_team(create_team_cfg)
        .await
        .context("expected to create team")?;
    let team_id = owner_team.team_id();
    info!(%team_id);

    info!("writing team IDs");
    operator.write("team.id", team_id).await?;
    membera.write("team.id", team_id).await?;
    memberb.write("team.id", team_id).await?;

    info!("creating default roles");
    let owner_role = owner
        .client
        .team(team_id)
        .roles()
        .await?
        .into_iter()
        .find(|role| role.name == "owner" && role.default)
        .context("unable to find owner role")?;
    let roles = owner_team.setup_default_roles(owner_role.id).await?;
    let admin_role = roles
        .iter()
        .find(|r| r.name == "admin")
        .context("no admin role")?
        .clone();
    let operator_role = roles
        .iter()
        .find(|r| r.name == "operator")
        .context("no operator role")?
        .clone();
    let member_role = roles
        .iter()
        .find(|r| r.name == "member")
        .context("no member role")?
        .clone();

    info!("adding admin to team");
    owner_team.add_device(admin.pk, Some(admin_role.id)).await?;

    info!("adding operator to team");
    owner_team
        .add_device(operator.pk, Some(operator_role.id))
        .await?;

    info!("adding membera to team");
    owner_team
        .add_device(membera.pk.clone(), Some(member_role.id))
        .await?;

    info!("adding memberb to team");
    owner_team
        .add_device(memberb.pk.clone(), Some(member_role.id))
        .await?;

    let add_team_cfg = {
        let qs_cfg = aranya_client::AddTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        aranya_client::AddTeamConfig::builder()
            .team_id(team_id)
            .quic_sync(qs_cfg)
            .build()?
    };

    let admin_team = admin.client.add_team(add_team_cfg.clone()).await?;
    let operator_team = operator.client.add_team(add_team_cfg.clone()).await?;
    let membera_team = membera.client.add_team(add_team_cfg.clone()).await?;
    let memberb_team = memberb.client.add_team(add_team_cfg.clone()).await?;

    admin_team.sync_now(owner_addr, None).await?;

    info!("creating label");
    let label = admin_team
        .create_label(text!("mylabel"), operator_role.id)
        .await?;
    debug!(?label);

    operator_team.sync_now(admin_addr, None).await?;

    membera_team.sync_now(operator_addr, None).await?;
    memberb_team.sync_now(operator_addr, None).await?;

    Ok(())
}
