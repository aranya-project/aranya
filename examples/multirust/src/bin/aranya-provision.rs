use std::{
    env,
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result};
use aranya_client::{client::Client, QuicSyncConfig, SyncPeerConfig, TeamConfig};
use aranya_daemon_api::{text, ChanOp, DeviceId, KeyBundle, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use tempfile::TempDir;
use tokio::{fs, process::Command, time::sleep};
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
            let cfg_path = config_dir.join("config.json");

            for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
                fs::create_dir_all(dir)
                    .await
                    .with_context(|| format!("unable to create directory: {}", dir.display()))?;
            }

            let buf = format!(
                r#"
                name: {user_name:?}
                runtime_dir: {runtime_dir:?}
                state_dir: {state_dir:?}
                cache_dir: {cache_dir:?}
                logs_dir: {logs_dir:?}
                config_dir: {config_dir:?}
                sync_addr: "127.0.0.1:0"
                quic_sync: {{ }}
                "#
            );
            fs::write(&cfg_path, buf).await.context("writing config")?;

            Daemon::spawn(daemon_path, &daemon_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = runtime_dir.join("uds.sock");

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

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
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

    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let root = env::current_dir()?.join("daemons");
    let mut owner = ClientCtx::new(&root, "owner", &daemon_path).await?;
    let mut admin = ClientCtx::new(&root, "admin", &daemon_path).await?;
    let mut operator = ClientCtx::new(&root, "operator", &daemon_path).await?;
    let mut membera = ClientCtx::new(&root, "member-a", &daemon_path).await?;
    let mut memberb = ClientCtx::new(&root, "member-b", &daemon_path).await?;

    operator.write("member-a.id", membera.id).await?;
    operator.write("member-b.id", memberb.id).await?;

    membera.write("member-b.id", memberb.id).await?;
    memberb.write("member-a.id", membera.id).await?;

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

    // Create a team.
    info!("creating team");
    let mut owner_team = owner
        .client
        .create_team(cfg.clone())
        .await
        .context("expected to create team")?;
    let team_id = owner_team.team_id();
    info!(%team_id);

    operator.write("team.id", team_id).await?;
    membera.write("team.id", team_id).await?;
    memberb.write("team.id", team_id).await?;

    let mut admin_team = admin.client.add_team(team_id, cfg.clone()).await?;
    let mut operator_team = operator.client.add_team(team_id, cfg.clone()).await?;
    let mut membera_team = membera.client.add_team(team_id, cfg.clone()).await?;
    let mut memberb_team = memberb.client.add_team(team_id, cfg.clone()).await?;

    info!("adding sync peers");
    owner_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;

    info!("adding admin to team");
    owner_team.add_device_to_team(admin.pk).await?;
    info!("assigning admin role");
    owner_team.assign_role(admin.id, Role::Admin).await?;

    info!("adding operator to team");
    owner_team.add_device_to_team(operator.pk).await?;

    sleep(sleep_interval).await;

    info!("assigning operator role");
    admin_team.assign_role(operator.id, Role::Operator).await?;

    sleep(sleep_interval).await;

    info!("adding membera to team");
    operator_team.add_device_to_team(membera.pk.clone()).await?;

    info!("adding memberb to team");
    operator_team.add_device_to_team(memberb.pk.clone()).await?;

    info!("creating aqc label");
    let label = operator_team.create_label(text!("mylabel")).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team.assign_label(membera.id, label, op).await?;
    info!("assigning label to memberb");
    operator_team.assign_label(memberb.id, label, op).await?;

    // wait for syncing.
    sleep(sleep_interval * 5).await;

    Ok(())
}
