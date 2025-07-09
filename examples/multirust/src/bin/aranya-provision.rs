use std::{
    env,
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result};
use aranya_client::{client::Client, SyncPeerConfig, TeamConfig};
use aranya_daemon_api::{ChanOp, DeviceId, KeyBundle, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
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

    async fn get_api_pk(path: &DaemonPath, cfg_path: &Path) -> Result<Vec<u8>> {
        let cfg_path = cfg_path.as_os_str().to_str().context("should be UTF-8")?;
        let mut cmd = Command::new(&path.0);
        cmd.kill_on_drop(true)
            .args(["--config", cfg_path])
            .arg("--print-api-pk");
        debug!(?cmd, "running daemon");
        let output = cmd.output().await.context("unable to run daemon")?;
        let pk_hex = String::from_utf8(output.stdout)?;
        let pk = hex::decode(pk_hex.trim())?;
        Ok(pk)
    }
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
    work_dir: PathBuf,
    #[allow(unused, reason = "drop side effects")]
    daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(root: &Path, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(user_name, "creating `ClientCtx`");

        let work_dir = root.join(user_name).join("state");
        let uds_api_path = work_dir.join("uds.sock");

        let api_pk;

        let daemon = {
            let cfg_path = work_dir.join("config.json");
            let pid_file = work_dir.join("daemon.pid");

            fs::create_dir_all(&work_dir).await?;

            let buf = format!(
                r#"
                name: {user_name:?}
                work_dir: {work_dir:?}
                uds_api_path: {uds_api_path:?}
                pid_file: {pid_file:?}
                sync_addr: "127.0.0.1:0"
                "#
            );
            fs::write(&cfg_path, buf).await.context("writing config")?;

            api_pk = Daemon::get_api_pk(daemon_path, &cfg_path).await?;

            Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = uds_api_path;

        // Give the daemon time to start up and write its public key.
        sleep(Duration::from_millis(100)).await;

        let any_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));

        let mut client = (|| {
            Client::builder()
                .with_daemon_uds_path(&uds_sock)
                .with_daemon_aqc_addr(&any_addr)
                .with_daemon_api_pk(&api_pk)
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
            work_dir,
            daemon,
        };

        Ok(this)
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }

    async fn write(&self, filename: &str, value: impl Display) -> Result<()> {
        Ok(fs::write(self.work_dir.join(filename), value.to_string()).await?)
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

    // get sync addresses.
    let owner_addr = owner.aranya_local_addr().await?;
    let admin_addr = admin.aranya_local_addr().await?;
    let operator_addr = operator.aranya_local_addr().await?;

    // Create a team.
    info!("creating team");
    let team_id = owner
        .client
        .create_team(TeamConfig::builder().build().expect("default config"))
        .await
        .context("expected to create team")?;
    info!(%team_id);

    operator.write("team.id", team_id).await?;
    membera.write("team.id", team_id).await?;
    memberb.write("team.id", team_id).await?;

    let mut owner_team = owner.client.team(team_id);
    let mut admin_team = admin.client.team(team_id);
    let mut operator_team = operator.client.team(team_id);
    let mut membera_team = membera.client.team(team_id);
    let mut memberb_team = memberb.client.team(team_id);

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
    let label = operator_team.create_label("mylabel".into()).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team.assign_label(membera.id, label, op).await?;
    info!("assigning label to memberb");
    operator_team.assign_label(memberb.id, label, op).await?;

    // wait for syncing.
    sleep(sleep_interval * 5).await;

    Ok(())
}
