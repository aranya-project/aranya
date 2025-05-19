use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{client::Client, Error, SyncPeerConfig, TeamConfig};
use aranya_daemon_api::{ChanOp, DeviceId, KeyBundle, NetIdentifier, Role};
use backon::{ExponentialBuilder, Retryable};
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
    time::sleep,
};
use tracing::{debug, info, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};

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
    // NB: These have important drop side effects.
    _work_dir: TempDir,
    _daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(team_name: &str, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(team_name, user_name, "creating `ClientCtx`");

        let work_dir = TempDir::with_prefix(user_name)?;

        // The path that the daemon will listen on.
        let uds_api_path = work_dir.path().join("uds.sock");

        let (daemon, pk) = {
            let work_dir = work_dir.path().join("daemon");
            fs::create_dir_all(&work_dir).await?;

            let cfg_path = work_dir.join("config.json");
            let pid_file = work_dir.join("pid");

            let buf = format!(
                r#"
{{
    "name": "daemon",
    "work_dir": "{}",
    "uds_api_path": "{}",
    "pid_file": "{}",
    "sync_addr": "127.0.0.1:0",
    "sync_version": "V1",
    "service_name": "Aranya-QUIC-sync-rust-example",
}}"#,
                work_dir.as_os_str().to_str().context("should be UTF-8")?,
                uds_api_path
                    .as_os_str()
                    .to_str()
                    .context("should be UTF-8")?,
                pid_file.as_os_str().to_str().context("should be UTF-8")?,
            );
            fs::write(&cfg_path, buf).await?;

            let pk = Daemon::get_api_pk(daemon_path, &cfg_path).await?;
            let daemon = Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?;
            (daemon, pk)
        };

        // Give the daemon time to start up.
        sleep(Duration::from_millis(100)).await;

        let mut client = (|| {
            Client::builder()
                .with_daemon_api_pk(&pk)
                .with_daemon_uds_path(&uds_api_path)
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

        Ok(Self {
            client,
            pk,
            id,
            _work_dir: work_dir,
            _daemon: daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
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

    info!("starting example Aranya application");

    let daemon_path = {
        let mut args = env::args();
        args.next(); // skip executable name
        let exe = args.next().context("missing `daemon` executable path")?;
        DaemonPath(PathBuf::from(exe))
    };

    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let team_name = "rust_example";
    let mut owner = ClientCtx::new(&team_name, "owner", &daemon_path).await?;
    let mut admin = ClientCtx::new(&team_name, "admin", &daemon_path).await?;
    let mut operator = ClientCtx::new(&team_name, "operator", &daemon_path).await?;
    let mut membera = ClientCtx::new(&team_name, "member_a", &daemon_path).await?;
    let mut memberb = ClientCtx::new(&team_name, "member_b", &daemon_path).await?;

    // Create a team.
    info!("creating team");
    let cfg = TeamConfig::builder().build()?;
    let team_id = owner
        .client
        .create_team(cfg)
        .await
        .context("expected to create team")?;
    info!(%team_id);

    // get sync addresses.
    let owner_addr = owner.aranya_local_addr().await?;
    let admin_addr = admin.aranya_local_addr().await?;
    let operator_addr = operator.aranya_local_addr().await?;
    let membera_addr = membera.aranya_local_addr().await?;
    let memberb_addr = memberb.aranya_local_addr().await?;

    // get aqc addresses.
    // TODO: use aqc_local_addr()
    let membera_aqc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let memberb_aqc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

    // setup sync peers.
    let mut owner_team = owner.client.team(team_id);
    let mut admin_team = admin.client.team(team_id);
    let mut operator_team = operator.client.team(team_id);
    let mut membera_team = membera.client.team(team_id);
    let mut memberb_team = memberb.client.team(team_id);

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
        .add_sync_peer(membera_addr.into(), sync_cfg.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_cfg.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_cfg.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_cfg.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_cfg)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team.add_device_to_team(membera.pk).await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team.add_device_to_team(memberb.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("assigning aqc net identifiers");
    operator_team
        .assign_aqc_net_identifier(membera.id, NetIdentifier(membera_aqc_addr.to_string()))
        .await?;
    operator_team
        .assign_aqc_net_identifier(memberb.id, NetIdentifier(memberb_aqc_addr.to_string()))
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries = membera.client.queries(team_id);
    let devices = queries.devices_on_team().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(membera.id).await?;
    info!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(membera.id).await?;
    info!("membera keybundle: {:?}", keybundle);
    let queried_membera_net_ident = queries.aqc_net_identifier(membera.id).await?;
    info!(
        "membera queried_membera_net_ident: {:?}",
        queried_membera_net_ident
    );
    let queried_memberb_net_ident = queries.aqc_net_identifier(memberb.id).await?;
    info!(
        "memberb queried_memberb_net_ident: {:?}",
        queried_memberb_net_ident
    );

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("demo aqc functionality");
    info!("creating aqc label");
    let label3 = operator_team.create_label("label3".to_string()).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team.assign_label(membera.id, label3, op).await?;
    info!("assigning label to memberb");
    operator_team.assign_label(memberb.id, label3, op).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // TODO: send AQC ctrl via network
    info!("creating acq bidi channel");
    let _aqc_id1 = membera
        .client
        .aqc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_aqc_addr.to_string()), label3)
        .await?;
    info!("receiving acq bidi channel");

    // TODO: send AQC data.
    info!("revoking label from membera");
    operator_team.revoke_label(membera.id, label3).await?;
    info!("revoking label from memberb");
    operator_team.revoke_label(memberb.id, label3).await?;
    info!("deleting label");
    admin_team.delete_label(label3).await?;

    info!("completed aqc demo");

    info!("completed example Aranya application");

    Ok(())
}
