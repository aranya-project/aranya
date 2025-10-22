// TODO(nikki): spawn the demo code as a separate process so we can remove measurement overhead, and
// migrate to benches/ or examples/.

use std::{
    env,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    afc::Channels,
    client::{ChanOp, KeyBundle, Role},
    AddTeamConfig, AddTeamQuicSyncConfig, Client, CreateTeamConfig, CreateTeamQuicSyncConfig,
    DeviceId, Error,
};
use aranya_daemon_api::text;
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
    time::sleep,
};
use tracing::{debug, info, warn, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};

use crate::{
    backend::MetricsConfig,
    harness::{Pid, ProcessMetricsCollector},
};
pub mod backend;
mod harness;

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
    // First, let's make sure we have the proper config data to even start before we log about setting up.
    let Ok(config_path) = env::var("CONFIG_PATH") else {
        bail!("No config path defined, please provide a toml file in `CONFIG_PATH=`.");
    };

    let buffer = fs::read_to_string(config_path).await?;
    let metrics_config: MetricsConfig = toml::from_str(&buffer)?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(DemoFilter {
                    env_filter: EnvFilter::try_from_env("ARANYA_EXAMPLE")
                        .unwrap_or_else(|_| EnvFilter::new("off")),
                }),
        )
        .init();

    info!("Starting Aranya Metrics Exporter...");

    // Since each job is unique based on a timestamp, let's print it both now and at the end.
    let job_name = metrics_config.job_name.clone();
    metrics_config.install()?;

    info!("Setting up daemons...");
    let (mut daemon_pids, demo_context) = setup_demo("rust_example").await?;
    daemon_pids.push(Pid::from_u32(std::process::id(), "example"));

    info!("Starting metrics collection for PIDs: {daemon_pids:?}");
    let mut metrics_collector = ProcessMetricsCollector::new(metrics_config, daemon_pids);
    tokio::spawn(async move { metrics_collector.start_collection_loop().await });

    info!("Running example code...");
    let demo_start = Instant::now();
    let result = run_demo_body(demo_context).await;
    match result {
        Ok(()) => info!(
            "Demo completed successfully, {} milliseconds, job {job_name}",
            demo_start.elapsed().as_millis()
        ),
        Err(ref e) => warn!("Demo failed with error: {e}"),
    }
    result
}

#[derive(Debug)]
#[clippy::has_significant_drop]
struct Daemon {
    // NB: This has important drop side effects.
    proc: Child,
}

impl Daemon {
    async fn spawn(path: &PathBuf, work_dir: &Path, cfg_path: &Path) -> Result<Self> {
        fs::create_dir_all(&work_dir).await?;

        let cfg_path = cfg_path.as_os_str().to_str().context("should be UTF-8")?;
        let mut cmd = Command::new(path);
        cmd.kill_on_drop(true)
            .current_dir(work_dir)
            .args(["--config", cfg_path]);
        debug!(?cmd, "spawning daemon");
        let proc = cmd.spawn().context("unable to spawn daemon")?;
        Ok(Self { proc })
    }

    fn pid(&self) -> Option<u32> {
        self.proc.id()
    }
}

/// An Aranya device.
#[derive(Debug)]
#[clippy::has_significant_drop]
struct ClientCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
    /// This needs to be stored so it lasts for the same lifetime as `Daemon`.
    _work_dir: TempDir,
    daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(team_name: &str, user_name: &str, daemon_path: &PathBuf) -> Result<Self> {
        info!(team_name, user_name, "creating `ClientCtx`");

        let _work_dir = TempDir::with_prefix(user_name)?;
        let work_path = _work_dir.path().join("daemon");

        let daemon = {
            const SUBDIR_NAMES: [&str; 5] = ["run", "state", "cache", "logs", "config"];
            let [runtime_dir, state_dir, cache_dir, logs_dir, config_dir] =
                SUBDIR_NAMES.map(|name| work_path.join(name));
            for path in [&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
                fs::create_dir_all(path)
                    .await
                    .with_context(|| format!("unable to create directory: {path:?}"))?;
            }

            let cfg_path = work_path.join("config.toml");
            let buf = format!(
                r#"
                name = "daemon"
                runtime_dir = {runtime_dir:?}
                state_dir = {state_dir:?}
                cache_dir = {cache_dir:?}
                logs_dir = {logs_dir:?}
                config_dir = {config_dir:?}

                [afc]
                enable = true
                shm_path = "/shm_${user_name}"
                max_chans = 10

                [sync.quic]
                enable = true
                addr = "127.0.0.1:0"
                "#
            );
            fs::write(&cfg_path, buf).await?;
            Daemon::spawn(daemon_path, &work_path, &cfg_path).await?
        };

        let uds_sock = work_path.join("run").join("uds.sock");

        let client = (|| Client::builder().daemon_uds_path(&uds_sock).connect())
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
            _work_dir,
            daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<Addr> {
        Ok(self.client.local_addr().await?)
    }
}

struct DemoContext {
    owner: ClientCtx,
    admin: ClientCtx,
    operator: ClientCtx,
    membera: ClientCtx,
    memberb: ClientCtx,
}

async fn setup_demo(team_name: &str) -> Result<(Vec<Pid>, DemoContext)> {
    let daemon_path = PathBuf::from(
        env::args()
            .nth(1)
            .context("missing `daemon` executable path")?,
    );

    // TODO(nikki): move TeamId here?

    const CLIENT_NAMES: [&str; 5] = ["owner", "admin", "operator", "member_a", "member_b"];
    let mut contexts: [Option<ClientCtx>; CLIENT_NAMES.len()] = Default::default();
    let mut daemon_pids: Vec<Pid> = Vec::with_capacity(CLIENT_NAMES.len() + 1);

    for (i, &user_name) in CLIENT_NAMES.iter().enumerate() {
        let ctx = ClientCtx::new(team_name, user_name, &daemon_path).await?;

        if let Some(pid) = ctx.daemon.pid() {
            daemon_pids.push(Pid::from_u32(pid, user_name));
        } else {
            warn!("Daemon PID not available for user: {user_name}");
        }

        contexts[i] = Some(ctx);
    }

    // If this panics, we have bigger things to worry about.
    let [owner, admin, operator, membera, memberb] =
        contexts.map(|ctx| ctx.expect("All contexts should have been initialized"));

    Ok((
        daemon_pids,
        DemoContext {
            owner,
            admin,
            operator,
            membera,
            memberb,
        },
    ))
}

async fn run_demo_body(ctx: DemoContext) -> Result<()> {
    // Define our constants and other accessors
    let seed_ikm = {
        let mut buf = [0; 32];
        ctx.owner.client.rand(&mut buf).await;
        buf
    };

    let owner_cfg = {
        let qs_cfg = CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        CreateTeamConfig::builder().quic_sync(qs_cfg).build()?
    };

    // Create a team.
    info!("creating team");
    let owner = ctx
        .owner
        .client
        .create_team(owner_cfg)
        .await
        .context("expected to create team")?;
    let team_id = owner.team_id();
    info!(%team_id);

    let add_team_cfg = {
        let qs_cfg = AddTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        AddTeamConfig::builder()
            .quic_sync(qs_cfg)
            .team_id(team_id)
            .build()?
    };

    let admin = ctx.admin.client.add_team(add_team_cfg.clone()).await?;
    let operator = ctx.operator.client.add_team(add_team_cfg.clone()).await?;
    let membera = ctx.membera.client.add_team(add_team_cfg.clone()).await?;
    let memberb = ctx.memberb.client.add_team(add_team_cfg).await?;

    // get sync addresses.
    let owner_addr = ctx.owner.aranya_local_addr().await?;
    let admin_addr = ctx.admin.aranya_local_addr().await?;
    let operator_addr = ctx.operator.aranya_local_addr().await?;

    // setup sync peers.
    info!("adding admin to team");
    owner.add_device_to_team(ctx.admin.pk).await?;
    owner.assign_role(ctx.admin.id, Role::Admin).await?;

    info!("adding operator to team");
    owner.add_device_to_team(ctx.operator.pk).await?;

    // Admin tries to assign a role
    info!("trying to assign the operator's role without a synced graph (this should fail)");
    match admin.assign_role(ctx.operator.id, Role::Operator).await {
        Ok(()) => bail!("expected role assignment to fail"),
        Err(Error::Aranya(_)) => {}
        Err(err) => bail!("unexpected error: {err:?}"),
    }

    // Admin syncs with the Owner peer and retries the role assignment command
    info!("syncing the graph for proper permissions");
    admin.sync_now(owner_addr, None).await?;

    info!("properly assigning the operator's role");
    admin.assign_role(ctx.operator.id, Role::Operator).await?;

    operator.sync_now(admin_addr, None).await?;

    // add membera to team.
    info!("adding membera to team");
    operator.add_device_to_team(ctx.membera.pk.clone()).await?;
    membera.sync_now(operator_addr, None).await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator.add_device_to_team(ctx.memberb.pk.clone()).await?;
    memberb.sync_now(operator_addr, None).await?;

    // fact database queries
    let queries = membera.queries();
    let devices = queries.devices_on_team().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(ctx.membera.id).await?;
    info!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(ctx.membera.id).await?;
    info!("membera keybundle: {:?}", keybundle);

    info!("demo afc functionality");
    info!("creating label");
    let label3 = operator.create_label(text!("label3")).await?;
    let op = ChanOp::SendRecv;

    info!("assigning label to membera");
    operator.assign_label(ctx.membera.id, label3, op).await?;

    info!("assigning label to memberb");
    operator.assign_label(ctx.memberb.id, label3, op).await?;

    membera.sync_now(operator_addr, None).await?;
    memberb.sync_now(operator_addr, None).await?;

    info!("memmbera creating channel");
    let (created_afc_chan, ctrl) = ctx
        .membera
        .client
        .afc()
        .create_uni_send_channel(team_id, ctx.memberb.id, label3)
        .await?;
    info!("memmberb receiving channel");
    let received_afc_chan = ctx.memberb.client.afc().recv_ctrl(team_id, ctrl).await?;

    info!("membera sealing afc data");
    let send_msg = b"hello";
    let mut ciphertext = vec![0u8; send_msg.len() + Channels::OVERHEAD];
    created_afc_chan.seal(&mut ciphertext, send_msg)?;

    info!("memberb opening afc data");
    let mut recv_msg = vec![0u8; ciphertext.len() - Channels::OVERHEAD];
    received_afc_chan.open(&mut recv_msg, &ciphertext)?;
    assert_eq!(send_msg.as_slice(), recv_msg.as_slice());

    info!("revoking label from membera");
    operator.revoke_label(ctx.membera.id, label3).await?;
    info!("revoking label from memberb");
    operator.revoke_label(ctx.memberb.id, label3).await?;

    admin.sync_now(operator_addr, None).await?;

    info!("deleting label");
    admin.delete_label(label3).await?;

    info!("Finished running example Aranya application");

    // sleep a moment so we can get a stable final state for all daemons
    sleep(Duration::from_millis(25)).await;

    Ok(())
}
