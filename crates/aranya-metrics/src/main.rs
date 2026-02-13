// TODO(nikki): spawn the demo code as a separate process so we can remove measurement overhead, and
// migrate to benches/ or examples/.

use std::{
    env,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{afc, text, Addr, ChanOp, Client, DeviceId, KeyBundle};
use backon::{ExponentialBuilder, Retryable as _};
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
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

        let client = (|| Client::builder().with_daemon_uds_path(&uds_sock).connect())
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
    // Create a team.
    info!("creating team");
    let owner = ctx
        .owner
        .client
        .create_team(Default::default())
        .await
        .context("expected to create team")?;
    let team_id = owner.team_id();
    info!(%team_id);

    // Create default roles
    info!("creating default roles");
    let owner_role = owner
        .roles()
        .await?
        .into_iter()
        .find(|role| role.name == "owner" && role.default)
        .context("unable to find owner role")?;
    let roles = owner.setup_default_roles(owner_role.id).await?;
    let admin_role = roles
        .iter()
        .find(|r| r.name == "admin")
        .ok_or_else(|| anyhow::anyhow!("no admin role"))?
        .clone();
    let operator_role = roles
        .iter()
        .find(|r| r.name == "operator")
        .ok_or_else(|| anyhow::anyhow!("no operator role"))?
        .clone();
    let member_role = roles
        .iter()
        .find(|r| r.name == "member")
        .ok_or_else(|| anyhow::anyhow!("no member role"))?
        .clone();

    // With mTLS, devices can use the team ID directly without add_team.
    // TODO: Delegate to admin and operator.
    let _admin = ctx.admin.client.team(team_id);
    let _operator = ctx.operator.client.team(team_id);
    let membera = ctx.membera.client.team(team_id);
    let memberb = ctx.memberb.client.team(team_id);

    // get sync addresses.
    let owner_addr = ctx.owner.aranya_local_addr().await?;
    let _admin_addr = ctx.admin.aranya_local_addr().await?;
    let _operator_addr = ctx.operator.aranya_local_addr().await?;

    // setup sync peers.
    info!("adding admin to team");
    owner.add_device(ctx.admin.pk, Some(admin_role.id)).await?;

    info!("adding operator to team");
    owner
        .add_device(ctx.operator.pk, Some(operator_role.id))
        .await?;

    // add membera to team.
    info!("adding membera to team");
    owner
        .add_device(ctx.membera.pk.clone(), Some(member_role.id))
        .await?;
    membera.sync_now(owner_addr, None).await?;

    // add memberb to team.
    info!("adding memberb to team");
    owner
        .add_device(ctx.memberb.pk.clone(), Some(member_role.id))
        .await?;
    memberb.sync_now(owner_addr, None).await?;

    // fact database queries
    let devices = membera.devices().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let owner_device = owner.device(ctx.owner.id);
    let owner_role = owner_device.role().await?.expect("expected owner role");
    info!("owner role: {:?}", owner_role);
    let keybundle = owner_device.keybundle().await?;
    info!("owner keybundle: {:?}", keybundle);

    info!("creating label");
    let label3 = owner.create_label(text!("label3"), owner_role.id).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    owner
        .device(ctx.membera.id)
        .assign_label(label3, op)
        .await?;
    info!("assigning label to memberb");
    owner
        .device(ctx.memberb.id)
        .assign_label(label3, op)
        .await?;

    membera.sync_now(owner_addr, None).await?;
    memberb.sync_now(owner_addr, None).await?;

    // Demo AFC.
    info!("demo afc functionality");

    // membera creates AFC channel.
    info!("creating afc send channel");
    let membera_afc = ctx.membera.client.afc();
    let (mut send, ctrl) = membera_afc
        .create_channel(team_id, ctx.memberb.id, label3)
        .await
        .expect("expected to create afc send channel");
    info!("created afc channel: {}", send.id());

    // memberb receives AFC channel.
    info!("receiving afc recv channel");
    let memberb_afc = ctx.memberb.client.afc();
    let recv = memberb_afc
        .accept_channel(team_id, ctrl)
        .await
        .expect("expected to receive afc channel");
    info!("received afc channel: {}", recv.id());

    // membera seals data for memberb.
    let afc_msg = "afc msg".as_bytes();
    info!(?afc_msg, "membera sealing data for memberb");
    let mut ciphertext = vec![0u8; afc_msg.len() + afc::Channels::OVERHEAD];
    send.seal(&mut ciphertext, afc_msg)
        .expect("expected to seal afc data");
    info!(?afc_msg, "membera sealed data for memberb");

    // This is where membera would send the ciphertext to memberb via the network.

    // memberb opens data from membera.
    info!("memberb receiving uni channel from membera");
    let mut plaintext = vec![0u8; ciphertext.len() - afc::Channels::OVERHEAD];
    info!("memberb opening data from membera");
    let seq1 = recv
        .open(&mut plaintext, &ciphertext)
        .expect("expected to open afc data");
    info!(?plaintext, "memberb opened data from membera");
    assert_eq!(afc_msg, plaintext);

    // seal/open again to get a new sequence number.
    send.seal(&mut ciphertext, afc_msg)
        .expect("expected to seal afc data");
    info!(?afc_msg, "membera sealed data for memberb");
    let seq2 = recv
        .open(&mut plaintext, &ciphertext)
        .expect("expected to open afc data");
    info!(?plaintext, "memberb opened data from membera");
    assert_eq!(afc_msg, plaintext);

    // AFC sequence numbers should be ascending.
    assert!(seq2 > seq1);

    // delete the channels
    info!("deleting afc channels");
    send.delete().await?;
    recv.delete().await?;
    info!("deleted afc channels");

    info!("completed afc demo");

    info!("revoking label from membera");
    owner.device(ctx.membera.id).revoke_label(label3).await?;
    info!("revoking label from memberb");
    owner.device(ctx.memberb.id).revoke_label(label3).await?;

    info!("deleting label");
    owner.delete_label(label3).await?;

    info!("completed example Aranya application");

    Ok(())
}
