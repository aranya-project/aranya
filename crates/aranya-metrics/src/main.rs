// TODO(nikki): spawn the demo code as a separate process so we can remove measurement overhead, and
// migrate to benches/ or examples/.

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    aqc::AqcPeerChannel, AddTeamConfig, AddTeamQuicSyncConfig, Client, CreateTeamConfig,
    CreateTeamQuicSyncConfig, Error,
};
use aranya_daemon_api::{text, ChanOp, DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use buggy::BugExt as _;
use bytes::Bytes;
use futures_util::future::try_join;
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
    aqc_addr: SocketAddr,
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

                aqc.enable = true

                [sync.quic]
                enable = true
                addr = "127.0.0.1:0"
                "#
            );
            fs::write(&cfg_path, buf).await?;
            Daemon::spawn(daemon_path, &work_path, &cfg_path).await?
        };

        let uds_sock = work_path.join("run").join("uds.sock");
        let any_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));

        let client = (|| {
            Client::builder()
                .daemon_uds_path(&uds_sock)
                .aqc_server_addr(&any_addr)
                .connect()
        })
        .retry(ExponentialBuilder::new())
        .await
        .context("unable to initialize client")?;

        let aqc_addr = client.aqc().context("AQC not enabled")?.server_addr();
        let pk = client
            .get_key_bundle()
            .await
            .context("expected key bundle")?;
        let id = client.get_device_id().await.context("expected device id")?;

        Ok(Self {
            client,
            aqc_addr,
            pk,
            id,
            _work_dir,
            daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<Addr> {
        Ok(self.client.local_addr().await?)
    }

    fn aqc_net_id(&self) -> NetIdentifier {
        NetIdentifier(
            self.aqc_addr
                .to_string()
                .try_into()
                .expect("addr is valid text"),
        )
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

    // get aqc addresses.
    debug!(?ctx.membera.aqc_addr, ?ctx.memberb.aqc_addr);

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
    admin.sync_now(owner_addr.into(), None).await?;

    info!("properly assigning the operator's role");
    admin.assign_role(ctx.operator.id, Role::Operator).await?;

    operator.sync_now(admin_addr.into(), None).await?;

    // add membera to team.
    info!("adding membera to team");
    operator.add_device_to_team(ctx.membera.pk.clone()).await?;
    membera.sync_now(operator_addr.into(), None).await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator.add_device_to_team(ctx.memberb.pk.clone()).await?;
    memberb.sync_now(operator_addr.into(), None).await?;

    info!("assigning aqc net identifiers");
    operator
        .assign_aqc_net_identifier(ctx.membera.id, ctx.membera.aqc_net_id())
        .await?;
    operator
        .assign_aqc_net_identifier(ctx.memberb.id, ctx.memberb.aqc_net_id())
        .await?;

    membera.sync_now(operator_addr.into(), None).await?;
    memberb.sync_now(operator_addr.into(), None).await?;

    // fact database queries
    let queries = membera.queries();
    let devices = queries.devices_on_team().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(ctx.membera.id).await?;
    info!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(ctx.membera.id).await?;
    info!("membera keybundle: {:?}", keybundle);
    let queried_membera_net_ident = queries.aqc_net_identifier(ctx.membera.id).await?;
    info!(
        "membera queried_membera_net_ident: {:?}",
        queried_membera_net_ident
    );
    let queried_memberb_net_ident = queries.aqc_net_identifier(ctx.memberb.id).await?;
    info!(
        "memberb queried_memberb_net_ident: {:?}",
        queried_memberb_net_ident
    );

    info!("demo aqc functionality");
    info!("creating aqc label");
    let label3 = operator.create_label(text!("label3")).await?;
    let op = ChanOp::SendRecv;

    info!("assigning label to membera");
    operator.assign_label(ctx.membera.id, label3, op).await?;

    info!("assigning label to memberb");
    operator.assign_label(ctx.memberb.id, label3, op).await?;

    membera.sync_now(operator_addr.into(), None).await?;
    memberb.sync_now(operator_addr.into(), None).await?;

    // Creating and receiving a channel "blocks" until both sides have
    // joined the channel, so we do them concurrently with `try_join`.
    let (mut created_aqc_chan, mut received_aqc_chan) = try_join(
        async {
            // membera creates a bidirectional channel.
            info!("membera creating acq bidi channel");
            let chan = ctx
                .membera
                .client
                .aqc()
                .context("AQC not enabled")?
                .create_bidi_channel(team_id, ctx.memberb.aqc_net_id(), label3)
                .await?;
            Ok(chan)
        },
        async {
            // memberb receives a bidirectional channel.
            info!("memberb receiving acq bidi channel");
            let AqcPeerChannel::Bidi(chan) = ctx
                .memberb
                .client
                .aqc()
                .context("AQC not enabled")?
                .receive_channel()
                .await?
            else {
                bail!("expected a bidirectional channel");
            };
            Ok(chan)
        },
    )
    .await?;

    // membera creates a new stream on the channel.
    info!("membera creating aqc bidi stream");
    let mut bidi1 = created_aqc_chan.create_bidi_stream().await?;

    // membera sends data via the aqc stream.
    info!("membera sending aqc data");
    let msg = Bytes::from_static(b"hello");
    bidi1.send(msg.clone()).await?;

    // memberb receives channel stream created by membera.
    info!("memberb receiving aqc bidi stream");
    let mut peer2 = received_aqc_chan
        .receive_stream()
        .await
        .assume("stream not received")?;

    // memberb receives data from stream.
    info!("memberb receiving acq data");
    let bytes = peer2.receive().await?.assume("no data received")?;
    assert_eq!(bytes, msg);

    info!("revoking label from membera");
    operator.revoke_label(ctx.membera.id, label3).await?;
    info!("revoking label from memberb");
    operator.revoke_label(ctx.memberb.id, label3).await?;

    admin.sync_now(operator_addr.into(), None).await?;

    info!("deleting label");
    admin.delete_label(label3).await?;

    info!("Finished running example Aranya application");

    // sleep a moment so we can get a stable final state for all daemons
    sleep(Duration::from_millis(25)).await;

    Ok(())
}
