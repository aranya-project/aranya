use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    aqc::AqcPeerChannel, client::Client, Error, QuicSyncConfig, SyncPeerConfig, TeamConfig,
};
use aranya_daemon_api::{text, ChanOp, DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use buggy::BugExt;
use bytes::Bytes;
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
        cmd.current_dir(work_dir)
            .args(["--config", cfg_path]);
        debug!(?cmd, "spawning daemon");
        let proc = cmd.spawn().context("unable to spawn daemon")?;
        Ok(Daemon {
            _proc: proc,
            _work_dir: work_dir.into(),
        })
    }
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    aqc_addr: SocketAddr,
    pk: KeyBundle,
    id: DeviceId,
    _work_dir: PathBuf,
    _daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(team_name: &str, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(team_name, user_name, "creating `ClientCtx`");

        let work_dir = PathBuf::from(format!("/tmp/aranya-{}-{}", user_name, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()));
        fs::create_dir_all(&work_dir).await?;

        let daemon = {
            let work_dir = work_dir.join("daemon");
            fs::create_dir_all(&work_dir).await?;

            let cfg_path = work_dir.join("config.json");

            let runtime_dir = work_dir.join("run");
            let state_dir = work_dir.join("state");
            let cache_dir = work_dir.join("cache");
            let logs_dir = work_dir.join("logs");
            let config_dir = work_dir.join("config");
            for dir in &[&runtime_dir, &state_dir, &cache_dir, &logs_dir, &config_dir] {
                fs::create_dir_all(dir)
                    .await
                    .with_context(|| format!("unable to create directory: {}", dir.display()))?;
            }

            let buf = format!(
                r#"
                name: "daemon"
                runtime_dir: {runtime_dir:?}
                state_dir: {state_dir:?}
                cache_dir: {cache_dir:?}
                logs_dir: {logs_dir:?}
                config_dir: {config_dir:?}
                sync_addr: "127.0.0.1:0"
                quic_sync: {{ }}
                "#
            );
            fs::write(&cfg_path, buf).await?;

            Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = work_dir.join("daemon").join("run").join("uds.sock");

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

        let aqc_server_addr = client.aqc().server_addr().context("exepcted server addr")?;
        let pk = client
            .get_key_bundle()
            .await
            .context("expected key bundle")?;
        let id = client.get_device_id().await.context("expected device id")?;

        Ok(Self {
            client,
            aqc_addr: aqc_server_addr,
            pk,
            id,
            _work_dir: work_dir,
            _daemon: daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
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

async fn print_state_dir(label: &str, path: &Path) {
    println!("\n===== DEBUG: {}: Listing {} =====", label, path.display());
    match fs::read_dir(path).await {
        Ok(mut entries) => {
            while let Ok(Some(entry)) = entries.next_entry().await {
                println!("  - {}", entry.path().display());
            }
        }
        Err(e) => println!("  (error reading dir: {})", e),
    }
    println!("===== END DEBUG: {} =====\n", label);
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
    let mut owner = ClientCtx::new(team_name, "owner", &daemon_path).await?;
    let mut admin = ClientCtx::new(team_name, "admin", &daemon_path).await?;
    let mut operator = ClientCtx::new(team_name, "operator", &daemon_path).await?;
    let mut membera = ClientCtx::new(team_name, "member_a", &daemon_path).await?;
    let mut memberb = ClientCtx::new(team_name, "member_b", &daemon_path).await?;

    // Debug: Print state directories after all daemons are started
    print_state_dir("Owner state dir after daemon start", &owner._work_dir.join("daemon").join("state")).await;
    print_state_dir("Admin state dir after daemon start", &admin._work_dir.join("daemon").join("state")).await;
    print_state_dir("Operator state dir after daemon start", &operator._work_dir.join("daemon").join("state")).await;
    print_state_dir("MemberA state dir after daemon start", &membera._work_dir.join("daemon").join("state")).await;
    print_state_dir("MemberB state dir after daemon start", &memberb._work_dir.join("daemon").join("state")).await;

    // Print all UDS socket paths for all daemons
    info!("=== UDS Socket Paths for All Daemons ===");
    info!("Owner UDS: {}", owner._work_dir.join("daemon").join("run").join("uds.sock").display());
    info!("Admin UDS: {}", admin._work_dir.join("daemon").join("run").join("uds.sock").display());
    info!("Operator UDS: {}", operator._work_dir.join("daemon").join("run").join("uds.sock").display());
    info!("MemberA UDS: {}", membera._work_dir.join("daemon").join("run").join("uds.sock").display());
    info!("MemberB UDS: {}", memberb._work_dir.join("daemon").join("run").join("uds.sock").display());
    info!("=========================================");
    
    // Export UDS paths as environment variables for CLI testing
    let env_vars = format!(
        "export OWNER_UDS={}\nexport ADMIN_UDS={}\nexport OPERATOR_UDS={}\nexport MEMBERA_UDS={}\nexport MEMBERB_UDS={}",
        owner._work_dir.join("daemon").join("run").join("uds.sock").display(),
        admin._work_dir.join("daemon").join("run").join("uds.sock").display(),
        operator._work_dir.join("daemon").join("run").join("uds.sock").display(),
        membera._work_dir.join("daemon").join("run").join("uds.sock").display(),
        memberb._work_dir.join("daemon").join("run").join("uds.sock").display()
    );
    println!("{}", env_vars);

    // Create the team config
    let seed_ikm = {
        let mut buf = [0; 32];
        owner.client.rand(&mut buf).await;
        buf
    };
    
    // Export seed-ikm-hex for CLI testing
    let seed_ikm_hex = seed_ikm.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    println!("export SEED_IKM_HEX={}", seed_ikm_hex);
    
    // Write environment variables to a file for easy sourcing
    let env_file = PathBuf::from("/tmp/aranya-env-vars.sh");
    let env_content = format!("{}\nexport SEED_IKM_HEX={}", env_vars, seed_ikm_hex);
    fs::write(&env_file, env_content).await?;
    println!("Environment variables written to: {}", env_file.display());
    println!("To load them, run: source {}", env_file.display());
    
    let cfg = {
        let qs_cfg = QuicSyncConfig::builder().seed_ikm(seed_ikm).build()?;
        TeamConfig::builder().quic_sync(qs_cfg).build()?
    };


    // get sync addresses.
    let owner_addr = owner.aranya_local_addr().await?;
    let admin_addr = admin.aranya_local_addr().await?;
    let operator_addr = operator.aranya_local_addr().await?;
    let membera_addr = membera.aranya_local_addr().await?;
    let memberb_addr = memberb.aranya_local_addr().await?;

    // get aqc addresses.
    debug!(?membera.aqc_addr, ?memberb.aqc_addr);

    // Create a team.
    info!("creating team");
    let mut owner_team = owner
        .client
        .create_team(cfg.clone())
        .await
        .context("expected to create team")?;
    let team_id = owner_team.team_id();
    info!(%team_id);
    print_state_dir("Owner state dir after team creation", &owner._work_dir.join("daemon").join("state")).await;
    
    // Export team ID for CLI testing
    println!("export TEAM_ID={}", team_id);
    
    // Export device IDs for CLI testing
    println!("export OWNER_DEVICE_ID={}", owner.id);
    println!("export ADMIN_DEVICE_ID={}", admin.id);
    println!("export OPERATOR_DEVICE_ID={}", operator.id);
    println!("export MEMBERA_DEVICE_ID={}", membera.id);
    println!("export MEMBERB_DEVICE_ID={}", memberb.id);
    
    // Export sync addresses for CLI testing
    println!("export OWNER_SYNC_ADDR={}", owner_addr);
    println!("export ADMIN_SYNC_ADDR={}", admin_addr);
    println!("export OPERATOR_SYNC_ADDR={}", operator_addr);
    println!("export MEMBERA_SYNC_ADDR={}", membera_addr);
    println!("export MEMBERB_SYNC_ADDR={}", memberb_addr);
    
    // Export AQC network IDs for CLI testing
    println!("export MEMBERA_AQC_NET_ID={}", membera.aqc_net_id());
    println!("export MEMBERB_AQC_NET_ID={}", memberb.aqc_net_id());
    
    // Update the env file with all new variables
    let env_content = format!(
        "{}\nexport SEED_IKM_HEX={}\nexport TEAM_ID={}\nexport OWNER_DEVICE_ID={}\nexport ADMIN_DEVICE_ID={}\nexport OPERATOR_DEVICE_ID={}\nexport MEMBERA_DEVICE_ID={}\nexport MEMBERB_DEVICE_ID={}\nexport OWNER_SYNC_ADDR={}\nexport ADMIN_SYNC_ADDR={}\nexport OPERATOR_SYNC_ADDR={}\nexport MEMBERA_SYNC_ADDR={}\nexport MEMBERB_SYNC_ADDR={}\nexport MEMBERA_AQC_NET_ID={}\nexport MEMBERB_AQC_NET_ID={}",
        env_vars, seed_ikm_hex, team_id, owner.id, admin.id, operator.id, membera.id, memberb.id, 
        owner_addr, admin_addr, operator_addr, membera_addr, memberb_addr, 
        membera.aqc_net_id(), memberb.aqc_net_id()
    );
    fs::write(&env_file, env_content).await?;

    let mut admin_team = admin.client.add_team(team_id, cfg.clone()).await?;
    print_state_dir("Admin state dir after add_team", &admin._work_dir.join("daemon").join("state")).await;
    let mut operator_team = operator.client.add_team(team_id, cfg.clone()).await?;
    print_state_dir("Operator state dir after add_team", &operator._work_dir.join("daemon").join("state")).await;
    let mut membera_team = membera.client.add_team(team_id, cfg.clone()).await?;
    print_state_dir("MemberA state dir after add_team", &membera._work_dir.join("daemon").join("state")).await;
    let mut memberb_team = memberb.client.add_team(team_id, cfg.clone()).await?;
    print_state_dir("MemberB state dir after add_team", &memberb._work_dir.join("daemon").join("state")).await;

    // setup sync peers.
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

    // Debug: Print state directories after sync
    print_state_dir("Owner state dir after sync", &owner._work_dir.join("daemon").join("state")).await;
    print_state_dir("Admin state dir after sync", &admin._work_dir.join("daemon").join("state")).await;
    print_state_dir("Operator state dir after sync", &operator._work_dir.join("daemon").join("state")).await;
    print_state_dir("MemberA state dir after sync", &membera._work_dir.join("daemon").join("state")).await;
    print_state_dir("MemberB state dir after sync", &memberb._work_dir.join("daemon").join("state")).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team.add_device_to_team(membera.pk.clone()).await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team.add_device_to_team(memberb.pk.clone()).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("assigning aqc net identifiers");
    operator_team
        .assign_aqc_net_identifier(membera.id, membera.aqc_net_id())
        .await?;
    operator_team
        .assign_aqc_net_identifier(memberb.id, memberb.aqc_net_id())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries_team = membera.client.team(team_id);
    let mut queries = queries_team.queries();
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
    let label3 = operator_team.create_label(text!("label3")).await?;
    
    // Export label ID for CLI testing
    println!("export LABEL_ID={}", label3);
    
    // Update env file with label ID
    let env_content = format!(
        "{}\nexport SEED_IKM_HEX={}\nexport TEAM_ID={}\nexport OWNER_DEVICE_ID={}\nexport ADMIN_DEVICE_ID={}\nexport OPERATOR_DEVICE_ID={}\nexport MEMBERA_DEVICE_ID={}\nexport MEMBERB_DEVICE_ID={}\nexport OWNER_SYNC_ADDR={}\nexport ADMIN_SYNC_ADDR={}\nexport OPERATOR_SYNC_ADDR={}\nexport MEMBERA_SYNC_ADDR={}\nexport MEMBERB_SYNC_ADDR={}\nexport MEMBERA_AQC_NET_ID={}\nexport MEMBERB_AQC_NET_ID={}\nexport LABEL_ID={}",
        env_vars, seed_ikm_hex, team_id, owner.id, admin.id, operator.id, membera.id, memberb.id, 
        owner_addr, admin_addr, operator_addr, membera_addr, memberb_addr, 
        membera.aqc_net_id(), memberb.aqc_net_id(), label3
    );
    fs::write(&env_file, env_content).await?;
    
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team.assign_label(membera.id, label3, op).await?;
    info!("assigning label to memberb");
    operator_team.assign_label(memberb.id, label3, op).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // membera creates a bidirectional channel.
    info!("membera creating acq bidi channel");
    // Prepare arguments that need to be captured by the async move block
    let memberb_net_identifier = memberb.aqc_net_id();

    let create_handle = tokio::spawn(async move {
        let channel_result = membera
            .client
            .aqc()
            .create_bidi_channel(team_id, memberb_net_identifier, label3)
            .await;
        (channel_result, membera) // Return membera along with the result
    });

    // memberb receives a bidirectional channel.
    info!("memberb receiving acq bidi channel");
    let AqcPeerChannel::Bidi(mut received_aqc_chan) =
        memberb.client.aqc().receive_channel().await?
    else {
        bail!("expected a bidirectional channel");
    };

    // Now await the completion of membera's channel creation
    let (created_aqc_chan_result, membera_returned) = create_handle
        .await
        .context("Task for membera creating bidi channel panicked")?;
    membera = membera_returned; // Assign the moved membera back
    let mut created_aqc_chan =
        created_aqc_chan_result.context("Membera failed to create bidi channel")?;

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
    operator_team.revoke_label(membera.id, label3).await?;
    info!("revoking label from memberb");
    operator_team.revoke_label(memberb.id, label3).await?;
    info!("deleting label");
    admin_team.delete_label(label3).await?;

    info!("completed aqc demo");

    info!("completed example Aranya application");

    Ok(())
}
