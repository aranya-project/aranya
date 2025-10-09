use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    afc,
    aqc::AqcPeerChannel,
    client::{ChanOp, Client, DeviceId, KeyBundle, NetIdentifier, Role},
    AddTeamConfig, AddTeamQuicSyncConfig, CreateTeamConfig, CreateTeamQuicSyncConfig, Error,
    SyncPeerConfig,
};
use aranya_daemon_api::text;
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use buggy::BugExt;
use bytes::Bytes;
use futures_util::future::try_join;
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
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    aqc_addr: SocketAddr,
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

        let daemon = {
            let shm = format!("/shm_{}", user_name);
            let _ = rustix::shm::unlink(&shm);
            let work_dir = work_dir.path().join("daemon");
            fs::create_dir_all(&work_dir).await?;

            let cfg_path = work_dir.join("config.toml");

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
                name = {user_name:?}
                runtime_dir = {runtime_dir:?}
                state_dir = {state_dir:?}
                cache_dir = {cache_dir:?}
                logs_dir = {logs_dir:?}
                config_dir = {config_dir:?}

                aqc.enable = true

                [afc]
                enable = true
                shm_path = {shm:?}
                max_chans = 100

                [sync.quic]
                enable = true
                addr = "127.0.0.1:0"
                "#
            );
            fs::write(&cfg_path, buf).await?;

            Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = work_dir.path().join("daemon").join("run").join("uds.sock");

        // Give the daemon time to start up and write its public key.
        sleep(Duration::from_millis(100)).await;

        let any_addr = Addr::from((Ipv4Addr::LOCALHOST, 0));
        let client = (|| {
            Client::builder()
                .daemon_uds_path(&uds_sock)
                .aqc_server_addr(&any_addr)
                .connect()
        })
        .retry(ExponentialBuilder::default())
        .await
        .context("unable to initialize client")?;

        let aqc_server_addr = client.aqc().context("AQC is enabled")?.server_addr();
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
        NetIdentifier::from_str(self.aqc_addr.to_string().as_str())
            .expect("expected net identifier")
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
    let owner = ClientCtx::new(team_name, "owner", &daemon_path).await?;
    let admin = ClientCtx::new(team_name, "admin", &daemon_path).await?;
    let operator = ClientCtx::new(team_name, "operator", &daemon_path).await?;
    let membera = ClientCtx::new(team_name, "member_a", &daemon_path).await?;
    let memberb = ClientCtx::new(team_name, "member_b", &daemon_path).await?;

    // Create the team config
    let seed_ikm = {
        let mut buf = [0; 32];
        owner.client.rand(&mut buf).await;
        buf
    };
    let owner_cfg = {
        let qs_cfg = CreateTeamQuicSyncConfig::builder()
            .seed_ikm(seed_ikm)
            .build()?;
        CreateTeamConfig::builder().quic_sync(qs_cfg).build()?
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
    let owner_team = owner
        .client
        .create_team(owner_cfg)
        .await
        .context("expected to create team")?;
    let team_id = owner_team.team_id();
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

    let admin_team = admin.client.add_team(add_team_cfg.clone()).await?;
    let operator_team = operator.client.add_team(add_team_cfg.clone()).await?;
    let membera_team = membera.client.add_team(add_team_cfg.clone()).await?;
    let memberb_team = memberb.client.add_team(add_team_cfg).await?;

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
    let queries = membera_team.queries();
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
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team.assign_label(membera.id, label3, op).await?;
    info!("assigning label to memberb");
    operator_team.assign_label(memberb.id, label3, op).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Creating and receiving a channel "blocks" until both sides have
    // joined the channel, so we do them concurrently with `try_join`.
    let (mut created_aqc_chan, mut received_aqc_chan) = try_join(
        async {
            // membera creates a bidirectional channel.
            info!("membera creating acq bidi channel");
            let chan = membera
                .client
                .aqc()
                .context("AQC is enabled")?
                .create_bidi_channel(team_id, memberb.aqc_net_id(), label3)
                .await?;
            Ok(chan)
        },
        async {
            // memberb receives a bidirectional channel.
            info!("memberb receiving acq bidi channel");
            let AqcPeerChannel::Bidi(chan) = memberb
                .client
                .aqc()
                .context("AQC is enabled")?
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

    // membera deletes the AQC channel.
    info!("membera deleting aqc channel");
    membera
        .client
        .aqc()
        .context("AQC is enabled")?
        .delete_bidi_channel(&mut created_aqc_chan)
        .await?;

    info!("completed aqc demo");

    // Demo AFC.
    info!("demo afc functionality");

    // membera creates AFC channel.
    info!("creating afc send channel");
    let membera_afc = membera.client.afc();
    let (send, ctrl) = membera_afc
        .create_uni_send_channel(team_id, memberb.id, label3)
        .await
        .expect("expected to create afc send channel");

    // memberb receives AFC channel.
    info!("receiving afc recv channel");
    let memberb_afc = memberb.client.afc();
    let recv = memberb_afc
        .recv_ctrl(team_id, ctrl)
        .await
        .expect("expected to receive afc channel");

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
    operator_team.revoke_label(membera.id, label3).await?;
    info!("revoking label from memberb");
    operator_team.revoke_label(memberb.id, label3).await?;
    info!("deleting label");
    admin_team.delete_label(label3).await?;

    info!("completed example Aranya application");

    Ok(())
}
