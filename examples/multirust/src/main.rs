use std::{
    env,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{
    aqc::AqcPeerChannel, client::Client, QuicSyncConfig, SyncPeerConfig, TeamConfig,
};
use aranya_daemon_api::{text, ChanOp, DeviceId, KeyBundle, NetIdentifier, Role, TeamId};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
use tempfile::TempDir;
use tokio::{
    fs,
    process::{Child, Command},
    time::sleep,
};
use tracing::{debug, info, info_span, Metadata};
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
            .env("ARANYA_DAEMON", "OFF")
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
    user_name: String,
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
            let work_dir = work_dir.path().join("daemon");
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
                sync_addr: "0.0.0.0:4545"
                quic_sync: {{ }}
                "#
            );
            fs::write(&cfg_path, buf).await?;

            Daemon::spawn(daemon_path, &work_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = work_dir.path().join("daemon").join("run").join("uds.sock");

        // Give the daemon time to start up and write its public key.
        sleep(Duration::from_millis(100)).await;

        let any_addr = Addr::from((Ipv4Addr::UNSPECIFIED, 6363));

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

        Ok(Self {
            client,
            pk,
            id,
            user_name: user_name.into(),
            _work_dir: work_dir,
            _daemon: daemon,
        })
    }

    async fn info(&self) -> UserInfo {
        UserInfo {
            id: self.id,
            pk: self.pk.clone(),
            addr: Addr::new(&self.user_name, 4545).expect("valid addr"),
            aqc_net_id: NetIdentifier(
                format!("{}:6363", self.user_name)
                    .try_into()
                    .expect("valid text"),
            ),
        }
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum User {
    Owner,
    Admin,
    Operator,
    MemberA,
    MemberB,
}

impl User {
    fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::MemberA => "member_a",
            Self::MemberB => "member_b",
        }
    }
}

struct Shared {
    base: PathBuf,
}

impl Shared {
    async fn write_team_id(&self, id: TeamId) {
        let path = self.base.join("team.id");
        fs::write(path, id.to_string())
            .await
            .expect("writing team id");
    }
    async fn read_team_id(&self) -> TeamId {
        let path = self.base.join("team.id");
        loop {
            sleep(Duration::from_secs(1)).await;
            let Ok(txt) = fs::read_to_string(&path).await else {
                continue;
            };
            let Ok(id) = txt.parse() else { continue };
            break id;
        }
    }

    async fn write_user_info(&self, user: User, info: UserInfo) {
        let mut path = self.base.join(user.as_str());
        path.set_extension("info");
        let bytes = postcard::to_allocvec(&info).expect("serializing user info");
        fs::write(path, bytes).await.expect("writing user info");
    }
    async fn read_user_info(&self, user: User) -> UserInfo {
        let mut path = self.base.join(user.as_str());
        path.set_extension("info");
        loop {
            sleep(Duration::from_secs(1)).await;
            let Ok(bytes) = fs::read(&path).await else {
                continue;
            };
            let Ok(info) = postcard::from_bytes(&bytes) else {
                continue;
            };
            break info;
        }
    }

    async fn read_total_info(&self) -> TotalInfo {
        TotalInfo {
            owner: self.read_user_info(User::Owner).await,
            admin: self.read_user_info(User::Admin).await,
            operator: self.read_user_info(User::Operator).await,
            member_a: self.read_user_info(User::MemberA).await,
            member_b: self.read_user_info(User::MemberB).await,
        }
    }
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct UserInfo {
    id: DeviceId,
    pk: KeyBundle,
    addr: Addr,
    aqc_net_id: NetIdentifier,
}

struct TotalInfo {
    owner: UserInfo,
    admin: UserInfo,
    operator: UserInfo,
    member_a: UserInfo,
    member_b: UserInfo,
}

impl TotalInfo {
    fn peers(&self, user: User) -> Vec<&UserInfo> {
        let mut out = Vec::new();
        if user != User::Owner {
            out.push(&self.owner);
        }
        if user != User::Admin {
            out.push(&self.admin);
        }
        if user != User::Operator {
            out.push(&self.operator);
        }
        if user != User::MemberA {
            out.push(&self.member_a);
        }
        if user != User::MemberB {
            out.push(&self.member_b);
        }
        out
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
                .with_filter(filter),
        )
        .init();

    info!("starting example Aranya application");

    let daemon_path;
    let name;
    let user;
    {
        let mut args = env::args();
        args.next(); // skip executable name
        let exe = args.next().context("missing `daemon` executable path")?;
        daemon_path = DaemonPath(PathBuf::from(exe));
        name = args.next().context("missing user name")?;
        user = match name.as_str() {
            "owner" => User::Owner,
            "admin" => User::Admin,
            "operator" => User::Operator,
            "member_a" => User::MemberA,
            "member_b" => User::MemberB,
            _ => bail!("unknown user {name}"),
        };
    };

    let _guard = info_span!("user", name).entered();

    let sync_interval = Duration::from_millis(50);
    let sleep_interval = Duration::from_secs(1);
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let mut ctx = ClientCtx::new("multirust", &name, &daemon_path).await?;

    // Create the team config
    let cfg = {
        let seed_ikm = [0u8; 32]; // INSECURE
        let qs_cfg = QuicSyncConfig::builder().seed_ikm(seed_ikm).build()?;
        TeamConfig::builder().quic_sync(qs_cfg).build()?
    };

    let shared = Shared {
        base: PathBuf::from("./shared/"),
    };

    shared.write_user_info(user, ctx.info().await).await;
    let info = shared.read_total_info().await;

    // Create a team.
    let team_id;
    if user == User::Owner {
        info!("creating team");
        team_id = ctx
            .client
            .create_team(cfg.clone())
            .await
            .context("expected to create team")?
            .team_id();
        shared.write_team_id(team_id).await;
    } else {
        team_id = shared.read_team_id().await;
        ctx.client.add_team(team_id, cfg.clone()).await?;
    };
    info!(%team_id);

    let mut team = ctx.client.team(team_id);

    // Add all sync peers
    info!("adding sync peers");
    for peer in info.peers(user) {
        team.add_sync_peer(peer.addr, sync_cfg.clone()).await?;
    }

    sleep(sleep_interval).await;

    if user == User::Owner {
        // setup sync peers.
        info!("adding admin to team");
        team.add_device_to_team(info.admin.pk).await?;
        team.assign_role(info.admin.id, Role::Admin).await?;

        info!("adding operator to team");
        team.add_device_to_team(info.operator.pk).await?;
    }

    sleep(sleep_interval).await;

    if user == User::Admin {
        info!("assigning role");
        team.assign_role(info.operator.id, Role::Operator).await?;
    }

    sleep(sleep_interval).await;

    if user == User::Operator {
        // add membera to team.
        info!("adding membera to team");
        team.add_device_to_team(info.member_a.pk.clone()).await?;

        // add memberb to team.
        info!("adding memberb to team");
        team.add_device_to_team(info.member_b.pk.clone()).await?;
    }

    sleep(sleep_interval).await;

    if user == User::Operator {
        info!("assigning aqc net identifiers");
        team.assign_aqc_net_identifier(info.member_a.id, info.member_a.aqc_net_id.clone())
            .await?;
        team.assign_aqc_net_identifier(info.member_b.id, info.member_b.aqc_net_id.clone())
            .await?;
    }

    sleep(sleep_interval).await;

    // // fact database queries
    // let mut queries_team = membera.client.team(team_id);
    // let mut queries = queries_team.queries();
    // let devices = queries.devices_on_team().await?;
    // info!("membera devices on team: {:?}", devices.iter().count());
    // let role = queries.device_role(membera.id).await?;
    // info!("membera role: {:?}", role);
    // let keybundle = queries.device_keybundle(membera.id).await?;
    // info!("membera keybundle: {:?}", keybundle);
    // let queried_membera_net_ident = queries.aqc_net_identifier(membera.id).await?;
    // info!(
    //     "membera queried_membera_net_ident: {:?}",
    //     queried_membera_net_ident
    // );
    // let queried_memberb_net_ident = queries.aqc_net_identifier(memberb.id).await?;
    // info!(
    //     "memberb queried_memberb_net_ident: {:?}",
    //     queried_memberb_net_ident
    // );

    // // wait for syncing.
    // sleep(sleep_interval).await;

    if user == User::Operator {
        info!("creating aqc label");
        let label3 = team.create_label(text!("label3")).await?;
        let op = ChanOp::SendRecv;
        info!("assigning label to membera");
        team.assign_label(info.member_a.id, label3, op).await?;
        info!("assigning label to memberb");
        team.assign_label(info.member_b.id, label3, op).await?;
    }

    sleep(sleep_interval * 5).await;

    if user == User::MemberA {
        // membera creates a bidirectional channel.
        info!("membera creating acq bidi channel");

        let label3 = team
            .queries()
            .labels()
            .await
            .context("failed to get labels")?
            .iter()
            .next()
            .context("missing label")?
            .clone();

        debug!(?label3.name);

        let mut aqc_chan = ctx
            .client
            .aqc()
            .create_bidi_channel(team_id, info.member_b.aqc_net_id.clone(), label3.id)
            .await
            .context("Membera failed to create bidi channel")?;

        // membera creates a new stream on the channel.
        info!("membera creating aqc bidi stream");
        let mut bidi1 = aqc_chan.create_bidi_stream().await?;

        // membera sends data via the aqc stream.
        info!("membera sending aqc data");
        let msg = Bytes::from_static(b"hello");
        bidi1.send(msg.clone()).await?;

        sleep(Duration::from_secs(2)).await;
    }

    if user == User::MemberB {
        // memberb receives a bidirectional channel.
        info!("memberb receiving acq bidi channel");
        let AqcPeerChannel::Bidi(mut received_aqc_chan) =
            ctx.client.aqc().receive_channel().await?
        else {
            bail!("expected a bidirectional channel");
        };

        // memberb receives channel stream created by membera.
        info!("memberb receiving aqc bidi stream");
        let mut peer2 = received_aqc_chan
            .receive_stream()
            .await
            .context("stream not received")?;

        // memberb receives data from stream.
        info!("memberb receiving acq data");
        let bytes = peer2.receive().await?.context("no data received")?;
        assert_eq!(bytes.as_ref(), b"hello");
    }

    // info!("revoking label from membera");
    // operator_team.revoke_label(membera.id, label3).await?;
    // info!("revoking label from memberb");
    // operator_team.revoke_label(memberb.id, label3).await?;
    // info!("deleting label");
    // admin_team.delete_label(label3).await?;

    // info!("completed aqc demo");

    info!("completed example Aranya application");

    Ok(())
}
