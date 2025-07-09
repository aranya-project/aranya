use std::{
    env::VarError,
    future::pending,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{aqc::AqcPeerChannel, client::Queries, Client, SyncPeerConfig};
use aranya_daemon_api::{DeviceId, NetIdentifier, TeamId};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use bytes::Bytes;
use tokio::{fs, process::Command, time::sleep};
use tracing::{debug, info, level_filters::LevelFilter, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};

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
    #[allow(unused, reason = "drop side effects")]
    daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(daemon_dir: &Path, user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        info!(user_name, "creating `ClientCtx`");

        let work_dir = daemon_dir.join("state");
        let uds_api_path = work_dir.join("uds.sock");

        let api_pk;
        let daemon = {
            let cfg_path = work_dir.join("config.json");
            let pid_file = work_dir.join("daemon.pid");

            let sync_addr = var_or(
                "ARANYA_SYNC_ADDR",
                Addr::from((Ipv4Addr::UNSPECIFIED, 1111)),
            )?;

            let buf = format!(
                r#"
                name: {user_name:?}
                work_dir: {work_dir:?}
                uds_api_path: {uds_api_path:?}
                pid_file: {pid_file:?}
                sync_addr: "{sync_addr}"
                "#
            );
            fs::write(&cfg_path, buf).await?;

            api_pk = Daemon::get_api_pk(daemon_path, &cfg_path).await?;

            Daemon::spawn(daemon_path, daemon_dir, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = uds_api_path;

        let aqc_addr =
            var_or::<Addr>("ARANYA_AQC_ADDR", Addr::from((Ipv4Addr::UNSPECIFIED, 2222)))?;

        // Give the daemon time to start up and write its public key.
        sleep(Duration::from_secs(1)).await;

        let client = (|| {
            Client::builder()
                .with_daemon_uds_path(&uds_sock)
                .with_daemon_aqc_addr(&aqc_addr)
                .with_daemon_api_pk(&api_pk)
                .connect()
        })
        .retry(ExponentialBuilder::default())
        .await
        .context("unable to initialize client")?;

        Ok(Self { client, daemon })
    }
}

fn var<T: FromStr<Err: Into<anyhow::Error>>>(name: &str) -> Result<T> {
    (|| std::env::var(name)?.parse().map_err(Into::into))()
        .with_context(|| format!("could not get env var {name}"))
}

fn var_or<T: FromStr<Err: Into<anyhow::Error>>>(name: &str, default: T) -> Result<T> {
    (|| {
        match std::env::var(name) {
            Ok(s) => s,
            Err(VarError::NotPresent) => return Ok(default),
            Err(e) => return Err(e.into()),
        }
        .parse()
        .map_err(Into::into)
    })()
    .with_context(|| format!("could not get env var {name}"))
}

async fn read<T: FromStr<Err: Into<anyhow::Error>>>(filename: &str) -> Result<T> {
    async {
        fs::read_to_string(Path::new("/app/state/").join(filename))
            .await?
            .parse()
            .map_err(Into::into)
    }
    .await
    .with_context(|| format!("could not get env var {filename}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = DemoFilter {
        env_filter: EnvFilter::builder()
            .with_default_directive(LevelFilter::OFF.into())
            .with_env_var("ARANYA_EXAMPLE")
            .from_env()?,
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

    let exe = std::env::current_exe()?;
    let user = exe
        .file_name()
        .context("has filename")?
        .to_str()
        .context("valid string")?
        .to_owned();
    let daemon_path = {
        let mut args = std::env::args_os();
        args.next(); // skip executable name
        DaemonPath(PathBuf::from(
            args.next().context("missing `daemon` executable path")?,
        ))
    };

    let team_id = read::<TeamId>("team.id").await?;
    let operator_sync_addr = var::<Addr>("ARANYA_OPERATOR_SYNC_ADDR");
    let member_a_device_id = read::<DeviceId>("member-a.id");
    let member_b_device_id = read::<DeviceId>("member-b.id");

    let sync_interval = Duration::from_millis(100);
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let mut ctx = ClientCtx::new(Path::new("/app/"), &user, &daemon_path).await?;

    match user.as_str() {
        "operator" => {
            let member_a_net_id = NetIdentifier(var::<String>("ARANYA_MEMBER_A_NET_ID")?);
            let member_b_net_id = NetIdentifier(var::<String>("ARANYA_MEMBER_B_NET_ID")?);
            let mut team = ctx.client.team(team_id);
            team.assign_aqc_net_identifier(member_a_device_id.await?, member_a_net_id)
                .await?;
            team.assign_aqc_net_identifier(member_b_device_id.await?, member_b_net_id)
                .await?;
            pending::<()>().await;
        }
        "member-a" => {
            let mut team = ctx.client.team(team_id);
            team.add_sync_peer(operator_sync_addr?, sync_cfg).await?;

            // membera creates a bidirectional channel.
            info!("membera creating acq bidi channel");

            let label = ctx
                .client
                .queries(team_id)
                .labels()
                .await
                .context("failed to get labels")?
                .iter()
                .next()
                .context("missing label")?
                .clone();
            debug!(?label.name);

            let member_b_net_id =
                get_net_id(ctx.client.queries(team_id), member_b_device_id.await?).await?;
            debug!(?member_b_net_id);

            let mut aqc_chan = ctx
                .client
                .aqc()
                .create_bidi_channel(team_id, member_b_net_id, label.id)
                .await
                .context("Membera failed to create bidi channel")?;

            // membera creates a new stream on the channel.
            info!("membera creating aqc bidi stream");
            let mut bidi1 = aqc_chan.create_bidi_stream().await?;

            // membera sends data via the aqc stream.
            let msg = Bytes::from_static(b"hello");
            info!(?msg, "membera sending aqc data");
            bidi1.send(msg.clone()).await?;

            pending::<()>().await;
        }
        "member-b" => {
            let mut team = ctx.client.team(team_id);
            team.add_sync_peer(operator_sync_addr?, sync_cfg).await?;

            let member_a_net_id =
                get_net_id(ctx.client.queries(team_id), member_a_device_id.await?).await?;
            debug!(?member_a_net_id);

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
            let msg = peer2.receive().await?.context("no data received")?;
            assert_eq!(msg.as_ref(), b"hello");

            info!(?msg, "received message from member a");
        }
        _ => bail!("unknown user {user:?}"),
    }

    Ok(())
}

async fn get_net_id(mut q: Queries<'_>, peer: DeviceId) -> Result<NetIdentifier> {
    loop {
        if let Some(net_id) = q
            .aqc_net_identifier(peer)
            .await
            .context("failed to get net ID")?
        {
            return Ok(net_id);
        }
        info!("waiting for net ID to be available...");
        sleep(Duration::from_secs(1)).await;
    }
}
