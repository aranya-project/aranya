use std::{
    env::{self, VarError},
    future::pending,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{Addr, ChanOp, Client, Device, DeviceId, Label, SyncPeerConfig, TeamId};
use backon::{ExponentialBuilder, Retryable as _};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    process::Command,
    time::sleep,
};
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
    async fn spawn(path: &DaemonPath, cfg_path: &Path) -> Result<Self> {
        let mut cmd = Command::new(&path.0);
        cmd.kill_on_drop(true)
            .args(["--config".as_ref(), cfg_path.as_os_str()]);
        debug!(?cmd, "spawning daemon");
        let proc = cmd.spawn().context("unable to spawn daemon")?;
        Ok(Daemon { proc })
    }
}

/// An Aranya device.
struct ClientCtx {
    client: Client,
    #[allow(unused, reason = "drop side effects")]
    daemon: Daemon,
}

impl ClientCtx {
    pub async fn new(user_name: &str, daemon_path: &DaemonPath) -> Result<Self> {
        let daemon_dir = env::current_dir()?;

        info!(user_name, "creating `ClientCtx`");

        let runtime_dir = Path::new("/var/run/aranya/");

        let daemon = {
            let state_dir = daemon_dir.join("state");
            let cache_dir = Path::new("/var/cache/aranya/");
            let logs_dir = Path::new("/var/log/aranya/");
            let config_dir = daemon_dir.join("config");
            let cfg_path = config_dir.join("config.toml");

            for dir in &[runtime_dir, cache_dir, logs_dir, &config_dir] {
                fs::create_dir_all(dir)
                    .await
                    .with_context(|| format!("unable to create directory: {}", dir.display()))?;
            }

            let sync_addr = var_or(
                "ARANYA_SYNC_ADDR",
                Addr::from((Ipv4Addr::UNSPECIFIED, 1111)),
            )?;

            let buf = format!(
                r#"
                name = {user_name:?}
                runtime_dir = {runtime_dir:?}
                state_dir = {state_dir:?}
                cache_dir = {cache_dir:?}
                logs_dir = {logs_dir:?}
                config_dir = {config_dir:?}

                [afc]
                enable = true
                shm_path = "/afc_shm"
                max_chans = 100

                [sync.quic]
                enable = true
                addr = "{sync_addr}"
                "#
            );
            fs::write(&cfg_path, buf).await?;

            Daemon::spawn(daemon_path, &cfg_path).await?
        };

        // The path that the daemon will listen on.
        let uds_sock = runtime_dir.join("uds.sock");

        let client = (|| Client::builder().with_daemon_uds_path(&uds_sock).connect())
            .retry(ExponentialBuilder::default())
            .await
            .context("unable to initialize client")?;

        Ok(Self { client, daemon })
    }
}

fn var<T: FromStr<Err: Into<anyhow::Error>>>(name: &str) -> Result<T> {
    (|| env::var(name)?.parse().map_err(Into::into))()
        .with_context(|| format!("could not get env var {name}"))
}

fn var_or<T: FromStr<Err: Into<anyhow::Error>>>(name: &str, default: T) -> Result<T> {
    (|| {
        match env::var(name) {
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
        fs::read_to_string(Path::new("./state/").join(filename))
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

    let exe = env::current_exe()?;
    let user = exe
        .file_name()
        .context("has filename")?
        .to_str()
        .context("valid string")?
        .to_owned();
    let daemon_path = {
        let mut args = env::args_os();
        args.next(); // skip executable name
        DaemonPath(PathBuf::from(
            args.next().context("missing `daemon` executable path")?,
        ))
    };

    let team_id = read::<TeamId>("team.id").await?;
    let operator_sync_addr = var::<Addr>("ARANYA_OPERATOR_SYNC_ADDR");
    let member_a_device_id = read::<DeviceId>("member-a.id").await?;
    let member_b_device_id = read::<DeviceId>("member-b.id").await?;
    let member_b_afc_addr = var::<Addr>("ARANYA_MEMBER_B_AFC_ADDR");

    let sync_interval = Duration::from_millis(100);
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let ctx = ClientCtx::new(&user, &daemon_path).await?;
    let team = ctx.client.team(team_id);

    match user.as_str() {
        "operator" => {
            let label = team
                .labels()
                .await
                .context("failed to get labels")?
                .iter()
                .next()
                .context("missing label")?
                .clone();
            debug!(?label.name);

            let op = ChanOp::SendRecv;
            info!("assigning label to membera");
            team.device(member_a_device_id)
                .assign_label(label.id, op)
                .await?;
            info!("assigning label to memberb");
            team.device(member_b_device_id)
                .assign_label(label.id, op)
                .await?;

            pending::<()>().await;
        }
        "member-a" => {
            team.add_sync_peer(operator_sync_addr?, sync_cfg).await?;

            let label = wait_for_assigned_label(team.device(member_a_device_id)).await?;
            info!(label.name = label.name.as_str(), %label.id, "found assigned label");

            info!("creating AFC channel");
            let (mut chan, ctrl) = ctx
                .client
                .afc()
                .create_channel(team_id, member_b_device_id, label.id)
                .await
                .context("Failed to create bidi channel")?;

            let stream = TcpStream::connect(member_b_afc_addr?.to_socket_addrs()).await?;

            let mut writer = BufWriter::new(stream);

            write_message(&mut writer, ctrl.as_bytes()).await?;
            info!("sent control message");

            let plaintext = "Hello to member B from member A!";
            let mut ciphertext = vec![0; plaintext.len() + aranya_client::afc::Channels::OVERHEAD];
            chan.seal(&mut ciphertext, plaintext.as_bytes())?;
            write_message(&mut writer, &ciphertext).await?;

            info!(plaintext, "sent data message");

            pending::<()>().await;
        }
        "member-b" => {
            team.add_sync_peer(operator_sync_addr?, sync_cfg).await?;

            let label = wait_for_assigned_label(team.device(member_b_device_id)).await?;
            info!(label.name = label.name.as_str(), %label.id, "found assigned label");

            let tcp = TcpListener::bind(member_b_afc_addr?.to_socket_addrs()).await?;
            let (stream, addr) = tcp.accept().await?;
            info!(%addr, "accepted stream");

            let mut reader = BufReader::new(stream);

            let ctrl = read_message(&mut reader).await?;
            let chan = ctx
                .client
                .afc()
                .accept_channel(team_id, ctrl.into())
                .await?;

            assert_eq!(label.id, chan.label_id());

            let data = read_message(&mut reader).await?;
            let mut plaintext = vec![0; data.len() - aranya_client::afc::Channels::OVERHEAD];
            chan.open(&mut plaintext, &data)?;

            let plaintext = str::from_utf8(&plaintext)?;

            info!(plaintext, "recv data message");

            info!("SUCCESS");
        }
        _ => bail!("unknown user {user:?}"),
    }

    Ok(())
}

async fn wait_for_assigned_label(device: Device<'_>) -> Result<Label> {
    loop {
        let assignments = device.label_assignments().await?;
        if let Some(label) = assignments.into_iter().next() {
            return Ok(label);
        }
        info!("waiting for assigned label to be available...");
        sleep(Duration::from_secs(1)).await;
    }
}

async fn write_message<W>(writer: &mut W, msg: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u16::try_from(msg.len()).context("ctrl too large")?;
    writer.write_u16(len).await?;
    writer.write_all(msg).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_message<R>(reader: &mut R) -> Result<Box<[u8]>>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u16().await?;
    let mut buf = vec![0; len.into()].into_boxed_slice();
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
