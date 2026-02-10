use std::{
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result};
#[cfg(feature = "preview")]
use aranya_client::HelloSubscriptionConfig;
use aranya_client::{
    afc,
    client::{ChanOp, Client, DeviceId, KeyBundle},
    text, AddTeamConfig, AddTeamQuicSyncConfig, Addr, CreateTeamConfig, CreateTeamQuicSyncConfig,
    ObjectId, Permission, Rank, SyncPeerConfig,
};
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
            _work_dir: work_dir,
            _daemon: daemon,
        })
    }

    async fn aranya_local_addr(&self) -> Result<Addr> {
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
    let sync_cfg = {
        let mut builder = SyncPeerConfig::builder();
        builder = builder.interval(sync_interval);
        #[cfg(feature = "preview")]
        {
            builder = builder.sync_on_hello(true);
        }
        builder.build()?
    };

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

    // Create a team.
    info!("creating team");
    let owner_team = owner
        .client
        .create_team(owner_cfg)
        .await
        .context("expected to create team")?;
    let team_id = owner_team.team_id();
    info!(%team_id);

    // Create default roles
    info!("creating default roles");
    owner
        .client
        .team(team_id)
        .roles()
        .await?
        .into_iter()
        .find(|role| role.name == "owner" && role.default)
        .context("unable to find owner role")?;
    let roles = owner_team.setup_default_roles_no_owning_role().await?;
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
    owner_team
        .add_device_with_rank(admin.pk, Some(admin_role.id), Rank::new(100))
        .await?;

    info!("adding operator to team");
    owner_team
        .add_device_with_rank(operator.pk, Some(operator_role.id), Rank::new(100))
        .await?;

    // Demo hello subscription functionality
    #[cfg(feature = "preview")]
    {
        info!("demonstrating hello subscription");

        // Admin subscribes to hello notifications from Owner
        info!("admin subscribing to hello notifications from owner");
        admin_team
            .sync_hello_subscribe(owner_addr, HelloSubscriptionConfig::default())
            .await?;

        // Operator subscribes to hello notifications from Admin
        info!("operator subscribing to hello notifications from admin");
        operator_team
            .sync_hello_subscribe(admin_addr, HelloSubscriptionConfig::default())
            .await?;

        sleep(sleep_interval).await;

        // Later, unsubscribe from hello notifications
        info!("admin unsubscribing from hello notifications from owner");
        admin_team.sync_hello_unsubscribe(owner_addr).await?;

        info!("operator unsubscribing from hello notifications from admin");
        operator_team.sync_hello_unsubscribe(admin_addr).await?;

        sleep(sleep_interval).await;
    }

    info!("adding sync peers");
    owner_team
        .add_sync_peer(admin_addr, sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr, sync_cfg.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr, sync_cfg.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr, sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr, sync_cfg.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr, sync_cfg.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr, sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr, sync_cfg.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr, sync_cfg.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr, sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr, sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr, sync_cfg.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr, sync_cfg.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr, sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr, sync_cfg.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr, sync_cfg.clone())
        .await?;
    memberb_team.add_sync_peer(membera_addr, sync_cfg).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    owner_team
        .add_device_with_rank(membera.pk.clone(), Some(member_role.id), Rank::new(100))
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    owner_team
        .add_device_with_rank(memberb.pk.clone(), Some(member_role.id), Rank::new(100))
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Demo custom roles.
    info!("demo custom roles functionality");

    // Create a custom role.
    info!("creating a custom role");
    let custom = ClientCtx::new(team_name, "custom", &daemon_path).await?;
    let custom_role_rank = Rank::new(50);
    let custom_role = owner_team
        .create_role(text!("custom_role"), custom_role_rank)
        .await?;

    // Add device to team to assign custom role to.
    info!("adding device to team to assign custom role to");
    owner_team
        .add_device_with_rank(custom.pk.clone(), None, custom_role_rank)
        .await?;

    // Add `CanUseAfc` permission to the custom role.
    owner_team
        .add_perm_to_role(custom_role.id, Permission::CanUseAfc)
        .await?;

    // Assign custom role to a device.
    info!("assigning custom role to a device");
    owner_team
        .device(custom.id)
        .assign_role(custom_role.id)
        .await?;

    // Demo change_rank/query_rank: verify the role has the rank it was created with,
    // then change it.
    let role_object_id: ObjectId = custom_role.id.into();
    let current_rank = owner_team.query_rank(role_object_id).await?;
    info!("custom role rank before change: {}", current_rank);
    assert_eq!(current_rank, custom_role_rank);

    let updated_role_rank = Rank::new(75);
    info!("changing custom role rank from {} to {}", custom_role_rank, updated_role_rank);
    owner_team
        .change_rank(role_object_id, custom_role_rank, updated_role_rank)
        .await?;

    let new_rank = owner_team.query_rank(role_object_id).await?;
    info!("custom role rank after change: {}", new_rank);
    assert_eq!(new_rank, updated_role_rank);

    // Revoke custom role from a device.
    info!("revoking custom role from a device");
    owner_team
        .device(custom.id)
        .revoke_role(custom_role.id)
        .await?;

    // Remove `CanUseAfc` permission from the custom role.
    info!("removing CanUseAfc permission from custom role");
    owner_team
        .remove_perm_from_role(custom_role.id, Permission::CanUseAfc)
        .await?;

    // Delete the custom role.
    info!("deleting custom role from team");
    owner_team.delete_role(custom_role.id).await?;

    // fact database queries
    let devices = membera_team.devices().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let owner_device = owner_team.device(owner.id);
    let owner_role = owner_device.role().await?.expect("expected owner role");
    info!("owner role: {:?}", owner_role);
    let keybundle = owner_device.keybundle().await?;
    info!("owner keybundle: {:?}", keybundle);

    info!("creating label");
    let label3 = owner_team
        .create_label_with_rank(text!("label3"), Rank::new(100))
        .await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    owner_team
        .device(membera.id)
        .assign_label(label3, op)
        .await?;
    info!("assigning label to memberb");
    owner_team
        .device(memberb.id)
        .assign_label(label3, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Demo AFC.
    info!("demo afc functionality");

    // membera creates AFC channel.
    info!("creating afc send channel");
    let membera_afc = membera.client.afc();
    let (mut send, ctrl) = membera_afc
        .create_channel(team_id, memberb.id, label3)
        .await
        .expect("expected to create afc send channel");
    info!("created afc channel: {}", send.id());

    // memberb receives AFC channel.
    info!("receiving afc recv channel");
    let memberb_afc = memberb.client.afc();
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
    owner_team.device(membera.id).revoke_label(label3).await?;
    info!("revoking label from memberb");
    owner_team.device(memberb.id).revoke_label(label3).await?;
    info!("deleting label");
    owner_team.delete_label(label3).await?;

    info!("completed example Aranya application");

    Ok(())
}
