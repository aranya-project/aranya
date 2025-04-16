use std::{
    net::SocketAddr,
    net::Ipv4Addr,
    path::PathBuf,
    time::Duration,
};
use aranya_daemon_api::ChanOp;
use anyhow::{bail, Context as _, Result};
use aranya_client::{client::Client, SyncPeerConfig};
use aranya_daemon::{
    config::{AfcConfig, Config},
    Daemon,
};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use tempfile::tempdir;
use tokio::{fs, task, time::sleep};
use tracing::{info, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};

struct TeamCtx {
    owner: UserCtx,
    admin: UserCtx,
    operator: UserCtx,
    membera: UserCtx,
    memberb: UserCtx,
}

impl TeamCtx {
    pub async fn new(name: String, daemon_work_dir: PathBuf, client_work_dir: PathBuf) -> Result<Self> {
        let owner = UserCtx::new(name.clone(), "owner".into(), daemon_work_dir.join("owner"), client_work_dir.join("owner")).await?;
        let admin = UserCtx::new(name.clone(), "admin".into(), daemon_work_dir.join("admin"), client_work_dir.join("admin")).await?;
        let operator =
            UserCtx::new(name.clone(), "operator".into(), daemon_work_dir.join("operator"), client_work_dir.join("operator")).await?;
        let membera =
            UserCtx::new(name.clone(), "membera".into(), daemon_work_dir.join("membera"), client_work_dir.join("membera")).await?;
        let memberb =
            UserCtx::new(name.clone(), "memberb".into(), daemon_work_dir.join("memberb"), client_work_dir.join("memberb")).await?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
        })
    }
}

struct UserCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
}

impl UserCtx {
    pub async fn new(team_name: String, name: String, daemon_work_dir: PathBuf, client_work_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(daemon_work_dir.clone()).await?;

        // Setup daemon config.
        let uds_api_path = daemon_work_dir.join("uds.sock");
        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let afc_shm_path = format!("/afc_{}_{}", team_name, name).to_string();
        let max_chans = 100;
        let cfg = Config {
            name: "daemon".into(),
            work_dir: daemon_work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: daemon_work_dir.join("pid"),
            sync_addr: any,
            afc: AfcConfig {
                shm_path: afc_shm_path.clone(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans,
            },
        };
        // Load daemon from config.
        // TODO: start daemons from binary rather than objects.
        let daemon = Daemon::load(cfg.clone())
            .await
            .context("unable to init daemon")?;
        // Start daemon.
        task::spawn(async move {
            daemon
                .run()
                .await
                .expect("expected no errors running daemon")
        });
        // give daemon time to setup UDS API.
        sleep(Duration::from_millis(100)).await;

        // Initialize the user library.
        let mut client = (|| {
            Client::connect(
                &cfg.uds_api_path,
                &client_work_dir,
            )
        })
        .retry(ExponentialBuilder::default())
        .await
        .context("unable to initialize client")?;

        // Get device id and key bundle.
        let pk = client.get_key_bundle().await.expect("expected key bundle");
        let id = client.get_device_id().await.expect("expected device id");

        Ok(Self { client, pk, id })
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

    let sync_interval = Duration::from_millis(100);
    let sleep_interval = sync_interval * 6;
    let sync_cfg = SyncPeerConfig::builder().interval(sync_interval).build()?;

    let daemon_tmp = tempdir()?;
    let daemon_work_dir = daemon_tmp.path().to_path_buf();
    let client_tmp = tempdir()?;
    let client_work_dir = client_tmp.path().to_path_buf();

    let mut team = TeamCtx::new("rust_example".into(), daemon_work_dir, client_work_dir).await?;

    // create team.
    info!("creating team");
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    // get sync addresses.
    let owner_addr = team.owner.aranya_local_addr().await?;
    let admin_addr = team.admin.aranya_local_addr().await?;
    let operator_addr = team.operator.aranya_local_addr().await?;
    let membera_addr = team.membera.aranya_local_addr().await?;
    let memberb_addr = team.memberb.aranya_local_addr().await?;

    // get aqc addresses.
    // TODO: use aqc_local_addr()
    let membera_aqc_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let memberb_aqc_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut membera_team = team.membera.client.team(team_id);
    let mut memberb_team = team.memberb.client.team(team_id);

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team.add_device_to_team(team.operator.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Admin tries to assign a role
    match admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await
    {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Daemon(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Admin syncs with the Owner peer and retries the role
    // assignment command
    admin_team.sync_now(owner_addr.into(), None).await?;
    sleep(sleep_interval).await;
    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

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
    operator_team.add_device_to_team(team.membera.pk).await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team.add_device_to_team(team.memberb.pk).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("assigning aqc net identifiers");
    operator_team
        .assign_aqc_net_identifier(team.membera.id, NetIdentifier(membera_aqc_addr.to_string()))
        .await?;
    operator_team
        .assign_aqc_net_identifier(team.memberb.id, NetIdentifier(memberb_aqc_addr.to_string()))
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries = team.membera.client.queries(team_id);
    let devices = queries.devices_on_team().await?;
    info!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(team.membera.id).await?;
    info!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    info!("membera keybundle: {:?}", keybundle);
    let queried_membera_net_ident = queries.aqc_net_identifier(team.membera.id).await?;
    info!("membera queried_membera_net_ident: {:?}", queried_membera_net_ident);
    let queried_memberb_net_ident = queries.aqc_net_identifier(team.memberb.id).await?;
    info!("memberb queried_memberb_net_ident: {:?}", queried_memberb_net_ident);

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("demo aqc functionality");
    info!("creating aqc label");
    let label3 = operator_team.create_label("label3".to_string()).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team.assign_label(team.membera.id, label3, op).await?;
    info!("assigning label to memberb");
    operator_team.assign_label(team.memberb.id, label3, op).await?;
    
    // wait for syncing.
    sleep(sleep_interval).await;

    // TODO: send AQC ctrl via network
    info!("creating acq bidi channel");
    let (_aqc_id1, aqc_bidi_ctrl) = team.membera.client.aqc().create_bidi_channel(team_id, NetIdentifier(memberb_aqc_addr.to_string()), label3).await?;
    info!("receiving acq bidi channel");
    team.memberb.client.aqc().receive_aqc_ctrl(team_id, aqc_bidi_ctrl).await?;
    
    // TODO: send AQC data.
    info!("revoking label from membera");
    operator_team.revoke_label(team.membera.id, label3).await?;
    info!("revoking label from memberb");
    operator_team.revoke_label(team.memberb.id, label3).await?;
    info!("deleting label");
    operator_team.delete_label(label3).await?;

    info!("completed aqc demo");

    info!("completed example Aranya application");

    Ok(())
}
