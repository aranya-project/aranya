use aranya_daemon_api::ChanOp;
use anyhow::{Context as _, Result};
use aranya_client::{DEFAULT_CMDS, client::Client, SyncPeerConfig, TeamConfig};
use aranya_daemon::{
    config::Config,
    Daemon,
};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use std::{net::Ipv4Addr, net::SocketAddr, path::PathBuf, time::Duration};
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
    pub async fn new(name: String, work_dir: PathBuf) -> Result<Self> {
        let owner = UserCtx::new(name.clone(), "owner".into(), work_dir.join("owner")).await?;
        let admin = UserCtx::new(name.clone(), "admin".into(), work_dir.join("admin")).await?;
        let operator =
            UserCtx::new(name.clone(), "operator".into(), work_dir.join("operator")).await?;
        let membera =
            UserCtx::new(name.clone(), "membera".into(), work_dir.join("membera")).await?;
        let memberb =
            UserCtx::new(name.clone(), "memberb".into(), work_dir.join("memberb")).await?;

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
    pub async fn new(_team_name: String, _name: String, work_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(work_dir.clone()).await?;

        // Setup daemon config.
        let uds_api_path = work_dir.join("uds.sock");
        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let cfg = Config {
            name: "daemon".into(),
            work_dir: work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: work_dir.join("pid"),
            sync_addr: any,
            afc: None,
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
        let mut client = (|| Client::connect(&cfg.uds_api_path))
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

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("rust_example".into(), work_dir).await?;

    // create team.
    info!("creating team");
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
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

    let admin_role = owner_team.create_role("admin".into()).await?;
    let operator_role = owner_team.create_role("operator".into()).await?;
    let member_role = owner_team.create_role("member".into()).await?;

    let role_list = [&admin_role, &operator_role, &member_role];
    for (perm, role_name) in DEFAULT_CMDS.iter() {
        for role in &role_list {
            if *role_name == role.name {
                owner_team
                    .assign_role_cmd(role.id, perm.to_string())
                    .await?;
            }
        }
    }

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk, 9000).await?;
    owner_team.assign_role(team.admin.id, admin_role.id).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team.add_device_to_team(team.operator.pk, 8000).await?;

    // Admin syncs with the Owner peer and retries the role
    // assignment command
    admin_team.sync_now(owner_addr.into(), None).await?;
    sleep(sleep_interval).await;
    owner_team
        .assign_role(team.operator.id, operator_role.id)
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
    owner_team.add_device_to_team(team.membera.pk, 7000).await?;
    owner_team
        .assign_role(team.membera.id, member_role.id)
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    owner_team.add_device_to_team(team.memberb.pk, 7000).await?;
    owner_team
        .assign_role(team.memberb.id, member_role.id)
        .await?;

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
    let mut queries = team.owner.client.queries(team_id);
    info!("query list of devices on team:");
    let devices = queries.devices_on_team().await?;
    for device in devices.iter() {
        info!("device: {}", device);
    }
    info!("query list of roles on team:");
    let roles = queries.roles_on_team().await?;
    for role in roles.iter() {
        info!("role: {:?}", role);
    }
    info!("membera devices on team: {:?}", devices.iter().count());
    for device in devices.iter() {
        info!("querying roles assigned to device: {}", device);
        let roles = queries.device_roles(*device).await?;
        for role in roles.iter() {
            info!("role: {:?}, device: {}", role, device);
        }
    }
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    info!("membera keybundle: {:?}", keybundle);
    let queried_membera_net_ident = queries.aqc_net_identifier(team.membera.id).await?;
    info!(
        "membera queried_membera_net_ident: {:?}",
        queried_membera_net_ident
    );
    let queried_memberb_net_ident = queries.aqc_net_identifier(team.memberb.id).await?;
    info!(
        "memberb queried_memberb_net_ident: {:?}",
        queried_memberb_net_ident
    );

    // wait for syncing.
    sleep(sleep_interval).await;

    info!("demo aqc functionality");
    info!("creating aqc label");
    let label3 = operator_team.create_label("label3".to_string()).await?;
    let op = ChanOp::SendRecv;
    info!("assigning label to membera");
    operator_team
        .assign_label(team.membera.id, label3, op)
        .await?;
    info!("assigning label to memberb");
    operator_team
        .assign_label(team.memberb.id, label3, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // TODO: send AQC ctrl via network
    info!("creating acq bidi channel");
    let (_aqc_id1, aqc_bidi_ctrl) = team
        .membera
        .client
        .aqc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_aqc_addr.to_string()), label3)
        .await?;
    info!("receiving acq bidi channel");
    team.memberb
        .client
        .aqc()
        .receive_aqc_ctrl(team_id, aqc_bidi_ctrl)
        .await?;

    // TODO: send AQC data.
    info!("revoking label from membera");
    operator_team.revoke_label(team.membera.id, label3).await?;
    info!("revoking label from memberb");
    operator_team.revoke_label(team.memberb.id, label3).await?;
    info!("deleting label");
    admin_team.delete_label(label3).await?;

    info!("completed aqc demo");

    info!("completed example Aranya application");

    Ok(())
}
