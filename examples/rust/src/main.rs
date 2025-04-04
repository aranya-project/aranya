use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use aranya_client::{afc::Message, client::Client, SyncPeerConfig};
use aranya_daemon::{
    config::{AfcConfig, Config},
    Daemon,
};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier, Role};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable};
use buggy::BugExt;
use tempfile::tempdir;
use tokio::{fs, task, time::sleep};
use tracing::{debug, info, Metadata};
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};
use aranya_client::Label;

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
    pub async fn new(team_name: String, name: String, work_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(work_dir.clone()).await?;

        // Setup daemon config.
        let uds_api_path = work_dir.join("uds.sock");
        let any = Addr::new("localhost", 0).expect("should be able to create new Addr");
        let afc_shm_path = format!("/afc_{}_{}", team_name, name).to_string();
        let max_chans = 100;
        let cfg = Config {
            name: "daemon".into(),
            work_dir: work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: work_dir.join("pid"),
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
                Path::new(&cfg.afc.shm_path),
                cfg.afc.max_chans,
                cfg.sync_addr.to_socket_addrs(),
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

    async fn afc_local_addr(&mut self) -> Result<SocketAddr> {
        Ok(self.client.afc().local_addr().await?)
    }
}

/// Repeatedly calls `poll_data`, followed by `handle_data`, until all of the
/// clients are pending.
// TODO(nikki): alternative to select!{} to resolve lifetime issues
macro_rules! do_poll {
    ($($client:expr),*) => {
        debug!(
            clients = stringify!($($client),*),
            "start `do_poll`",
        );
        loop {
            let mut afcs = [ $($client.afc()),* ];
            let mut afcs = afcs.iter_mut();
            tokio::select! {
                biased;
                $(data = afcs.next().assume("macro enforces client count")?.poll_data() => {
                    $client.afc().handle_data(data?).await?
                },)*
                _ = async {} => break,
            }
        }
        debug!(
            clients = stringify!($($client),*),
            "finish `do_poll`",
        );
    };
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

    let mut team = TeamCtx::new("test_afc_router".into(), work_dir).await?;

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

    // get afc addresses.
    let membera_afc_addr = team.membera.afc_local_addr().await?;
    let memberb_afc_addr = team.memberb.afc_local_addr().await?;

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

    // operator assigns labels for AFC channels.
    let label1 = Label::new(1);
    operator_team.create_label(label1).await?;
    operator_team.assign_label(team.membera.id, label1).await?;
    operator_team.assign_label(team.memberb.id, label1).await?;

    let label2 = Label::new(2);
    operator_team.create_label(label2).await?;
    operator_team.assign_label(team.membera.id, label2).await?;
    operator_team.assign_label(team.memberb.id, label2).await?;

    // assign network addresses.
    operator_team
        .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator_team
        .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;
    operator_team
        .assign_aqc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator_team
        .assign_aqc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
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
    let labels = queries.device_label_assignments(team.membera.id).await?;
    info!("membera labels: {:?}", labels.__data());
    let afc_net_identifier = queries.afc_net_identifier(team.membera.id).await?;
    info!("membera afc_net_identifer: {:?}", afc_net_identifier);
    let aqc_net_identifier = queries.aqc_net_identifier(team.membera.id).await?;
    info!("membera aqc_net_identifer: {:?}", aqc_net_identifier);
    let label_exists = queries.label_exists(label1).await?;
    info!("membera label1 exists?: {:?}", label_exists);

    info!("demo afc functionality");
    // membera creates bidi channel with memberb
    let afc_id1 = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
        .await?;

    // membera creates bidi channel with memberb
    let afc_id2 = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label2)
        .await?;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    do_poll!(team.membera.client, team.memberb.client);

    let msg = "hello world label1";
    team.membera
        .client
        .afc()
        .send_data(afc_id1, msg.as_bytes())
        .await?;
    debug!(?msg, "sent message");

    let msg = "hello world label2";
    team.membera
        .client
        .afc()
        .send_data(afc_id2, msg.as_bytes())
        .await?;
    debug!(?msg, "sent message");

    sleep(Duration::from_millis(100)).await;
    do_poll!(team.membera.client, team.memberb.client);

    let Some(Message { data, label, .. }) = team.memberb.client.afc().try_recv_data() else {
        bail!("no message available!")
    };
    debug!(
        n = data.len(),
        ?label,
        "received message: {:?}",
        core::str::from_utf8(&data)?
    );

    let Some(Message { data, label, .. }) = team.memberb.client.afc().try_recv_data() else {
        bail!("no message available!")
    };
    debug!(
        n = data.len(),
        ?label,
        "received message: {:?}",
        core::str::from_utf8(&data)?
    );

    info!("completed afc demo")

    info!("demo aqc functionality")
    let label3 = operator_team.create_aqc_label("label3".into_string()).await?;
    let op = ChanOp::ReadWrite;
    operator_team.assign_aqc_label(label3, team.membera.id, op).await?;
    operator_team.assign_aqc_label(label3, team.memberb.id, op).await?;
    
    // TODO: send AQC ctrl via network
    
    let (_aqc_id1, aqc_bidi_ctrl) = team.membera.client.aqc().create_bidi_channel(NetIdentifier(memberb_afc_addr.to_string()), label3).await?;
    team.memberb.client.aqc().receive_aqc_ctrl(aqc_bidi_ctrl).await?;
    
    // TODO: send AQC data.

    operator_team.revoke_aqc_label(team.membera.id, label3).await?;
    operator_team.revoke_aqc_label(team.memberb.id, label3).await?;
    operator_team.delete_aqc_label(label3).await?;

    info!("completed aqc demo")

    info!("completed example Aranya application");

    Ok(())
}
