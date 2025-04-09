//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]
#[cfg(feature = "afc")]
use std::path::Path;
use std::{fmt, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use aranya_client::client::Client;
#[cfg(feature = "afc")]
use aranya_client::SyncPeerConfig;
use aranya_crypto::{hash::Hash, rust::Sha256};
use aranya_daemon::{
    config::{AfcConfig, Config},
    Daemon,
};
use aranya_daemon_api::{DeviceId, KeyBundle, Role};
use aranya_util::addr::Addr;
use backon::{ExponentialBuilder, Retryable};
use spideroak_base58::ToBase58;
use tempfile::tempdir;
use test_log::test;
use tokio::{
    fs,
    task::{self, AbortHandle},
    time::{self, Sleep},
};
use tracing::{debug, info, instrument};

#[instrument(skip_all, fields(%duration = FmtDuration(d)))]
fn sleep(d: Duration) -> Sleep {
    debug!("sleeping");

    time::sleep(d)
}

/// Formats a [`Duration`].
///
/// It uses the same syntax as Go's `time.Duration`.
pub struct FmtDuration(Duration);

impl fmt::Display for FmtDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < Duration::ZERO {
            write!(f, "-")?;
        }
        // Same as
        //    let mut d self.0.abs_diff(Duration::ZERO);
        // but for MSRV <= 1.80.
        let mut d = if let Some(res) = self.0.checked_sub(Duration::ZERO) {
            res
        } else {
            Duration::ZERO.checked_sub(self.0).unwrap()
        };

        // Small number, format it with small units.
        if d < Duration::from_secs(1) {
            if d.is_zero() {
                return write!(f, "0s");
            }

            const MICROSECOND: u128 = 1000;
            const MILLISECOND: u128 = 1000 * MICROSECOND;

            // NB: the unwrap and error cases should never happen
            // since `d` is less than one second.
            let ns = d.as_nanos();
            if ns < MICROSECOND {
                return write!(f, "{ns}ns");
            }

            let (v, width, fmt) = if ns < MILLISECOND {
                (MICROSECOND, 3, "µs")
            } else {
                (MILLISECOND, 6, "ms")
            };

            let quo = ns / v;
            let rem = ns % v;
            write!(f, "{quo}")?;
            if rem > 0 {
                let (rem, width) = trim(rem, width);
                write!(f, ".{rem:0width$}")?;
            }
            return write!(f, "{fmt}");
        }

        let hours = d.as_secs() / 3600;
        if hours > 0 {
            write!(f, "{hours}h")?;
            d -= Duration::from_secs(hours * 3600);
        }

        let mins = d.as_secs() / 60;
        if mins > 0 {
            write!(f, "{mins}m")?;
            d -= Duration::from_secs(mins * 60);
        }

        let secs = d.as_secs();
        write!(f, "{secs}")?;
        d -= Duration::from_secs(secs);

        if !d.is_zero() {
            // NB: the unwrap and error cases should never happen
            // since `d` is less than one second.
            let (ns, width) = trim(d.as_nanos(), 9);
            write!(f, ".{ns:0width$}")?;
        }
        write!(f, "s")
    }
}

/// Trim up to `width` trailing zeros from `d`.
fn trim(mut d: u128, mut width: usize) -> (u128, usize) {
    while width > 0 {
        if d % 10 != 0 {
            break;
        }
        d /= 10;
        width -= 1;
    }
    (d, width)
}

/// Repeatedly calls `poll_data`, followed by `handle_data`, until all of the
/// clients are pending.
// TODO(nikki): alternative to select!{} to resolve lifetime issues
#[cfg(any())]
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

#[allow(dead_code)] // memberb is unused if AFC is disabled
struct TeamCtx {
    owner: DeviceCtx,
    admin: DeviceCtx,
    operator: DeviceCtx,
    membera: DeviceCtx,
    memberb: DeviceCtx,
}

impl TeamCtx {
    pub async fn new(name: String, work_dir: PathBuf) -> Result<Self> {
        let owner = DeviceCtx::new(name.clone(), "owner".into(), work_dir.join("owner")).await?;
        let admin = DeviceCtx::new(name.clone(), "admin".into(), work_dir.join("admin")).await?;
        let operator =
            DeviceCtx::new(name.clone(), "operator".into(), work_dir.join("operator")).await?;
        let membera =
            DeviceCtx::new(name.clone(), "membera".into(), work_dir.join("membera")).await?;
        let memberb =
            DeviceCtx::new(name.clone(), "memberb".into(), work_dir.join("memberb")).await?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
        })
    }
}

#[allow(dead_code)]
struct DeviceCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
    daemon: AbortHandle,
    cfg: Config,
}

fn get_shm_path(path: String) -> String {
    if cfg!(target_os = "macos") && path.len() > 31 {
        // Shrink the size of the team name down to 22 bytes
        // to work within macOS's limits.
        let d = Sha256::hash(path.as_bytes());
        let t: [u8; 16] = d[..16].try_into().unwrap();
        return format!("/{}", t.to_base58());
    };
    path
}

impl DeviceCtx {
    pub async fn new(team_name: String, name: String, work_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(work_dir.clone()).await?;

        #[allow(unused_variables)]
        let afc_shm_path = get_shm_path(format!("/{team_name}_{name}"));

        // Setup daemon config.
        let uds_api_path = work_dir.join("uds.sock");
        let max_chans = 100;
        let cfg = Config {
            name: "daemon".into(),
            work_dir: work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: work_dir.join("pid"),
            sync_addr: Addr::new("localhost", 0)?,
            afc: AfcConfig {
                shm_path: afc_shm_path.clone(),
                unlink_on_startup: true,
                unlink_at_exit: true,
                create: true,
                max_chans,
            },
        };
        // Load daemon from config.
        let daemon = Daemon::load(cfg.clone())
            .await
            .context("unable to init daemon")?;
        // Start daemon.
        let handle = task::spawn(async move {
            daemon
                .run()
                .await
                .expect("expected no errors running daemon")
        })
        .abort_handle();
        // give daemon time to setup UDS API.
        sleep(Duration::from_millis(100)).await;

        // Initialize the user library.
        let mut client = {
            #[cfg(feature = "afc")]
            {
                let mut client = (|| {
                    Client::connect(
                        &uds_api_path,
                        Path::new(&afc_shm_path),
                        max_chans,
                        "localhost:0",
                    )
                })
                .retry(ExponentialBuilder::default())
                .await
                .context("unable to init client")?;
                client.afc().set_name(name);
                client
            }
            #[cfg(not(feature = "afc"))]
            (|| Client::connect(&uds_api_path))
                .retry(ExponentialBuilder::default())
                .await
                .context("unable to init client")?
        };

        // Get device id and key bundle.
        let pk = client.get_key_bundle().await.expect("expected key bundle");
        let id = client.get_device_id().await.expect("expected device id");

        Ok(Self {
            client,
            pk,
            id,
            daemon: handle,
            cfg,
        })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }

    #[cfg(any())]
    async fn afc_local_addr(&mut self) -> Result<SocketAddr> {
        Ok(self.client.afc().local_addr().await?)
    }
}

impl Drop for DeviceCtx {
    fn drop(&mut self) {
        self.daemon.abort();
    }
}

/// Tests sync_now() by demonstrating that an admin cannot assign a role to a device until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_sync_now".into(), work_dir).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);

    // get sync addresses.
    let owner_addr = team.owner.aranya_local_addr().await?;

    // setup team handles.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk.clone()).await?;

    // add operator to team.
    info!("adding operator to team");
    owner_team
        .add_device_to_team(team.operator.pk.clone())
        .await?;

    // Assign role to Admin
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

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
    sleep(Duration::from_secs(1)).await;
    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    Ok(())
}

#[cfg(feature = "afc")]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_one_way_two_chans() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sync_config = SyncPeerConfig::builder().interval(interval).build()?;
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_afc_one_way_two_chans".into(), work_dir).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);
    // TODO: implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // get sync addresses.
    let owner_addr = team.owner.aranya_local_addr().await?;
    let admin_addr = team.admin.aranya_local_addr().await?;
    let operator_addr = team.operator.aranya_local_addr().await?;
    let membera_addr = team.membera.aranya_local_addr().await?;
    let memberb_addr = team.memberb.aranya_local_addr().await?;

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut membera_team = team.membera.client.team(team_id);
    let mut memberb_team = team.memberb.client.team(team_id);

    owner_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_config.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_config)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk.clone()).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team
        .add_device_to_team(team.operator.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team
        .add_device_to_team(team.membera.pk.clone())
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team
        .add_device_to_team(team.memberb.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    #[cfg(any())]
    {
        // get afc addresses.
        let membera_afc_addr = team.membera.afc_local_addr().await?;
        let memberb_afc_addr = team.memberb.afc_local_addr().await?;

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
        // TODO: use aqc addr
        operator_team
            .assign_aqc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
            .await?;
        operator_team
            .assign_aqc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
            .await?;
    }

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries = team.membera.client.queries(team_id);
    let devices = queries.devices_on_team().await?;
    assert_eq!(devices.iter().count(), 5);
    debug!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(team.membera.id).await?;
    assert_eq!(role, Role::Member);
    debug!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    debug!("membera keybundle: {:?}", keybundle);

    #[cfg(any())]
    {
        let aqc_net_identifier = queries
            .aqc_net_identifier(team.membera.id)
            .await?
            .expect("expected net identifier");
        assert_eq!(
            aqc_net_identifier,
            NetIdentifier(membera_afc_addr.to_string())
        );

        let labels = queries.device_label_assignments(team.membera.id).await?;
        assert_eq!(labels.iter().count(), 2);
        debug!("membera labels: {:?}", labels.__data());

        let afc_net_identifier = queries
            .afc_net_identifier(team.membera.id)
            .await?
            .expect("expected net identifier");
        assert_eq!(
            afc_net_identifier,
            NetIdentifier(membera_afc_addr.to_string())
        );
        debug!("membera afc_net_identifer: {:?}", afc_net_identifier);

        debug!("membera aqc_net_identifer: {:?}", aqc_net_identifier);
        let label_exists = queries.label_exists(label1).await?;
        assert!(label_exists);
        debug!("membera label1 exists?: {:?}", label_exists);

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

        let msgs = ["hello world label1", "hello world label2"];

        team.membera
            .client
            .afc()
            .send_data(afc_id1, msgs[0].as_bytes())
            .await?;
        debug!(msg = msgs[0], "sent message");

        team.membera
            .client
            .afc()
            .send_data(afc_id2, msgs[1].as_bytes())
            .await?;
        debug!(msg = msgs[1], "sent message");

        sleep(sleep_interval).await;
        do_poll!(team.membera.client, team.memberb.client);

        let got = team
            .memberb
            .client
            .afc()
            .try_recv_data()
            .expect("should have a message");
        let want = Message {
            data: msgs[0].as_bytes().to_vec(),
            // We don't know the address of outgoing connections, so
            // assume `got.addr` is correct here.
            address: got.address,
            channel: afc_id1,
            label: label1,
            seq: Seq::ZERO,
        };
        assert_eq!(got, want);

        let got = team
            .memberb
            .client
            .afc()
            .try_recv_data()
            .expect("should have a message");
        let want = Message {
            data: msgs[1].as_bytes().to_vec(),
            // We don't know the address of outgoing connections, so
            // assume `got.addr` is correct here.
            address: got.address,
            channel: afc_id2,
            label: label2,
            seq: Seq::ZERO,
        };
        assert_eq!(got, want);
    }

    Ok(())
}

/// Tests AFC two way communication within one channel.
#[cfg(feature = "afc")]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_two_way_one_chan() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sync_config = SyncPeerConfig::builder().interval(interval).build()?;
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_afc_two_way_one_chan".into(), work_dir).await?;

    // create team.
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

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut membera_team = team.membera.client.team(team_id);
    let mut memberb_team = team.memberb.client.team(team_id);

    owner_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_config.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_config)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk.clone()).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team
        .add_device_to_team(team.operator.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team
        .add_device_to_team(team.membera.pk.clone())
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team
        .add_device_to_team(team.memberb.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // ==== BASIC SETUP DONE ====

    // operator assigns labels for AFC channels.
    #[cfg(any())]
    {
        // get afc addresses.
        let membera_afc_addr = team.membera.afc_local_addr().await?;
        let memberb_afc_addr = team.memberb.afc_local_addr().await?;

        let label1 = Label::new(1);
        operator_team.create_label(label1).await?;
        operator_team.assign_label(team.membera.id, label1).await?;
        operator_team.assign_label(team.memberb.id, label1).await?;

        // assign network addresses.
        operator_team
            .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
            .await?;
        operator_team
            .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
            .await?;

        // wait for syncing.
        sleep(sleep_interval).await;

        // membera creates bidi channel with memberb
        let afc_id1 = team
            .membera
            .client
            .afc()
            .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
            .await?;

        let msg = "a to b";
        team.membera
            .client
            .afc()
            .send_data(afc_id1, msg.as_bytes())
            .await?;
        debug!(msg = msg, "sent message");

        do_poll!(team.membera.client, team.memberb.client);

        let got = team
            .memberb
            .client
            .afc()
            .try_recv_data()
            .expect("should have a message");
        let want = Message {
            data: msg.as_bytes().to_vec(),
            // We don't know the address of outgoing connections, so
            // assume `got.addr` is correct here.
            address: got.address,
            channel: afc_id1,
            label: label1,
            seq: Seq::ZERO,
        };
        assert_eq!(got, want, "a->b");

        let msg = "b to a";
        team.memberb
            .client
            .afc()
            .send_data(afc_id1, msg.as_bytes())
            .await?;
        debug!(msg, "sent message");

        sleep(Duration::from_secs(1)).await;
        do_poll!(team.membera.client, team.memberb.client);

        let want = Message {
            data: msg.as_bytes().to_vec(),
            address: memberb_afc_addr,
            channel: afc_id1,
            label: label1,
            seq: Seq::ZERO,
        };
        let got = team
            .membera
            .client
            .afc()
            .try_recv_data()
            .expect("should have a message");
        assert_eq!(got, want, "b->a");
    }

    Ok(())
}

/// A positive test that sequence numbers are monotonic.
#[cfg(feature = "afc")]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_monotonic_seq() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sync_config = SyncPeerConfig::builder().interval(interval).build()?;
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_afc_monotonic_seq".into(), work_dir).await?;

    // create team.
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

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut membera_team = team.membera.client.team(team_id);
    let mut memberb_team = team.memberb.client.team(team_id);

    owner_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_config.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_config)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk.clone()).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team
        .add_device_to_team(team.operator.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team
        .add_device_to_team(team.membera.pk.clone())
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team
        .add_device_to_team(team.memberb.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // ==== BASIC SETUP DONE ====

    #[cfg(any())]
    {
        // get afc addresses.
        let membera_afc_addr = team.membera.afc_local_addr().await?;
        let memberb_afc_addr = team.memberb.afc_local_addr().await?;

        // operator assigns labels for AFC channels.
        let label1 = Label::new(1);
        operator_team.create_label(label1).await?;
        operator_team.assign_label(team.membera.id, label1).await?;
        operator_team.assign_label(team.memberb.id, label1).await?;

        // assign network addresses.
        operator_team
            .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
            .await?;
        operator_team
            .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
            .await?;

        // wait for syncing.
        sleep(sleep_interval).await;

        // membera creates bidi channel with memberb
        let afc_id1 = team
            .membera
            .client
            .afc()
            .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label1)
            .await?;

        for i in 0..10u64 {
            let seq = Seq::new(i);

            let msg = format!("ping {i}");
            team.membera
                .client
                .afc()
                .send_data(afc_id1, msg.as_bytes())
                .await?;
            debug!(msg = msg, "sent message");

            sleep(Duration::from_secs(1)).await;
            do_poll!(team.membera.client, team.memberb.client);
            do_poll!(team.membera.client, team.memberb.client);

            let got = team
                .memberb
                .client
                .afc()
                .try_recv_data()
                .expect("should have a message");
            let want = Message {
                data: msg.into(),
                // We don't know the address of outgoing connections,
                // so assume `got.addr` is correct here.
                address: got.address,
                channel: afc_id1,
                label: label1,
                seq,
            };
            assert_eq!(got, want, "a->b");

            let msg = format!("pong {i}");
            team.memberb
                .client
                .afc()
                .send_data(afc_id1, msg.as_bytes())
                .await?;
            debug!(msg, "sent message");

            sleep(Duration::from_secs(1)).await;
            do_poll!(team.membera.client, team.memberb.client);
            do_poll!(team.membera.client, team.memberb.client);

            let want = Message {
                data: msg.into(),
                address: memberb_afc_addr,
                channel: afc_id1,
                label: label1,
                seq,
            };
            let got = team
                .membera
                .client
                .afc()
                .try_recv_data()
                .expect("should have a message");
            assert_eq!(got, want, "b->a");
        }
    }

    Ok(())
}

/// This tests a bug where if the daemon is killed after registering net identifiers, they're not
/// reloaded upon reboot, which causes create_bidi_channel to fail with "unable to lookup peer".
#[cfg(feature = "afc")]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_afc_persist_net_identifier() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sync_config = SyncPeerConfig::builder().interval(interval).build()?;
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_afc_persist_net_identifier".into(), work_dir.clone()).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);
    // TODO: implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

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

    owner_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_config.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk.clone()).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team
        .add_device_to_team(team.operator.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team
        .add_device_to_team(team.membera.pk.clone())
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team
        .add_device_to_team(team.memberb.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // operator assigns labels for AFC channels.
    let label = Label::new(1);
    operator_team.create_label(label).await?;
    operator_team.assign_label(team.membera.id, label).await?;
    operator_team.assign_label(team.memberb.id, label).await?;

    // assign network addresses.
    operator_team
        .assign_afc_net_identifier(team.membera.id, NetIdentifier(membera_afc_addr.to_string()))
        .await?;
    operator_team
        .assign_afc_net_identifier(team.memberb.id, NetIdentifier(memberb_afc_addr.to_string()))
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // Kill the team, and reload it, to simulate the bug.
    drop(team.membera);
    team.membera = DeviceCtx::new(
        "test_afc_persist_net_identifier".into(),
        "membera".into(),
        work_dir.join("membera"),
    )
    .await?;

    // Create a new channel, which should fail to lookup peer if we haven't re-populated afc_peers.
    let _ = team
        .membera
        .client
        .afc()
        .create_bidi_channel(team_id, NetIdentifier(memberb_afc_addr.to_string()), label)
        .await?;

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    Ok(())
}
