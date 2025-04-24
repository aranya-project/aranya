//! Integration tests for the user library.

#![allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    rust_2018_idioms
)]

use std::{fmt, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use aranya_client::{Client, SyncPeerConfig, TeamConfig};
use aranya_daemon::{
    config::{AqcConfig, Config},
    Daemon,
};
use aranya_daemon_api::{DeviceId, KeyBundle, Role, TeamId};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use test_log::test;
use tokio::{
    fs,
    task::{self, AbortHandle},
    time::{self, Sleep},
};
use tracing::{debug, info, instrument};

const SYNC_INTERVAL: Duration = Duration::from_millis(100);
// Allow for one missed sync and a misaligned sync rate, while keeping run times low.
const SLEEP_INTERVAL: Duration = Duration::from_millis(250);

#[instrument(skip_all, fields(%duration = FmtDuration(d)))]
fn sleep(d: Duration) -> Sleep {
    debug!("sleeping");

    time::sleep(d)
}

/// Formats a [`Duration`], using the same syntax as Go's `time.Duration`.
struct FmtDuration(Duration);

impl fmt::Display for FmtDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < Duration::ZERO {
            write!(f, "-")?;
        }

        let mut d = self.0.abs_diff(Duration::ZERO);

        // Small number, format it with small units.
        if d < Duration::from_secs(1) {
            if d.is_zero() {
                return write!(f, "0s");
            }

            const MICROSECOND: u128 = 1000;
            const MILLISECOND: u128 = 1000 * MICROSECOND;

            // NB: the unwrap and error cases should never happen since `d` is less than one second.
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
            // NB: the unwrap and error cases should never happen since `d` is less than one second.
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

struct TeamCtx {
    owner: DeviceCtx,
    admin: DeviceCtx,
    operator: DeviceCtx,
    membera: DeviceCtx,
    memberb: DeviceCtx,
}

impl TeamCtx {
    async fn new(name: &str, work_dir: PathBuf) -> Result<Self> {
        let owner = DeviceCtx::new(name, "owner", work_dir.join("owner")).await?;
        let admin = DeviceCtx::new(name, "admin", work_dir.join("admin")).await?;
        let operator = DeviceCtx::new(name, "operator", work_dir.join("operator")).await?;
        let membera = DeviceCtx::new(name, "membera", work_dir.join("membera")).await?;
        let memberb = DeviceCtx::new(name, "memberb", work_dir.join("memberb")).await?;

        Ok(Self {
            owner,
            admin,
            operator,
            membera,
            memberb,
        })
    }

    fn devices(&mut self) -> [&mut DeviceCtx; 5] {
        [
            &mut self.owner,
            &mut self.admin,
            &mut self.operator,
            &mut self.membera,
            &mut self.memberb,
        ]
    }

    async fn add_all_sync_peers(&mut self, team_id: TeamId) -> Result<()> {
        let config = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
        let mut devices = self.devices();
        for i in 0..devices.len() {
            let (device, peers) = devices[i..].split_first_mut().unwrap();
            for peer in peers {
                device
                    .client
                    .team(team_id)
                    .add_sync_peer(peer.aranya_local_addr().await?.into(), config.clone())
                    .await?;
                peer.client
                    .team(team_id)
                    .add_sync_peer(device.aranya_local_addr().await?.into(), config.clone())
                    .await?;
            }
        }
        Ok(())
    }

    async fn add_all_device_roles(&mut self, team_id: TeamId) -> Result<()> {
        // Shorthand for the teams we need to operate on.
        let mut owner_team = self.owner.client.team(team_id);
        let mut admin_team = self.admin.client.team(team_id);
        let mut operator_team = self.operator.client.team(team_id);

        // Add the admin as a new device, and assign its role.
        info!("adding admin to team");
        owner_team.add_device_to_team(self.admin.pk.clone()).await?;
        owner_team.assign_role(self.admin.id, Role::Admin).await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner_team
            .add_device_to_team(self.operator.pk.clone())
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Assign the operator its role.
        admin_team
            .assign_role(self.operator.id, Role::Operator)
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Add member A as a new device.
        info!("adding membera to team");
        operator_team
            .add_device_to_team(self.membera.pk.clone())
            .await?;

        // Add member A as a new device.
        info!("adding memberb to team");
        operator_team
            .add_device_to_team(self.memberb.pk.clone())
            .await?;

        // Make sure they see the configuration change.
        sleep(SLEEP_INTERVAL).await;

        Ok(())
    }
}

struct DeviceCtx {
    client: Client,
    pk: KeyBundle,
    id: DeviceId,
    daemon: AbortHandle,
}

impl DeviceCtx {
    async fn new(_team_name: &str, _name: &str, work_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(work_dir.clone()).await?;

        // Setup daemon config.
        let uds_api_path = work_dir.join("uds.sock");
        let cfg = Config {
            name: "daemon".into(),
            work_dir: work_dir.clone(),
            uds_api_path: uds_api_path.clone(),
            pid_file: work_dir.join("pid"),
            sync_addr: Addr::new("localhost", 0)?,
            afc: None,
            aqc: None,
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
        sleep(SLEEP_INTERVAL).await;

        let pk_path = cfg.daemon_api_pk_path();
        let pk = (|| Daemon::load_api_pk(&pk_path))
            .retry(ExponentialBuilder::default())
            .await
            .context("unable to find `ApiKeyId`")?;

        // Initialize the user library.
        let mut client = (|| {
            Client::builder()
                .with_daemon_api_pk(&pk)
                .with_daemon_uds_path(&uds_api_path)
                .connect()
        })
        .retry(ExponentialBuilder::default())
        .await
        .context("unable to init client")?;

        // Get device id and key bundle.
        let pk = client.get_key_bundle().await.expect("expected key bundle");
        let id = client.get_device_id().await.expect("expected device id");

        Ok(Self {
            client,
            pk,
            id,
            daemon: handle,
        })
    }

    async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }
}

impl Drop for DeviceCtx {
    fn drop(&mut self) {
        self.daemon.abort();
    }
}

/// Tests sync_now() by showing that an admin cannot assign any roles until it syncs with the owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_now() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_sync_now", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // TODO(geoff): implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another.
    team.add_all_sync_peers(team_id).await?;

    // Grab the shorthand for our address.
    let owner_addr = team.owner.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut owner = team.owner.client.team(team_id);
    let mut admin = team.admin.client.team(team_id);

    // Add the admin as a new device, but don't give it a role.
    info!("adding admin to team");
    owner.add_device_to_team(team.admin.pk.clone()).await?;

    // Add the operator as a new device, but don't give it a role.
    info!("adding operator to team");
    owner.add_device_to_team(team.operator.pk.clone()).await?;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner.assign_role(team.admin.id, Role::Admin).await?;

    // Now, we try to assign a role using the admin, which is expected to fail.
    match admin.assign_role(team.operator.id, Role::Operator).await {
        Ok(_) => bail!("Expected role assignment to fail"),
        Err(aranya_client::Error::Aranya(_)) => {}
        Err(_) => bail!("Unexpected error"),
    }

    // Let's sync immediately, which will propagate the role change.
    admin.sync_now(owner_addr.into(), None).await?;
    sleep(SLEEP_INTERVAL).await;

    // Now we should be able to successfully assign a role.
    admin.assign_role(team.operator.id, Role::Operator).await?;

    Ok(())
}

/// Tests functionality to make sure that we can query the fact database for various things.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_query_functions() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_query_functions", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    /*
     * TODO(geoff): implement this
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // Test all our fact database queries.
    let mut queries = team.membera.client.queries(team_id);

    // First, let's check how many devices are on the team.
    let devices = queries.devices_on_team().await?;
    assert_eq!(devices.iter().count(), 5);
    debug!("membera devices on team: {:?}", devices.iter().count());

    // Check the specific role(s) a device has.
    let role = queries.device_role(team.membera.id).await?;
    assert_eq!(role, Role::Member);
    debug!("membera role: {:?}", role);

    // Make sure that we have the correct keybundle.
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    debug!("membera keybundle: {:?}", keybundle);

    // TODO(nikki): device_label_assignments, label_exists, labels

    // TODO(nikki): if cfg!(feature = "aqc") { aqc_net_identifier } and have aqc on by default.

    Ok(())
}

// TODO(nikki): aqc testing variants.
