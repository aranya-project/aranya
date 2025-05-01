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

use anyhow::{Context, Result};
use aranya_client::{Client, SyncPeerConfig, TeamConfig};
use aranya_daemon::{config::Config, Daemon};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier, Op, Role, TeamId};
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
    roles: Option<RoleCtx>,
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
            roles: None,
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

    async fn create_all_roles(&mut self, team_id: TeamId) -> Result<()> {
        let mut owner_team = self.owner.client.team(team_id);

        // Assign commands to roles.
        let roles = owner_team.setup_default_roles().await?;
        assert_eq!(roles.iter().count(), 3);
        let mut roles_iter = roles.iter();
        let admin_role = roles_iter.next().expect("expected admin role");
        assert_eq!(admin_role.name, "admin");
        let operator_role = roles_iter.next().expect("expected operator role");
        assert_eq!(operator_role.name, "operator");
        let member_role = roles_iter.next().expect("expected member role");
        assert_eq!(member_role.name, "member");
        let default_roles = RoleCtx {
            admin: admin_role.clone(),
            operator: operator_role.clone(),
            member: member_role.clone(),
        };

        // Create a dummy role and assign a dummy command to it.
        let _dummy_role = owner_team.create_role("dummy".to_string()).await?;
        owner_team
            .assign_operation_to_role(admin_role.id, Op::DeleteLabel)
            .await?;

        self.roles = Some(default_roles);

        Ok(())
    }

    async fn add_all_device_roles(&mut self, team_id: TeamId) -> Result<()> {
        // Shorthand for the teams we need to operate on.
        let mut owner_team = self.owner.client.team(team_id);

        // Add the admin as a new device, and assign its role.
        info!("adding admin to team");
        owner_team
            .add_device_to_team(self.admin.pk.clone(), 9000)
            .await?;
        // TODO: verify that assigning a lower precedence can result in loss of operation authorization.
        owner_team
            .assign_device_precedence(self.admin.id, 8500)
            .await?;
        let roles = self.roles.clone().unwrap();
        owner_team
            .assign_role(self.admin.id, roles.admin.id)
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Add the operator as a new device.
        info!("adding operator to team");
        owner_team
            .add_device_to_team(self.operator.pk.clone(), 8000)
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Assign the operator its role.
        owner_team
            .assign_role(self.operator.id, roles.operator.id)
            .await?;

        // Make sure it sees the configuration change.
        sleep(SLEEP_INTERVAL).await;

        // Add member A as a new device.
        info!("adding membera to team");
        owner_team
            .add_device_to_team(self.membera.pk.clone(), 7000)
            .await?;
        // Assign the membera its role.
        owner_team
            .assign_role(self.membera.id, roles.member.id)
            .await?;

        // Add member A as a new device.
        info!("adding memberb to team");
        owner_team
            .add_device_to_team(self.memberb.pk.clone(), 6000)
            .await?;
        // Assign the memberb its role.
        owner_team
            .assign_role(self.memberb.id, roles.member.id)
            .await?;

        // Make sure they see the configuration change.
        sleep(SLEEP_INTERVAL).await;

        Ok(())
    }

    async fn delete_all_roles(&mut self, team_id: TeamId) -> Result<()> {
        let owner = &mut self.owner.client;
        let owner_id = owner.get_device_id().await?;
        let owner_roles = owner.queries(team_id).device_roles(owner_id).await?;
        let owner_role = owner_roles.iter().next().unwrap();

        // Revoke roles from devices.
        let devices = owner.queries(team_id).devices_on_team().await?;
        for device in devices.iter() {
            if *device != owner_id {
                let roles = owner.queries(team_id).device_roles(*device).await?;
                for role in roles.iter() {
                    owner.team(team_id).revoke_role(*device, role.id).await?;
                }
            }
        }

        // Revoke commands from roles.
        let roles = &mut owner.queries(team_id).roles_on_team().await?;
        for role in roles.iter() {
            if role.id != owner_role.id {
                let ops = owner.queries(team_id).role_ops(role.id).await?;
                for op in ops.iter() {
                    owner
                        .team(team_id)
                        .revoke_role_operation(role.id, *op)
                        .await?;
                }
            }
        }

        // TODO: delete all roles.

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RoleCtx {
    // Note: owner role is created by policy by default.
    admin: Role,
    operator: Role,
    member: Role,
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

// Tests that if an operation is revoked from a role, the role can no longer execute the operation.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_revoke_operation() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_revoke_operation", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Create all team roles.
    team.create_all_roles(team_id).await?;
    let roles = team.roles.clone().unwrap();

    // Tell all peers to sync with one another.
    team.add_all_sync_peers(team_id).await?;

    // Add all devices to team.
    team.add_all_device_roles(team_id).await?;

    // give daemon time to setup UDS API.
    sleep(SLEEP_INTERVAL).await;

    // Grab the shorthand for the teams we need to operate on.
    let membera_id = team.membera.client.get_device_id().await?;

    let mut owner = team.owner.client.team(team_id);
    let mut operator = team.operator.client.team(team_id);

    // Verify that operator can execute operation.
    operator
        .assign_aqc_net_identifier(membera_id, NetIdentifier("127.0.0.1:1010".to_string()))
        .await
        .expect("expected aqc net identifier assignment to succeed");

    // Revoke the operation from the operator role.
    owner
        .revoke_role_operation(roles.operator.id, Op::SetAqcNetworkName)
        .await?;

    // Make sure operator sees the configuration change.
    sleep(SLEEP_INTERVAL).await;

    // Verify that operator cannot execute operation.
    operator
        .assign_aqc_net_identifier(membera_id, NetIdentifier("127.0.0.1:1020".to_string()))
        .await
        .expect_err("expected aqc net identifier assignment to fail");

    Ok(())
}

// Tests that if a role is revoked from a device, the device can no longer execute an operation.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_revoke_role() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_revoke_role", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Create all team roles.
    team.create_all_roles(team_id).await?;
    let roles = team.roles.clone().unwrap();

    // Tell all peers to sync with one another.
    team.add_all_sync_peers(team_id).await?;

    // Add all devices to team.
    team.add_all_device_roles(team_id).await?;

    // give daemon time to setup UDS API.
    sleep(SLEEP_INTERVAL).await;

    // Grab the shorthand for the teams we need to operate on.
    let membera_id = team.membera.client.get_device_id().await?;
    let operator_id = team.operator.client.get_device_id().await?;
    let mut owner = team.owner.client.team(team_id);
    let mut operator = team.operator.client.team(team_id);

    // Verify that operator can execute operation.
    operator
        .assign_aqc_net_identifier(membera_id, NetIdentifier("127.0.0.1:1010".to_string()))
        .await
        .expect("expected aqc net identifier assignment to succeed");

    // Revoke operator role from operator device.
    owner.revoke_role(operator_id, roles.operator.id).await?;

    // Make sure operator sees the configuration change.
    sleep(SLEEP_INTERVAL).await;

    // Verify that operator cannot execute operation.
    operator
        .assign_aqc_net_identifier(membera_id, NetIdentifier("127.0.0.1:1020".to_string()))
        .await
        .expect_err("expected aqc net identifier assignment to fail");

    Ok(())
}

/// Tests that device precedence can affect whether a device is authorized to execute certain operations.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_device_precedence() -> Result<()> {
    // Set up our team context so we can run the test.
    let work_dir = tempfile::tempdir()?.path().to_path_buf();
    let mut team = TeamCtx::new("test_device_precedence", work_dir).await?;

    // Create the initial team, and get our TeamId.
    let cfg = TeamConfig::builder().build()?;
    let team_id = team
        .owner
        .client
        .create_team(cfg)
        .await
        .expect("expected to create team");
    info!(?team_id);

    // Create all team roles.
    team.create_all_roles(team_id).await?;

    // Tell all peers to sync with one another.
    team.add_all_sync_peers(team_id).await?;

    // Add all devices to team.
    team.add_all_device_roles(team_id).await?;

    // give daemon time to setup UDS API.
    sleep(SLEEP_INTERVAL).await;

    // Grab the shorthand for the teams we need to operate on.
    let membera_id = team.membera.client.get_device_id().await?;
    let operator_id = team.operator.client.get_device_id().await?;
    let mut owner = team.owner.client.team(team_id);
    let mut operator = team.operator.client.team(team_id);

    // Verify that operator can execute operation.
    operator
        .assign_aqc_net_identifier(membera_id, NetIdentifier("127.0.0.1:1010".to_string()))
        .await
        .expect("expected aqc net identifier assignment to succeed");

    // Set operator precedence to zero to ensure it cannot execute any operations.
    owner.assign_device_precedence(operator_id, 0).await?;

    // Make sure operator sees the configuration change.
    sleep(SLEEP_INTERVAL).await;

    // Verify that operator cannot execute operation.
    operator
        .assign_aqc_net_identifier(membera_id, NetIdentifier("127.0.0.1:1020".to_string()))
        .await
        .expect_err("expected aqc net identifier assignment to fail");

    Ok(())
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

    // Create all team roles.
    team.create_all_roles(team_id).await?;
    let roles = team.roles.clone().unwrap();

    // Grab the shorthand for our address.
    let owner_addr = team.owner.aranya_local_addr().await?;

    // Grab the shorthand for the teams we need to operate on.
    let mut owner = team.owner.client.team(team_id);

    // Add the admin as a new device, but don't give it a role.
    info!("adding admin to team");
    owner.add_device_to_team(team.admin.pk.clone(), 100).await?;

    // Sync once to initialize the graph.
    let mut admin = team.admin.client.team(team_id);
    admin.sync_now(owner_addr.into(), None).await?;
    sleep(SLEEP_INTERVAL).await;

    // Finally, let's give the admin its role, but don't sync with peers.
    owner.assign_role(team.admin.id, roles.admin.id).await?;

    // Try to query admin role before syncing
    {
        let mut queries = team.admin.client.queries(team_id);
        let admin_roles = queries.device_roles(team.admin.id).await?;
        assert_eq!(admin_roles.iter().count(), 0);
    }

    // Let's sync immediately, which will propagate the role assignment.
    let mut admin: aranya_client::Team<'_> = team.admin.client.team(team_id);
    admin.sync_now(owner_addr.into(), None).await?;
    sleep(SLEEP_INTERVAL).await;

    // Try to query operator role after syncing
    {
        let mut queries = team.admin.client.queries(team_id);
        let admin_roles = queries.device_roles(team.admin.id).await?;
        assert_eq!(admin_roles.iter().count(), 1);
    }

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

    // Create all team roles.
    team.create_all_roles(team_id).await?;

    // Tell all peers to sync with one another, and assign their roles.
    team.add_all_sync_peers(team_id).await?;
    team.add_all_device_roles(team_id).await?;

    // give daemon time to setup UDS API.
    sleep(SLEEP_INTERVAL).await;

    // Test all our fact database queries.
    let mut queries = team.membera.client.queries(team_id);

    // First, let's check how many devices are on the team.
    let devices = queries.devices_on_team().await?;
    assert_eq!(devices.iter().count(), 5);
    debug!("membera devices on team: {:?}", devices.iter().count());

    // Check the specific role(s) a device has.
    let roles = queries.device_roles(team.membera.id).await?;
    let role = roles.iter().next().unwrap();
    assert_eq!(role.name, "member");
    debug!("membera role: {:?}", role.name);

    // Make sure that we have the correct keybundle.
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    debug!("membera keybundle: {:?}", keybundle);

    // TODO(nikki): device_label_assignments, label_exists, labels

    // TODO(nikki): if cfg!(feature = "aqc") { aqc_net_identifier } and have aqc on by default.

    team.delete_all_roles(team_id).await?;

    Ok(())
}
