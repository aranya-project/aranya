#![allow(dead_code)]
use std::{fmt, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use aranya_client::{client::Client, SyncPeerConfig};
use aranya_daemon::{config::Config, Daemon};
use aranya_daemon_api::{DeviceId, KeyBundle, NetIdentifier, Role, TeamId};
use aranya_util::Addr;
use backon::{ExponentialBuilder, Retryable as _};
use tokio::{
    fs,
    task::{self, AbortHandle},
    time::{self, Sleep},
};
use tracing::{debug, info, instrument};

const SYNC_INTERVAL: Duration = Duration::from_millis(100);
// Allow for one missed sync and a misaligned sync rate, while keeping run times low.
pub const SLEEP_INTERVAL: Duration = Duration::from_millis(250);

#[instrument(skip_all, fields(%duration = FmtDuration(d)))]
pub fn sleep(d: Duration) -> Sleep {
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

pub struct TeamCtx {
    pub owner: DeviceCtx,
    pub admin: DeviceCtx,
    pub operator: DeviceCtx,
    pub membera: DeviceCtx,
    pub memberb: DeviceCtx,
}

impl TeamCtx {
    pub async fn new(name: &str, work_dir: PathBuf, port_start: u16) -> Result<Self> {
        let owner = DeviceCtx::new(
            name,
            "owner",
            work_dir.join("owner"),
            port_start
                .checked_add(1)
                .expect("expected to choose port number"),
        )
        .await?;
        let admin = DeviceCtx::new(
            name,
            "admin",
            work_dir.join("admin"),
            port_start
                .checked_add(2)
                .expect("expected to choose port number"),
        )
        .await?;
        let operator = DeviceCtx::new(
            name,
            "operator",
            work_dir.join("operator"),
            port_start
                .checked_add(3)
                .expect("expected to choose port number"),
        )
        .await?;
        let membera = DeviceCtx::new(
            name,
            "membera",
            work_dir.join("membera"),
            port_start
                .checked_add(4)
                .expect("expected to choose port number"),
        )
        .await?;
        let memberb = DeviceCtx::new(
            name,
            "memberb",
            work_dir.join("memberb"),
            port_start
                .checked_add(5)
                .expect("expected to choose port number"),
        )
        .await?;

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

    pub async fn add_all_sync_peers(&mut self, team_id: TeamId) -> Result<()> {
        let config = SyncPeerConfig::builder().interval(SYNC_INTERVAL).build()?;
        let mut devices = self.devices();
        for i in 0..devices.len() {
            let (device, peers) = devices[i..].split_first_mut().expect("expected device");
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

    pub async fn add_all_device_roles(&mut self, team_id: TeamId) -> Result<()> {
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

pub struct DeviceCtx {
    pub client: Client,
    pub pk: KeyBundle,
    pub id: DeviceId,
    pub daemon: AbortHandle,
    pub aqc_addr: NetIdentifier,
    pub port: u16,
}

impl DeviceCtx {
    async fn new(_team_name: &str, _name: &str, work_dir: PathBuf, port: u16) -> Result<Self> {
        let aqc_addr = Addr::new("127.0.0.1", port).expect("unable to init AQC address");
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
        let pk = daemon.public_api_key().await?;
        let pk_bytes = pk.encode()?;
        let handle = task::spawn(async move {
            daemon
                .run()
                .await
                .expect("expected no errors running daemon")
        })
        .abort_handle();

        // give daemon time to setup UDS API.
        sleep(SLEEP_INTERVAL).await;

        // Initialize the user library.
        let (mut client, _aqc_addr) = (|| {
            Client::builder()
                .with_daemon_uds_path(&uds_api_path)
                .with_daemon_api_pk(&pk_bytes)
                .with_daemon_aqc_addr(&aqc_addr)
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
            aqc_addr: NetIdentifier(aqc_addr.to_string()),
            port,
        })
    }

    pub async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.local_addr().await?)
    }

    pub async fn aqc_client_addr(&self) -> Result<SocketAddr> {
        Ok(self.client.aqc_client_addr().await?)
    }
}

impl Drop for DeviceCtx {
    fn drop(&mut self) {
        self.daemon.abort();
    }
}
