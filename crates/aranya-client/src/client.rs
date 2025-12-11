//! Client-daemon connection.

mod device;
mod label;
mod role;
mod team;

use std::{fmt::Debug, io, path::Path};

use anyhow::Context as _;
use aranya_crypto::{Csprng, Rng};
#[doc(inline)]
pub use aranya_daemon_api::ChanOp;
use aranya_daemon_api::{
    crypto::{
        txp::{self, LengthDelimitedCodec},
        PublicApiKey,
    },
    DaemonApiClient, Version, CS,
};
#[cfg(feature = "preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
#[doc(inline)]
pub use aranya_daemon_api::{
    RoleManagementPerm as RoleManagementPermission, SimplePerm as Permission,
};
use aranya_util::{error::ReportExt, Addr};
use tarpc::context;
use tokio::{fs, net::UnixStream};
use tracing::{debug, error, info};
#[cfg(feature = "afc")]
use {
    crate::afc::{ChannelKeys as AfcChannelKeys, Channels as AfcChannels},
    std::sync::Arc,
};

#[doc(inline)]
pub use crate::client::{
    device::{Device, DeviceId, Devices, KeyBundle},
    label::{Label, LabelId, Labels},
    role::{Role, RoleId, Roles},
    team::{Team, TeamId},
};
use crate::{
    config::{AddTeamConfig, CreateTeamConfig},
    error::{self, aranya_error, InvalidArg, IpcError, Result},
};

/// Builds a [`Client`].
#[derive(Debug, Default)]
pub struct ClientBuilder<'a> {
    /// The UDS that the daemon is listening on.
    #[cfg(unix)]
    daemon_uds_path: Option<&'a Path>,
}

impl ClientBuilder<'_> {
    /// Creates a new client builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a client connection to the daemon.
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::net::Ipv4Addr;
    /// # use aranya_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let client = Client::builder()
    ///     .with_daemon_uds_path("/var/run/aranya/uds.sock".as_ref())
    ///     .connect()
    ///     .await?;
    /// #    Ok(())
    /// # }
    pub async fn connect(self) -> Result<Client> {
        let Some(uds_path) = self.daemon_uds_path else {
            return Err(IpcError::new(InvalidArg::new(
                "daemon_uds_path",
                "must specify the daemon's UDS path",
            ))
            .into());
        };

        async {
            info!(path = ?uds_path, "connecting to daemon");

            let daemon = {
                let pk = {
                    // The public key is located next to the socket.
                    let api_pk_path = uds_path.parent().unwrap_or(uds_path).join("api.pk");
                    let bytes = fs::read(&api_pk_path)
                        .await
                        .with_context(|| "unable to read daemon API public key")
                        .map_err(IpcError::new)?;
                    PublicApiKey::<CS>::decode(&bytes)
                        .context("unable to decode public API key")
                        .map_err(IpcError::new)?
                };

                let uds_path = uds_path
                    .canonicalize()
                    .context("could not canonicalize uds_path")
                    .map_err(error::other)?;
                let sock = UnixStream::connect(&uds_path)
                    .await
                    .context("unable to connect to UDS path")
                    .map_err(IpcError::new)?;
                let info = uds_path.as_os_str().as_encoded_bytes();
                let codec = LengthDelimitedCodec::builder()
                    .max_frame_length(usize::MAX)
                    .new_codec();
                let transport = txp::client(sock, codec, Rng, pk, info);

                DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn()
            };
            debug!("connected to daemon");

            let got = daemon
                .version(context::current())
                .await
                .map_err(IpcError::new)?
                .context("unable to retrieve daemon version")
                .map_err(error::other)?;
            let want = Version::parse(env!("CARGO_PKG_VERSION"))
                .context("unable to parse `CARGO_PKG_VERSION`")
                .map_err(error::other)?;
            if got.major != want.major || got.minor != want.minor {
                return Err(IpcError::new(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("version mismatch: `{got}` != `{want}`"),
                ))
                .into());
            }
            debug!(client = ?want, daemon = ?got, "versions");

            #[cfg(feature = "afc")]
            let afc_keys = {
                let afc_shm_info = daemon
                    .afc_shm_info(context::current())
                    .await
                    .map_err(IpcError::new)?
                    .context("unable to retrieve afc shm info")
                    .map_err(error::other)?;
                Arc::new(AfcChannelKeys::new(&afc_shm_info)?)
            };

            let client = Client {
                daemon,
                #[cfg(feature = "afc")]
                afc_keys,
            };

            Ok(client)
        }
        .await
        .inspect_err(
            |err: &crate::Error| error!(error = %err.report(), "unable to connect to daemon"),
        )
    }
}

impl<'a> ClientBuilder<'a> {
    /// Specifies the UDS socket path the daemon is listening on.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    pub fn with_daemon_uds_path(mut self, sock: &'a Path) -> Self {
        self.daemon_uds_path = Some(sock);
        self
    }
}

/// A client for invoking actions on and processing effects from
/// the Aranya graph.
///
/// `Client` interacts with the [Aranya daemon] over
/// a platform-specific IPC mechanism.
///
/// [Aranya daemon]: https://crates.io/crates/aranya-daemon
#[derive(Debug)]
pub struct Client {
    /// RPC connection to the daemon
    pub(crate) daemon: DaemonApiClient,
    /// AFC channel keys.
    #[cfg(feature = "afc")]
    afc_keys: Arc<AfcChannelKeys>,
}

impl Client {
    /// Returns a builder for `Client`.
    pub fn builder<'a>() -> ClientBuilder<'a> {
        ClientBuilder::new()
    }

    /// Returns the address that the Aranya sync server is bound to.
    pub async fn local_addr(&self) -> Result<Addr> {
        self.daemon
            .aranya_local_addr(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&self) -> Result<KeyBundle> {
        self.daemon
            .get_key_bundle(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(KeyBundle::from_api)
    }

    /// Gets the public device ID for this device.
    pub async fn get_device_id(&self) -> Result<DeviceId> {
        self.daemon
            .get_device_id(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(DeviceId::from_api)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&self, cfg: CreateTeamConfig) -> Result<Team<'_>> {
        let team_id = self
            .daemon
            .create_team(context::current(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
            .map(TeamId::from_api)?;
        Ok(Team {
            client: self,
            id: team_id.into_api(),
        })
    }

    /// Generate random bytes from a CSPRNG.
    /// Can be used to generate IKM for a generating a PSK seed.
    pub async fn rand(&self, buf: &mut [u8]) {
        <Rng as Csprng>::fill_bytes(&mut Rng, buf);
    }

    /// Get an existing team.
    pub fn team(&self, team_id: TeamId) -> Team<'_> {
        Team {
            client: self,
            id: team_id.into_api(),
        }
    }

    /// Add a team to local device storage.
    pub async fn add_team(&self, cfg: AddTeamConfig) -> Result<Team<'_>> {
        let cfg = aranya_daemon_api::AddTeamConfig::from(cfg);
        let team_id = TeamId::from_api(cfg.team_id);

        self.daemon
            .add_team(context::current(), cfg)
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Team {
            client: self,
            id: team_id.into_api(),
        })
    }

    /// Remove a team from local device storage.
    pub async fn remove_team(&self, team_id: TeamId) -> Result<()> {
        self.daemon
            .remove_team(context::current(), team_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Get access to Aranya Fast Channels.
    #[cfg(feature = "afc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "afc")))]
    pub fn afc(&self) -> AfcChannels {
        AfcChannels::new(self.daemon.clone(), self.afc_keys.clone())
    }
}
