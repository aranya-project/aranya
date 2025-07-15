use std::{io, net::SocketAddr, path::Path};

use anyhow::Context as _;
use aranya_crypto::{Csprng, Rng};
// TODO(eric): Wrap these.
pub use aranya_daemon_api::KeyBundle;
use aranya_daemon_api::{
    crypto::{
        txp::{self, LengthDelimitedCodec},
        PublicApiKey,
    },
    DaemonApiClient, Version, CS,
};
use aranya_util::Addr;
use tarpc::context;
use tokio::{fs, net::UnixStream};
use tracing::{debug, error, info, instrument};

use crate::{
    aqc::{AqcChannels, AqcClient},
    client::{DeviceId, Team, TeamId},
    config::TeamConfig,
    error::{self, aranya_error, InvalidArg, IpcError, Result},
};

/// Builds a [`Client`].
#[derive(Clone, Debug)]
pub struct ClientBuilder<'a> {
    /// The UDS that the daemon is listening on.
    #[cfg(unix)]
    uds_path: Option<&'a Path>,
    // AQC address.
    aqc_addr: Option<&'a Addr>,
}

impl ClientBuilder<'_> {
    pub fn new() -> Self {
        Self {
            uds_path: None,
            aqc_addr: None,
        }
    }

    /// Connects to the daemon.
    pub async fn connect(self) -> Result<Client> {
        let Some(sock) = self.uds_path else {
            return Err(IpcError::new(InvalidArg::new(
                "with_daemon_uds_path",
                "must specify the daemon's UDS path",
            ))
            .into());
        };

        let Some(aqc_addr) = &self.aqc_addr else {
            return Err(IpcError::new(InvalidArg::new(
                "with_daemon_aqc_addr",
                "must specify the AQC server address",
            ))
            .into());
        };
        Client::connect(sock, aqc_addr)
            .await
            .inspect_err(|err| error!(?err, "unable to connect to daemon"))
    }
}

impl Default for ClientBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ClientBuilder<'a> {
    /// Specifies the UDS socket path the daemon is listening on.
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    pub fn with_daemon_uds_path(mut self, sock: &'a Path) -> Self {
        self.uds_path = Some(sock);
        self
    }

    /// Specifies the AQC server address.
    pub fn with_daemon_aqc_addr(mut self, addr: &'a Addr) -> Self {
        self.aqc_addr = Some(addr);
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
    /// Support for AQC
    pub(crate) aqc: AqcClient,
}

impl Client {
    /// Returns a builder for `Client`.
    pub fn builder<'a>() -> ClientBuilder<'a> {
        ClientBuilder::new()
    }

    /// Creates a client connection to the daemon.
    #[instrument(skip_all)]
    async fn connect(uds_path: &Path, aqc_addr: &Addr) -> Result<Self> {
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

            let sock = UnixStream::connect(uds_path)
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

        let aqc_server_addr = aqc_addr
            .lookup()
            .await
            .context("unable to resolve AQC server address")
            .map_err(error::other)?
            .next()
            .expect("expected AQC server address");
        let aqc = AqcClient::new(aqc_server_addr, daemon.clone()).await?;
        let client = Self { daemon, aqc };

        Ok(client)
    }

    /// Returns the address that the Aranya sync server is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        self.daemon
            .aranya_local_addr(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Returns the address that the AQC client is bound to.
    pub async fn aqc_client_addr(&self) -> Result<SocketAddr> {
        Ok(self.aqc.client_addr()) // TODO: Remove error?
    }

    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&self) -> Result<KeyBundle> {
        self.daemon
            .get_key_bundle(context::current())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
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
    pub async fn create_team(&self, cfg: TeamConfig) -> Result<Team<'_>> {
        let team_id = self
            .daemon
            .create_team(context::current(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)?;
        Ok(Team {
            client: self,
            id: team_id,
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

    /// Add a team to the local device store.
    pub async fn add_team(&self, team: TeamId, cfg: TeamConfig) -> Result<()> {
        self.daemon
            .add_team(context::current(), team.into_api(), cfg.into())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Remove a team from local device storage.
    pub async fn remove_team(&self, team_id: TeamId) -> Result<()> {
        self.daemon
            .remove_team(context::current(), team_id.into_api())
            .await
            .map_err(IpcError::new)?
            .map_err(aranya_error)
    }

    /// Get access to Aranya QUIC Channels.
    pub fn aqc(&self) -> AqcChannels<'_> {
        AqcChannels::new(self)
    }
}
