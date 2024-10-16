//! Implementation of daemon's `tarpc` API.
//! Trait for API interface is defined in `crates/daemon-api`

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::{
    future::{self, Future},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use aranya_crypto::{Csprng, Rng};
use aranya_daemon_api::{
    Addr as ApiAddr, AfcCtrl, ChannelId, DaemonApi, DeviceId, Error, KeyBundle as ApiKeyBundle,
    Label as ApiLabel, NetIdentifier, NodeId, Result as ApiResult, Role as ApiRole, TeamId,
};
use aranya_fast_channels::Label;
use aranya_keygen::PublicKeys;
use futures_util::{StreamExt, TryStreamExt};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    addr::Addr,
    aranya::Actions,
    policy::{ChanOp, KeyBundle, Role},
    sync::SyncPeers,
    Client, CS,
};

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

/// Daemon API Server.
///
/// Hosts a `tarpc` server listening on a UDS socket path.
/// The user library will make requests to this API.
pub struct DaemonApiServer<S> {
    daemon_sock: PathBuf,
    handler: DaemonApiHandler<S>,
}

#[derive(Clone)]
struct DaemonApiHandler<S> {
    client: Arc<Client>,
    #[allow(dead_code)] // TODO
    afc: S,
    pk: Arc<PublicKeys<CS>>,
    peers: SyncPeers,
}

impl<S: Clone + Send + 'static> DaemonApiServer<S> {
    /// Create new RPC server.
    #[instrument(skip_all)]
    pub fn new(
        client: Arc<Client>,
        afc: S,
        daemon_sock: PathBuf,
        pk: Arc<PublicKeys<CS>>,
        peers: SyncPeers,
    ) -> Result<Self> {
        info!("uds path: {:?}", daemon_sock);
        Ok(Self {
            daemon_sock,
            handler: DaemonApiHandler {
                client,
                afc,
                pk,
                peers,
            },
        })
    }

    /// Run the RPC server.
    #[instrument(skip_all)]
    pub async fn serve(self) -> Result<()> {
        let mut listener =
            tarpc::serde_transport::unix::listen(self.daemon_sock.clone(), Json::default).await?;
        info!(
            "listening on {:?}",
            listener
                .local_addr()
                .as_pathname()
                .expect("expected uds api path to be set")
        );
        listener.config_mut().max_frame_length(usize::MAX);
        listener
            .inspect_err(|err| warn!(%err, "accept error"))
            // Ignore accept errors.
            .filter_map(|r| future::ready(r.ok()))
            .map(server::BaseChannel::with_defaults)
            // serve is generated by the service attribute. It takes as input any type implementing
            // the generated World trait.
            .map(|channel| {
                debug!("accepted channel connection");
                channel
                    .execute(self.handler.clone().serve())
                    .for_each(spawn)
            })
            // Max 10 channels.
            .buffer_unordered(10)
            .for_each(|_| async {})
            .await;

        Ok(())
    }
}

impl<S> DaemonApiHandler<S> {
    fn get_pk(&self) -> ApiResult<KeyBundle> {
        KeyBundle::try_from(&*self.pk).map_err(|_| Error::Unknown)
    }
}

// TODO: implement all the trait methods.
impl<S: Clone + Send + 'static> DaemonApi for DaemonApiHandler<S> {
    #[instrument(skip(self))]
    async fn initialize(self, _: context::Context) -> ApiResult<()> {
        info!("initialize");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_key_bundle(self, _: context::Context) -> ApiResult<ApiKeyBundle> {
        Ok(self.get_pk()?.into())
    }

    #[instrument(skip(self))]
    async fn get_device_id(self, _: context::Context) -> ApiResult<DeviceId> {
        Ok(self
            .pk
            .ident_pk
            .id()
            .map_err(|_| Error::Unknown)?
            .into_id()
            .into())
    }

    #[instrument(skip(self))]
    async fn add_sync_peer(
        self,
        _: context::Context,
        addr: ApiAddr,
        team: TeamId,
        interval: Duration,
    ) -> ApiResult<()> {
        let peer = Addr::from_str(addr.0.as_str()).map_err(|_| Error::Unknown)?;
        self.peers
            .add_peer(peer, interval, team.into_id().into())
            .await
            .map_err(|_| Error::Unknown)
    }

    #[instrument(skip(self))]
    async fn remove_sync_peer(
        self,
        _: context::Context,
        addr: ApiAddr,
        team: TeamId,
    ) -> ApiResult<()> {
        let peer = Addr::from_str(addr.0.as_str()).map_err(|_| Error::Unknown)?;
        self.peers
            .remove_peer(peer, team.into_id().into())
            .await
            .map_err(|_| Error::Unknown)
    }

    #[instrument(skip(self))]
    async fn add_team(self, _: context::Context, team: TeamId) -> ApiResult<()> {
        todo!()
    }

    #[instrument(skip(self))]
    async fn remove_team(self, _: context::Context, team: TeamId) -> ApiResult<()> {
        todo!();
    }

    #[instrument(skip(self))]
    async fn create_team(self, _: context::Context) -> ApiResult<TeamId> {
        info!("create_team");
        let nonce = &mut [0u8; 16];
        Rng.fill_bytes(nonce);
        let pk = self.get_pk()?;
        let (graph_id, _) = self
            .client
            .create_team(pk, Some(nonce))
            .await
            .map_err(|_| Error::Unknown)?;
        debug!(?graph_id);
        Ok(graph_id.into_id().into())
    }

    #[instrument(skip(self))]
    async fn close_team(self, _: context::Context, team: TeamId) -> ApiResult<()> {
        todo!();
    }

    #[instrument(skip(self))]
    async fn add_device_to_team(
        self,
        _: context::Context,
        team: TeamId,
        keys: ApiKeyBundle,
    ) -> ApiResult<()> {
        if let Err(e) = self
            .client
            .actions(&team.into_id().into())
            .add_member(keys.into())
            .await
        {
            error!(?e);
            return Err(e).map_err(|_| Error::Unknown);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_device_from_team(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
    ) -> ApiResult<()> {
        if let Err(e) = self
            .client
            .actions(&team.into_id().into())
            .remove_member(device.into_id().into())
            .await
        {
            error!(?e);
            return Err(e).map_err(|_| Error::Unknown);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_role(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        role: ApiRole,
    ) -> ApiResult<()> {
        if let Err(e) = self
            .client
            .actions(&team.into_id().into())
            .assign_role(device.into_id().into(), role.into())
            .await
        {
            error!(?e);
            return Err(e).map_err(|_| Error::Unknown);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_role(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        role: ApiRole,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .revoke_role(device.into_id().into(), role.into())
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_net_name(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .set_network_name(device.into_id().into(), name.0)
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_net_name(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        name: NetIdentifier,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .unset_network_name(device.into_id().into())
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_label(
        self,
        _: context::Context,
        team: TeamId,
        label: ApiLabel,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .define_label(Label::new(label.0))
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_label(
        self,
        _: context::Context,
        team: TeamId,
        label: ApiLabel,
    ) -> ApiResult<()> {
        self.client
            .actions(&team.into_id().into())
            .undefine_label(Label::new(label.0))
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn assign_label(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        label: ApiLabel,
    ) -> ApiResult<()> {
        let id = self.pk.ident_pk.id().map_err(|_| Error::Unknown)?;
        // TODO: support other channel permissions.
        self.client
            .actions(&team.into_id().into())
            .assign_label(id, Label::new(label.0), ChanOp::ReadWrite)
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_label(
        self,
        _: context::Context,
        team: TeamId,
        device: DeviceId,
        label: ApiLabel,
    ) -> ApiResult<()> {
        let id = self.pk.ident_pk.id().map_err(|_| Error::Unknown)?;
        self.client
            .actions(&team.into_id().into())
            .revoke_label(id, Label::new(label.0))
            .await
            .map_err(|_| Error::Unknown)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn create_channel(
        self,
        _: context::Context,
        team: TeamId,
        peer: NetIdentifier,
        label: ApiLabel,
    ) -> ApiResult<(ChannelId, NodeId, AfcCtrl)> {
        // TODO: self.afc.add()
        todo!();
    }

    #[instrument(skip(self))]
    async fn delete_channel(self, _: context::Context, chan: ChannelId) -> ApiResult<AfcCtrl> {
        // TODO: self.afc.remove()
        todo!();
    }

    #[instrument(skip(self))]
    async fn receive_afc_ctrl(self, _: context::Context, ctrl: AfcCtrl) -> ApiResult<()> {
        todo!();
    }
}

impl From<ApiKeyBundle> for KeyBundle {
    fn from(value: ApiKeyBundle) -> Self {
        KeyBundle {
            ident_key: value.identity,
            sign_key: value.signing,
            enc_key: value.encoding,
        }
    }
}

impl From<KeyBundle> for ApiKeyBundle {
    fn from(value: KeyBundle) -> Self {
        ApiKeyBundle {
            identity: value.ident_key,
            signing: value.sign_key,
            encoding: value.enc_key,
        }
    }
}

impl From<ApiRole> for Role {
    fn from(value: ApiRole) -> Self {
        match value {
            ApiRole::Owner => Role::Owner,
            ApiRole::Admin => Role::Admin,
            ApiRole::Operator => Role::Operator,
            ApiRole::Member => Role::Member,
        }
    }
}
