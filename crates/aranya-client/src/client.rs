use std::{collections::BTreeMap, net::SocketAddr, path::Path, str::FromStr, time::Duration};

use aranya_daemon_api::{
    AfcId, DaemonApiClient, DeviceId, KeyBundle, NetIdentifier, Role, TeamId, CS,
};
use aranya_fast_channels::{shm::ReadState, ChannelId, Label};
use aranya_util::addr::Addr;
use tarpc::{context, tokio_serde::formats::Json};
use tracing::{debug, info, instrument};

use crate::{
    afc::{setup_afc_shm, App, PollData, Router},
    Error, Result,
};

pub struct Client {
    daemon: DaemonApiClient,
    /// AFC data router.
    afc: Router<ReadState<CS>>,
    /// Application abstraction for sending/receiving data between application and the AFC router.
    app: App,
    /// AFC channels.
    chans: BTreeMap<AfcId, (TeamId, NetIdentifier, Label)>,
}

impl Client {
    /// Creates a client connected to the daemon.
    #[instrument(skip_all)]
    pub async fn connect(
        daemon_sock: &Path,
        afc_shm_path: &Path,
        max_chans: usize,
        afc_addr: Addr,
    ) -> Result<Self> {
        info!("uds path: {:?}", daemon_sock);
        let transport = tarpc::serde_transport::unix::connect(daemon_sock, Json::default)
            .await
            .map_err(Error::Connecting)?;
        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to: {:?}", daemon_sock);
        let read = setup_afc_shm(afc_shm_path, max_chans)?;
        let afc = aranya_fast_channels::Client::new(read);
        let (afc, app) = Router::new(afc, afc_addr).await.map_err(Error::AfcRouter)?;
        debug!(
            "afc router bound to: {:?}",
            afc.local_addr().map_err(Error::AfcRouter)?
        );
        Ok(Self {
            daemon,
            afc,
            app,
            chans: BTreeMap::new(),
        })
    }

    /// Returns address Aranya sync server bound to.
    pub async fn aranya_local_addr(&self) -> Result<SocketAddr> {
        Ok(self.daemon.aranya_local_addr(context::current()).await??)
    }

    /// Returns address AFC server bound to.
    pub async fn afc_local_addr(&self) -> Result<SocketAddr> {
        self.afc.local_addr().map_err(Error::AfcRouter)
    }

    /// Creates a bidirectional AFC channel.
    pub async fn create_channel(
        &mut self,
        team: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> Result<AfcId> {
        debug!("creating AFC channel in Aranya");
        let node_id = self.afc.get_next_node_id().await?;
        let (afc_id, ctrl) = self
            .daemon
            .create_channel(context::current(), team, peer.clone(), node_id, label)
            .await??;
        debug!("creating AFC channel in AFC");
        // TODO: use existing mapping from `assign_net_name`
        let addr = Addr::from_str(&peer.0)
            .map_err(|_| Error::AfcRouter(crate::afc::AfcRouterError::AppWrite))?;
        let addr = addr
            .lookup()
            .await
            .map_err(|_| Error::AfcRouter(crate::afc::AfcRouterError::AppWrite))?;
        debug!(?label, ?team, ?addr, "sending ctrl msg");
        let channel_id = ChannelId::new(node_id, label);
        self.afc.insert_channel_id(afc_id, channel_id).await?;
        self.app.send_ctrl(SocketAddr::V4(addr), team, ctrl).await?;
        self.chans.insert(afc_id, (team, peer, label));
        debug!(?team, ?addr, ?label, "AFC channel created");
        Ok(afc_id)
    }

    pub async fn delete_channel(&mut self, chan: AfcId) -> Result<()> {
        let _ctrl = self
            .daemon
            .delete_channel(context::current(), chan)
            .await??;
        self.chans.remove(&chan);
        // TODO: delete AFC channel from AFC router.
        todo!()
    }

    /// Poll for new data and handle it.
    pub async fn poll(&mut self) -> Result<()> {
        let data = self.poll_data().await?;
        self.handle_data(data).await
    }

    /// Poll for new data.
    pub async fn poll_data(&mut self) -> Result<PollData> {
        #![allow(clippy::disallowed_macros)]
        let data = tokio::select! {
            result = self.app.recv_ctrl() => result?,
            result = self.afc.poll() => result?,
        };
        Ok(data)
    }

    /// Handle any received data.
    pub async fn handle_data(&mut self, data: PollData) -> Result<()> {
        match data {
            PollData::Ctrl(ctrl) => {
                debug!("client lib received AFC ctrl msg");
                let node_id = ctrl.node_id;
                let (afc_id, label) = self
                    .daemon
                    .receive_afc_ctrl(context::current(), ctrl.team_id, node_id, ctrl.afc_ctrl)
                    .await??;
                let channel_id = ChannelId::new(node_id, label);
                self.afc.insert_channel_id(afc_id, channel_id).await?;
            }
            _ => {
                self.afc.handle_data(data).await?;
            }
        }
        Ok(())
    }

    pub async fn send_data(&mut self, chan: AfcId, data: Vec<u8>) -> Result<()> {
        if let Some((_team_id, peer, label)) = self.chans.get(&chan) {
            let addr = Addr::from_str(&peer.0).map_err(|_| crate::afc::AfcRouterError::AppWrite)?;
            let addr = addr
                .lookup()
                .await
                .map_err(|_| crate::afc::AfcRouterError::AppWrite)?;
            self.app
                .send_data(SocketAddr::V4(addr), *label, chan, data)
                .await?;
        }
        Ok(())
    }

    // TODO: return [`NetIdentifier`] instead of [`SocketAddr`].
    pub async fn recv_data(&mut self) -> Result<(Vec<u8>, SocketAddr, AfcId, Label)> {
        let (plaintext, addr, afc_id, label) = self.app.recv().await.map_err(Error::AfcRouter)?;
        debug!(n = plaintext.len(), "received AFC data message");
        Ok((plaintext, addr, afc_id, label))
    }
}

impl Client {
    /// Initializes the device if it doesn't exist.
    ///
    /// Creates directories, keys, etc.
    pub async fn initialize(&mut self) -> Result<()> {
        Ok(self.daemon.initialize(context::current()).await??)
    }

    /// Gets the public key bundle for this device.
    pub async fn get_key_bundle(&mut self) -> Result<KeyBundle> {
        Ok(self.daemon.get_key_bundle(context::current()).await??)
    }

    /// Gets the public device id.
    pub async fn get_device_id(&mut self) -> Result<DeviceId> {
        Ok(self.daemon.get_device_id(context::current()).await??)
    }

    /// Create a new graph/team with the current device as the owner.
    pub async fn create_team(&mut self) -> Result<TeamId> {
        Ok(self.daemon.create_team(context::current()).await??)
    }

    /// remove a team from the local device store.
    pub async fn add_team(&mut self, team: TeamId) -> Result<()> {
        Ok(self.daemon.add_team(context::current(), team).await??)
    }

    /// remove a team from the local device store.
    pub async fn remove_team(&mut self, _team: TeamId) -> Result<()> {
        todo!()
    }

    /// Get an existing team.
    pub fn team(&mut self, id: TeamId) -> Team<'_> {
        Team { client: self, id }
    }
}

pub struct Team<'a> {
    client: &'a mut Client,
    id: TeamId,
}

impl Team<'_> {
    /// Adds the peer for automatic periodic syncing.
    pub async fn add_sync_peer(&mut self, addr: Addr, interval: Duration) -> Result<()> {
        Ok(self
            .client
            .daemon
            .add_sync_peer(context::current(), addr, self.id, interval)
            .await??)
    }

    /// Removes the peer from automatic syncing.
    pub async fn remove_sync_peer(&mut self, addr: Addr) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_sync_peer(context::current(), addr, self.id)
            .await??)
    }

    /// close the team and stop all operations on the graph.
    pub async fn close_team(&mut self) -> Result<()> {
        Ok(self
            .client
            .daemon
            .close_team(context::current(), self.id)
            .await??)
    }

    /// add a device to the team with the default role
    pub async fn add_device_to_team(&mut self, keys: KeyBundle) -> Result<()> {
        Ok(self
            .client
            .daemon
            .add_device_to_team(context::current(), self.id, keys)
            .await??)
    }

    /// remove a device from the team
    pub async fn remove_device_from_team(&mut self, device: DeviceId) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_device_from_team(context::current(), self.id, device)
            .await??)
    }

    /// assign a role to a device
    pub async fn assign_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_role(context::current(), self.id, device, role)
            .await??)
    }

    /// remove a role from a device
    pub async fn revoke_role(&mut self, device: DeviceId, role: Role) -> Result<()> {
        Ok(self
            .client
            .daemon
            .revoke_role(context::current(), self.id, device, role)
            .await??)
    }

    /// associate a network address to a device for use with AFC.
    ///
    /// If the address already exists for this device, it is replaced with the new address. Capable
    /// of resolving addresses via DNS, required to be statically mapped to IPV4. For use with
    /// OpenChannel and receiving messages. Can take either DNS name or IPV4. MVP would need
    /// reverse lookup. TODO more work required on the address assignment. Currently one name per
    /// device.
    pub async fn assign_net_name(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_net_name(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// disassociate a network address from a device.
    pub async fn remove_net_name(
        &mut self,
        device: DeviceId,
        net_identifier: NetIdentifier,
    ) -> Result<()> {
        Ok(self
            .client
            .daemon
            .remove_net_name(context::current(), self.id, device, net_identifier)
            .await??)
    }

    /// create a label
    pub async fn create_label(&mut self, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .create_label(context::current(), self.id, label)
            .await??)
    }

    /// delete a label
    pub async fn delete_label(&mut self, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .delete_label(context::current(), self.id, label)
            .await??)
    }

    /// assign a label to a device so that it can be used for AFC
    pub async fn assign_label(&mut self, device: DeviceId, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .assign_label(context::current(), self.id, device, label)
            .await??)
    }

    /// revoke a label from a device
    pub async fn revoke_label(&mut self, device: DeviceId, label: Label) -> Result<()> {
        Ok(self
            .client
            .daemon
            .revoke_label(context::current(), self.id, device, label)
            .await??)
    }
}
