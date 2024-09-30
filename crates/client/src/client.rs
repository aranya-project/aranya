use std::{path::Path, time::Duration};

use daemon_api::{
    Addr, ApsCtrl, ChannelId, DaemonApiClient, DeviceId, KeyBundle, Label, NetIdentifier, Role,
    TeamId,
};
use tarpc::{context, tokio_serde::formats::Json};
use tracing::{debug, info, instrument};

use crate::{Error, Result};

pub struct Client {
    daemon: DaemonApiClient,
    // TODO: APS Router.
}

impl Client {
    /// Creates a client connected to the daemon.
    #[instrument(skip_all)]
    pub async fn connect(daemon_sock: &Path) -> Result<Self> {
        info!("uds path: {:?}", daemon_sock);
        let transport = tarpc::serde_transport::unix::connect(daemon_sock, Json::default)
            .await
            .map_err(Error::Connecting)?;
        let daemon = DaemonApiClient::new(tarpc::client::Config::default(), transport).spawn();
        debug!("connected to: {:?}", daemon_sock);
        Ok(Self { daemon })
    }

    pub async fn create_channel(
        &mut self,
        team: TeamId,
        peer: NetIdentifier,
        label: Label,
    ) -> Result<ChannelId> {
        let (_chan, _node, _ctrl) = self
            .daemon
            .create_channel(context::current(), team, peer, label)
            .await??;
        // TODO: APS Router.
        //self.aps.send_ctrl(chan, ctrl).await;
        //Ok(chan)
        todo!()
    }

    pub async fn delete_channel(&mut self, chan: ChannelId) -> Result<()> {
        let _ctrl = self
            .daemon
            .delete_channel(context::current(), chan)
            .await??;
        // TODO: APS Router.
        //self.aps.send_ctrl(chan, ctrl).await;
        todo!()
    }

    pub async fn receive_aps_ctrl(&mut self, ctrl: ApsCtrl) -> Result<()> {
        self.daemon
            .receive_aps_ctrl(context::current(), ctrl)
            .await??;
        todo!()
    }

    pub async fn send_data(&mut self, _chan: ChannelId, _data: Vec<u8>) {
        // TODO: APS Router.
        //self.aps.send_data(chan, data).await;
        todo!()
    }

    pub async fn recv_data(&mut self) -> Option<(ChannelId, Vec<u8>)> {
        // TODO: APS Router.
        //self.aps.recv_data().await
        todo!()
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

    /// associate a network address to a device for use with APS.
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

    /// assign a label to a device so that it can be used for APS
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
