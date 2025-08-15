//! Utilities for encrypting/decrypting onboarding data and passing it between peers.

use std::time::Duration;

use age::secrecy::SecretString;
use anyhow::Result;
use aranya_daemon_api::{DeviceId, KeyBundle, TeamId};
use aranya_util::Addr;
use serde::{Deserialize, Serialize};

use crate::{
    age::AgeEncryptor,
    tcp::{TcpClient, TcpServer},
};

/// How long to wait between syncs.
pub const SYNC_INTERVAL: Duration = Duration::from_millis(100);
/// How long to wait to sync new effects.
pub const SLEEP_INTERVAL: Duration = Duration::from_millis(600);

/// Team info sent from team owner to other devices during onboarding.
#[derive(Debug, Serialize, Deserialize)]
pub struct TeamInfo {
    /// Aranya team ID.
    pub team_id: TeamId,
    /// QUIC syncer seed IKM (initial key material).
    pub seed_ikm: [u8; 32],
}

/// Device info sent between peers during onboarding.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device name.
    pub name: String,
    /// Device ID.
    pub device_id: DeviceId,
    /// Device public key bundle.
    pub pk: KeyBundle,
}

/// Object for simplifying Aranya team onboarding.
/// Sends/receives serialized, encrypted team info for onboarding such as:
/// - Team ID
/// - Device ID
/// - Device public key bundles
#[derive(Debug)]
pub struct Onboard {
    /// `age` encryptor for encrypting/decrypting onboarding data with a passphrase.
    encryptor: AgeEncryptor,
    /// TCP server for receiving onboarding data.
    server: TcpServer,
}

impl Onboard {
    /// Create a new instance of the onboarding object.
    pub async fn new(tcp_addr: Addr, passphrase: SecretString) -> Result<Self> {
        let encryptor = AgeEncryptor::new(passphrase);
        let server = TcpServer::bind(tcp_addr).await?;
        Ok(Self { encryptor, server })
    }

    /// Send onboarding data. Serialize, encrypt, then send over TCP.
    pub async fn send<T>(&self, data: &T, peer: Addr) -> Result<()>
    where
        T: Serialize,
    {
        let mut stream = TcpClient::connect(peer).await?;
        let serialized = postcard::to_allocvec::<T>(data)?;
        let ciphertext = self.encryptor.encrypt(&serialized)?;
        stream.send(&ciphertext).await?;

        Ok(())
    }

    /// Receive onboarding data. Receive ciphertext via TCP, decrypt, deserialize.
    pub async fn recv<T>(&self) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        let ciphertext = self.server.recv().await?;
        let plaintext = self.encryptor.decrypt(&ciphertext)?;
        let deserialized: T = postcard::from_bytes(&plaintext)?;

        Ok(deserialized)
    }
}
