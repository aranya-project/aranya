//! Utilities for encrypting/decrypting onboarding data and passing it between peers.

use age::secrecy::SecretString;
use anyhow::Result;
use aranya_util::Addr;
use serde::{Deserialize, Serialize};

use crate::{
    age::AgeEncryptor,
    tcp::{TcpClient, TcpServer},
};

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
