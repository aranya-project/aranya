//! HPKE encryption context.
//!
//! [`Ctx`] holds the symmetric keys used to encrypt and decrypt messages between the client and
//! server. It is created during the initial handshake and refreshed on each rekey.
//!
//! After creation, the context can then be used standalone, or split via [`Ctx::into_parts`] to
//! obtain the encrypt and decrypt halves for separate reader/writer tasks.

use std::{fmt, io, iter};

use aranya_crypto::{
    dangerous::spideroak_crypto::{
        hpke::{self, Hpke, HpkeError, Mode, Seq},
        import::Import,
        kem::Kem,
    },
    CipherSuite, Csprng,
};
use buggy::BugExt as _;
use serde::{de::DeserializeOwned, Serialize};

use super::{Data, Side};
use crate::crypto::{ApiKey, PublicApiKey};

pub(super) type Encap<CS> = <<CS as CipherSuite>::Kem as Kem>::Encap;
pub(super) type SealCtx<CS> = hpke::SealCtx<<CS as CipherSuite>::Aead>;
pub(super) type OpenCtx<CS> = hpke::OpenCtx<<CS as CipherSuite>::Aead>;

/// HPKE encryption context for one side of a connection.
///
/// The client creates one the first time it tries to write to the server. It sends the HPKE peer
/// encapsulation to the server, then begins sending ciphertext.
///
/// The server creates one the first time it receives a HPKE peer encapsulation from the client.
pub(super) struct Ctx<CS: CipherSuite> {
    pub(super) seal: SealCtx<CS>,
    open: OpenCtx<CS>,
    side: Side,
}

impl<CS: CipherSuite> Ctx<CS> {
    // Contextual binding for exporting the server's encryption key and nonce.
    const SERVER_KEY_CTX: &[u8] = b"aranya daemon api server seal key";
    const SERVER_NONCE_CTX: &[u8] = b"aranya daemon api server seal nonce";

    /// Creates the HPKE encryption context for the client.
    ///
    /// Returns the context and the HPKE encapsulation that must be sent to the server (via a
    /// `Rekey` message) so it can derive the matching context.
    pub(super) fn client<R: Csprng>(
        rng: R,
        pk: &PublicApiKey<CS>,
        info: &[u8],
    ) -> Result<(Self, Encap<CS>), HpkeError> {
        let (enc, send) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send(
            rng,
            Mode::Base,
            pk.as_inner(),
            iter::once(info),
        )?;
        // NB: These are the reverse of the server's keys.
        let (open_key, open_nonce) = {
            let key = send.export(Self::SERVER_KEY_CTX)?;
            let nonce = send.export(Self::SERVER_NONCE_CTX)?;
            (key, nonce)
        };
        let (seal_key, seal_nonce) = send
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;

        let ctx = Self {
            seal: hpke::SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?,
            open: hpke::OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?,
            side: Side::Client,
        };
        Ok((ctx, enc))
    }

    /// Creates the HPKE encryption context for the server.
    ///
    /// `enc` is the HPKE encapsulation received from the client in a `Rekey` message.
    pub(super) fn server(sk: &ApiKey<CS>, info: &[u8], enc: &[u8]) -> Result<Self, HpkeError> {
        let enc = Encap::<CS>::import(enc)?;

        let recv = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
            Mode::Base,
            &enc,
            sk.as_inner(),
            iter::once(info),
        )?;
        // NB: These are the reverse of the client's keys.
        let (seal_key, seal_nonce) = {
            let key = recv.export(Self::SERVER_KEY_CTX)?;
            let nonce = recv.export(Self::SERVER_NONCE_CTX)?;
            (key, nonce)
        };
        let (open_key, open_nonce) = recv
            .into_raw_parts()
            .assume("should be able to decompose `SendCtx`")?;

        Ok(Self {
            seal: hpke::SealCtx::new(&seal_key, &seal_nonce, Seq::ZERO)?,
            open: hpke::OpenCtx::new(&open_key, &open_nonce, Seq::ZERO)?,
            side: Side::Server,
        })
    }

    /// Serializes `item`, encrypts and authenticates the resulting bytes, and returns the
    /// ciphertext.
    ///
    /// `side` represents the current side performing the encryption.
    pub(super) fn encrypt<T: Serialize>(&mut self, item: &T) -> io::Result<Data> {
        super::seal::<CS, _>(&mut self.seal, item, self.side)
    }

    /// Decrypts and authenticates `data`, then deserializes the resulting plaintext and returns the
    /// resulting `Item`.
    ///
    /// `side` represents the side that created `data`.
    pub(super) fn decrypt<T: DeserializeOwned>(&mut self, data: Data) -> io::Result<T> {
        super::open::<CS, _>(&mut self.open, data, self.side)
    }

    /// Destructure into seal and open halves.
    ///
    /// Used by `into_split()` to distribute the halves into the writer and reader.
    pub(super) fn into_parts(self) -> (SealCtx<CS>, OpenCtx<CS>) {
        (self.seal, self.open)
    }
}

impl<CS: CipherSuite> fmt::Debug for Ctx<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx")
            .field("side", &self.side)
            .finish_non_exhaustive()
    }
}
