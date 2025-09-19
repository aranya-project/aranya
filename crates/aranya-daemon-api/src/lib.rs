//! Internal crate for `aranya-client` and `aranya-daemon`.
//!
//! This crate is an implementation detail for `aranya-client`
//! and `aranya-daemon` and is exposed out of necessity. It is
//! permanently unstable and does NOT promise backward
//! compatibility.

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "afc", not(feature = "preview")))]
compile_error!(
    "AFC is currently a preview feature. Enable the 'preview' feature to opt into preview APIs."
);

pub mod crypto;
mod service;

pub use service::*;
