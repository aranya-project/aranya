//! Internal crate for `aranya-client` and `aranya-daemon`.
//!
//! This crate is an implementation detail for `aranya-client`
//! and `aranya-daemon`. It is exposed out of necessity. It is
//! permanently unstable and does NOT promise backward
//! compatibility.

pub mod crypto;
mod service;

pub use service::*;
