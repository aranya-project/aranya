//! The Daemon library.
//!
//! This crate is an implementation detail for the
//! `aranya-daemon` executable. It is permanently unstable and
//! does NOT promise backward compatibility.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unstable_name_collisions)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::implicit_saturating_sub,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::transmute_ptr_to_ptr,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(all(feature = "aqc", not(feature = "experimental")))]
compile_error!(
    "AQC is currently experimental. Enable the 'experimental' feature to opt into experimental APIs."
);

pub mod actions;
pub mod aranya;
pub mod config;
#[rustfmt::skip]
pub mod policy;
pub mod sync;
pub mod vm_policy;

#[cfg(feature = "afc")]
mod afc;
mod api;
mod aqc;
mod daemon;
mod keystore;
mod util;

#[cfg(test)]
mod test;

pub use aranya_util::Addr;
pub use daemon::*;
pub use keystore::AranyaStore;

#[cfg(all(feature = "afc", not(feature = "preview")))]
compile_error!(
    "AFC is currently a preview feature. Enable the 'preview' feature to opt into preview APIs."
);
