//! Client C API.

#![warn(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::implicit_saturating_sub,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications,
    missing_docs
)]

pub mod api;
pub(crate) mod imp;
