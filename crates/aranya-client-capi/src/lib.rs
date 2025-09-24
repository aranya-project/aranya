//! Client C API.

#![warn(
    clippy::alloc_instead_of_core,
    clippy::implicit_saturating_sub,
    clippy::missing_panics_doc,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::unimplemented,
    missing_docs
)]

#[cfg(all(feature = "aqc", not(feature = "experimental")))]
compile_error!(
    "AQC is currently experimental. Enable the 'experimental' feature to opt into experimental APIs."
);

pub mod api;
pub(crate) mod imp;
