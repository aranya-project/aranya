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

pub mod api;
pub(crate) mod imp;
