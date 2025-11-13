//! Client C API.

#[doc(hidden)]
pub mod defs;

#[allow(missing_docs)]
#[allow(clippy::transmute_ptr_to_ptr)]
#[allow(non_upper_case_globals)]
#[allow(unused_attributes)]
#[allow(unused_imports)]
#[allow(unused_qualifications)]
#[allow(unused_unsafe)]
#[allow(clippy::undocumented_unsafe_blocks)]
#[allow(rustdoc::broken_intra_doc_links)]
#[rustfmt::skip]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}
pub use generated::*;
