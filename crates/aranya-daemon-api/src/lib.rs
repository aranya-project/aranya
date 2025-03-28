//! The Aranya Daemon API.
//!
//! The Aranya Daemon API is a shared interface between the Aranya client and
//! daemon. This crate mainly contains a trait that defines the RPC calls that
//! [`tarpc`] uses to communicate and also handles type conversions
//! between the external client and internal Aranya functionality.
//!
//! [`tarpc`]: https://crates.io/crates/tarpc
//!
//! For more information, refer to: https://docs.rs/aranya-client/latest/aranya_client/

mod service;

pub use service::*;
