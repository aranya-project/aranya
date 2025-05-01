//! The Aranya Daemon IPC API.
//!
//! The Aranya Daemon IPC API is a shared interface between the Aranya client and
//! daemon. This crate mainly contains a trait that defines the RPC calls that
//! [`tarpc`] uses to communicate and also handles type conversions
//! between the external client and internal Aranya functionality.
//!
//! [`tarpc`]: https://crates.io/crates/tarpc
//!
//! For more information, refer to: <https://docs.rs/aranya-client>

mod service;

pub use service::*;
