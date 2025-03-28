//! The Aranya Daemon API.
//!
//! The Aranya Daemon API is the interface between the Aranya client and
//! daemon. This crate is set-up for the client and daemon to use [`tarpc`]
//! over Unix domain sockets to communicate and also handles type conversions
//! between the external client and internal Aranya functionality.
//!
//! [`tarpc`]: https://crates.io/crates/tarpc
//!
//! For more information, refer to: https://docs.rs/aranya-client/latest/aranya_client/

mod service;

pub use service::*;
