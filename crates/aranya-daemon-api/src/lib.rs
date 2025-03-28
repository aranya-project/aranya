//! The Aranya Daemon API.
//!
//! The Aranya Daemon API is the interface between the Aranya client and
//! daemon. This crate is set-up for the client and daemon to use [`tarpc`]
//! over Unix domain sockets to communicate and also handles type conversions
//! between the external client and internal Aranya functionality.
//!
//! [`tarpc`]: https://crates.io/crates/tarpc
//!
//! For more information, refer to:
//! - The [`aranya-client` README]
//! - The [`aranya-daemon` README]
//!
//! [`aranya-client` README]: https://github.com/aranya-project/aranya/tree/main/crates/aranya-client/README.md
//! [`aranya-daemon` README]: https://github.com/aranya-project/aranya/tree/main/crates/aranya-daemon/README.md

mod service;

pub use service::*;
