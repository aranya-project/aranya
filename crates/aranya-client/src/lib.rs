//! The Aranya client library.
//!
//! The Aranya Client library provides the following features to application developers:
//! - IDAM/RBAC/ABAC (identity & access management, role-based access controls, attribute-based access controls, security controls)
//! - Aranya Fast Channels (secure, encrypted bidirectional data transmission)
//!
//! For more information refer to:
//! - The `aranya-client` [README]
//! - The [walkthrough]
//!
//! [README]: https://github.com/aranya-project/aranya/tree/main/crates/aranya-client/README.md
//! [walkthrough]: https://github.com/aranya-project/aranya/tree/main/docs/walkthrough.md

pub mod aqc;
pub mod client;
pub mod config;
pub mod error;

#[doc(inline)]
pub use crate::{
    client::{Client, DeviceId, Label, LabelId, Role, RoleId, Team, TeamId},
    config::{SyncPeerConfig, SyncPeerConfigBuilder, TeamConfig, TeamConfigBuilder},
    error::{ConfigError, Error, Result},
};
