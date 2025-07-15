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

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aqc;
pub mod client;
pub mod config;
pub mod error;
pub mod sync;
mod util;

pub use aranya_policy_text::{text, Text};

#[doc(inline)]
pub use crate::{
    client::{
        ChanOp, Client, DeviceId, InvalidNetIdentifier, KeyBundle, Label, LabelId, Labels,
        NetIdentifier, Role, RoleId, Roles, Team, TeamId,
    },
    config::{
        QuicSyncConfig, QuicSyncConfigBuilder, SyncPeerConfig, SyncPeerConfigBuilder, TeamConfig,
        TeamConfigBuilder,
    },
    error::{ConfigError, Error, Result},
};
