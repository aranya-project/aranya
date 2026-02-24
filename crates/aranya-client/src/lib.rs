//! The Aranya client library.
//!
//! The Aranya Client library provides the following features to application developers:
//! - IDAM/RBAC/ABAC (identity & access management, role-based access controls, attribute-based access controls, security controls)
//! - Aranya Fast Channels (secure, encrypted data transmission)
//!
//! For more information refer to:
//! - The `aranya-client` [README]
//! - The [walkthrough]
//!
//! [README]: https://github.com/aranya-project/aranya/tree/main/crates/aranya-client/README.md
//! [walkthrough]: https://github.com/aranya-project/aranya/tree/main/docs/walkthrough.md

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::implicit_saturating_sub,
    clippy::missing_panics_doc,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::unimplemented,
    missing_docs
)]

// TODO: https://github.com/aranya-project/aranya/issues/448
#[cfg(not(feature = "default"))]
compile_error!("'default' feature must be enabled!");

pub mod afc;
pub mod client;
pub mod config;
pub mod error;
mod util;

pub use aranya_daemon_api::{ObjectId, Rank};
pub use aranya_policy_text::{text, Text};
pub use aranya_util::Addr;

#[doc(inline)]
pub use crate::client::Permission;
#[cfg(feature = "preview")]
#[cfg_attr(docsrs, doc(cfg(feature = "preview")))]
#[doc(inline)]
pub use crate::config::{HelloSubscriptionConfig, HelloSubscriptionConfigBuilder};
#[doc(inline)]
pub use crate::{
    client::{
        ChanOp, Client, Device, DeviceId, Devices, Label, LabelId, Labels, PublicKeyBundle, Role,
        RoleId, Roles, Team, TeamId,
    },
    config::{
        AddTeamConfig, AddTeamConfigBuilder, AddTeamQuicSyncConfig, CreateTeamConfig,
        CreateTeamConfigBuilder, CreateTeamQuicSyncConfig, CreateTeamQuicSyncConfigBuilder,
        SyncPeerConfig, SyncPeerConfigBuilder,
    },
    error::{ConfigError, Error, Result},
};
