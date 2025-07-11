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
#![warn(
    clippy::alloc_instead_of_core,
    clippy::implicit_saturating_sub,
    clippy::missing_panics_doc,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::unimplemented,
    missing_docs
)]

pub mod aqc;
pub mod client;
pub mod config;
pub mod error;

#[doc(inline)]
pub use crate::{
    client::{Client, Team},
    config::{
        AddTeamConfig, AddTeamConfigBuilder, AddTeamQuicSyncConfig, CreateTeamConfig,
        CreateTeamConfigBuilder, CreateTeamQuicSyncConfig, CreateTeamQuicSyncConfigBuilder,
        SyncPeerConfig, SyncPeerConfigBuilder,
    },
    error::{ConfigError, Error, Result},
};
