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

#[cfg(all(feature = "aqc", not(feature = "experimental")))]
compile_error!(
    "AQC is currently experimental. Enable the 'experimental' feature to opt into experimental APIs."
);

#[cfg(all(feature = "afc", not(feature = "preview")))]
compile_error!(
    "AFC is currently a preview feature. Enable the 'preview' feature to opt into preview APIs."
);

#[cfg(feature = "afc")]
pub mod afc;
pub mod aqc;
pub mod client;
pub mod config;
pub mod error;

#[doc(inline)]
pub use crate::{
    client::{Client, DeviceId, LabelId, Team, TeamId},
    config::{
        AddTeamConfig, AddTeamConfigBuilder, AddTeamQuicSyncConfig, CreateTeamConfig,
        CreateTeamConfigBuilder, CreateTeamQuicSyncConfig, CreateTeamQuicSyncConfigBuilder,
        SyncPeerConfig, SyncPeerConfigBuilder,
    },
    error::{ConfigError, Error, Result},
};
