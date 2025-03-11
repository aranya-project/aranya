//! # Aranya Client
//! The `aranya-client` library is the main way to interact with Aranya.
//!
//! This provides a high level API to communicate with an [`aranya-daemon`] instance,
//! including adding and removing peers to sync with, managing permissions
//! for various devices,
//!
//! The Aranya client library.
//!
//! The Aranya Client library provides the following features to application
//! developers:
//! - IDAM/RBAC/ABAC (identity & access management, role-based access controls,
//!   attribute-based access controls, security controls)
//! - Aranya Fast Channels (secure, encrypted bidirectional data transmission)
//!
//! For more information refer to:
//! - The `aranya-client` [README]
//! - The [walkthrough]
//!
//! [README]:
//!     https://github.com/aranya-project/aranya/tree/main/crates/aranya-client/README.md
//! [walkthrough]:
//!     https://github.com/aranya-project/aranya/tree/main/docs/walkthrough.md
//! [`aranya-daemon`]: <https://docs.rs/aranya-daemon>

pub mod afc;
pub mod client;
pub mod prelude;

mod error;

#[doc(inline)]
pub use crate::{
    client::Client,
    error::{Error, Result},
};
