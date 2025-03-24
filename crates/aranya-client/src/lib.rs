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

#[cfg(feature = "experimental")]
pub mod afc;
pub mod client;
pub mod error;

#[doc(inline)]
#[cfg(feature = "experimental")]
pub use crate::afc::{AfcId, FastChannels, Label, Message, PollData};
#[doc(inline)]
pub use crate::{
    client::{Client, Team},
    error::{AfcError, Error, Result},
};
