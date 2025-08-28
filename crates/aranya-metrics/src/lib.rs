//! Metrics Collection for the Aranya Project.
//!
//! This crate contains tooling that allows for collecting various metrics from various systems
//! inside Aranya. This includes things like disk, memory, and cpu usage.
#![warn(clippy::missing_docs_in_private_items, missing_docs)]

pub mod backend;
pub mod harness;
