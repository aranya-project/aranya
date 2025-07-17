#![warn(clippy::missing_docs_in_private_items, missing_docs)]
//! Metrics Collection for the Aranya Project.
//!
//! This crate contains tooling that allows for collecting various metrics from various systems
//! inside Aranya. This includes things like disk, memory, and cpu usage.

pub mod backend;
pub mod harness;
