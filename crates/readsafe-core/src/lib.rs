//! readsafe-core: parsing, classification, redaction, and narrow updates
//! for sensitive structured files.
//!
//! # Output non-disclosure rules
//!
//! Everything this crate exposes for rendering — manifests, scan metadata,
//! errors, validation reasons — is built from structural identifiers and
//! fixed strings. Raw file values live only in [`dotenv::Entry::value`] and
//! the transient `serde_json::Value`s inside [`jsonish`]; they are consumed
//! in-process and never formatted into any output type. Error reasons are
//! `&'static str` by construction (see [`error::SafeError`]) so a value
//! cannot reach an error message.

pub mod classify;
pub mod dotenv;
pub mod error;
pub mod fsops;
pub mod jsonish;
pub mod manifest;
pub mod validators;
