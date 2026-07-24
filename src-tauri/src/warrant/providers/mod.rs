//! One submodule per provider.
//!
//! Only `meta` is implemented in the MVP.  The other modules contain stub
//! parsers that return `ParseError::NotImplemented` — this keeps the UI
//! tile / registry shape stable so adding a real implementation later is
//! purely additive.

pub mod meta;

pub mod snapchat;
pub mod kik;
pub mod discord;
pub mod google;
pub mod yahoo;
pub mod x;
pub mod whatsapp;

/// Generic catalog fallback used when a provider parser rejects a return and
/// the operator consents to a degraded import.  Not a `Provider` variant.
pub mod generic;

// Shared utilities used by multiple providers.
pub(crate) mod mbox_lib;
