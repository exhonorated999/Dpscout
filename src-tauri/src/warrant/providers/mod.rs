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
