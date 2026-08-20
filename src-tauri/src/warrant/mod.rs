//! Warrant Triage — parses search-warrant returns from social-media providers.
//!
//! Architecture
//! ============
//! A `WarrantParser` trait abstracts over each provider's format.  The
//! [`registry`] module wires up one parser per [`Provider`] variant.  The
//! frontend picks a provider, hands a file path to [`registry::parse`], and
//! receives a [`ParsedReturn`] which is a flat list of [`WarrantItem`]s
//! plus case metadata.
//!
//! Triage state (bucket assignments, notes, save/load) lives in
//! [`triage_state`] and is wired up to Tauri commands by Step 3 of the
//! milestone plan.

pub mod providers;
pub mod triage_state;
pub mod report;
pub mod report_investigation;
pub mod commands;
pub mod scan;
pub mod investigation;
pub mod sample;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Provider identity ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Meta,
    Snapchat,
    Kik,
    Discord,
    Google,
    Yahoo,
    X,
    WhatsApp,
}

impl Provider {
    pub fn display_name(self) -> &'static str {
        match self {
            Provider::Meta => "Meta (Facebook/Instagram)",
            Provider::Snapchat => "Snapchat",
            Provider::Kik => "KIK",
            Provider::Discord => "Discord",
            Provider::Google => "Google",
            Provider::Yahoo => "Yahoo",
            Provider::X => "X (Twitter)",
            Provider::WhatsApp => "WhatsApp",
        }
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ParseError {
    NotImplemented,
    WrongFormat,
    Io(std::io::Error),
    Zip(zip::result::ZipError),
    Other(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::NotImplemented => write!(f, "provider parser not implemented yet"),
            ParseError::WrongFormat => {
                write!(f, "file does not match the expected format for this provider")
            }
            ParseError::Io(e) => write!(f, "I/O error: {}", e),
            ParseError::Zip(e) => write!(f, "zip error: {}", e),
            ParseError::Other(s) => write!(f, "parse error: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

impl From<zip::result::ZipError> for ParseError {
    fn from(e: zip::result::ZipError) -> Self {
        ParseError::Zip(e)
    }
}

// `thiserror` isn't yet in Cargo.toml — hand-rolled Display above keeps the
// dep tree minimal.  If error variants grow, consider pulling it in.

// ─── Case + items ────────────────────────────────────────────────────────

/// Top-level case metadata extracted during parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WarrantCase {
    pub case_id: String,                 // generated uuid
    pub provider: Provider,
    pub provider_display: String,        // e.g. "Meta (Facebook)"
    pub source_filename: String,
    pub imported_at: String,             // RFC3339
    pub target_account: Option<String>,  // e.g. Meta Account Identifier
    pub date_range: Option<String>,
    pub generated_at_source: Option<String>, // Meta "Generated" timestamp
    /// Working directory where extracted media lives, relative to
    /// the app's warrant_cases root.  Set by the registry, not the parser.
    pub media_root: Option<String>,
}

/// A single triageable item — a message, a photo, an IP event, etc.
/// Every section across every provider is flattened into this shape so the
/// UI can show one unified list with section filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WarrantItem {
    pub id: String,                     // stable per-case id, e.g. "msg-001"
    pub section: String,                // provider section, e.g. "unified_messages"
    pub section_display: String,        // pretty label for UI, e.g. "Messages"
    pub timestamp: Option<String>,      // best-effort, source format preserved
    pub author: Option<String>,
    pub recipient: Option<String>,
    pub body_text: Option<String>,
    pub summary: Option<String>,        // one-line tile preview
    pub raw_fields: serde_json::Value,  // every field the parser saw
    pub attachments: Vec<String>,       // linked_media filenames (relative)
    // Triage state — populated by the user, persisted in .scoutcase
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub is_flagged: bool,
}

/// What [`WarrantParser::parse`] returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedReturn {
    pub case: WarrantCase,
    pub items: Vec<WarrantItem>,
    pub default_buckets: Vec<BucketTemplate>,
}

// ─── Buckets ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketTemplate {
    pub name: String,
    pub color: String,    // hex, e.g. "#ef4444"
    pub description: Option<String>,
}

// ─── The parser trait ────────────────────────────────────────────────────

/// One impl per provider.  Implementations live in [`providers`].
pub trait WarrantParser: Send + Sync {
    fn provider(&self) -> Provider;

    /// Cheap sanity check on a user-picked file BEFORE we attempt to fully
    /// parse it.  Should be fast (open zip, look at a couple entries).
    /// Returns Ok(true) if this parser recognises the file, Ok(false) if
    /// not.  Errors are reserved for I/O.
    fn accepts(&self, path: &Path) -> Result<bool, ParseError>;

    /// Parse the file.  The parser should NOT extract media to disk — the
    /// registry handles that and rewrites `WarrantItem::attachments`
    /// entries to point at the extracted paths.
    fn parse(
        &self,
        path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError>;

    /// Default bucket set for this provider.  Shown pre-seeded in the
    /// triage UI; user can rename/add/delete.
    fn default_buckets(&self) -> Vec<BucketTemplate>;
}

// ─── Registry ────────────────────────────────────────────────────────────

pub mod registry {
    use super::*;

    /// Build the runtime list of parsers.  Order matters for the UI tiles:
    /// Meta first, then the (currently stub) providers.
    pub fn all() -> Vec<Box<dyn WarrantParser>> {
        vec![
            Box::new(super::providers::meta::MetaWarrantParser::new()),
            Box::new(super::providers::snapchat::SnapchatWarrantParser),
            Box::new(super::providers::kik::KikWarrantParser),
            Box::new(super::providers::discord::DiscordWarrantParser),
            Box::new(super::providers::google::GoogleWarrantParser),
            Box::new(super::providers::yahoo::YahooWarrantParser),
            Box::new(super::providers::x::XWarrantParser),
            Box::new(super::providers::whatsapp::WhatsAppWarrantParser),
        ]
    }

    /// Look up the parser for a given provider.
    pub fn for_provider(p: Provider) -> Option<Box<dyn WarrantParser>> {
        match p {
            Provider::Meta => Some(Box::new(super::providers::meta::MetaWarrantParser::new())),
            Provider::Snapchat => Some(Box::new(super::providers::snapchat::SnapchatWarrantParser)),
            Provider::Kik => Some(Box::new(super::providers::kik::KikWarrantParser)),
            Provider::Discord => Some(Box::new(super::providers::discord::DiscordWarrantParser)),
            Provider::Google => Some(Box::new(super::providers::google::GoogleWarrantParser)),
            Provider::Yahoo => Some(Box::new(super::providers::yahoo::YahooWarrantParser)),
            Provider::X => Some(Box::new(super::providers::x::XWarrantParser)),
            Provider::WhatsApp => Some(Box::new(super::providers::whatsapp::WhatsAppWarrantParser)),
        }
    }

    /// Convenience helper for callers that just want "parse this".
    pub fn parse(
        provider: Provider,
        zip_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        let parser =
            for_provider(provider).ok_or_else(|| ParseError::Other("unknown provider".into()))?;
        parser.parse(zip_path, media_extract_dir)
    }
}

// ─── Small helper used across providers ──────────────────────────────────

/// Get the OS-temp / app-local "warrant_cases" root.  Each case lives in
/// `<root>/<case_id>/media/`.  Pure path math — does not create dirs.
pub fn cases_root() -> PathBuf {
    crate::app_paths::cases_root()
}
