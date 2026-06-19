//! Warrant **structural sample** builder.
//!
//! Goal
//! ====
//! Walk a warrant return (directory or `.zip`) and produce a JSON envelope
//! that describes the *shape* of every file inside — directory layout,
//! file extensions/formats, key trees, HTML tag structure, CSV headers,
//! MBOX header-name frequency, etc. — while **never** capturing case
//! content (no message bodies, no header values, no CSV cell values,
//! no PDF text) and **never** capturing identifying filenames.
//!
//! Submitters of unsupported warrant formats use this to send the parser
//! author enough information to write a real parser without exposing any
//! evidence.
//!
//! Privacy model
//! -------------
//! * Filenames are replaced with `file_NNN.ext` (sequential per parent
//!   directory) — parsers should not rely on filenames, only on location
//!   + file type.
//! * Directory components matching PII shapes (email / phone / UUID /
//!   high-entropy id) are replaced with `<redacted-*>` placeholders.
//!   Structural folder names (`Messages`, `Attachments`, etc.) are kept.
//! * Per-file `structure` blocks contain only counts, type tags, and
//!   format inferences — never raw values.
//!
//! Phase 1 scope (this PR)
//! -----------------------
//! - Core types + envelope schema
//! - Recursive walker (handles directories AND `.zip` files transparently)
//! - Per-format structural fingerprint dispatchers (JSON, HTML, CSV/TSV,
//!   MBOX, PDF, binary)
//! - Value-format inference (timestamps / uuid / email / phone / url / etc.)
//! - Path sanitization (filename redaction + PII-shape directory scrub)
//!
//! Phase 2 (next PR): Tauri commands + frontend UI.
//! Phase 3 (later): Server endpoint + admin dashboard.

pub mod format_infer;
pub mod json_schema;
pub mod html_fp;
pub mod csv_fp;
pub mod mbox_fp;
pub mod pdf_fp;
pub mod path_sanitize;

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

// ─── Limits & knobs ──────────────────────────────────────────────────────

/// Per-file inspection cap (bytes).  Files larger than this still get a
/// path/size/ext entry but `structure` is set to `Skipped("too_large")`.
/// JSON / HTML / MBOX inspectors stream-process inside this budget.
pub const PER_FILE_BUDGET_BYTES: u64 = 64 * 1024 * 1024; // 64 MB

/// Maximum total files captured in one envelope.  Stops the walk after this
/// (extras counted in `root_summary.truncated_files`).
pub const MAX_FILES: usize = 50_000;

/// Maximum depth captured for HTML / JSON trees.  Deeper nodes summarised.
pub const MAX_STRUCTURE_DEPTH: usize = 32;

/// Per-tree node cap (HTML / JSON).  Beyond this we stop recording siblings.
pub const MAX_NODES_PER_FILE: usize = 100_000;

/// Total envelope size soft cap (bytes).  Walker stops adding rich
/// `structure` objects past this — falls back to file-summary entries.
pub const ENVELOPE_SOFT_CAP_BYTES: usize = 8 * 1024 * 1024; // 8 MB

// ─── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SampleError {
    Io(std::io::Error),
    Zip(zip::result::ZipError),
    Json(serde_json::Error),
    Other(String),
}

impl std::fmt::Display for SampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SampleError::Io(e) => write!(f, "I/O error: {}", e),
            SampleError::Zip(e) => write!(f, "zip error: {}", e),
            SampleError::Json(e) => write!(f, "json error: {}", e),
            SampleError::Other(s) => write!(f, "sample error: {}", s),
        }
    }
}

impl std::error::Error for SampleError {}

impl From<std::io::Error> for SampleError {
    fn from(e: std::io::Error) -> Self { SampleError::Io(e) }
}
impl From<zip::result::ZipError> for SampleError {
    fn from(e: zip::result::ZipError) -> Self { SampleError::Zip(e) }
}
impl From<serde_json::Error> for SampleError {
    fn from(e: serde_json::Error) -> Self { SampleError::Json(e) }
}

// ─── Envelope schema (the JSON we send to the server) ────────────────────

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleEnvelope {
    pub schema_version: u32,
    pub scout_version: String,
    pub submitted_at: String,
    pub provider_hint: String,
    pub submitter_email: String,
    pub submitter_notes: String,
    pub agency_name: String,
    pub license_key_last4: String,
    pub root_summary: RootSummary,
    pub tree: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RootSummary {
    pub total_files: usize,
    pub total_bytes: u64,
    pub max_depth: usize,
    /// Files that exceeded `MAX_FILES` and were skipped from `tree`.
    #[serde(default)]
    pub truncated_files: usize,
    /// Distribution of detected formats: `{"html": 312, "json": 45, ...}`
    pub format_counts: std::collections::BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub ext: String,
    pub format: String,
    /// Format-specific structural fingerprint.  Untyped JSON so each
    /// inspector can shape it freely.
    pub structure: serde_json::Value,
}

// ─── Detected formats ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    Json,
    Html,
    Csv,
    Tsv,
    Mbox,
    Eml,
    Pdf,
    Xml,
    Text,
    Binary,
}

impl DetectedFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            DetectedFormat::Json => "json",
            DetectedFormat::Html => "html",
            DetectedFormat::Csv => "csv",
            DetectedFormat::Tsv => "tsv",
            DetectedFormat::Mbox => "mbox",
            DetectedFormat::Eml => "eml",
            DetectedFormat::Pdf => "pdf",
            DetectedFormat::Xml => "xml",
            DetectedFormat::Text => "text",
            DetectedFormat::Binary => "binary",
        }
    }
}

/// Decide format from extension first, then peek at content if ambiguous.
pub fn detect_format(path: &Path, peek: &[u8]) -> DetectedFormat {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "json" => DetectedFormat::Json,
        "html" | "htm" | "xhtml" => DetectedFormat::Html,
        "csv" => DetectedFormat::Csv,
        "tsv" => DetectedFormat::Tsv,
        "mbox" | "mboxrd" | "mbx" => DetectedFormat::Mbox,
        "eml" | "msg" => DetectedFormat::Eml,
        "pdf" => DetectedFormat::Pdf,
        "xml" => DetectedFormat::Xml,
        "txt" | "log" | "md" => DetectedFormat::Text,
        _ => sniff_format(peek),
    }
}

fn sniff_format(peek: &[u8]) -> DetectedFormat {
    if peek.starts_with(b"%PDF-") {
        return DetectedFormat::Pdf;
    }
    // Strip BOM
    let head = if peek.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &peek[3..]
    } else {
        peek
    };
    let head_trim = head
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(64)
        .collect::<Vec<u8>>();

    if head_trim.starts_with(b"<!DOCTYPE html") || head_trim.starts_with(b"<html")
        || head_trim.starts_with(b"<HTML") {
        return DetectedFormat::Html;
    }
    if head_trim.starts_with(b"<?xml") || head_trim.starts_with(b"<") {
        return DetectedFormat::Xml;
    }
    if head_trim.first() == Some(&b'{') || head_trim.first() == Some(&b'[') {
        return DetectedFormat::Json;
    }
    if head.starts_with(b"From ") {
        return DetectedFormat::Mbox;
    }
    // Heuristic: mostly-ASCII printable -> text
    let printable = head.iter().take(512)
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if head.len() >= 16 && printable * 10 >= head.len().min(512) * 9 {
        DetectedFormat::Text
    } else {
        DetectedFormat::Binary
    }
}

// ─── Build options ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub provider_hint: String,
    pub submitter_email: String,
    pub submitter_notes: String,
    pub agency_name: String,
    pub license_key_last4: String,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            provider_hint: String::new(),
            submitter_email: String::new(),
            submitter_notes: String::new(),
            agency_name: String::new(),
            license_key_last4: String::new(),
        }
    }
}

// ─── Top-level: build envelope from path ─────────────────────────────────

/// Build a structural sample envelope from a folder OR a `.zip` file.
pub fn build_envelope(
    root: &Path,
    opts: BuildOptions,
) -> Result<SampleEnvelope, SampleError> {
    let mut entries: Vec<FileEntry> = Vec::new();
    let mut summary = RootSummary::default();
    let mut envelope_bytes: usize = 0;
    let mut sanitizer = path_sanitize::PathSanitizer::new();

    if root.is_file()
        && root.extension().and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("zip")).unwrap_or(false)
    {
        walk_zip(root, &mut entries, &mut summary, &mut envelope_bytes, &mut sanitizer)?;
    } else if root.is_dir() {
        walk_dir(root, &mut entries, &mut summary, &mut envelope_bytes, &mut sanitizer)?;
    } else {
        return Err(SampleError::Other(format!(
            "root path is neither a directory nor a .zip: {}",
            root.display()
        )));
    }

    let envelope = SampleEnvelope {
        schema_version: SCHEMA_VERSION,
        scout_version: env!("CARGO_PKG_VERSION").to_string(),
        submitted_at: chrono::Utc::now().to_rfc3339(),
        provider_hint: opts.provider_hint,
        submitter_email: opts.submitter_email,
        submitter_notes: opts.submitter_notes,
        agency_name: opts.agency_name,
        license_key_last4: opts.license_key_last4,
        root_summary: summary,
        tree: entries,
    };

    Ok(envelope)
}

// ─── Directory walker ────────────────────────────────────────────────────

fn walk_dir(
    root: &Path,
    entries: &mut Vec<FileEntry>,
    summary: &mut RootSummary,
    envelope_bytes: &mut usize,
    sanitizer: &mut path_sanitize::PathSanitizer,
) -> Result<(), SampleError> {
    use walkdir::WalkDir;

    for de in WalkDir::new(root).follow_links(false) {
        let de = match de {
            Ok(d) => d,
            Err(_) => continue,
        };
        if !de.file_type().is_file() {
            continue;
        }
        if entries.len() >= MAX_FILES {
            summary.truncated_files += 1;
            continue;
        }

        let abs = de.path();
        let rel = abs.strip_prefix(root).unwrap_or(abs).to_path_buf();
        let depth = rel.components().count();
        if depth > summary.max_depth {
            summary.max_depth = depth;
        }

        let size = de.metadata().map(|m| m.len()).unwrap_or(0);
        summary.total_bytes = summary.total_bytes.saturating_add(size);

        let entry = inspect_file_from_disk(&rel, abs, size, *envelope_bytes, sanitizer)?;
        *summary.format_counts.entry(entry.format.clone()).or_insert(0) += 1;
        *envelope_bytes = envelope_bytes
            .saturating_add(approx_entry_size(&entry));
        entries.push(entry);
    }
    summary.total_files = entries.len() + summary.truncated_files;
    Ok(())
}

// ─── Zip walker ──────────────────────────────────────────────────────────

fn walk_zip(
    zip_path: &Path,
    entries: &mut Vec<FileEntry>,
    summary: &mut RootSummary,
    envelope_bytes: &mut usize,
    sanitizer: &mut path_sanitize::PathSanitizer,
) -> Result<(), SampleError> {
    let file = File::open(zip_path)?;
    let mut zr = zip::ZipArchive::new(file)?;

    for i in 0..zr.len() {
        let mut zf = zr.by_index(i)?;
        if zf.is_dir() {
            continue;
        }
        if entries.len() >= MAX_FILES {
            summary.truncated_files += 1;
            continue;
        }
        let name = zf.name().to_string();
        let size = zf.size();
        summary.total_bytes = summary.total_bytes.saturating_add(size);

        let rel = PathBuf::from(&name);
        let depth = rel.components().count();
        if depth > summary.max_depth {
            summary.max_depth = depth;
        }

        let entry = inspect_zip_entry(&rel, size, &mut zf, *envelope_bytes, sanitizer)?;
        *summary.format_counts.entry(entry.format.clone()).or_insert(0) += 1;
        *envelope_bytes = envelope_bytes
            .saturating_add(approx_entry_size(&entry));
        entries.push(entry);
    }
    summary.total_files = entries.len() + summary.truncated_files;
    Ok(())
}

// ─── Per-file inspection ─────────────────────────────────────────────────

fn inspect_file_from_disk(
    rel: &Path,
    abs: &Path,
    size: u64,
    envelope_bytes: usize,
    sanitizer: &mut path_sanitize::PathSanitizer,
) -> Result<FileEntry, SampleError> {
    let ext = rel.extension().and_then(|e| e.to_str()).unwrap_or("")
        .to_ascii_lowercase();

    // Read up to a small peek window for format sniffing
    let peek = read_peek(abs).unwrap_or_default();
    let fmt = detect_format(rel, &peek);

    let structure = if size > PER_FILE_BUDGET_BYTES {
        serde_json::json!({ "skipped": "too_large" })
    } else if envelope_bytes >= ENVELOPE_SOFT_CAP_BYTES {
        serde_json::json!({ "skipped": "envelope_cap" })
    } else {
        let mut content: Vec<u8> = Vec::with_capacity(size as usize);
        if let Ok(mut f) = File::open(abs) {
            let _ = f.read_to_end(&mut content);
        }
        inspect_bytes(fmt, &content)
    };

    Ok(FileEntry {
        path: sanitizer.sanitize(rel),
        size,
        ext,
        format: fmt.as_str().to_string(),
        structure,
    })
}

fn inspect_zip_entry(
    rel: &Path,
    size: u64,
    zf: &mut zip::read::ZipFile,
    envelope_bytes: usize,
    sanitizer: &mut path_sanitize::PathSanitizer,
) -> Result<FileEntry, SampleError> {
    let ext = rel.extension().and_then(|e| e.to_str()).unwrap_or("")
        .to_ascii_lowercase();

    // Read up to (PER_FILE_BUDGET_BYTES) into memory for inspection
    let cap = std::cmp::min(size, PER_FILE_BUDGET_BYTES) as usize;
    let mut buf = vec![0u8; cap];
    let n = zf.read(&mut buf).unwrap_or(0);
    buf.truncate(n);
    let fmt = detect_format(rel, &buf);

    let structure = if size > PER_FILE_BUDGET_BYTES {
        serde_json::json!({ "skipped": "too_large" })
    } else if envelope_bytes >= ENVELOPE_SOFT_CAP_BYTES {
        serde_json::json!({ "skipped": "envelope_cap" })
    } else {
        inspect_bytes(fmt, &buf)
    };

    Ok(FileEntry {
        path: sanitizer.sanitize(rel),
        size,
        ext,
        format: fmt.as_str().to_string(),
        structure,
    })
}

/// Dispatch to the right per-format inspector.  Each returns
/// `serde_json::Value` keyed however that inspector likes; callers store
/// it under `FileEntry.structure`.
fn inspect_bytes(fmt: DetectedFormat, content: &[u8]) -> serde_json::Value {
    match fmt {
        DetectedFormat::Json => json_schema::inspect(content),
        DetectedFormat::Html => html_fp::inspect(content),
        DetectedFormat::Csv => csv_fp::inspect(content, b','),
        DetectedFormat::Tsv => csv_fp::inspect(content, b'\t'),
        DetectedFormat::Mbox => mbox_fp::inspect(content),
        DetectedFormat::Eml => mbox_fp::inspect_single_message(content),
        DetectedFormat::Pdf => pdf_fp::inspect(content),
        DetectedFormat::Xml => html_fp::inspect_xml(content),
        DetectedFormat::Text => serde_json::json!({
            "byte_count": content.len(),
            "line_count": count_lines(content),
        }),
        DetectedFormat::Binary => serde_json::json!({ "byte_count": content.len() }),
    }
}

// ─── Small helpers ───────────────────────────────────────────────────────

fn read_peek(p: &Path) -> std::io::Result<Vec<u8>> {
    let f = File::open(p)?;
    let mut br = BufReader::new(f);
    let mut buf = vec![0u8; 1024];
    let n = br.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn count_lines(content: &[u8]) -> usize {
    content.iter().filter(|&&b| b == b'\n').count() + 1
}

fn approx_entry_size(entry: &FileEntry) -> usize {
    // Rough cost: path + 200B fixed + serialized structure bytes
    entry.path.len()
        + 200
        + serde_json::to_string(&entry.structure)
            .map(|s| s.len())
            .unwrap_or(64)
}

// ─── (unused for now but kept for streaming MBOX inspection) ──────────────
#[allow(dead_code)]
fn read_lines_lossy<R: BufRead>(reader: R) -> impl Iterator<Item = String> {
    reader
        .split(b'\n')
        .filter_map(|r| r.ok())
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_html_by_ext() {
        let p = Path::new("foo.html");
        assert_eq!(detect_format(p, b""), DetectedFormat::Html);
    }
    #[test]
    fn detect_json_by_ext() {
        let p = Path::new("foo.json");
        assert_eq!(detect_format(p, b""), DetectedFormat::Json);
    }
    #[test]
    fn detect_mbox_by_ext() {
        let p = Path::new("Inbox.mbox");
        assert_eq!(detect_format(p, b""), DetectedFormat::Mbox);
    }
    #[test]
    fn detect_html_by_sniff() {
        let p = Path::new("nofmt");
        assert_eq!(
            detect_format(p, b"<!DOCTYPE html><html><body></body></html>"),
            DetectedFormat::Html
        );
    }
    #[test]
    fn detect_pdf_by_sniff() {
        let p = Path::new("nofmt");
        assert_eq!(detect_format(p, b"%PDF-1.5\n"), DetectedFormat::Pdf);
    }
    #[test]
    fn detect_mbox_by_sniff() {
        let p = Path::new("nofmt");
        assert_eq!(
            detect_format(p, b"From foo@example.com Mon Jan 01 00:00:00 1970"),
            DetectedFormat::Mbox
        );
    }
    #[test]
    fn detect_binary() {
        let p = Path::new("blob");
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(detect_format(p, &bytes), DetectedFormat::Binary);
    }

    /// Integration smoke against the real YAHOO-11540.zip sample.
    /// Ignored by default — run explicitly with:
    ///   cargo test --lib warrant::sample::tests::smoke_yahoo_zip -- --ignored --nocapture
    #[test]
    #[ignore]
    fn smoke_yahoo_zip() {
        let path = Path::new(
            r"C:\Users\JUSTI\Workspace\uploads\YAHOO-11540.zip",
        );
        if !path.exists() {
            eprintln!("YAHOO-11540.zip not present, skipping");
            return;
        }
        let env = build_envelope(
            path,
            BuildOptions {
                provider_hint: "Yahoo".into(),
                submitter_email: "test@example.com".into(),
                submitter_notes: "smoke".into(),
                agency_name: "Test PD".into(),
                license_key_last4: "TEST".into(),
            },
        )
        .expect("envelope built");

        println!("files captured: {}", env.root_summary.total_files);
        println!("total bytes:    {}", env.root_summary.total_bytes);
        println!("max depth:      {}", env.root_summary.max_depth);
        println!("format counts:  {:?}", env.root_summary.format_counts);

        let j = serde_json::to_string(&env).unwrap();
        println!("envelope size:  {} bytes", j.len());
        // Show first 3 entries' paths + format
        for e in env.tree.iter().take(3) {
            println!("  {} ({}, {} bytes)", e.path, e.format, e.size);
        }

        // Privacy guardrails — content markers should NOT appear in
        // per-file `structure` blocks AND no PII shapes should appear
        // in any path (filenames are sequenced as `file_NNN.ext` and
        // directory components matching PII are redacted).
        let leak_markers = [
            "Subject:",
            "Newman-Id:",
            "victim",
            "suspect",
            "password",
            "<body>",
        ];
        for e in env.tree.iter() {
            let s = serde_json::to_string(&e.structure).unwrap_or_default();
            for m in &leak_markers {
                assert!(
                    !s.contains(m),
                    "PRIVACY LEAK in {} -> structure contains {:?}",
                    e.path,
                    m
                );
            }
            assert!(
                !e.path.contains('@'),
                "PRIVACY LEAK: path still contains '@': {}",
                e.path
            );
            assert!(
                !e.path.to_ascii_lowercase().contains("yahoo.com"),
                "PRIVACY LEAK: path still contains 'yahoo.com': {}",
                e.path
            );
        }
        assert!(env.root_summary.total_files > 0, "no files captured");
    }
}
