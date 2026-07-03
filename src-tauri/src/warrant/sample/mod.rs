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

pub const SCHEMA_VERSION: u32 = 2;

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
    Image,
    Video,
    Audio,
    Excel,
    Word,
    Powerpoint,
    Archive,
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
            DetectedFormat::Image => "image",
            DetectedFormat::Video => "video",
            DetectedFormat::Audio => "audio",
            DetectedFormat::Excel => "excel",
            DetectedFormat::Word => "word",
            DetectedFormat::Powerpoint => "powerpoint",
            DetectedFormat::Archive => "archive",
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
        "txt" | "log" | "md" => classify_textlike(peek),
        // Images
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "tiff" | "tif"
        | "bmp" | "heic" | "heif" | "svg" | "ico" | "avif"
            => DetectedFormat::Image,
        // Video
        "mp4" | "m4v" | "mov" | "mkv" | "avi" | "wmv" | "webm"
        | "flv" | "3gp" | "3g2" | "mpg" | "mpeg"
            => DetectedFormat::Video,
        // Audio
        "mp3" | "m4a" | "wav" | "aac" | "ogg" | "opus" | "flac"
        | "wma" | "amr"
            => DetectedFormat::Audio,
        // Spreadsheets
        "xlsx" | "xlsm" | "xlsb" | "xls" | "ods" => DetectedFormat::Excel,
        // Word processor docs
        "docx" | "doc" | "odt" | "rtf" => DetectedFormat::Word,
        // Presentations
        "pptx" | "ppt" | "odp" => DetectedFormat::Powerpoint,
        // Archives (top-level .zip is special-cased during walk; this
        // catches inner archives we don't recurse into).
        "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "tgz"
            => DetectedFormat::Archive,
        _ => sniff_format(peek),
    }
}

fn sniff_format(peek: &[u8]) -> DetectedFormat {
    if peek.starts_with(b"%PDF-") {
        return DetectedFormat::Pdf;
    }
    // Common media / office magic bytes.
    if let Some(fmt) = sniff_binary_magic(peek) {
        return fmt;
    }
    // X / Twitter productions wrap JSON in a PGP cleartext signature and use
    // `.txt` (or no) extensions.  Peek past the wrapper for a JSON opener.
    if peek_is_jsonish(peek) {
        return DetectedFormat::Json;
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

/// Magic-byte sniffer for media + office container formats. Returns
/// `Some(fmt)` only for confident matches; ambiguous bytes fall through
/// to the text/binary heuristic.
fn sniff_binary_magic(peek: &[u8]) -> Option<DetectedFormat> {
    if peek.len() < 4 { return None; }
    // ── Images ──
    if peek.starts_with(&[0xFF, 0xD8, 0xFF]) { return Some(DetectedFormat::Image); } // JPEG
    if peek.starts_with(&[0x89, b'P', b'N', b'G']) { return Some(DetectedFormat::Image); } // PNG
    if peek.starts_with(b"GIF87a") || peek.starts_with(b"GIF89a") {
        return Some(DetectedFormat::Image);
    }
    if peek.starts_with(b"BM") { return Some(DetectedFormat::Image); } // BMP
    // RIFF container: WEBP, WAV, AVI all share this prefix.
    if peek.len() >= 12 && &peek[0..4] == b"RIFF" {
        return match &peek[8..12] {
            b"WEBP" => Some(DetectedFormat::Image),
            b"WAVE" => Some(DetectedFormat::Audio),
            b"AVI " => Some(DetectedFormat::Video),
            _ => Some(DetectedFormat::Binary),
        };
    }
    // TIFF (little + big endian)
    if peek.starts_with(&[0x49, 0x49, 0x2A, 0x00])
        || peek.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
    {
        return Some(DetectedFormat::Image);
    }
    // ISO BMFF box header: `....ftypXXXX` at offset 4 — MP4 / MOV / HEIC / 3GP.
    if peek.len() >= 12 && &peek[4..8] == b"ftyp" {
        let brand = &peek[8..12];
        return match brand {
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis"
            | b"hevm" | b"hevs" | b"mif1" | b"msf1" | b"avif"
                => Some(DetectedFormat::Image),
            b"qt  " | b"mp41" | b"mp42" | b"isom" | b"M4V "
            | b"3gp4" | b"3gp5" | b"3g2a" | b"M4VP" | b"dash"
                => Some(DetectedFormat::Video),
            b"M4A " | b"M4B " => Some(DetectedFormat::Audio),
            _ => Some(DetectedFormat::Video), // unknown ftyp brand → assume video container
        };
    }
    // ── Audio ──
    if peek.starts_with(b"ID3") { return Some(DetectedFormat::Audio); } // MP3 w/ID3
    if peek.len() >= 2 && peek[0] == 0xFF && (peek[1] & 0xE0) == 0xE0 {
        // MPEG audio frame (mp3 without ID3 tag)
        return Some(DetectedFormat::Audio);
    }
    if peek.starts_with(b"OggS") { return Some(DetectedFormat::Audio); }
    if peek.starts_with(b"fLaC") { return Some(DetectedFormat::Audio); }
    // ── Video ──
    if peek.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some(DetectedFormat::Video); // Matroska / WebM (EBML)
    }
    if peek.starts_with(&[0x00, 0x00, 0x01, 0xBA])
        || peek.starts_with(&[0x00, 0x00, 0x01, 0xB3])
    {
        return Some(DetectedFormat::Video); // MPEG-PS / MPEG-1/2 video
    }
    // ── Office (CFB / OLE — legacy .doc/.xls/.ppt) ──
    if peek.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        // Without parsing the storage tree we can't tell doc vs xls vs ppt.
        // Default to Word as the most common; caller still has the
        // extension if present.
        return Some(DetectedFormat::Word);
    }
    // ── ZIP container (.docx/.xlsx/.pptx/.zip) ──
    // PK\x03\x04 magic. We can't cheaply peek the central directory in
    // the first 1KiB, so we report Archive and let the extension override.
    if peek.starts_with(&[0x50, 0x4B, 0x03, 0x04])
        || peek.starts_with(&[0x50, 0x4B, 0x05, 0x06])
        || peek.starts_with(&[0x50, 0x4B, 0x07, 0x08])
    {
        return Some(DetectedFormat::Archive);
    }
    // ── Other archives ──
    if peek.starts_with(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) {
        return Some(DetectedFormat::Archive); // RAR
    }
    if peek.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(DetectedFormat::Archive); // 7z
    }
    None
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
        DetectedFormat::Json => {
            let (bytes, meta) = normalize_jsonish(content);
            let mut fp = json_schema::inspect(&bytes);
            if let serde_json::Value::Object(map) = &mut fp {
                if meta.pgp_signed {
                    map.insert("pgp_signed".into(), serde_json::json!(true));
                    map.insert("container".into(), serde_json::json!("pgp_cleartext"));
                }
                if meta.marker_delimited {
                    map.insert("marker_delimited".into(), serde_json::json!(true));
                    map.insert("object_count".into(), serde_json::json!(meta.object_count));
                }
            }
            fp
        }
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
        DetectedFormat::Image
        | DetectedFormat::Video
        | DetectedFormat::Audio => serde_json::json!({
            "byte_count": content.len(),
            "media_subtype": media_subtype(content),
        }),
        DetectedFormat::Excel
        | DetectedFormat::Word
        | DetectedFormat::Powerpoint => serde_json::json!({
            "byte_count": content.len(),
            "container": office_container(content),
        }),
        DetectedFormat::Archive => serde_json::json!({
            "byte_count": content.len(),
            "container": archive_kind(content),
        }),
        DetectedFormat::Binary => serde_json::json!({ "byte_count": content.len() }),
    }
}

/// Best-effort media subtype (`"jpeg"`, `"png"`, `"mp4"`, `"mov"`, etc.).
/// Returns `"unknown"` when we can't tell from the magic bytes alone.
fn media_subtype(content: &[u8]) -> &'static str {
    if content.len() < 12 { return "unknown"; }
    if content.starts_with(&[0xFF, 0xD8, 0xFF]) { return "jpeg"; }
    if content.starts_with(&[0x89, b'P', b'N', b'G']) { return "png"; }
    if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") { return "gif"; }
    if content.starts_with(b"BM") { return "bmp"; }
    if content.starts_with(&[0x49, 0x49, 0x2A, 0x00])
        || content.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
    { return "tiff"; }
    if &content[0..4] == b"RIFF" {
        return match &content[8..12] {
            b"WEBP" => "webp",
            b"WAVE" => "wav",
            b"AVI " => "avi",
            _ => "riff",
        };
    }
    if &content[4..8] == b"ftyp" {
        let brand = &content[8..12];
        return match brand {
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis"
            | b"hevm" | b"hevs" | b"mif1" | b"msf1" => "heif",
            b"avif" => "avif",
            b"qt  " => "mov",
            b"mp41" | b"mp42" | b"isom" | b"M4V " | b"M4VP" | b"dash" => "mp4",
            b"3gp4" | b"3gp5" | b"3g2a" => "3gp",
            b"M4A " | b"M4B " => "m4a",
            _ => "iso_bmff",
        };
    }
    if content.starts_with(b"ID3") || (content[0] == 0xFF && (content[1] & 0xE0) == 0xE0) {
        return "mp3";
    }
    if content.starts_with(b"OggS") { return "ogg"; }
    if content.starts_with(b"fLaC") { return "flac"; }
    if content.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) { return "matroska"; }
    "unknown"
}

/// Container kind for Office docs. Modern Office (xlsx/docx/pptx) is a
/// ZIP, legacy is CFB. Caller already has the extension to disambiguate
/// xlsx-vs-docx-vs-pptx.
fn office_container(content: &[u8]) -> &'static str {
    if content.starts_with(&[0x50, 0x4B, 0x03, 0x04]) { return "ooxml_zip"; }
    if content.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return "cfb_legacy";
    }
    "unknown"
}

/// Archive subtype.
fn archive_kind(content: &[u8]) -> &'static str {
    if content.starts_with(&[0x50, 0x4B, 0x03, 0x04])
        || content.starts_with(&[0x50, 0x4B, 0x05, 0x06])
        || content.starts_with(&[0x50, 0x4B, 0x07, 0x08])
    {
        return "zip";
    }
    if content.starts_with(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) { return "rar"; }
    if content.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) { return "7z"; }
    if content.starts_with(&[0x1F, 0x8B]) { return "gzip"; }
    if content.starts_with(b"BZh") { return "bzip2"; }
    if content.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) { return "xz"; }
    "unknown"
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

// ─── PGP-cleartext-aware JSON detection (X / Twitter productions) ─────────

/// `.txt` files that are actually JSON (X wraps each record file in a PGP
/// cleartext signature) get routed to the JSON fingerprinter; plain text
/// stays text.
fn classify_textlike(peek: &[u8]) -> DetectedFormat {
    if peek_is_jsonish(peek) {
        DetectedFormat::Json
    } else {
        DetectedFormat::Text
    }
}

/// True if the first non-whitespace byte (after stripping an optional PGP
/// cleartext-signature wrapper and BOM) opens a JSON object/array.
fn peek_is_jsonish(peek: &[u8]) -> bool {
    let head = if peek.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &peek[3..]
    } else {
        peek
    };
    if let Some(inner) = strip_pgp_cleartext_bytes(head) {
        return first_nonws_is_json(&inner);
    }
    first_nonws_is_json(head)
}

fn first_nonws_is_json(bytes: &[u8]) -> bool {
    for &b in bytes {
        if b.is_ascii_whitespace() {
            continue;
        }
        return b == b'{' || b == b'[';
    }
    false
}

/// Strip a PGP cleartext-signature wrapper, returning just the payload
/// bytes.  Returns `None` when the content isn't PGP-cleartext-signed.
fn strip_pgp_cleartext_bytes(content: &[u8]) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
    const SIG: &str = "-----BEGIN PGP SIGNATURE-----";

    let text = String::from_utf8_lossy(content);
    let begin = text.find(BEGIN)?;
    let after = &text[begin + BEGIN.len()..];
    // Payload starts after the blank line that ends the armor headers.
    let body_start = after
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| after.find("\n\n").map(|i| i + 2))
        .unwrap_or(0);
    let rest = &after[body_start..];
    let end = rest.find(SIG).unwrap_or(rest.len());
    let body = &rest[..end];

    // Un-escape cleartext dash-escaping ("- " at line start → "").
    let mut out = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        if let Some(stripped) = line.strip_prefix("- ") {
            out.push_str(stripped);
        } else {
            out.push_str(line);
        }
    }
    Some(out.trim().as_bytes().to_vec())
}

#[derive(Default)]
struct JsonMeta {
    pgp_signed: bool,
    marker_delimited: bool,
    object_count: usize,
}

/// Turn possibly-PGP-wrapped, possibly-marker-delimited content into a clean
/// JSON byte buffer suitable for the schema fingerprinter.  X tweet/DM files
/// are a *stream* of `{...}` objects rather than a single JSON array, so we
/// wrap the extracted objects into an array to fingerprint the element shape.
fn normalize_jsonish(content: &[u8]) -> (Vec<u8>, JsonMeta) {
    let mut meta = JsonMeta::default();
    let body: Vec<u8> = match strip_pgp_cleartext_bytes(content) {
        Some(b) => {
            meta.pgp_signed = true;
            b
        }
        None => content.to_vec(),
    };

    // Already a valid JSON document?  Use as-is.
    if serde_json::from_slice::<serde_json::Value>(&body).is_ok() {
        return (body, meta);
    }

    // Otherwise pull out concatenated top-level objects and wrap them.
    let objs = extract_json_objects_bytes(&body);
    if !objs.is_empty() {
        meta.marker_delimited = true;
        meta.object_count = objs.len();
        if let Ok(bytes) = serde_json::to_vec(&serde_json::Value::Array(objs)) {
            return (bytes, meta);
        }
    }

    (body, meta)
}

/// Balanced-brace scanner: pull top-level `{...}` objects out of a byte
/// buffer that isn't a strict JSON document (string/escape aware).
fn extract_json_objects_bytes(bytes: &[u8]) -> Vec<serde_json::Value> {
    let s = String::from_utf8_lossy(bytes);
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0usize;
    let mut in_str = false;
    let mut esc = false;

    for (i, &c) in b.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            b'}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s[start..=i]) {
                            out.push(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
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

    // ─── X / Twitter: PGP-wrapped JSON in .txt files ───────────────────

    fn pgp_wrap(body: &str) -> String {
        format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}\n-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n",
            body
        )
    }

    #[test]
    fn txt_plain_stays_text() {
        let p = Path::new("notes.txt");
        assert_eq!(detect_format(p, b"just some notes\nmore notes"), DetectedFormat::Text);
    }

    #[test]
    fn txt_with_pgp_json_detected_as_json() {
        let wrapped = pgp_wrap("[{\"account\":{\"accountId\":\"12345\"}}]");
        let p = Path::new("1234-account.txt");
        assert_eq!(detect_format(p, wrapped.as_bytes()), DetectedFormat::Json);
    }

    #[test]
    fn pgp_marker_delimited_tweets_fingerprint_captures_fields() {
        // Two concatenated tweet objects (the real X shape) inside a PGP wrapper.
        let body = "{\"tweet\":{\"id_str\":\"111\",\"full_text\":\"secret text one\"}}\n\
                    {\"tweet\":{\"id_str\":\"222\",\"full_text\":\"secret text two\"}}";
        let wrapped = pgp_wrap(body);
        let fmt = detect_format(Path::new("tweets.txt"), wrapped.as_bytes());
        assert_eq!(fmt, DetectedFormat::Json);

        let structure = inspect_bytes(fmt, wrapped.as_bytes());
        let s = serde_json::to_string(&structure).unwrap();

        // Structural key paths must be captured...
        assert!(s.contains("[].tweet.id_str"), "missing tweet.id_str path: {s}");
        assert!(s.contains("[].tweet.full_text"), "missing full_text path");
        // ...the PGP + marker-delimited flags surfaced...
        assert!(s.contains("pgp_signed"), "missing pgp_signed flag");
        assert!(s.contains("marker_delimited"), "missing marker_delimited flag");
        // ...and NO actual content leaks.
        assert!(!s.contains("secret text"), "content value leaked into fingerprint!");
    }

    #[test]
    fn pgp_dm_fingerprint_no_value_leak() {
        let body = "[{\"dmConversation\":{\"conversationId\":\"1-2\",\"messages\":[\
                    {\"messageCreate\":{\"id\":\"m1\",\"senderId\":\"1\",\"recipientId\":\"2\",\
                    \"text\":\"meet me at midnight\"}}]}}]";
        let wrapped = pgp_wrap(body);
        let fmt = detect_format(Path::new("direct-messages.txt"), wrapped.as_bytes());
        assert_eq!(fmt, DetectedFormat::Json);
        let structure = inspect_bytes(fmt, wrapped.as_bytes());
        let s = serde_json::to_string(&structure).unwrap();
        assert!(s.contains("messageCreate.text"), "missing DM text path");
        assert!(!s.contains("midnight"), "DM content leaked!");
    }

    // ─── Media + Office detection ──────────────────────────────────────

    #[test]
    fn detect_image_by_ext() {
        for (name, expect) in &[
            ("photo.jpg", DetectedFormat::Image),
            ("photo.jpeg", DetectedFormat::Image),
            ("img.PNG", DetectedFormat::Image),
            ("a.gif", DetectedFormat::Image),
            ("h.heic", DetectedFormat::Image),
            ("w.webp", DetectedFormat::Image),
            ("a.bmp", DetectedFormat::Image),
            ("a.tiff", DetectedFormat::Image),
            ("a.svg", DetectedFormat::Image),
        ] {
            assert_eq!(detect_format(Path::new(name), b""), *expect,
                "wrong format for {}", name);
        }
    }

    #[test]
    fn detect_video_by_ext() {
        for name in &["clip.mp4", "vid.MOV", "movie.mkv", "v.webm", "a.avi"] {
            assert_eq!(detect_format(Path::new(name), b""), DetectedFormat::Video,
                "wrong format for {}", name);
        }
    }

    #[test]
    fn detect_audio_by_ext() {
        for name in &["song.mp3", "voice.m4a", "rec.wav", "track.flac", "v.opus"] {
            assert_eq!(detect_format(Path::new(name), b""), DetectedFormat::Audio,
                "wrong format for {}", name);
        }
    }

    #[test]
    fn detect_excel_by_ext() {
        for name in &["sheet.xlsx", "old.xls", "macro.xlsm", "calc.ods"] {
            assert_eq!(detect_format(Path::new(name), b""), DetectedFormat::Excel,
                "wrong format for {}", name);
        }
    }

    #[test]
    fn detect_word_by_ext() {
        for name in &["doc.docx", "old.doc", "doc.odt", "page.rtf"] {
            assert_eq!(detect_format(Path::new(name), b""), DetectedFormat::Word,
                "wrong format for {}", name);
        }
    }

    #[test]
    fn detect_powerpoint_by_ext() {
        for name in &["deck.pptx", "old.ppt", "slides.odp"] {
            assert_eq!(detect_format(Path::new(name), b""), DetectedFormat::Powerpoint,
                "wrong format for {}", name);
        }
    }

    #[test]
    fn detect_image_by_magic() {
        let p = Path::new("noext");
        // JPEG
        assert_eq!(detect_format(p, &[0xFF, 0xD8, 0xFF, 0xE0]), DetectedFormat::Image);
        // PNG
        assert_eq!(detect_format(p, b"\x89PNG\r\n\x1a\n"), DetectedFormat::Image);
        // GIF
        assert_eq!(detect_format(p, b"GIF89a..."), DetectedFormat::Image);
        // HEIC (ISO BMFF with `heic` brand)
        let mut heic = vec![0u8, 0, 0, 32];
        heic.extend_from_slice(b"ftyp");
        heic.extend_from_slice(b"heic");
        heic.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_format(p, &heic), DetectedFormat::Image);
    }

    #[test]
    fn detect_video_by_magic() {
        let p = Path::new("noext");
        // MP4 (ISO BMFF `mp42` brand)
        let mut mp4 = vec![0u8, 0, 0, 32];
        mp4.extend_from_slice(b"ftyp");
        mp4.extend_from_slice(b"mp42");
        mp4.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_format(p, &mp4), DetectedFormat::Video);
        // QuickTime MOV
        let mut mov = vec![0u8, 0, 0, 32];
        mov.extend_from_slice(b"ftyp");
        mov.extend_from_slice(b"qt  ");
        mov.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_format(p, &mov), DetectedFormat::Video);
        // Matroska / WebM (EBML)
        assert_eq!(detect_format(p, &[0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0]),
            DetectedFormat::Video);
    }

    #[test]
    fn detect_audio_by_magic() {
        let p = Path::new("noext");
        // MP3 with ID3
        assert_eq!(detect_format(p, b"ID3\x04\0\0\0\0\0\0"), DetectedFormat::Audio);
        // WAV (RIFF + WAVE)
        let mut wav = Vec::from(*b"RIFF");
        wav.extend_from_slice(&[0u8; 4]);
        wav.extend_from_slice(b"WAVE");
        assert_eq!(detect_format(p, &wav), DetectedFormat::Audio);
        // Ogg
        assert_eq!(detect_format(p, b"OggS\0\0\0\0"), DetectedFormat::Audio);
        // FLAC
        assert_eq!(detect_format(p, b"fLaC\0\0\0\0"), DetectedFormat::Audio);
    }

    #[test]
    fn detect_office_legacy_cfb_magic() {
        let p = Path::new("noext");
        // CFB OLE2 magic — legacy .doc / .xls / .ppt all share this.
        let cfb = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0u8, 0u8];
        assert_eq!(detect_format(p, &cfb), DetectedFormat::Word);
    }

    #[test]
    fn detect_archive_by_magic() {
        let p = Path::new("noext");
        // ZIP (also matches docx/xlsx/pptx without extension hint)
        assert_eq!(detect_format(p, b"PK\x03\x04\0\0\0\0"), DetectedFormat::Archive);
        // RAR
        assert_eq!(detect_format(p, b"Rar!\x1A\x07\0"), DetectedFormat::Archive);
        // 7z
        assert_eq!(detect_format(p, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]),
            DetectedFormat::Archive);
    }

    #[test]
    fn extension_overrides_zip_magic_for_office() {
        // docx is a ZIP — but extension should classify it as Word.
        let p = Path::new("memo.docx");
        assert_eq!(detect_format(p, b"PK\x03\x04\0\0\0\0"), DetectedFormat::Word);
        let p = Path::new("data.xlsx");
        assert_eq!(detect_format(p, b"PK\x03\x04\0\0\0\0"), DetectedFormat::Excel);
        let p = Path::new("deck.pptx");
        assert_eq!(detect_format(p, b"PK\x03\x04\0\0\0\0"), DetectedFormat::Powerpoint);
    }

    #[test]
    fn media_structure_has_no_pixel_data() {
        // A JPEG with embedded "secret" string after the header — we
        // must surface only byte_count + media_subtype, never the bytes.
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg.extend_from_slice(b"GPS:34.0522,-118.2437 SECRET_PAYLOAD_AAA");
        let s = inspect_bytes(DetectedFormat::Image, &jpeg);
        let raw = serde_json::to_string(&s).unwrap();
        assert!(!raw.contains("SECRET_PAYLOAD_AAA"),
            "raw bytes leaked from image structure: {}", raw);
        assert!(!raw.contains("GPS"),
            "GPS hint leaked from image structure: {}", raw);
        assert!(raw.contains("jpeg"));
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

    /// Integration smoke against the real Meta clean-data zip — verifies
    /// the html_fp envelope upgrades (title_text, label_vocab, sentinel
    /// phrases, per_id_skeleton) actually capture the labels a parser
    /// author needs.
    ///   cargo test --lib warrant::sample::tests::smoke_meta_zip -- --ignored --nocapture
    #[test]
    #[ignore]
    fn smoke_meta_zip() {
        let path = Path::new(
            r"C:\Users\JUSTI\Downloads\Clean Data Archive for Distribution[4] (1).zip",
        );
        if !path.exists() {
            eprintln!("Meta clean zip not present at {:?}, skipping", path);
            return;
        }
        let env = build_envelope(
            path,
            BuildOptions {
                provider_hint: "meta clean".into(),
                submitter_email: "test@example.com".into(),
                submitter_notes: "smoke meta".into(),
                agency_name: "Test PD".into(),
                license_key_last4: "TEST".into(),
            },
        )
        .expect("envelope built");

        println!("files captured: {}", env.root_summary.total_files);
        println!("format counts:  {:?}", env.root_summary.format_counts);

        // Find each HTML entry and assert the new fields are populated.
        let mut html_seen = 0usize;
        let mut combined_title = String::new();
        let mut combined_labels: Vec<String> = Vec::new();
        let mut combined_ids: Vec<String> = Vec::new();
        for e in env.tree.iter().filter(|e| e.format == "html") {
            html_seen += 1;
            let s = &e.structure;
            if let Some(t) = s.get("title_text").and_then(|v| v.as_str()) {
                if !t.is_empty() {
                    combined_title.push_str(t);
                    combined_title.push(' ');
                }
            }
            if let Some(arr) = s.get("label_vocab").and_then(|v| v.as_array()) {
                for entry in arr {
                    if let Some(t) = entry.get("text").and_then(|v| v.as_str()) {
                        combined_labels.push(t.to_string());
                    }
                }
            }
            if let Some(obj) = s.get("per_id_skeleton").and_then(|v| v.as_object()) {
                for k in obj.keys() { combined_ids.push(k.clone()); }
            }
        }
        println!("html files:     {}", html_seen);
        println!("combined title: {:?}", combined_title);
        println!("sample labels:  {:?}",
            combined_labels.iter().take(20).collect::<Vec<_>>());
        println!("ids w/skeleton: {:?}",
            combined_ids.iter().take(10).collect::<Vec<_>>());

        assert!(html_seen >= 1, "no HTML files in envelope");
        assert!(combined_title.to_ascii_lowercase().contains("facebook"),
            "title_text missing Facebook signal: {:?}", combined_title);
        // Meta records use these labels — at least some must surface.
        let want_any = ["Author", "Sent", "Body", "Posted", "Status",
                        "Type", "Size", "Thread"];
        let hit = want_any.iter().any(|l|
            combined_labels.iter().any(|t| t == l));
        assert!(hit, "label_vocab missed all Meta labels: {:?}", combined_labels);
        // At least one property-* bucket id should be in per_id_skeleton.
        assert!(combined_ids.iter().any(|i| i.starts_with("property-")),
            "per_id_skeleton missing property-* buckets: {:?}", combined_ids);
    }
}
