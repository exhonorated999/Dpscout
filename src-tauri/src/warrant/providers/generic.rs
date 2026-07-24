//! Generic catalog fallback.
//!
//! When a user-picked provider parser rejects a return (`accepts()` == false)
//! and the operator consents to a degraded import, we still want to surface
//! *something* usable rather than dead-ending.  This module walks the return
//! (directory or `.zip`), and produces a [`ParsedReturn`] containing:
//!
//! * **Media items** — images / video / audio, extracted (up to a budget) so
//!   Hash Scan / Media Scan / Project VIC can act on them.
//! * **Document items** — json / csv / html / pdf / office / text, copied
//!   (small ones) with a text preview where meaningful.
//! * **A file manifest** — `_manifest.csv` listing EVERY file (path, size,
//!   format) so nothing in the return is invisible, plus one summary item.
//!
//! This is deliberately NOT a `WarrantParser` / `Provider` variant: it's a
//! plain fallback the import command calls after operator consent.  The case
//! keeps the operator's chosen provider but is labelled as a generic import.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use chrono::Utc;
use uuid::Uuid;

use crate::warrant::sample::{detect_format, DetectedFormat};
use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem,
};

// ─── Budgets ────────────────────────────────────────────────────────────
// Bound disk + payload on massive returns (e.g. a 78 GB / 75k-file export).
// Everything beyond a budget is still recorded in the manifest — just not
// extracted or shown as its own tile.

const MAX_MEDIA_EXTRACT_FILES: usize = 5_000;
const MAX_MEDIA_EXTRACT_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
const MAX_DOC_ITEMS: usize = 2_000;
const MAX_DOC_EXTRACT_BYTES: u64 = 25 * 1024 * 1024; // 25 MB / doc
const PEEK_BYTES: usize = 512;
const DOC_PREVIEW_BYTES: usize = 4_000;

// ─── Public entry point ───────────────────────────────────────────────────

/// Build a generic catalog `ParsedReturn` for `archive` (dir or .zip).
/// The caller (import command) overwrites `case.case_id`, `media_root`, and
/// `source_filename`, exactly as it does for real provider parsers.
pub fn catalog(
    archive: &Path,
    media_dir: &Path,
    chosen: Provider,
) -> Result<ParsedReturn, ParseError> {
    fs::create_dir_all(media_dir)?;
    let mut cat = Catalog::default();

    if archive.is_dir() {
        cat.walk_dir(archive, media_dir)?;
    } else if archive
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
    {
        cat.walk_zip(archive, media_dir)?;
    } else {
        return Err(ParseError::Other(format!(
            "generic catalog: {} is neither a directory nor a .zip",
            archive.display()
        )));
    }

    cat.finish(media_dir);

    let case = WarrantCase {
        case_id: Uuid::new_v4().to_string(),
        provider: chosen,
        provider_display: format!(
            "Generic import — {} format not recognized",
            chosen.display_name()
        ),
        source_filename: archive
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into()),
        imported_at: Utc::now().to_rfc3339(),
        target_account: None,
        date_range: None,
        generated_at_source: None,
        media_root: Some(media_dir.to_string_lossy().into_owned()),
    };

    Ok(ParsedReturn {
        case,
        items: cat.items,
        default_buckets: default_buckets(),
    })
}

pub fn default_buckets() -> Vec<BucketTemplate> {
    vec![
        BucketTemplate {
            name: "CSAM".into(),
            color: "#ef4444".into(),
            description: Some("Child sexual abuse material".into()),
        },
        BucketTemplate {
            name: "Relevant".into(),
            color: "#82C341".into(),
            description: Some("Evidence relevant to the case".into()),
        },
        BucketTemplate {
            name: "Review".into(),
            color: "#f59e0b".into(),
            description: Some("Needs a closer look".into()),
        },
        BucketTemplate {
            name: "Not Relevant".into(),
            color: "#6b7280".into(),
            description: None,
        },
    ]
}

// ─── Accumulator ────────────────────────────────────────────────────────

#[derive(Default)]
struct Catalog {
    items: Vec<WarrantItem>,
    manifest: Vec<(String, u64, String)>, // (path, size, format)
    total_files: usize,
    total_bytes: u64,
    media_total: usize,
    media_extracted: usize,
    media_extracted_bytes: u64,
    doc_total: usize,
    doc_items: usize,
    fmt_counts: BTreeMap<String, usize>,
    seq: usize,
}

impl Catalog {
    fn next_id(&mut self, prefix: &str) -> String {
        self.seq += 1;
        format!("{}-{:06}", prefix, self.seq)
    }

    // ── Directory walk ──
    fn walk_dir(&mut self, root: &Path, media_dir: &Path) -> Result<(), ParseError> {
        use walkdir::WalkDir;
        for de in WalkDir::new(root).follow_links(false) {
            let de = match de {
                Ok(d) => d,
                Err(_) => continue,
            };
            if !de.file_type().is_file() {
                continue;
            }
            let abs = de.path();
            let rel = abs
                .strip_prefix(root)
                .unwrap_or(abs)
                .to_string_lossy()
                .replace('\\', "/");
            let size = de.metadata().map(|m| m.len()).unwrap_or(0);

            // Cheap peek for format sniffing (media is decided by extension).
            let peek = read_head(abs, PEEK_BYTES);
            let fmt = detect_format(Path::new(&rel), &peek);
            self.record(&rel, size, fmt);

            if is_media(fmt) {
                self.media_total += 1;
                if self.can_extract_media(size) {
                    let out = safe_out_name(self.seq, &rel);
                    if fs::copy(abs, media_dir.join(&out)).is_ok() {
                        self.media_extracted += 1;
                        self.media_extracted_bytes =
                            self.media_extracted_bytes.saturating_add(size);
                        self.push_media_item(&rel, size, fmt, Some(out));
                    }
                }
            } else {
                self.doc_total += 1;
                if self.doc_items < MAX_DOC_ITEMS {
                    let mut extracted = None;
                    let mut preview = None;
                    if size <= MAX_DOC_EXTRACT_BYTES {
                        if let Ok(bytes) = fs::read(abs) {
                            if is_text_like(fmt) {
                                preview = Some(text_preview(&bytes));
                            }
                            let out = safe_out_name(self.seq, &rel);
                            if fs::write(media_dir.join(&out), &bytes).is_ok() {
                                extracted = Some(out);
                            }
                        }
                    }
                    self.push_doc_item(&rel, size, fmt, extracted, preview);
                }
            }
        }
        Ok(())
    }

    // ── Zip walk ──
    fn walk_zip(&mut self, zip_path: &Path, media_dir: &Path) -> Result<(), ParseError> {
        let file = File::open(zip_path)?;
        let mut zr = zip::ZipArchive::new(file)?;
        for i in 0..zr.len() {
            let mut zf = zr.by_index(i)?;
            if zf.is_dir() {
                continue;
            }
            let rel = zf.name().replace('\\', "/");
            let size = zf.size();

            // Read a small head for sniffing.
            let mut head = vec![0u8; PEEK_BYTES.min(size as usize)];
            let n = zf.read(&mut head).unwrap_or(0);
            head.truncate(n);
            let fmt = detect_format(Path::new(&rel), &head);
            self.record(&rel, size, fmt);

            if is_media(fmt) {
                self.media_total += 1;
                if self.can_extract_media(size) {
                    let out = safe_out_name(self.seq, &rel);
                    // Stream head + remainder to disk (avoids buffering GBs).
                    if let Ok(mut outf) = File::create(media_dir.join(&out)) {
                        let ok = outf.write_all(&head).is_ok()
                            && std::io::copy(&mut zf, &mut outf).is_ok();
                        if ok {
                            self.media_extracted += 1;
                            self.media_extracted_bytes =
                                self.media_extracted_bytes.saturating_add(size);
                            self.push_media_item(&rel, size, fmt, Some(out));
                        }
                    }
                }
            } else {
                self.doc_total += 1;
                if self.doc_items < MAX_DOC_ITEMS {
                    let mut extracted = None;
                    let mut preview = None;
                    if size <= MAX_DOC_EXTRACT_BYTES {
                        // head already holds the first PEEK_BYTES; read the rest.
                        let mut bytes = head.clone();
                        let _ = zf.read_to_end(&mut bytes);
                        if is_text_like(fmt) {
                            preview = Some(text_preview(&bytes));
                        }
                        let out = safe_out_name(self.seq, &rel);
                        if fs::write(media_dir.join(&out), &bytes).is_ok() {
                            extracted = Some(out);
                        }
                    }
                    self.push_doc_item(&rel, size, fmt, extracted, preview);
                }
            }
        }
        Ok(())
    }

    fn record(&mut self, rel: &str, size: u64, fmt: DetectedFormat) {
        self.total_files += 1;
        self.total_bytes = self.total_bytes.saturating_add(size);
        *self.fmt_counts.entry(fmt.as_str().to_string()).or_insert(0) += 1;
        self.manifest
            .push((rel.to_string(), size, fmt.as_str().to_string()));
    }

    fn can_extract_media(&self, size: u64) -> bool {
        self.media_extracted < MAX_MEDIA_EXTRACT_FILES
            && self.media_extracted_bytes.saturating_add(size) <= MAX_MEDIA_EXTRACT_BYTES
    }

    fn push_media_item(
        &mut self,
        rel: &str,
        size: u64,
        fmt: DetectedFormat,
        extracted: Option<String>,
    ) {
        let id = self.next_id("media");
        self.items.push(WarrantItem {
            id,
            section: "media".into(),
            section_display: "Media".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: None,
            summary: Some(format!("{}  ·  {}", rel, human_size(size))),
            raw_fields: serde_json::json!({
                "source_path": rel,
                "size_bytes": size,
                "format": fmt.as_str(),
            }),
            attachments: extracted.into_iter().collect(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }

    fn push_doc_item(
        &mut self,
        rel: &str,
        size: u64,
        fmt: DetectedFormat,
        extracted: Option<String>,
        preview: Option<String>,
    ) {
        self.doc_items += 1;
        let id = self.next_id("doc");
        self.items.push(WarrantItem {
            id,
            section: "documents".into(),
            section_display: "Documents".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: preview,
            summary: Some(format!("{}  ·  {}  ·  {}", rel, fmt.as_str(), human_size(size))),
            raw_fields: serde_json::json!({
                "source_path": rel,
                "size_bytes": size,
                "format": fmt.as_str(),
            }),
            attachments: extracted.into_iter().collect(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }

    /// Write the full manifest CSV and emit the summary item.
    fn finish(&mut self, media_dir: &Path) {
        let manifest_name = "_manifest.csv";
        let mut csv = String::from("path,size_bytes,format\n");
        for (path, size, fmt) in &self.manifest {
            csv.push_str(&csv_quote(path));
            csv.push(',');
            csv.push_str(&size.to_string());
            csv.push(',');
            csv.push_str(fmt);
            csv.push('\n');
        }
        let manifest_attached = File::create(media_dir.join(manifest_name))
            .and_then(|mut f| f.write_all(csv.as_bytes()))
            .is_ok();

        let media_not_extracted = self.media_total.saturating_sub(self.media_extracted);
        let docs_not_shown = self.doc_total.saturating_sub(self.doc_items);
        let id = self.next_id("manifest");
        let summary = format!(
            "{} files · {} · {} media ({} extracted), {} documents",
            self.total_files,
            human_size(self.total_bytes),
            self.media_total,
            self.media_extracted,
            self.doc_total,
        );
        self.items.insert(
            0,
            WarrantItem {
                id,
                section: "manifest".into(),
                section_display: "File Manifest".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text: Some(format!(
                    "Generic catalog of an unrecognized return.\n\n\
                     Total files: {}\nTotal size: {}\n\
                     Media files: {} ({} extracted for scanning, {} cataloged in manifest only)\n\
                     Documents: {} ({} shown, {} in manifest only)\n\n\
                     Full file listing: {}",
                    self.total_files,
                    human_size(self.total_bytes),
                    self.media_total,
                    self.media_extracted,
                    media_not_extracted,
                    self.doc_total,
                    self.doc_items,
                    docs_not_shown,
                    manifest_name,
                )),
                summary: Some(summary),
                raw_fields: serde_json::json!({
                    "total_files": self.total_files,
                    "total_bytes": self.total_bytes,
                    "media_total": self.media_total,
                    "media_extracted": self.media_extracted,
                    "documents_total": self.doc_total,
                    "documents_shown": self.doc_items,
                    "format_counts": self.fmt_counts,
                }),
                attachments: if manifest_attached {
                    vec![manifest_name.to_string()]
                } else {
                    Vec::new()
                },
                bucket: None,
                note: None,
                is_flagged: false,
            },
        );
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn is_media(f: DetectedFormat) -> bool {
    matches!(
        f,
        DetectedFormat::Image | DetectedFormat::Video | DetectedFormat::Audio
    )
}

fn is_text_like(f: DetectedFormat) -> bool {
    matches!(
        f,
        DetectedFormat::Json
            | DetectedFormat::Html
            | DetectedFormat::Csv
            | DetectedFormat::Tsv
            | DetectedFormat::Xml
            | DetectedFormat::Text
            | DetectedFormat::Mbox
            | DetectedFormat::Eml
    )
}

fn read_head(p: &Path, max: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max];
    if let Ok(mut f) = File::open(p) {
        let n = f.read(&mut buf).unwrap_or(0);
        buf.truncate(n);
        buf
    } else {
        Vec::new()
    }
}

/// Sanitize an archive-relative path into a flat, collision-free output name.
fn safe_out_name(seq: usize, rel: &str) -> String {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let cleaned: String = base
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 32 => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());
    let cleaned = if cleaned.is_empty() { "file" } else { cleaned };
    format!("{:06}_{}", seq, cleaned)
}

fn text_preview(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out: String = text.chars().take(DOC_PREVIEW_BYTES).collect();
    if text.chars().count() > DOC_PREVIEW_BYTES {
        out.push('…');
    }
    out
}

fn human_size(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} {}", n, UNITS[0])
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

fn csv_quote(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_formats() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn safe_out_name_flattens_and_prefixes() {
        assert_eq!(safe_out_name(7, "a/b/c.jpg"), "000007_c.jpg");
        assert_eq!(safe_out_name(1, "weird:name?.txt"), "000001_weird_name_.txt");
    }

    #[test]
    fn csv_quote_escapes() {
        assert_eq!(csv_quote("plain"), "plain");
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
        assert_eq!(csv_quote("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn media_classification() {
        assert!(is_media(DetectedFormat::Image));
        assert!(is_media(DetectedFormat::Video));
        assert!(is_media(DetectedFormat::Audio));
        assert!(!is_media(DetectedFormat::Json));
        assert!(!is_media(DetectedFormat::Pdf));
    }
}
