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

// Chat-log ingestion budgets.
const MAX_CHAT_FILE_BYTES: u64 = 50 * 1024 * 1024; // 50 MB / candidate file
const MAX_CHAT_MESSAGES_TOTAL: usize = 200_000; // across the whole return

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
    chat_files: usize,
    chat_msgs: usize,
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
                    let out = ensure_media_ext(safe_out_name(self.seq, &rel), &peek);
                    if fs::copy(abs, media_dir.join(&out)).is_ok() {
                        self.media_extracted += 1;
                        self.media_extracted_bytes =
                            self.media_extracted_bytes.saturating_add(size);
                        self.push_media_item(&rel, size, fmt, Some(out));
                    }
                }
            } else {
                self.doc_total += 1;
                // Try to interpret the file as a chat log first (csv/tsv/
                // html/excel). If it parses into messages, they're surfaced
                // in the conversation view instead of an opaque doc tile.
                let handled_as_chat = size <= MAX_CHAT_FILE_BYTES
                    && is_chat_eligible(fmt)
                    && {
                        let bytes = if matches!(fmt, DetectedFormat::Excel) {
                            Vec::new() // excel read from `abs` path, not bytes
                        } else {
                            fs::read(abs).unwrap_or_default()
                        };
                        self.try_chat(&rel, fmt, &bytes, Some(abs), media_dir)
                    };
                if !handled_as_chat && self.doc_items < MAX_DOC_ITEMS {
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
                    let out = ensure_media_ext(safe_out_name(self.seq, &rel), &head);
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
                // Read the full entry once (bounded), reused by the chat and
                // document paths. `head` already holds the first PEEK_BYTES.
                let read_cap = MAX_CHAT_FILE_BYTES.max(MAX_DOC_EXTRACT_BYTES);
                let mut bytes = head.clone();
                if size <= read_cap {
                    let _ = zf.read_to_end(&mut bytes);
                }
                let handled_as_chat = size <= MAX_CHAT_FILE_BYTES
                    && is_chat_eligible(fmt)
                    && self.try_chat(&rel, fmt, &bytes, None, media_dir);
                if !handled_as_chat && self.doc_items < MAX_DOC_ITEMS {
                    let mut extracted = None;
                    let mut preview = None;
                    if size <= MAX_DOC_EXTRACT_BYTES {
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

    /// Attempt to interpret a file as a chat log and, on success, emit one
    /// `unified_messages` item per message (grouped into a single thread named
    /// after the file). Returns `true` when the file was consumed as a chat.
    ///
    /// `bytes` holds the file content for csv/tsv/html. For excel, either
    /// `excel_path` points at an on-disk copy (directory walk) or, when it's
    /// `None` (zip walk), the bytes are spilled to a temp file under
    /// `media_dir` so calamine can open a path.
    fn try_chat(
        &mut self,
        rel: &str,
        fmt: DetectedFormat,
        bytes: &[u8],
        excel_path: Option<&Path>,
        media_dir: &Path,
    ) -> bool {
        if self.chat_msgs >= MAX_CHAT_MESSAGES_TOTAL {
            return false;
        }

        // 1) Parse the file into (headers, rows).
        let table: Option<(Vec<String>, Vec<Vec<String>>)> = match fmt {
            DetectedFormat::Csv => parse_delimited(bytes, b','),
            DetectedFormat::Tsv => parse_delimited(bytes, b'\t'),
            DetectedFormat::Html => parse_html_table(bytes),
            DetectedFormat::Excel => match excel_path {
                Some(p) => parse_excel(p),
                None => {
                    // Spill zip bytes to a temp file for calamine, then remove.
                    let tmp = media_dir.join(format!(".chat_tmp_{}.bin", self.seq));
                    let parsed = if fs::write(&tmp, bytes).is_ok() {
                        parse_excel(&tmp)
                    } else {
                        None
                    };
                    let _ = fs::remove_file(&tmp);
                    parsed
                }
            },
            _ => None,
        };
        let (headers, rows) = match table {
            Some(t) if !t.1.is_empty() => t,
            _ => return false,
        };

        // 2) Map columns to chat roles.
        let cols = map_columns(&headers);
        let text_col = match cols.text {
            Some(c) => c,
            None => return false,
        };

        // 3) Acceptance: strong column signal, OR a filename hint plus a text
        //    column. Avoids treating arbitrary spreadsheets as conversations.
        let strong = cols.sender.is_some() || cols.timestamp.is_some();
        if !(strong || filename_hint(rel)) {
            return false;
        }

        // 4) Build messages.
        let convo = conversation_label(rel);
        let mut produced = 0usize;
        for row in &rows {
            if self.chat_msgs >= MAX_CHAT_MESSAGES_TOTAL {
                break;
            }
            let text = row.get(text_col).map(|s| s.trim()).unwrap_or("");
            if text.is_empty() {
                continue;
            }
            let sender = cols
                .sender
                .and_then(|i| row.get(i))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let timestamp = cols
                .timestamp
                .and_then(|i| row.get(i))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            // Preserve every column for the detail panel.
            let raw: serde_json::Map<String, serde_json::Value> = headers
                .iter()
                .enumerate()
                .filter_map(|(i, h)| {
                    let v = row.get(i).map(|s| s.trim()).unwrap_or("");
                    if v.is_empty() {
                        None
                    } else {
                        Some((h.clone(), serde_json::Value::String(v.to_string())))
                    }
                })
                .collect();

            self.push_chat_item(&convo, sender, timestamp, text.to_string(), rel, raw);
            produced += 1;
        }

        if produced == 0 {
            return false;
        }
        self.chat_files += 1;
        true
    }

    fn push_chat_item(
        &mut self,
        convo: &str,
        sender: Option<String>,
        timestamp: Option<String>,
        text: String,
        rel: &str,
        mut raw: serde_json::Map<String, serde_json::Value>,
    ) {
        self.chat_msgs += 1;
        let id = self.next_id("msg");
        let who = sender.clone().unwrap_or_else(|| "Unknown".into());
        let preview: String = text.chars().take(120).collect();
        raw.insert(
            "source_path".into(),
            serde_json::Value::String(rel.to_string()),
        );
        raw.insert(
            "conversation".into(),
            serde_json::Value::String(convo.to_string()),
        );
        self.items.push(WarrantItem {
            id,
            section: "unified_messages".into(),
            section_display: "Messages".into(),
            timestamp,
            author: sender,
            // Recipient = conversation label so every row in a file collapses
            // into one thread in the ChatView (which groups by the non-owner
            // participant; with no case owner, that's the recipient).
            recipient: Some(convo.to_string()),
            body_text: Some(text),
            summary: Some(format!("{}: {}", who, preview)),
            raw_fields: serde_json::Value::Object(raw),
            attachments: Vec::new(),
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
            "{} files · {} · {} media ({} extracted), {} chat msgs, {} documents",
            self.total_files,
            human_size(self.total_bytes),
            self.media_total,
            self.media_extracted,
            self.chat_msgs,
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
                     Chat logs: {} messages parsed from {} file(s)\n\
                     Documents: {} ({} shown, {} in manifest only)\n\n\
                     Full file listing: {}",
                    self.total_files,
                    human_size(self.total_bytes),
                    self.media_total,
                    self.media_extracted,
                    media_not_extracted,
                    self.chat_msgs,
                    self.chat_files,
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
                    "chat_messages": self.chat_msgs,
                    "chat_files": self.chat_files,
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

// ─── Chat-log detection & parsing ─────────────────────────────────────────

/// Formats we'll attempt to read as a chat log.
fn is_chat_eligible(f: DetectedFormat) -> bool {
    matches!(
        f,
        DetectedFormat::Csv | DetectedFormat::Tsv | DetectedFormat::Html | DetectedFormat::Excel
    )
}

/// Filename tokens that strongly suggest a conversation export. Kept
/// deliberately specific to avoid catching arbitrary spreadsheets/logs.
const CHAT_FILENAME_HINTS: &[&str] = &[
    "message", "messages", "chat", "chats", "conversation", "conversations",
    "dm", "dms", "sms", "texts", "imessage", "whatsapp", "messenger",
    "transcript", "inbox", "chatlog",
];

fn filename_hint(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    CHAT_FILENAME_HINTS.iter().any(|h| base.contains(h))
}

/// A conversation label used to group all messages from one file into a
/// single thread. Derived from the file's base name (without extension).
fn conversation_label(rel: &str) -> String {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let stem = base.rsplit_once('.').map(|(s, _)| s).unwrap_or(base);
    let stem = stem.trim();
    if stem.is_empty() {
        "Conversation".to_string()
    } else {
        stem.to_string()
    }
}

#[derive(Default)]
struct ColMap {
    sender: Option<usize>,
    timestamp: Option<usize>,
    text: Option<usize>,
}

const SENDER_KEYS: &[&str] = &[
    "sender", "from", "author", "username", "user name", "screen name",
    "participant", "display name", "displayname", "handle", "account",
    "sender name", "from_user", "user id", "userid",
];
const TIME_KEYS: &[&str] = &[
    "timestamp", "datetime", "date/time", "date time", "date sent",
    "sent date", "created at", "created", "sent", "date", "time", "when",
];
const TEXT_KEYS: &[&str] = &[
    "message body", "message text", "message", "content", "body", "text",
    "msg", "comment", "transcript", "caption",
];

fn header_matches(header: &str, keys: &[&str]) -> bool {
    let h = header.trim().to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    keys.iter().any(|k| h == *k || h.contains(k))
}

/// Assign header columns to chat roles. Timestamp is resolved first (so a
/// "message date" column is treated as a date, not the message body), then
/// sender, then text — each taking the first unclaimed matching header.
fn map_columns(headers: &[String]) -> ColMap {
    let mut cols = ColMap::default();
    let mut claimed = vec![false; headers.len()];

    fn assign(headers: &[String], keys: &[&str], claimed: &mut [bool]) -> Option<usize> {
        for (i, h) in headers.iter().enumerate() {
            if claimed[i] {
                continue;
            }
            if header_matches(h, keys) {
                claimed[i] = true;
                return Some(i);
            }
        }
        None
    }

    cols.timestamp = assign(headers, TIME_KEYS, &mut claimed);
    cols.sender = assign(headers, SENDER_KEYS, &mut claimed);
    cols.text = assign(headers, TEXT_KEYS, &mut claimed);
    cols
}

/// Parse CSV/TSV bytes into (headers, rows). Uses a flexible reader so ragged
/// rows don't abort the whole file.
fn parse_delimited(bytes: &[u8], delim: u8) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .has_headers(false)
        .from_reader(bytes);

    let mut records = rdr.records();
    let headers: Vec<String> = match records.next() {
        Some(Ok(r)) => r.iter().map(|s| s.to_string()).collect(),
        _ => return None,
    };
    if headers.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    for rec in records.flatten() {
        rows.push(rec.iter().map(|s| s.to_string()).collect());
    }
    Some((headers, rows))
}

/// Parse the first `<table>` in an HTML document into (headers, rows).
fn parse_html_table(bytes: &[u8]) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    use scraper::{Html, Selector};
    let text = String::from_utf8_lossy(bytes);
    let doc = Html::parse_document(&text);
    let table_sel = Selector::parse("table").ok()?;
    let tr_sel = Selector::parse("tr").ok()?;
    let cell_sel = Selector::parse("th,td").ok()?;

    let table = doc.select(&table_sel).next()?;
    let mut rows_iter = table.select(&tr_sel);

    let cell_text = |el: scraper::ElementRef| -> String {
        el.text()
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };

    let header_row = rows_iter.next()?;
    let headers: Vec<String> = header_row.select(&cell_sel).map(cell_text).collect();
    if headers.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    for tr in rows_iter {
        let cells: Vec<String> = tr.select(&cell_sel).map(cell_text).collect();
        if !cells.is_empty() {
            rows.push(cells);
        }
    }
    Some((headers, rows))
}

/// Parse the first worksheet of an Excel workbook into (headers, rows).
/// Cell values are stringified via `Display` to stay agnostic of calamine's
/// data enum naming across versions.
fn parse_excel(path: &Path) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    use calamine::{open_workbook_auto, Reader};
    let mut wb = open_workbook_auto(path).ok()?;
    let name = wb.sheet_names().first()?.clone();
    let range = wb.worksheet_range(&name).ok()?;
    let mut it = range.rows();
    let headers: Vec<String> = it.next()?.iter().map(|c| c.to_string()).collect();
    if headers.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    for r in it {
        rows.push(r.iter().map(|c| c.to_string()).collect());
    }
    Some((headers, rows))
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

/// If `name` has no recognizable media extension, sniff one from the file's
/// magic bytes and append it. Generic returns frequently contain media with
/// no extension (e.g. `attachments/…/file_0007`) or a wrong one; a correct
/// extension lets the thumbnail command, the grid auto-layout heuristic, and
/// the OS "open" association all recognize the file.
fn ensure_media_ext(name: String, head: &[u8]) -> String {
    let has_known_ext = Path::new(&name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let e = e.to_ascii_lowercase();
            matches!(
                e.as_str(),
                "jpg" | "jpeg" | "png" | "gif" | "webp" | "tiff" | "tif" | "bmp"
                | "heic" | "heif" | "ico" | "avif"
                | "mp4" | "m4v" | "mov" | "mkv" | "avi" | "wmv" | "webm" | "flv"
                | "3gp" | "3g2" | "mpg" | "mpeg"
                | "mp3" | "m4a" | "wav" | "aac" | "ogg" | "opus" | "flac" | "wma" | "amr"
            )
        })
        .unwrap_or(false);
    if has_known_ext {
        return name;
    }
    match sniff_magic_ext(head) {
        Some(ext) => format!("{}.{}", name, ext),
        None => name,
    }
}

/// Best-effort container/format detection from leading bytes. Returns a
/// concrete extension for the common image/video/audio types the app cares
/// about. Only formats with reliable magic numbers are listed.
fn sniff_magic_ext(head: &[u8]) -> Option<&'static str> {
    if head.len() < 4 {
        return None;
    }
    // Images
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpg");
    }
    if head.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some("png");
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Some("gif");
    }
    if head.starts_with(b"BM") {
        return Some("bmp");
    }
    if head.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || head.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
        return Some("tiff");
    }
    // RIFF containers: WEBP (image) vs WAV/AVI (av)
    if head.len() >= 12 && head.starts_with(b"RIFF") {
        match &head[8..12] {
            b"WEBP" => return Some("webp"),
            b"WAVE" => return Some("wav"),
            b"AVI " => return Some("avi"),
            _ => {}
        }
    }
    // ISO-BMFF (ftyp): mp4/mov/heic/avif — inspect major brand
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        let brand = &head[8..12];
        return Some(match brand {
            b"heic" | b"heix" | b"hevc" | b"heim" | b"heis" => "heic",
            b"mif1" | b"msf1" => "heif",
            b"avif" => "avif",
            b"qt  " => "mov",
            _ => "mp4",
        });
    }
    // Audio / video misc
    if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some("mkv"); // also webm; mkv is a safe superset for open/thumb
    }
    if head.starts_with(b"OggS") {
        return Some("ogg");
    }
    if head.starts_with(b"fLaC") {
        return Some("flac");
    }
    if head.starts_with(b"ID3") || head.starts_with(&[0xFF, 0xFB]) || head.starts_with(&[0xFF, 0xF3]) {
        return Some("mp3");
    }
    None
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

    #[test]
    fn sniff_ext_from_magic() {
        assert_eq!(sniff_magic_ext(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("jpg"));
        assert_eq!(sniff_magic_ext(b"\x89PNG\r\n\x1a\n"), Some("png"));
        assert_eq!(sniff_magic_ext(b"GIF89a......"), Some("gif"));
        let mut webp = Vec::from(&b"RIFF"[..]);
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBP");
        assert_eq!(sniff_magic_ext(&webp), Some("webp"));
        assert_eq!(sniff_magic_ext(b"not a known header"), None);
    }

    #[test]
    fn ensure_media_ext_appends_when_missing() {
        // No extension + jpeg magic → appends .jpg
        assert_eq!(
            ensure_media_ext("000007_file_045".to_string(), &[0xFF, 0xD8, 0xFF, 0xE0]),
            "000007_file_045.jpg"
        );
        // Already has a known media extension → unchanged
        assert_eq!(
            ensure_media_ext("000007_pic.png".to_string(), &[0xFF, 0xD8, 0xFF]),
            "000007_pic.png"
        );
        // Unknown magic + no ext → unchanged
        assert_eq!(
            ensure_media_ext("000007_blob".to_string(), b"zzzz"),
            "000007_blob"
        );
    }

    #[test]
    fn filename_hints_detect_chats() {
        assert!(filename_hint("export/messages.csv"));
        assert!(filename_hint("WhatsApp Chat with Bob.txt"));
        assert!(filename_hint("dm_history.html"));
        assert!(!filename_hint("financials_2024.xlsx"));
        assert!(!filename_hint("catalog.csv"));
    }

    #[test]
    fn conversation_label_uses_stem() {
        assert_eq!(conversation_label("a/b/messages_with_bob.csv"), "messages_with_bob");
        assert_eq!(conversation_label("chat.html"), "chat");
    }

    #[test]
    fn column_mapping_prioritizes_roles() {
        let headers = vec![
            "Timestamp".to_string(),
            "Sender".to_string(),
            "Message".to_string(),
            "Attachment".to_string(),
        ];
        let cols = map_columns(&headers);
        assert_eq!(cols.timestamp, Some(0));
        assert_eq!(cols.sender, Some(1));
        assert_eq!(cols.text, Some(2));

        // "message date" should resolve as a timestamp, not the text body.
        let headers2 = vec!["Message Date".to_string(), "From".to_string(), "Body".to_string()];
        let cols2 = map_columns(&headers2);
        assert_eq!(cols2.timestamp, Some(0));
        assert_eq!(cols2.sender, Some(1));
        assert_eq!(cols2.text, Some(2));
    }

    #[test]
    fn parse_delimited_reads_headers_and_rows() {
        let csv = b"sender,timestamp,message\nAlice,2024-01-01,Hi there\nBob,2024-01-02,Hello";
        let (headers, rows) = parse_delimited(csv, b',').unwrap();
        assert_eq!(headers, vec!["sender", "timestamp", "message"]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][2], "Hi there");
    }

    #[test]
    fn html_table_parsed_into_rows() {
        let html = br#"<html><body><table>
            <tr><th>Sender</th><th>Time</th><th>Message</th></tr>
            <tr><td>Alice</td><td>10:00</td><td>hey</td></tr>
            <tr><td>Bob</td><td>10:01</td><td>yo</td></tr>
        </table></body></html>"#;
        let (headers, rows) = parse_html_table(html).unwrap();
        assert_eq!(headers, vec!["Sender", "Time", "Message"]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][2], "yo");
    }

    #[test]
    fn chat_dir_ingest_produces_messages() {
        // A CSV with chat columns should be surfaced as unified_messages.
        let tmp = std::env::temp_dir().join(format!("scout_chat_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let media = tmp.join("media");
        std::fs::create_dir_all(&media).unwrap();
        std::fs::write(
            tmp.join("messages.csv"),
            b"Sender,Timestamp,Message\nAlice,2024-01-01T10:00,Hi Bob\nBob,2024-01-01T10:01,Hey Alice\n",
        )
        .unwrap();

        let parsed = catalog(&tmp, &media, Provider::Discord).unwrap();
        let msgs: Vec<_> = parsed
            .items
            .iter()
            .filter(|i| i.section == "unified_messages")
            .collect();
        assert_eq!(msgs.len(), 2, "expected 2 chat messages");
        assert_eq!(msgs[0].author.as_deref(), Some("Alice"));
        assert_eq!(msgs[0].recipient.as_deref(), Some("messages"));
        assert_eq!(msgs[0].body_text.as_deref(), Some("Hi Bob"));
        // A random spreadsheet (no chat columns, no hint) stays a document.
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn non_chat_spreadsheet_stays_document() {
        let tmp = std::env::temp_dir().join(format!("scout_doc_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let media = tmp.join("media");
        std::fs::create_dir_all(&media).unwrap();
        std::fs::write(
            tmp.join("inventory.csv"),
            b"sku,qty,price\nA1,10,5.00\nB2,3,9.99\n",
        )
        .unwrap();

        let parsed = catalog(&tmp, &media, Provider::Discord).unwrap();
        let msgs = parsed.items.iter().filter(|i| i.section == "unified_messages").count();
        let docs = parsed.items.iter().filter(|i| i.section == "documents").count();
        assert_eq!(msgs, 0, "inventory sheet must not be treated as chat");
        assert!(docs >= 1, "inventory sheet should be a document");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
