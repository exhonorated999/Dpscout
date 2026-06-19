//! Kik Interactive (Kik Messenger) warrant-return parser.
//!
//! Format reference
//! ----------------
//! Kik productions ship as a "completed-documents" outer ZIP:
//!
//!   KIK-{caseId}-completed-documents.zip
//!     Production Order Result Legend. {month year}.pdf
//!     {username}_case{caseId}.zip                     ← inner ZIP
//!       {username}_case{caseId}/
//!         kik sw sign.pdf                              (signed warrant)
//!         {username}/
//!           content/                                   (media files, no
//!                                                       extension or .jpg
//!                                                       / .mp4 etc.)
//!             4a1c0bdc-3ceb-41c0-989d-afe622eacc42
//!             ee43d53b-4124-4d75-bf20-fc57e50959eb.jpg
//!             …
//!           logs/
//!             bind.txt
//!             chat_sent.txt
//!             chat_sent_received.txt
//!             chat_platform_sent.txt
//!             chat_platform_sent_received.txt
//!             friend_added.txt
//!             block_user.txt
//!             group_send_msg.txt
//!             group_receive_msg.txt
//!             group_send_msg_platform.txt
//!             group_receive_msg_platform.txt
//!             Subscriber-data-{username}.pdf
//!             CoA {username}_encrypted_.pdf
//!
//! Every log file is TAB-delimited with NO header row.  The first column is
//! always a 13-digit Unix millisecond timestamp; the last column is the
//! human-readable datetime string (provider time zone).  Column layouts
//! follow Kik's "Production Order Result Legend":
//!
//!     bind.txt:                ts_ms, username, ip, port, datetime, country
//!     friend_added.txt:        ts_ms, user, friend_username, datetime
//!     block_user.txt:          ts_ms, user, blocked_username, datetime
//!     chat_sent.txt:           ts_ms, sender, recipient, msg_count, ip, datetime
//!     chat_sent_received.txt:  ts_ms, sender, recipient, msg_count, "REDACTED", datetime
//!     chat_platform_sent.txt:  ts_ms, sender, recipient, mediaType, media_uuid, ip, datetime
//!     chat_platform_sent_received.txt:
//!                              ts_ms, sender, recipient, mediaType, media_uuid,
//!                              "REDACTED", datetime
//!     group_send_msg.txt:      ts_ms, sender, group_id, recipient, msg_count, ip, datetime
//!     group_receive_msg.txt:   ts_ms, sender, group_id, recipient, msg_count,
//!                              "REDACTED", datetime
//!     group_send_msg_platform.txt:
//!                              ts_ms, sender, group_id, recipient, mediaType,
//!                              media_uuid, ip, datetime
//!     group_receive_msg_platform.txt:
//!                              ts_ms, sender, group_id, recipient, mediaType,
//!                              media_uuid, "REDACTED", datetime
//!
//! Note: Kik logs server-side fan-out for group messages — the same payload
//! is logged once PER recipient in the group.  We deduplicate by
//! (timestamp, sender, group_id [, media_uuid]) and present a single
//! triage item whose `body_text` lists every recipient that received it.
//! That collapses a 2,000-row group_send_msg_platform.txt into a much
//! more manageable number of distinct media events.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

pub struct KikWarrantParser;

// ─── WarrantParser impl ─────────────────────────────────────────────────

impl WarrantParser for KikWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Kik
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_kik_format(path));
        }

        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        // Strong signals:
        //   * any /logs/<known kik log>.txt entry inside the archive
        //   * an inner `*_case*.zip`
        //   * the Production Order Result Legend PDF
        for i in 0..zip.len() {
            let raw = zip.by_index(i)?.name().to_string();
            let lower = raw.to_ascii_lowercase();
            if is_known_kik_log(&lower) {
                return Ok(true);
            }
            if lower.contains("_case") && lower.ends_with(".zip") {
                return Ok(true);
            }
            if lower.contains("production order result legend") {
                return Ok(true);
            }
            if lower.contains("kik sw sign") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn parse(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        fs::create_dir_all(media_extract_dir)?;

        let mut sources = Sources::default();
        if archive_path.is_dir() {
            collect_sources_from_dir(archive_path, media_extract_dir, &mut sources)?;
        } else {
            collect_sources_from_zip(archive_path, media_extract_dir, &mut sources)?;
        }

        if sources.logs.is_empty() && sources.subscriber_pdf.is_none() {
            return Err(ParseError::Other(
                "No Kik production files (logs/) found in input".into(),
            ));
        }

        // Build parse context.
        let mut ctx = ParseCtx::default();
        ctx.account_username = sources.account_username.clone();
        ctx.case_number = sources.case_number.clone();
        if let Some(u) = &sources.account_username {
            ctx.target_account = Some(u.clone());
        }

        // Bio first (so it always shows up at the top).
        emit_subscriber_bio(&sources, &mut ctx);

        // Log file dispatch.  Each handler walks its own TSV.
        let read = |name: &str| -> Option<&str> { sources.logs.get(name).map(|s| s.as_str()) };

        if let Some(text) = read("bind.txt") {
            emit_binds(text, &mut ctx);
        }
        if let Some(text) = read("friend_added.txt") {
            emit_friends(text, &mut ctx);
        }
        if let Some(text) = read("block_user.txt") {
            emit_blocks(text, &mut ctx);
        }
        if let Some(text) = read("chat_sent.txt") {
            emit_dm_text(text, MsgDirection::Sent, &mut ctx);
        }
        if let Some(text) = read("chat_sent_received.txt") {
            emit_dm_text(text, MsgDirection::Received, &mut ctx);
        }
        if let Some(text) = read("chat_platform_sent.txt") {
            emit_dm_media(text, MsgDirection::Sent, &sources, &mut ctx);
        }
        if let Some(text) = read("chat_platform_sent_received.txt") {
            emit_dm_media(text, MsgDirection::Received, &sources, &mut ctx);
        }
        if let Some(text) = read("group_send_msg.txt") {
            emit_group_text(text, MsgDirection::Sent, &mut ctx);
        }
        if let Some(text) = read("group_receive_msg.txt") {
            emit_group_text(text, MsgDirection::Received, &mut ctx);
        }
        if let Some(text) = read("group_send_msg_platform.txt") {
            emit_group_media(text, MsgDirection::Sent, &sources, &mut ctx);
        }
        if let Some(text) = read("group_receive_msg_platform.txt") {
            emit_group_media(text, MsgDirection::Received, &sources, &mut ctx);
        }

        // Warrant cover / sign PDFs → request_parameters item.
        emit_request_parameters(&sources, &mut ctx);

        // Phase 3: build case metadata.
        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let case = WarrantCase {
            case_id,
            provider: Provider::Kik,
            provider_display: "Kik".to_string(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.target_account.clone(),
            date_range: ctx.date_range.clone(),
            generated_at_source: ctx.case_number.clone().map(|c| format!("case {}", c)),
            media_root: Some(media_extract_dir.to_string_lossy().into_owned()),
        };

        Ok(ParsedReturn {
            case,
            items: ctx.items,
            default_buckets: self.default_buckets(),
        })
    }

    fn default_buckets(&self) -> Vec<BucketTemplate> {
        vec![
            BucketTemplate {
                name: "CSAM".into(),
                color: "#ef4444".into(),
                description: Some("Child sexual abuse material".into()),
            },
            BucketTemplate {
                name: "Chats of Interest".into(),
                color: "#82C341".into(),
                description: Some("DMs / group msgs relevant to the case".into()),
            },
            BucketTemplate {
                name: "Group Activity".into(),
                color: "#6c8aed".into(),
                description: Some("Group rooms worth flagging".into()),
            },
            BucketTemplate {
                name: "Unrelated".into(),
                color: "#6b7280".into(),
                description: None,
            },
            BucketTemplate {
                name: "Needs Follow-Up".into(),
                color: "#f59e0b".into(),
                description: None,
            },
        ]
    }
}

// ─── Constants ──────────────────────────────────────────────────────────

const KIK_LOG_NAMES: &[&str] = &[
    "bind.txt",
    "chat_sent.txt",
    "chat_sent_received.txt",
    "chat_platform_sent.txt",
    "chat_platform_sent_received.txt",
    "friend_added.txt",
    "block_user.txt",
    "group_send_msg.txt",
    "group_receive_msg.txt",
    "group_send_msg_platform.txt",
    "group_receive_msg_platform.txt",
];

fn is_known_kik_log(lower: &str) -> bool {
    KIK_LOG_NAMES
        .iter()
        .any(|n| lower.ends_with(&format!("/logs/{}", n)) || lower.ends_with(&format!("logs/{}", n)))
}

// ─── Internal types ─────────────────────────────────────────────────────

#[derive(Default)]
struct Sources {
    /// log file basename → file content (UTF-8).
    /// e.g. `"bind.txt"` → entire TSV.
    logs: HashMap<String, String>,
    /// UUID (filename stem) → relative path under `media_extract_dir`.
    content_files: HashMap<String, String>,
    /// Inferred account username from inner-zip name or path.
    account_username: Option<String>,
    /// Inferred case number (e.g. "9445") from inner-zip name.
    case_number: Option<String>,
    /// Relative path of subscriber-data PDF (if seen).
    subscriber_pdf: Option<String>,
    /// Relative path of CoA (Certificate of Authenticity) PDF.
    coa_pdf: Option<String>,
    /// Relative path of the signed warrant PDF, if present.
    sw_sign_pdf: Option<String>,
    /// Relative path of the Production Order Result Legend, if present.
    legend_pdf: Option<String>,
}

#[derive(Default)]
struct ParseCtx {
    items: Vec<WarrantItem>,
    id_seq: HashMap<&'static str, usize>,
    target_account: Option<String>,
    account_username: Option<String>,
    case_number: Option<String>,
    /// "min_ts → max_ts" derived from logs (epoch-ms → datetime via the
    /// human datetime column when available).
    date_range: Option<String>,
    min_dt: Option<String>,
    max_dt: Option<String>,
}

impl ParseCtx {
    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:05}", prefix, *n)
    }

    fn touch_date(&mut self, dt: &str) {
        if dt.is_empty() {
            return;
        }
        match (&self.min_dt, &self.max_dt) {
            (None, _) => {
                self.min_dt = Some(dt.to_string());
                self.max_dt = Some(dt.to_string());
            }
            (Some(min), Some(max)) => {
                if dt < min.as_str() {
                    self.min_dt = Some(dt.to_string());
                }
                if dt > max.as_str() {
                    self.max_dt = Some(dt.to_string());
                }
            }
            _ => {}
        }
        if let (Some(a), Some(b)) = (&self.min_dt, &self.max_dt) {
            self.date_range = Some(format!("{} → {}", a, b));
        }
    }
}

#[derive(Clone, Copy)]
enum MsgDirection {
    Sent,
    Received,
}

impl MsgDirection {
    fn label(self) -> &'static str {
        match self {
            MsgDirection::Sent => "sent",
            MsgDirection::Received => "received",
        }
    }
}

// ─── Filesystem / zip ingestion ─────────────────────────────────────────

const IMAGE_EXTS: &[&str] = &[".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif"];
const VIDEO_EXTS: &[&str] = &[".mp4", ".mov", ".webm", ".m4v", ".3gp"];

/// Walk a Kik-format directory (already extracted by the user).
fn collect_sources_from_dir(
    root: &Path,
    media_dir: &Path,
    sources: &mut Sources,
) -> Result<(), ParseError> {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            // Skip macOS resource forks.
            if name.starts_with("._") || name == ".DS_Store" || name == "__MACOSX" {
                continue;
            }
            let parent_name = p
                .parent()
                .and_then(|x| x.file_name())
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if parent_name == "__MACOSX" {
                continue;
            }

            if p.is_dir() {
                // Try to learn the username from the inner case folder
                // structure: `{username}_case{N}/`.
                if let Some((u, c)) = parse_case_folder(&name) {
                    if sources.account_username.is_none() {
                        sources.account_username = Some(u);
                    }
                    if sources.case_number.is_none() {
                        sources.case_number = Some(c);
                    }
                }
                stack.push(p);
                continue;
            }

            ingest_file(&p, &name, root, media_dir, sources);

            // Inner ZIPs: if the user pointed us at the outer "completed
            // documents" folder, recurse into nested {username}_case{N}.zip.
            if name.to_ascii_lowercase().ends_with(".zip")
                && name.to_ascii_lowercase().contains("_case")
            {
                if let Err(e) = ingest_inner_zip_file(&p, media_dir, sources) {
                    eprintln!("[kik] inner-zip ingest failed for {:?}: {}", p, e);
                }
            }
        }
    }
    Ok(())
}

fn ingest_file(
    p: &Path,
    name: &str,
    root: &Path,
    media_dir: &Path,
    sources: &mut Sources,
) {
    let rel = p
        .strip_prefix(root)
        .map(|x| x.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string_lossy().into_owned())
        .replace('\\', "/");
    let lower = rel.to_ascii_lowercase();
    let basename = name;

    // Logs/.txt → keep text in memory.
    if lower.contains("/logs/") {
        if let Some(known) = KIK_LOG_NAMES
            .iter()
            .find(|kn| lower.ends_with(&format!("/{}", kn)))
        {
            if let Ok(bytes) = fs::read(p) {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                sources.logs.insert(known.to_string(), text);
            }
            return;
        }
        // PDF that lives under logs/
        if lower.ends_with(".pdf") {
            let dest_name = sanitize_filename(basename);
            let dest = media_dir.join(&dest_name);
            let _ = fs::copy(p, &dest);
            if lower.contains("subscriber-data") {
                sources.subscriber_pdf = Some(dest_name);
            } else if lower.contains("coa") {
                sources.coa_pdf = Some(dest_name);
            }
            return;
        }
    }

    // Content directory (media).
    if lower.contains("/content/") {
        if let Some(stem) = uuid_from_basename(basename) {
            let dest_name = sanitize_filename(basename);
            let dest = media_dir.join(&dest_name);
            if fs::copy(p, &dest).is_ok() {
                sources.content_files.insert(stem, dest_name);
            }
        }
        return;
    }

    // Other PDFs at the case root.
    if lower.ends_with(".pdf") {
        let dest_name = sanitize_filename(basename);
        let dest = media_dir.join(&dest_name);
        let _ = fs::copy(p, &dest);
        if lower.contains("kik sw sign") {
            sources.sw_sign_pdf = Some(dest_name);
        } else if lower.contains("production order result legend") {
            sources.legend_pdf = Some(dest_name);
        }
    }
}

/// Open a `_case{N}.zip` file from the filesystem and ingest its members.
fn ingest_inner_zip_file(
    path: &Path,
    media_dir: &Path,
    sources: &mut Sources,
) -> Result<(), ParseError> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        if let Some((u, c)) = parse_case_folder(name.trim_end_matches(".zip")) {
            if sources.account_username.is_none() {
                sources.account_username = Some(u);
            }
            if sources.case_number.is_none() {
                sources.case_number = Some(c);
            }
        }
    }
    walk_zip(&mut zip, media_dir, sources)
}

/// Open an archive directly (outer ZIP, OR an inner ZIP) and ingest.
fn collect_sources_from_zip(
    archive_path: &Path,
    media_dir: &Path,
    sources: &mut Sources,
) -> Result<(), ParseError> {
    let file = File::open(archive_path)?;
    let mut zip = ZipArchive::new(file)?;

    // First pass: identify any nested `_case{N}.zip` entries to recurse
    // into.  Kik wraps the real production in an outer "completed
    // documents" envelope.
    let mut inner_zip_names: Vec<String> = Vec::new();
    let mut has_kik_logs_directly = false;

    for i in 0..zip.len() {
        let raw = zip.by_index(i)?.name().to_string();
        let lower = raw.to_ascii_lowercase();
        if lower.contains("__macosx/") || lower.contains("/._") || lower.starts_with("._") {
            continue;
        }
        if lower.ends_with(".zip") && lower.contains("_case") {
            inner_zip_names.push(raw);
        } else if is_known_kik_log(&lower) {
            has_kik_logs_directly = true;
        }
    }

    // If we have logs at the top level, walk this archive directly.
    if has_kik_logs_directly {
        walk_zip(&mut zip, media_dir, sources)?;
    }

    // For every nested case zip, read into memory and reopen.
    for inner_name in inner_zip_names {
        let basename = inner_name.rsplit('/').next().unwrap_or(&inner_name);
        if let Some((u, c)) = parse_case_folder(basename.trim_end_matches(".zip")) {
            if sources.account_username.is_none() {
                sources.account_username = Some(u);
            }
            if sources.case_number.is_none() {
                sources.case_number = Some(c);
            }
        }
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut entry = zip.by_name(&inner_name)?;
            entry.read_to_end(&mut buf)?;
        }
        match ZipArchive::new(Cursor::new(buf)) {
            Ok(mut inner) => {
                walk_zip(&mut inner, media_dir, sources)?;
            }
            Err(e) => {
                eprintln!("[kik] inner zip {} open failed: {}", inner_name, e);
            }
        }
    }

    Ok(())
}

fn walk_zip<R: Read + std::io::Seek>(
    zip: &mut ZipArchive<R>,
    media_dir: &Path,
    sources: &mut Sources,
) -> Result<(), ParseError> {
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let raw = entry.name().to_string();
        let lower = raw.to_ascii_lowercase();

        // Skip macOS metadata.
        if lower.contains("__macosx/") || lower.contains("/._") || lower.starts_with("._") {
            continue;
        }

        let basename = raw.rsplit('/').next().unwrap_or(&raw).to_string();

        // Learn username/case from path segments too.
        if sources.account_username.is_none() {
            for seg in raw.split('/') {
                if let Some((u, c)) = parse_case_folder(seg) {
                    sources.account_username = Some(u);
                    sources.case_number = Some(c);
                    break;
                }
            }
        }

        // Logs/.txt → buffer text.
        if lower.contains("/logs/") {
            if let Some(known) = KIK_LOG_NAMES
                .iter()
                .find(|kn| lower.ends_with(&format!("/{}", kn)))
            {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                let text = String::from_utf8_lossy(&bytes).into_owned();
                sources.logs.insert(known.to_string(), text);
                continue;
            }
            if lower.ends_with(".pdf") {
                let dest_name = sanitize_filename(&basename);
                let dest = media_dir.join(&dest_name);
                let mut out = File::create(&dest)?;
                std::io::copy(&mut entry, &mut out)?;
                if lower.contains("subscriber-data") {
                    sources.subscriber_pdf = Some(dest_name);
                } else if lower.contains("coa") {
                    sources.coa_pdf = Some(dest_name);
                }
                continue;
            }
        }

        // Content/ media files (UUIDs with or without extensions).
        if lower.contains("/content/") {
            if let Some(stem) = uuid_from_basename(&basename) {
                let dest_name = sanitize_filename(&basename);
                let dest = media_dir.join(&dest_name);
                let mut out = File::create(&dest)?;
                std::io::copy(&mut entry, &mut out)?;
                sources.content_files.insert(stem, dest_name);
                continue;
            }
        }

        // Other PDFs (warrant sign, legend, etc.) at the case root.
        if lower.ends_with(".pdf") {
            let dest_name = sanitize_filename(&basename);
            let dest = media_dir.join(&dest_name);
            let mut out = File::create(&dest)?;
            std::io::copy(&mut entry, &mut out)?;
            if lower.contains("kik sw sign") {
                sources.sw_sign_pdf = Some(dest_name);
            } else if lower.contains("production order result legend") {
                sources.legend_pdf = Some(dest_name);
            }
            continue;
        }
    }
    Ok(())
}

/// Parse a `{username}_case{N}` segment.  Returns `(username, caseNumber)`
/// if the segment looks like a Kik inner case directory or zip stem.
fn parse_case_folder(name: &str) -> Option<(String, String)> {
    // Find "_case" and require digits after it.
    let lower = name.to_ascii_lowercase();
    let idx = lower.find("_case")?;
    let after = &name[idx + "_case".len()..];
    let case_num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if case_num.is_empty() {
        return None;
    }
    let username = name[..idx].to_string();
    if username.is_empty() {
        return None;
    }
    Some((username, case_num))
}

/// A Kik media UUID is 36 chars in 8-4-4-4-12 form.  Filename may be the
/// bare UUID OR `{uuid}.{ext}`.  Return the bare UUID stem.
fn uuid_from_basename(basename: &str) -> Option<String> {
    let stem = basename.rsplit_once('.').map(|(s, _)| s).unwrap_or(basename);
    if stem.len() != 36 {
        return None;
    }
    let bytes = stem.as_bytes();
    let dash_at = [8, 13, 18, 23];
    for (i, b) in bytes.iter().enumerate() {
        if dash_at.contains(&i) {
            if *b != b'-' {
                return None;
            }
        } else if !b.is_ascii_hexdigit() {
            return None;
        }
    }
    Some(stem.to_string())
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

// ─── Quick detection for `accepts(dir)` ─────────────────────────────────

fn dir_has_kik_format(dir: &Path) -> bool {
    let mut stack: Vec<(PathBuf, u32)> = vec![(dir.to_path_buf(), 0)];
    while let Some((cur, depth)) = stack.pop() {
        if depth > 5 {
            continue;
        }
        let entries = match fs::read_dir(&cur) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let lname = name.to_ascii_lowercase();
            if p.is_dir() {
                if lname == "logs" || lname == "content" || parse_case_folder(&name).is_some() {
                    return true;
                }
                stack.push((p, depth + 1));
            } else if KIK_LOG_NAMES.iter().any(|kn| &lname == kn)
                || lname.contains("kik sw sign")
                || lname.contains("production order result legend")
            {
                return true;
            }
        }
    }
    false
}

// ─── TSV parsing ────────────────────────────────────────────────────────

/// Split a non-empty TSV row.  Trims trailing `\r`.
fn split_tsv(line: &str) -> Vec<&str> {
    let l = line.strip_suffix('\r').unwrap_or(line);
    l.split('\t').collect()
}

fn iter_tsv(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines().filter(|l| !l.trim().is_empty()).map(split_tsv)
}

/// Get cell or empty.
fn cell(row: &[&str], i: usize) -> String {
    row.get(i).map(|s| s.trim().to_string()).unwrap_or_default()
}

// ─── Subscriber bio ─────────────────────────────────────────────────────

fn emit_subscriber_bio(sources: &Sources, ctx: &mut ParseCtx) {
    let username = sources
        .account_username
        .clone()
        .or_else(|| ctx.target_account.clone());
    if username.is_none() && sources.subscriber_pdf.is_none() {
        return;
    }

    let mut fields: Vec<Value> = Vec::new();
    if let Some(u) = &username {
        fields.push(json!({ "label": "Kik Username", "value": u }));
    }
    if let Some(c) = &sources.case_number {
        fields.push(json!({ "label": "Kik Case #", "value": c }));
    }
    let mut attachments: Vec<String> = Vec::new();
    if let Some(pdf) = &sources.subscriber_pdf {
        fields.push(json!({ "label": "Subscriber Data PDF", "value": pdf }));
        attachments.push(pdf.clone());
    }
    if let Some(pdf) = &sources.coa_pdf {
        fields.push(json!({ "label": "Certificate of Authenticity", "value": pdf }));
        attachments.push(pdf.clone());
    }

    let summary = match (&username, &sources.case_number) {
        (Some(u), Some(c)) => format!("{} · case {}", u, c),
        (Some(u), None) => u.clone(),
        (None, Some(c)) => format!("case {}", c),
        _ => "Kik subscriber".into(),
    };

    let body = fields
        .iter()
        .filter_map(|f| {
            let l = f.get("label").and_then(|v| v.as_str())?;
            let v = f.get("value").and_then(|v| v.as_str())?;
            Some(format!("{}: {}", l, v))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let id = ctx.next_id("bio");
    ctx.items.push(WarrantItem {
        id,
        section: "bio".into(),
        section_display: "Subscriber Details".into(),
        timestamp: None,
        author: username.clone(),
        recipient: None,
        body_text: Some(body),
        summary: Some(summary),
        raw_fields: json!({ "fields": fields }),
        attachments,
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

// ─── bind.txt → login_history ───────────────────────────────────────────

fn emit_binds(text: &str, ctx: &mut ParseCtx) {
    for row in iter_tsv(text) {
        // ts_ms, username, ip, port, datetime, country
        let ts_ms = cell(&row, 0);
        let username = cell(&row, 1);
        let ip = cell(&row, 2);
        let port = cell(&row, 3);
        let datetime = cell(&row, 4);
        let country = cell(&row, 5);

        if username.is_empty() && ip.is_empty() && datetime.is_empty() {
            continue;
        }
        ctx.touch_date(&datetime);

        let summary = format!(
            "{} · {} ({})",
            if datetime.is_empty() { "?" } else { &datetime },
            if ip.is_empty() { "?" } else { &ip },
            if country.is_empty() { "?" } else { &country },
        );
        let body = format!(
            "Username: {}\nIP: {}\nPort: {}\nCountry: {}\nTimestamp: {}",
            username, ip, port, country, datetime
        );
        let id = ctx.next_id("login");
        ctx.items.push(WarrantItem {
            id,
            section: "login_history".into(),
            section_display: "Login History".into(),
            timestamp: if datetime.is_empty() { None } else { Some(datetime.clone()) },
            author: if username.is_empty() { None } else { Some(username.clone()) },
            recipient: None,
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": ts_ms,
                "username": username,
                "ip": ip,
                "port": port,
                "datetime": datetime,
                "country": country,
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── friend_added.txt → friends ─────────────────────────────────────────

fn emit_friends(text: &str, ctx: &mut ParseCtx) {
    for row in iter_tsv(text) {
        // ts_ms, user, friend_username, datetime
        let ts_ms = cell(&row, 0);
        let user = cell(&row, 1);
        let friend = cell(&row, 2);
        let datetime = cell(&row, 3);

        if user.is_empty() && friend.is_empty() {
            continue;
        }
        ctx.touch_date(&datetime);

        let summary = format!(
            "{} added {}",
            if user.is_empty() { "?" } else { &user },
            if friend.is_empty() { "?" } else { &friend },
        );
        let body = format!(
            "Account: {}\nFriend Added: {}\nTimestamp: {}",
            user, friend, datetime
        );
        let id = ctx.next_id("friend");
        ctx.items.push(WarrantItem {
            id,
            section: "friends".into(),
            section_display: "Friends".into(),
            timestamp: if datetime.is_empty() { None } else { Some(datetime.clone()) },
            author: if user.is_empty() { None } else { Some(user.clone()) },
            recipient: if friend.is_empty() { None } else { Some(friend.clone()) },
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": ts_ms,
                "user": user,
                "friend": friend,
                "datetime": datetime,
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── block_user.txt → blocks ────────────────────────────────────────────

fn emit_blocks(text: &str, ctx: &mut ParseCtx) {
    for row in iter_tsv(text) {
        let ts_ms = cell(&row, 0);
        let user = cell(&row, 1);
        let blocked = cell(&row, 2);
        let datetime = cell(&row, 3);
        if user.is_empty() && blocked.is_empty() {
            continue;
        }
        ctx.touch_date(&datetime);
        let summary = format!(
            "{} blocked {}",
            if user.is_empty() { "?" } else { &user },
            if blocked.is_empty() { "?" } else { &blocked },
        );
        let body = format!(
            "Account: {}\nBlocked User: {}\nTimestamp: {}",
            user, blocked, datetime
        );
        let id = ctx.next_id("block");
        ctx.items.push(WarrantItem {
            id,
            section: "blocks".into(),
            section_display: "Blocked Users".into(),
            timestamp: if datetime.is_empty() { None } else { Some(datetime.clone()) },
            author: if user.is_empty() { None } else { Some(user.clone()) },
            recipient: if blocked.is_empty() { None } else { Some(blocked.clone()) },
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": ts_ms,
                "user": user,
                "blocked": blocked,
                "datetime": datetime,
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── DM text (chat_sent / chat_sent_received) ───────────────────────────

fn emit_dm_text(text: &str, dir: MsgDirection, ctx: &mut ParseCtx) {
    for row in iter_tsv(text) {
        // ts_ms, sender, recipient, msg_count, ip|REDACTED, datetime
        let ts_ms = cell(&row, 0);
        let sender = cell(&row, 1);
        let recipient = cell(&row, 2);
        let msg_count = cell(&row, 3);
        let ip = cell(&row, 4);
        let datetime = cell(&row, 5);
        if sender.is_empty() && recipient.is_empty() {
            continue;
        }
        ctx.touch_date(&datetime);

        let count_int: i64 = msg_count.parse().unwrap_or(0);
        let count_part = if count_int > 1 {
            format!(" · {} msgs", count_int)
        } else {
            String::new()
        };
        let summary = format!(
            "{} → {}{} ({})",
            if sender.is_empty() { "?" } else { &sender },
            if recipient.is_empty() { "?" } else { &recipient },
            count_part,
            dir.label(),
        );
        let body = format!(
            "Direction: {}\nSender: {}\nRecipient: {}\nMessage Count: {}\nIP: {}\nTimestamp: {}",
            dir.label(),
            sender,
            recipient,
            msg_count,
            ip,
            datetime
        );
        let id = ctx.next_id("dm");
        ctx.items.push(WarrantItem {
            id,
            section: "unified_messages".into(),
            section_display: "Messages".into(),
            timestamp: if datetime.is_empty() { None } else { Some(datetime.clone()) },
            author: if sender.is_empty() { None } else { Some(sender.clone()) },
            recipient: if recipient.is_empty() { None } else { Some(recipient.clone()) },
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": ts_ms,
                "sender": sender,
                "recipient": recipient,
                "msg_count": msg_count,
                "ip": ip,
                "datetime": datetime,
                "direction": dir.label(),
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── DM media (chat_platform_sent / chat_platform_sent_received) ────────

fn emit_dm_media(
    text: &str,
    dir: MsgDirection,
    sources: &Sources,
    ctx: &mut ParseCtx,
) {
    for row in iter_tsv(text) {
        // ts_ms, sender, recipient, mediaType, media_uuid, ip|REDACTED, datetime
        let ts_ms = cell(&row, 0);
        let sender = cell(&row, 1);
        let recipient = cell(&row, 2);
        let media_type = cell(&row, 3);
        let media_uuid = cell(&row, 4);
        let ip = cell(&row, 5);
        let datetime = cell(&row, 6);

        if sender.is_empty() && recipient.is_empty() && media_uuid.is_empty() {
            continue;
        }
        ctx.touch_date(&datetime);

        let mut attachments: Vec<String> = Vec::new();
        if !media_uuid.is_empty() {
            if let Some(file) = sources.content_files.get(&media_uuid) {
                attachments.push(file.clone());
            }
        }

        let attach_note = if attachments.is_empty() {
            "(media file not in production)".to_string()
        } else {
            format!("Attachment: {}", attachments.join(", "))
        };
        let summary = format!(
            "{} → {} · {} ({})",
            if sender.is_empty() { "?" } else { &sender },
            if recipient.is_empty() { "?" } else { &recipient },
            if media_type.is_empty() { "Media" } else { &media_type },
            dir.label(),
        );
        let body = format!(
            "Direction: {}\nSender: {}\nRecipient: {}\nMedia Type: {}\nMedia UUID: {}\nIP: {}\nTimestamp: {}\n{}",
            dir.label(),
            sender,
            recipient,
            media_type,
            media_uuid,
            ip,
            datetime,
            attach_note
        );
        let id = ctx.next_id("dmedia");
        ctx.items.push(WarrantItem {
            id,
            section: "media_messages".into(),
            section_display: "Media Messages".into(),
            timestamp: if datetime.is_empty() { None } else { Some(datetime.clone()) },
            author: if sender.is_empty() { None } else { Some(sender.clone()) },
            recipient: if recipient.is_empty() { None } else { Some(recipient.clone()) },
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": ts_ms,
                "sender": sender,
                "recipient": recipient,
                "media_type": media_type,
                "media_uuid": media_uuid,
                "ip": ip,
                "datetime": datetime,
                "direction": dir.label(),
            }),
            attachments,
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── Group text (group_send_msg / group_receive_msg) ────────────────────
//
// Each row represents ONE group-member fanout of a single message — Kik's
// servers log delivery once per recipient.  We collapse by
// (ts_ms, sender, group_id) so a 5-member group that received 1 broadcast
// emits 1 triage item, not 5.

#[derive(Default)]
struct GroupTextBucket {
    ts_ms: String,
    datetime: String,
    sender: String,
    group_id: String,
    msg_count_total: i64,
    ip: String,
    recipients: Vec<String>,
}

fn emit_group_text(text: &str, dir: MsgDirection, ctx: &mut ParseCtx) {
    // Preserve insertion order with BTreeMap on a sortable key (the
    // 13-digit timestamp prefix makes it chronological).
    let mut buckets: BTreeMap<String, GroupTextBucket> = BTreeMap::new();

    for row in iter_tsv(text) {
        // ts_ms, sender, group_id, recipient, msg_count, ip|REDACTED, datetime
        let ts_ms = cell(&row, 0);
        let sender = cell(&row, 1);
        let group_id = cell(&row, 2);
        let recipient = cell(&row, 3);
        let msg_count = cell(&row, 4);
        let ip = cell(&row, 5);
        let datetime = cell(&row, 6);

        if sender.is_empty() && group_id.is_empty() {
            continue;
        }
        let key = format!("{}|{}|{}", ts_ms, sender, group_id);
        let b = buckets.entry(key).or_insert_with(|| GroupTextBucket {
            ts_ms: ts_ms.clone(),
            datetime: datetime.clone(),
            sender: sender.clone(),
            group_id: group_id.clone(),
            msg_count_total: 0,
            ip: ip.clone(),
            recipients: Vec::new(),
        });
        if !recipient.is_empty() && !b.recipients.contains(&recipient) {
            b.recipients.push(recipient);
        }
        b.msg_count_total += msg_count.parse::<i64>().unwrap_or(0);
        if b.ip.is_empty() && !ip.is_empty() {
            b.ip = ip;
        }
        if b.datetime.is_empty() && !datetime.is_empty() {
            b.datetime = datetime;
        }
    }

    for (_, b) in buckets {
        ctx.touch_date(&b.datetime);
        let recip_preview = if b.recipients.len() <= 3 {
            b.recipients.join(", ")
        } else {
            format!("{} +{} more", b.recipients[..3].join(", "), b.recipients.len() - 3)
        };
        let summary = format!(
            "{} → group {} · {} recipients ({})",
            if b.sender.is_empty() { "?" } else { &b.sender },
            short_group_id(&b.group_id),
            b.recipients.len(),
            dir.label(),
        );
        let body = format!(
            "Direction: {}\nSender: {}\nGroup ID: {}\nRecipients ({}): {}\nDelivery rows: {}\nIP: {}\nTimestamp: {}",
            dir.label(),
            b.sender,
            b.group_id,
            b.recipients.len(),
            recip_preview,
            b.msg_count_total,
            b.ip,
            b.datetime
        );
        let id = ctx.next_id("gchat");
        ctx.items.push(WarrantItem {
            id,
            section: "group_chats".into(),
            section_display: "Group Chats".into(),
            timestamp: if b.datetime.is_empty() { None } else { Some(b.datetime.clone()) },
            author: if b.sender.is_empty() { None } else { Some(b.sender.clone()) },
            recipient: if b.group_id.is_empty() { None } else { Some(b.group_id.clone()) },
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": b.ts_ms,
                "sender": b.sender,
                "group_id": b.group_id,
                "recipients": b.recipients,
                "msg_count_total": b.msg_count_total,
                "ip": b.ip,
                "datetime": b.datetime,
                "direction": dir.label(),
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── Group media (group_send_msg_platform / group_receive_msg_platform) ──
//
// Same fanout pattern as group text, but with an associated media_uuid.
// We bucket by (ts_ms, sender, group_id, media_uuid) so each piece of
// shared media → one triage item.

#[derive(Default)]
struct GroupMediaBucket {
    ts_ms: String,
    datetime: String,
    sender: String,
    group_id: String,
    media_type: String,
    media_uuid: String,
    ip: String,
    recipients: Vec<String>,
}

fn emit_group_media(
    text: &str,
    dir: MsgDirection,
    sources: &Sources,
    ctx: &mut ParseCtx,
) {
    let mut buckets: BTreeMap<String, GroupMediaBucket> = BTreeMap::new();

    for row in iter_tsv(text) {
        // ts_ms, sender, group_id, recipient, mediaType, media_uuid, ip|REDACTED, datetime
        let ts_ms = cell(&row, 0);
        let sender = cell(&row, 1);
        let group_id = cell(&row, 2);
        let recipient = cell(&row, 3);
        let media_type = cell(&row, 4);
        let media_uuid = cell(&row, 5);
        let ip = cell(&row, 6);
        let datetime = cell(&row, 7);

        if sender.is_empty() && group_id.is_empty() && media_uuid.is_empty() {
            continue;
        }
        let key = format!("{}|{}|{}|{}", ts_ms, sender, group_id, media_uuid);
        let b = buckets.entry(key).or_insert_with(|| GroupMediaBucket {
            ts_ms: ts_ms.clone(),
            datetime: datetime.clone(),
            sender: sender.clone(),
            group_id: group_id.clone(),
            media_type: media_type.clone(),
            media_uuid: media_uuid.clone(),
            ip: ip.clone(),
            recipients: Vec::new(),
        });
        if !recipient.is_empty() && !b.recipients.contains(&recipient) {
            b.recipients.push(recipient);
        }
        if b.ip.is_empty() && !ip.is_empty() {
            b.ip = ip;
        }
        if b.datetime.is_empty() && !datetime.is_empty() {
            b.datetime = datetime;
        }
    }

    for (_, b) in buckets {
        ctx.touch_date(&b.datetime);

        let mut attachments: Vec<String> = Vec::new();
        if !b.media_uuid.is_empty() {
            if let Some(file) = sources.content_files.get(&b.media_uuid) {
                attachments.push(file.clone());
            }
        }
        let attach_note = if attachments.is_empty() {
            "(media file not in production)".to_string()
        } else {
            format!("Attachment: {}", attachments.join(", "))
        };

        let recip_preview = if b.recipients.len() <= 3 {
            b.recipients.join(", ")
        } else {
            format!("{} +{} more", b.recipients[..3].join(", "), b.recipients.len() - 3)
        };
        let summary = format!(
            "{} → group {} · {} · {} recipients ({})",
            if b.sender.is_empty() { "?" } else { &b.sender },
            short_group_id(&b.group_id),
            if b.media_type.is_empty() { "Media" } else { &b.media_type },
            b.recipients.len(),
            dir.label(),
        );
        let body = format!(
            "Direction: {}\nSender: {}\nGroup ID: {}\nMedia Type: {}\nMedia UUID: {}\nRecipients ({}): {}\nIP: {}\nTimestamp: {}\n{}",
            dir.label(),
            b.sender,
            b.group_id,
            b.media_type,
            b.media_uuid,
            b.recipients.len(),
            recip_preview,
            b.ip,
            b.datetime,
            attach_note
        );

        let id = ctx.next_id("gmedia");
        ctx.items.push(WarrantItem {
            id,
            section: "group_media".into(),
            section_display: "Group Media".into(),
            timestamp: if b.datetime.is_empty() { None } else { Some(b.datetime.clone()) },
            author: if b.sender.is_empty() { None } else { Some(b.sender.clone()) },
            recipient: if b.group_id.is_empty() { None } else { Some(b.group_id.clone()) },
            body_text: Some(body),
            summary: Some(summary),
            raw_fields: json!({
                "ts_ms": b.ts_ms,
                "sender": b.sender,
                "group_id": b.group_id,
                "recipients": b.recipients,
                "media_type": b.media_type,
                "media_uuid": b.media_uuid,
                "ip": b.ip,
                "datetime": b.datetime,
                "direction": dir.label(),
            }),
            attachments,
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

/// Shorten a Kik group id like `1100258890805_g` for display.
fn short_group_id(g: &str) -> String {
    if g.len() <= 14 {
        g.to_string()
    } else {
        format!("…{}", &g[g.len() - 10..])
    }
}

// ─── Request parameters / cover documents ───────────────────────────────

fn emit_request_parameters(sources: &Sources, ctx: &mut ParseCtx) {
    let mut attachments: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    if let Some(p) = &sources.sw_sign_pdf {
        attachments.push(p.clone());
        lines.push(format!("Signed Warrant: {}", p));
    }
    if let Some(p) = &sources.legend_pdf {
        attachments.push(p.clone());
        lines.push(format!("Production Order Result Legend: {}", p));
    }
    if let Some(p) = &sources.coa_pdf {
        if !attachments.contains(p) {
            attachments.push(p.clone());
            lines.push(format!("Certificate of Authenticity: {}", p));
        }
    }
    if attachments.is_empty() {
        return;
    }

    let id = ctx.next_id("rp");
    ctx.items.push(WarrantItem {
        id,
        section: "request_parameters".into(),
        section_display: "Request Parameters".into(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(lines.join("\n")),
        summary: Some(format!("{} request document(s)", attachments.len())),
        raw_fields: json!({ "documents": attachments }),
        attachments,
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

// Image/Video extensions kept around for any future media-type inference.
#[allow(dead_code)]
fn ext_is_image(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    IMAGE_EXTS.iter().any(|e| lower.ends_with(e))
}
#[allow(dead_code)]
fn ext_is_video(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    VIDEO_EXTS.iter().any(|e| lower.ends_with(e))
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Run a smoke test against an unpacked Kik sample.  Set
    /// `KIK_TEST_SAMPLE_ZIP` to the outer "completed-documents" ZIP, or
    /// `KIK_TEST_SAMPLE_DIR` to an already-extracted folder.
    #[test]
    fn end_to_end_against_sample() {
        let Some(input) = env::var_os("KIK_TEST_SAMPLE_ZIP")
            .or_else(|| env::var_os("KIK_TEST_SAMPLE_DIR"))
        else {
            eprintln!("[kik test] KIK_TEST_SAMPLE_ZIP / DIR not set — skipping");
            return;
        };
        let path = std::path::PathBuf::from(input);
        if !path.exists() {
            eprintln!("[kik test] sample path does not exist: {:?}", path);
            return;
        }

        let parser = KikWarrantParser;
        let accept = parser.accepts(&path).expect("accepts() failed");
        assert!(accept, "parser did not accept the sample");

        let tmp = std::env::temp_dir().join(format!(
            "kik_test_media_{}",
            uuid::Uuid::new_v4().to_string()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let result = parser.parse(&path, &tmp).expect("parse() failed");

        println!(
            "[kik test] target={:?} date_range={:?} generated_at={:?} items={}",
            result.case.target_account,
            result.case.date_range,
            result.case.generated_at_source,
            result.items.len()
        );

        // Count by section.
        let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
        for it in &result.items {
            *counts.entry(it.section.as_str()).or_insert(0) += 1;
        }
        println!("[kik test] section counts: {:?}", counts);

        // Sample summaries for a few sections.
        for sect in ["bio", "login_history", "unified_messages", "group_media"] {
            if let Some(item) = result.items.iter().find(|i| i.section == sect) {
                println!(
                    "[kik test] {:>20} → {}",
                    sect,
                    item.summary.as_deref().unwrap_or("(no summary)")
                );
            }
        }

        assert!(result.case.target_account.is_some(), "no target account detected");
        assert!(!result.items.is_empty(), "no items produced");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
