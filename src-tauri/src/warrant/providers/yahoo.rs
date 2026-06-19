//! Yahoo (Verizon Media / Yahoo Inc.) warrant-return parser.
//!
//! Format reference
//! ----------------
//! Yahoo law-enforcement productions are delivered as a top-level folder
//! (or a zip of one) named like `YAHOO-{caseId}` containing:
//!
//!   YAHOO-{caseId}/
//!     Yahoo Records Declaration-YAHOO-{caseId}.pdf
//!     Production Files/
//!       SUBSCRIBER_DETAILS_{n}/
//!         {target}_{folderId}/
//!           {target}-subscriber_details-MM.DD.YYYY.html
//!       LOGIN_DATA_{n}/
//!         {target}_{folderId}/
//!           {target}-lt-activity.csv
//!           {target}-lt-activity.html
//!       MAIL_{n}/            (optional — emails)
//!       CONTACTS_{n}/        (optional)
//!       CALENDAR_{n}/        (optional)
//!       FLICKR_{n}/          (optional)
//!       MESSENGER_{n}/       (optional)
//!       LOCATION_{n}/        (optional)
//!
//! The numeric suffix on each section folder (e.g. `_3`, `_5`) is Yahoo's
//! internal request-line identifier; it varies between productions.
//!
//! Each Yahoo HTML document is a single-page report containing one or more
//! `<div class="datainfo">` sections.  Inside each section the column
//! header row uses `<div class="row title">` and subsequent rows are
//! `<div class="row">` with `<div class="value mid">` / `<div class="value
//! long">` cells.  Field-style rows (label → value) appear in the
//! `<div class="userinfo">` block as `<div class="label">Name</div>Value`.
//!
//! The Login Activity CSV has a 4-line preamble (`Search for,...`,
//! `Date Range,...`, `Time Zone,...`, `Total Results,...`) followed by a
//! header row and data rows.  If `Total Results` is `0` the CSV is empty
//! and the HTML displays a "no records that meet the search criteria"
//! placeholder.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use scraper::{ElementRef, Html, Selector};
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

// MBOX / RFC822 utilities shared with Google (and any future email-bearing
// provider).  Yahoo productions can ship a `.mbox` per account when mail is
// requested; we parse it exactly the same way as Gmail's "All mail.mbox".
use super::mbox_lib::{split_mbox, parse_email_message, EmailMsg};

pub struct YahooWarrantParser;

// ─── WarrantParser impl ─────────────────────────────────────────────────

impl WarrantParser for YahooWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Yahoo
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_yahoo_format(path));
        }

        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        // Strong signal: any subscriber_details*.html OR lt-activity.csv
        // inside a "Production Files/" or directly named YAHOO-{id} folder.
        for i in 0..zip.len() {
            let name = zip.by_index(i)?.name().to_string();
            let lower = name.to_lowercase();
            if lower.contains("subscriber_details")
                || lower.contains("lt-activity.csv")
                || lower.contains("yahoo records declaration")
            {
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

        // Phase 1: gather every text file we care about into memory and
        // copy media (PDF declarations) to the case media dir.
        let sources = if archive_path.is_dir() {
            collect_sources_from_dir(archive_path, media_extract_dir)?
        } else {
            collect_sources_from_zip(archive_path, media_extract_dir)?
        };

        if sources.text_files.is_empty() && sources.media_files.is_empty() {
            return Err(ParseError::Other(
                "No Yahoo production files found in input".into(),
            ));
        }

        // Phase 2: parse subscriber details + login activity into rows.
        let mut ctx = ParseCtx::default();
        ctx.media_dir = media_extract_dir.to_path_buf();

        // Subscriber Details — emits a "bio" item per account.
        for (rel_path, html) in iter_files(&sources, |p| {
            p.to_ascii_lowercase().contains("subscriber_details")
                && p.to_ascii_lowercase().ends_with(".html")
        }) {
            emit_subscriber_details(rel_path, html, &mut ctx);
        }

        // Login Activity — emits a row per login event, plus a row per
        // account_action event (Yahoo splits them in the same HTML doc).
        for (rel_path, html) in iter_files(&sources, |p| {
            p.to_ascii_lowercase().contains("lt-activity")
                && p.to_ascii_lowercase().ends_with(".html")
        }) {
            emit_login_activity(rel_path, html, &mut ctx);
        }

        // Fallback to CSV if HTML wasn't shipped for some account.
        for (rel_path, text) in iter_files(&sources, |p| {
            p.to_ascii_lowercase().contains("lt-activity")
                && p.to_ascii_lowercase().ends_with(".csv")
        }) {
            emit_login_activity_csv(rel_path, text, &mut ctx);
        }

        // Mail — Yahoo ships either a real `.mbox` (preferred — full RFC822
        // with attachments) or, in older productions, one HTML file per
        // message under MAIL_*.  We handle both.
        //
        // 1.  Real `.mbox` files — parsed via the shared mbox_lib helper.
        for (rel_path, text) in iter_files(&sources, |p| {
            p.to_ascii_lowercase().ends_with(".mbox")
        }) {
            emit_email_from_mbox(rel_path, text, &mut ctx);
        }

        // 2.  Fallback: per-message HTML files under MAIL_*.  These give us
        //     the subject + body only (no attachments, no envelope).
        for (rel_path, html) in iter_files(&sources, |p| {
            let lower = p.to_ascii_lowercase();
            lower.contains("/mail_") && lower.ends_with(".html")
        }) {
            emit_mail_placeholder(rel_path, html, &mut ctx);
        }

        // Records Declaration PDF — link as an attachment on a single
        // "request_parameters" item so investigators can open it.
        for media_rel in &sources.media_files {
            let lower = media_rel.to_ascii_lowercase();
            if lower.contains("records declaration") || lower.ends_with(".pdf") {
                emit_records_declaration(media_rel, &mut ctx);
            }
        }

        // Phase 3: build case metadata.
        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let case = WarrantCase {
            case_id,
            provider: Provider::Yahoo,
            provider_display: "Yahoo".to_string(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.target_account.clone(),
            date_range: ctx.date_range.clone(),
            generated_at_source: ctx.generated_at_source.clone(),
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
                name: "Emails of Interest".into(),
                color: "#7B0099".into(),
                description: Some("Mail messages relevant to the investigation".into()),
            },
            BucketTemplate {
                name: "Account Activity".into(),
                color: "#6366f1".into(),
                description: Some("Logins / account changes worth flagging".into()),
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

// ─── Internal types ─────────────────────────────────────────────────────

/// In-memory bundle of files found inside the production.  The text map
/// keys are forward-slash relative paths (case preserved as discovered)
/// so callers can still inspect the original folder structure for hints.
struct Sources {
    /// rel_path → decoded UTF-8 text content.
    text_files: HashMap<String, String>,
    /// Relative paths of binary files (PDF, mail attachments, etc.) that
    /// have been copied to the case media dir.
    media_files: Vec<String>,
}

#[derive(Default)]
struct ParseCtx {
    items: Vec<WarrantItem>,
    id_seq: HashMap<&'static str, usize>,
    /// First non-empty `Target` field seen (e.g. `gamerboychris@yahoo.com`).
    target_account: Option<String>,
    /// First non-empty Yahoo "Date Range" string we discover.
    date_range: Option<String>,
    /// First subscriber-details filename suffix (production date) we see.
    generated_at_source: Option<String>,
    /// Where mail attachments (and any other binary spill from parsers)
    /// should be written.  Set by `parse()` before any emit_* runs.
    media_dir: PathBuf,
}

impl ParseCtx {
    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }
}

// ─── Filesystem / zip ingestion ─────────────────────────────────────────

const TEXT_EXTS: &[&str] = &[".html", ".htm", ".csv", ".txt", ".json", ".xml", ".mbox", ".eml"];
const BINARY_EXTS: &[&str] = &[
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif",
    ".mp4", ".mov", ".webm", ".m4v", ".mp3", ".wav", ".m4a",
];

fn collect_sources_from_dir(root: &Path, media_dir: &Path) -> Result<Sources, ParseError> {
    let mut sources = Sources {
        text_files: HashMap::new(),
        media_files: Vec::new(),
    };

    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            // Skip macOS resource forks.
            if name.starts_with("._") || name == ".DS_Store" {
                continue;
            }
            // Skip __MACOSX side-channel folders.
            let parent_name = p
                .parent()
                .and_then(|x| x.file_name())
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if parent_name == "__MACOSX" || name == "__MACOSX" {
                continue;
            }

            if p.is_dir() {
                stack.push(p);
                continue;
            }

            let rel = pathdiff_for(&p, root);
            let rel_norm = rel.replace('\\', "/");
            let lower = rel_norm.to_ascii_lowercase();

            if has_ext(&lower, TEXT_EXTS) {
                if let Ok(bytes) = fs::read(&p) {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    sources.text_files.insert(rel_norm, text);
                }
            } else if has_ext(&lower, BINARY_EXTS) {
                let dest_name = sanitize_filename(&name);
                let dest = media_dir.join(&dest_name);
                if let Err(e) = fs::copy(&p, &dest) {
                    eprintln!("yahoo: failed copying {} → {:?}: {}", rel_norm, dest, e);
                } else {
                    sources.media_files.push(dest_name);
                }
            }
        }
    }

    Ok(sources)
}

fn collect_sources_from_zip(archive_path: &Path, media_dir: &Path) -> Result<Sources, ParseError> {
    let file = File::open(archive_path)?;
    let mut zip = ZipArchive::new(file)?;
    let mut sources = Sources {
        text_files: HashMap::new(),
        media_files: Vec::new(),
    };

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let raw = entry.name().to_string();
        // Skip macOS metadata.
        if raw.contains("__MACOSX/") || raw.contains("/._") || raw.starts_with("._") {
            continue;
        }
        let basename = raw.rsplit('/').next().unwrap_or(&raw).to_string();
        let lower = raw.to_ascii_lowercase();

        if has_ext(&lower, TEXT_EXTS) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let text = String::from_utf8_lossy(&buf).into_owned();
            sources.text_files.insert(raw.replace('\\', "/"), text);
        } else if has_ext(&lower, BINARY_EXTS) {
            let dest_name = sanitize_filename(&basename);
            let dest = media_dir.join(&dest_name);
            let mut out = File::create(&dest)?;
            std::io::copy(&mut entry, &mut out)?;
            sources.media_files.push(dest_name);
        }
    }

    Ok(sources)
}

fn pathdiff_for(p: &Path, root: &Path) -> String {
    p.strip_prefix(root)
        .map(|x| x.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string_lossy().into_owned())
}

fn has_ext(name: &str, exts: &[&str]) -> bool {
    exts.iter().any(|e| name.ends_with(e))
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

fn iter_files<'a, F>(
    sources: &'a Sources,
    pred: F,
) -> impl Iterator<Item = (&'a str, &'a str)> + 'a
where
    F: Fn(&str) -> bool + 'a,
{
    sources
        .text_files
        .iter()
        .filter(move |(k, _)| pred(k))
        .map(|(k, v)| (k.as_str(), v.as_str()))
}

// ─── Quick detection for `accepts(dir)` ─────────────────────────────────

fn dir_has_yahoo_format(dir: &Path) -> bool {
    // Walk up to two levels looking for a Yahoo signature.  A single
    // `Production Files` folder, a `Yahoo Records Declaration*.pdf`, or
    // any `*-subscriber_details*.html` / `*-lt-activity.*` is enough.
    let mut stack: Vec<(PathBuf, u32)> = vec![(dir.to_path_buf(), 0)];
    while let Some((cur, depth)) = stack.pop() {
        if depth > 4 {
            continue;
        }
        let entries = match fs::read_dir(&cur) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let lname = name.to_ascii_lowercase();
            if p.is_dir() {
                if lname == "production files"
                    || lname.starts_with("subscriber_details")
                    || lname.starts_with("login_data")
                    || lname.starts_with("mail_")
                {
                    return true;
                }
                stack.push((p, depth + 1));
            } else if lname.contains("subscriber_details")
                || lname.contains("lt-activity")
                || (lname.contains("yahoo") && lname.contains("records declaration"))
            {
                return true;
            }
        }
    }
    false
}

// ─── Subscriber Details parsing ─────────────────────────────────────────

/// Yahoo subscriber-details HTML structure:
///
///     <div class="userinfo">
///       <div class="sectionhdr">Request Information</div>
///       <div class="row"><div class="label">Target</div>gamerboychris@yahoo.com</div>
///       ...
///     </div>
///     <div class="datainfo">
///       <div class="sectionhdr">User Information</div>
///       <div class="row title">…header…</div>
///       <div class="row"><div class="value mid">Other Identities</div>
///                        <div class="value long">gamerboychris <br></div></div>
///       ...
///     </div>
///
/// We pull every (label, value) pair from both the `userinfo` block and
/// the row-based `datainfo` blocks (treating the first cell as label, the
/// second as value).
fn emit_subscriber_details(source: &str, html: &str, ctx: &mut ParseCtx) {
    let doc = Html::parse_document(html);
    let sel_userinfo_rows = Selector::parse("div.userinfo > div.row").unwrap();
    let sel_label = Selector::parse("div.label").unwrap();
    let sel_datainfo = Selector::parse("div.datainfo").unwrap();
    let sel_data_row = Selector::parse("div.row").unwrap();
    let sel_value = Selector::parse("div.value").unwrap();
    let sel_section_hdr = Selector::parse("div.sectionhdr").unwrap();

    let mut request_info: Vec<(String, String)> = Vec::new();
    let mut user_info: Vec<(String, String)> = Vec::new();
    let mut current_target: Option<String> = None;

    // --- userinfo block: "Target", "Brand", etc. -------------------------
    for row in doc.select(&sel_userinfo_rows) {
        let label = row
            .select(&sel_label)
            .next()
            .map(|e| collapse_ws(&extract_text(e)))
            .unwrap_or_default();
        if label.is_empty() {
            continue;
        }
        // The value is everything after the label div in the row.  Easiest
        // way to get it: take the row's full text minus the label text.
        let full = collapse_ws(&extract_text(row));
        let value = full
            .strip_prefix(&label)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| full.clone());
        if !value.is_empty() {
            if label.eq_ignore_ascii_case("target") {
                current_target = Some(value.clone());
            }
            request_info.push((label, value));
        }
    }

    // --- datainfo blocks: tabular rows ----------------------------------
    for block in doc.select(&sel_datainfo) {
        let block_title = block
            .select(&sel_section_hdr)
            .next()
            .map(|e| collapse_ws(&extract_text(e)))
            .unwrap_or_default();

        // Skip the title row (class includes "title") — we want data rows only.
        for row in block.select(&sel_data_row) {
            let classes = row
                .value()
                .attr("class")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if classes.contains("title") {
                continue;
            }
            let cells: Vec<String> = row
                .select(&sel_value)
                .map(|e| collapse_ws(&extract_text_with_br(e)))
                .collect();

            if cells.len() < 2 {
                continue;
            }
            let label = cells[0].clone();
            let value = cells[1..].join(" ").trim().to_string();
            if label.is_empty() || value.is_empty() {
                continue;
            }
            // Prefix with block title for non-User Information sections so
            // investigators can tell which block a field came from.
            let final_label = if block_title.eq_ignore_ascii_case("User Information")
                || block_title.is_empty()
            {
                label
            } else {
                format!("{} · {}", block_title, label)
            };
            user_info.push((final_label, value));
        }
    }

    if request_info.is_empty() && user_info.is_empty() {
        return;
    }

    // Lift target/date for case-level metadata.
    if ctx.target_account.is_none() {
        if let Some(t) = current_target.clone() {
            ctx.target_account = Some(t);
        }
    }
    if ctx.generated_at_source.is_none() {
        if let Some(date) = extract_production_date(source) {
            ctx.generated_at_source = Some(date);
        }
    }

    // Build the WarrantItem.
    let mut fields: Vec<Value> = Vec::new();
    for (l, v) in &request_info {
        fields.push(json!({ "label": l, "value": v, "block": "Request Information" }));
    }
    for (l, v) in &user_info {
        fields.push(json!({ "label": l, "value": v, "block": "User Information" }));
    }

    let summary_bits: Vec<String> = ["Target", "Full Name", "GUID"]
        .iter()
        .filter_map(|wanted| {
            request_info
                .iter()
                .chain(user_info.iter())
                .find(|(l, _)| l.eq_ignore_ascii_case(wanted))
                .map(|(_, v)| v.clone())
        })
        .collect();
    let summary = if summary_bits.is_empty() {
        format!("Account · {} fields", fields.len())
    } else {
        summary_bits.join(" · ")
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
        author: current_target.clone(),
        recipient: None,
        body_text: Some(body),
        summary: Some(summary),
        raw_fields: json!({
            "fields": fields,
            "source": source,
        }),
        attachments: Vec::new(),
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

/// Pull a `MM.DD.YYYY` (or `MM-DD-YYYY`) chunk out of a path like
/// `…/gamerboychris@yahoo.com-subscriber_details-08.26.2025.html`.
fn extract_production_date(source: &str) -> Option<String> {
    let basename = source.rsplit('/').next().unwrap_or(source);
    // Strip the extension before scanning so trailing `.html` doesn't get
    // swept into our date capture.
    let stem = basename.rsplit_once('.').map(|(s, _)| s).unwrap_or(basename);

    // Walk left → right collecting runs of digits/`.`/`-` and pick the
    // longest run that contains at least two separators (so we don't
    // capture a single year or zip).
    let mut best = String::new();
    let mut buf = String::new();
    for c in stem.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() || c == '.' || c == '-' {
            buf.push(c);
        } else {
            let sep_count = buf.chars().filter(|c| *c == '.' || *c == '-').count();
            if sep_count >= 2 && buf.len() > best.len() {
                best = buf.clone();
            }
            buf.clear();
        }
    }
    // Trim leading/trailing separators.
    let trimmed = best.trim_matches(|c: char| c == '.' || c == '-').to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

// ─── Login Activity parsing (HTML) ──────────────────────────────────────

/// The Login Activity HTML contains two `<div class="datainfo">` blocks:
///   1. "Login Activity"   — login events
///   2. "Account_action"   — account-modification events
///
/// Both share the same column schema: User ID | IP | Port | TimeStamp.
/// When there are zero records, Yahoo inserts a `<div class="row">There
/// are no login activity records that meet the search criteria.</div>` —
/// we treat that as "no rows" and emit nothing for that block.  We still
/// pull the request envelope (Target / Date Range / Time Zone) regardless.
fn emit_login_activity(source: &str, html: &str, ctx: &mut ParseCtx) {
    let doc = Html::parse_document(html);
    let sel_userinfo_rows = Selector::parse("div.userinfo > div.row").unwrap();
    let sel_label = Selector::parse("div.label").unwrap();
    let sel_datainfo = Selector::parse("div.datainfo").unwrap();
    let sel_section_hdr = Selector::parse("div.sectionhdr").unwrap();
    let sel_data_row = Selector::parse("div.row").unwrap();
    let sel_value = Selector::parse("div.value").unwrap();

    // Request envelope (Target / Start / End / Time Zone)
    let mut target: Option<String> = None;
    let mut start_date: Option<String> = None;
    let mut end_date: Option<String> = None;

    for row in doc.select(&sel_userinfo_rows) {
        let label = row
            .select(&sel_label)
            .next()
            .map(|e| collapse_ws(&extract_text(e)))
            .unwrap_or_default();
        if label.is_empty() {
            continue;
        }
        let full = collapse_ws(&extract_text(row));
        let value = full
            .strip_prefix(&label)
            .map(|s| s.trim().to_string())
            .unwrap_or(full.clone());
        match label.to_ascii_lowercase().as_str() {
            "target" => target = Some(value),
            "start date" => start_date = Some(value),
            "end date" => end_date = Some(value),
            _ => {}
        }
    }

    if ctx.target_account.is_none() {
        if let Some(t) = target.clone() {
            ctx.target_account = Some(t);
        }
    }
    if ctx.date_range.is_none() {
        if let (Some(s), Some(e)) = (start_date.as_ref(), end_date.as_ref()) {
            ctx.date_range = Some(format!("{} → {}", s, e));
        }
    }

    // Walk each datainfo block; the section header text tells us whether
    // we're looking at logins or account_action events.
    for block in doc.select(&sel_datainfo) {
        let hdr = block
            .select(&sel_section_hdr)
            .next()
            .map(|e| collapse_ws(&extract_text(e)))
            .unwrap_or_default();
        let section_key: &'static str = if hdr.eq_ignore_ascii_case("Account_action") {
            "account_action"
        } else {
            "login_history"
        };
        let section_display = if section_key == "account_action" {
            "Account Action".to_string()
        } else {
            "Login History".to_string()
        };

        for row in block.select(&sel_data_row) {
            let classes = row
                .value()
                .attr("class")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if classes.contains("title") {
                continue;
            }
            let cells: Vec<String> = row
                .select(&sel_value)
                .map(|e| collapse_ws(&extract_text_with_br(e)))
                .collect();

            // If the row has no .value cells, it's the "no records" notice.
            if cells.is_empty() {
                continue;
            }
            // We expect 4 cells (User ID, IP, Port, Timestamp).  Pad/truncate
            // defensively rather than dropping the row.
            let user_id = cells.first().cloned().unwrap_or_default();
            let ip = cells.get(1).cloned().unwrap_or_default();
            let port = cells.get(2).cloned().unwrap_or_default();
            let ts = cells.get(3).cloned().unwrap_or_default();

            if user_id.is_empty() && ip.is_empty() && ts.is_empty() {
                continue;
            }

            let summary = format!(
                "{} · {} · {}",
                if ts.is_empty() { "?" } else { &ts },
                if ip.is_empty() { "?" } else { &ip },
                if user_id.is_empty() { "?" } else { &user_id },
            );

            let id = ctx.next_id(if section_key == "account_action" {
                "act"
            } else {
                "login"
            });
            ctx.items.push(WarrantItem {
                id,
                section: section_key.into(),
                section_display: section_display.clone(),
                timestamp: if ts.is_empty() { None } else { Some(ts.clone()) },
                author: if user_id.is_empty() { None } else { Some(user_id.clone()) },
                recipient: None,
                body_text: Some(format!(
                    "User ID: {}\nIP: {}\nPort: {}\nTimestamp: {}",
                    user_id, ip, port, ts
                )),
                summary: Some(summary),
                raw_fields: json!({
                    "user_id": user_id,
                    "ip": ip,
                    "port": port,
                    "timestamp": ts,
                    "source": source,
                }),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

/// CSV fallback for login activity.  Yahoo's CSV layout:
///
///     Search for,gamerboychris@yahoo.com
///     Date Range,2022-01-01 00:00:01 / 2025-08-25 23:59:59
///     Time Zone,(UTC) Universal Time Coordinated
///     Total Results,0
///     Type,User ID,IP Address,Port,Timestamp
///     <data rows>
fn emit_login_activity_csv(source: &str, text: &str, ctx: &mut ParseCtx) {
    let mut lines = text.lines();
    let mut header_seen = false;
    let mut total_results_str: Option<String> = None;

    // Capture preamble; bail on first row that looks like the header.
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("Search for,") {
            let val = trimmed.split_once(',').map(|(_, v)| v.trim().to_string());
            if let Some(v) = val {
                if ctx.target_account.is_none() && !v.is_empty() {
                    ctx.target_account = Some(v);
                }
            }
        } else if trimmed.starts_with("Date Range,") {
            let val = trimmed.split_once(',').map(|(_, v)| v.trim().to_string());
            if let Some(v) = val {
                if ctx.date_range.is_none() && !v.is_empty() {
                    ctx.date_range = Some(v);
                }
            }
        } else if trimmed.starts_with("Total Results,") {
            total_results_str = trimmed.split_once(',').map(|(_, v)| v.trim().to_string());
        } else if trimmed.starts_with("Type,") || trimmed.starts_with("User ID,") {
            // Header row — start consuming data rows on the next iteration.
            header_seen = true;
            break;
        }
    }

    if !header_seen {
        return;
    }

    // If we already emitted login items from HTML for this same account,
    // the CSV would just duplicate them.  Skip when zero results are
    // declared — saves us emitting nothing rows.
    if matches!(total_results_str.as_deref(), Some("0")) {
        return;
    }

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cells: Vec<String> = split_csv_row(line);
        // Yahoo's "Type,User ID,IP Address,Port,Timestamp" → 5 cells.
        // If there are only 4 (no "Type" column), shift labels accordingly.
        let (type_, user_id, ip, port, ts) = match cells.len() {
            5 => (
                cells[0].clone(),
                cells[1].clone(),
                cells[2].clone(),
                cells[3].clone(),
                cells[4].clone(),
            ),
            4 => (
                "login".into(),
                cells[0].clone(),
                cells[1].clone(),
                cells[2].clone(),
                cells[3].clone(),
            ),
            _ => continue,
        };

        let section_key: &'static str = if type_.eq_ignore_ascii_case("account_action") {
            "account_action"
        } else {
            "login_history"
        };
        let section_display = if section_key == "account_action" {
            "Account Action".to_string()
        } else {
            "Login History".to_string()
        };

        let summary = format!(
            "{} · {} · {}",
            if ts.is_empty() { "?" } else { &ts },
            if ip.is_empty() { "?" } else { &ip },
            if user_id.is_empty() { "?" } else { &user_id },
        );

        let id = ctx.next_id(if section_key == "account_action" {
            "act"
        } else {
            "login"
        });
        ctx.items.push(WarrantItem {
            id,
            section: section_key.into(),
            section_display,
            timestamp: if ts.is_empty() { None } else { Some(ts.clone()) },
            author: if user_id.is_empty() { None } else { Some(user_id.clone()) },
            recipient: None,
            body_text: Some(format!(
                "Type: {}\nUser ID: {}\nIP: {}\nPort: {}\nTimestamp: {}",
                type_, user_id, ip, port, ts
            )),
            summary: Some(summary),
            raw_fields: json!({
                "type": type_,
                "user_id": user_id,
                "ip": ip,
                "port": port,
                "timestamp": ts,
                "source": source,
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── Mail: real `.mbox` parsing ─────────────────────────────────────────

/// Image / video extensions we surface as their own gallery items in
/// addition to attaching them to the parent email.
const MAIL_IMAGE_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp",
];
const MAIL_VIDEO_EXTS: &[&str] = &[
    ".mp4", ".mov", ".webm", ".m4v", ".3gp", ".mkv",
];

/// Parse one Yahoo `.mbox` and emit a WarrantItem per message into the
/// `emails` section.  Attachments are written into `ctx.media_dir`.
fn emit_email_from_mbox(source: &str, text: &str, ctx: &mut ParseCtx) {
    let raw_messages = split_mbox(text);
    for raw in raw_messages {
        let msg = parse_email_message(&raw);
        emit_email_item(source, msg, ctx);
    }
}

fn emit_email_item(source: &str, msg: EmailMsg, ctx: &mut ParseCtx) {
    let id = ctx.next_id("email");

    // Promote `From` to target_account if Yahoo subscriber HTML wasn't
    // present (some productions ship mail-only).
    if ctx.target_account.is_none() {
        if let Some(from) = msg.from.as_ref() {
            if let Some(email) = extract_email_address(from) {
                ctx.target_account = Some(email);
            }
        }
    }

    // Write attachments to ctx.media_dir, build attachments lists.
    let mut attachment_files: Vec<String> = Vec::new();
    let mut attachment_meta: Vec<Value> = Vec::new();
    for (fname, mime, bytes) in &msg.attachments {
        let safe_name = sanitize_filename(fname);
        let unique_name = format!("{}_{}", id, safe_name);
        let out_path = ctx.media_dir.join(&unique_name);
        if let Ok(mut f) = File::create(&out_path) {
            if f.write_all(bytes).is_ok() {
                attachment_files.push(unique_name.clone());
                attachment_meta.push(json!({
                    "originalName": fname,
                    "mimeType": mime,
                    "size": bytes.len(),
                    "storedAs": unique_name,
                }));

                // Also surface images / videos in the gallery.
                let lower = fname.to_lowercase();
                if MAIL_IMAGE_EXTS.iter().any(|e| lower.ends_with(e))
                    || MAIL_VIDEO_EXTS.iter().any(|e| lower.ends_with(e))
                {
                    let photo_id = ctx.next_id("photo");
                    ctx.items.push(WarrantItem {
                        id: photo_id,
                        section: "photos".into(),
                        section_display: "Photos".into(),
                        timestamp: msg.date.clone(),
                        author: msg.from.clone(),
                        recipient: msg.to.clone(),
                        body_text: None,
                        summary: Some(fname.clone()),
                        raw_fields: json!({
                            "originalName": fname,
                            "mimeType": mime,
                            "size": bytes.len(),
                            "storedAs": unique_name,
                            "fromEmail": id.clone(),
                            "source": source,
                        }),
                        attachments: vec![unique_name.clone()],
                        bucket: None,
                        note: None,
                        is_flagged: false,
                    });
                }
            }
        }
    }

    let summary = format!(
        "{} — {}",
        msg.from.as_deref().unwrap_or("(unknown sender)"),
        msg.subject.as_deref().unwrap_or("(no subject)"),
    );

    let raw = json!({
        "from": msg.from,
        "to": msg.to,
        "cc": msg.cc,
        "bcc": msg.bcc,
        "subject": msg.subject,
        "date": msg.date,
        "messageId": msg.message_id,
        "labels": msg.labels,
        "receivedIps": msg.received_ips,
        "attachments": attachment_meta,
        "source": source,
    });

    ctx.items.push(WarrantItem {
        id,
        section: "emails".into(),
        section_display: "Emails".into(),
        timestamp: msg.date.clone(),
        author: msg.from.clone(),
        recipient: msg.to.clone(),
        body_text: msg.body_text,
        summary: Some(summary),
        raw_fields: raw,
        attachments: attachment_files,
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

/// Pull `foo@bar.com` out of `"Name" <foo@bar.com>` or raw `foo@bar.com`.
fn extract_email_address(s: &str) -> Option<String> {
    if let (Some(lt), Some(gt)) = (s.find('<'), s.rfind('>')) {
        if gt > lt {
            let inner = &s[lt + 1..gt];
            if inner.contains('@') {
                return Some(inner.trim().to_string());
            }
        }
    }
    let trimmed = s.trim();
    if trimmed.contains('@') && !trimmed.contains(char::is_whitespace) {
        return Some(trimmed.to_string());
    }
    None
}

// ─── Mail placeholder ───────────────────────────────────────────────────

/// Surface every mail HTML file as a generic email entry until we have a
/// representative sample to fully parse.  Investigators can still preview
/// the raw HTML in the triage UI and bucket / flag it.
fn emit_mail_placeholder(source: &str, html: &str, ctx: &mut ParseCtx) {
    let doc = Html::parse_document(html);
    let sel_title = Selector::parse("title").unwrap();
    let sel_body = Selector::parse("body").unwrap();

    let subject = doc
        .select(&sel_title)
        .next()
        .map(|e| collapse_ws(&extract_text(e)))
        .filter(|s| !s.is_empty())
        .or_else(|| {
            // Yahoo Mail exports also often embed the subject in a
            // `<div class="subject">…</div>` block.
            let sel = Selector::parse("div.subject").ok()?;
            doc.select(&sel).next().map(|e| collapse_ws(&extract_text(e)))
        });

    let body_text = doc
        .select(&sel_body)
        .next()
        .map(|e| collapse_ws(&extract_text(e)));

    let basename = source.rsplit('/').next().unwrap_or(source).to_string();

    let id = ctx.next_id("mail");
    ctx.items.push(WarrantItem {
        id,
        section: "emails".into(),
        section_display: "Emails".into(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: body_text.clone(),
        summary: subject.clone().or(Some(basename.clone())),
        raw_fields: json!({
            "subject": subject,
            "source": source,
            "file": basename,
        }),
        attachments: Vec::new(),
        bucket: None,
        note: None,
        is_flagged: false,
    });

    // Suppress unused-warning when html is small / we didn't get a body.
    let _ = html.len();
}

// ─── Records Declaration ────────────────────────────────────────────────

fn emit_records_declaration(media_rel: &str, ctx: &mut ParseCtx) {
    let id = ctx.next_id("decl");
    ctx.items.push(WarrantItem {
        id,
        section: "request_parameters".into(),
        section_display: "Records Declaration".into(),
        timestamp: None,
        author: Some("Yahoo Inc.".into()),
        recipient: None,
        body_text: Some(format!(
            "Yahoo Records Declaration (signed certification of authenticity).\nFile: {}",
            media_rel
        )),
        summary: Some("Records Declaration (PDF)".into()),
        raw_fields: json!({
            "type": "records_declaration",
            "file": media_rel,
        }),
        attachments: vec![media_rel.to_string()],
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

// ─── HTML / CSV helpers ─────────────────────────────────────────────────

fn extract_text(e: ElementRef) -> String {
    e.text().collect::<Vec<_>>().join(" ")
}

/// Collect text but turn <br> tags into newlines.  Yahoo uses <br> to
/// separate multi-valued fields (e.g. Password Change Event(s)).
fn extract_text_with_br(e: ElementRef) -> String {
    let mut out = String::new();
    for child in e.children() {
        match child.value() {
            scraper::Node::Text(t) => out.push_str(&t),
            scraper::Node::Element(el) => {
                if el.name() == "br" {
                    out.push('\n');
                } else if let Some(ref_) = ElementRef::wrap(child) {
                    out.push_str(&extract_text_with_br(ref_));
                }
            }
            _ => {}
        }
    }
    out
}

fn collapse_ws(s: &str) -> String {
    // Normalise whitespace runs but preserve real newlines.
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for c in s.chars() {
        if c == '\n' {
            // flush any pending space then emit newline.
            out.push('\n');
            in_space = false;
        } else if c.is_whitespace() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out.trim().to_string()
}

fn split_csv_row(line: &str) -> Vec<String> {
    // Minimal quote-aware CSV splitter — enough for Yahoo's simple output.
    let mut cells: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                cells.push(std::mem::take(&mut cur).trim().to_string());
            }
            _ => cur.push(c),
        }
    }
    cells.push(cur.trim().to_string());
    cells
}

// Drag the `Cursor` import along even if not used yet — Yahoo Mail samples
// may need byte-cursor reading later.
#[allow(dead_code)]
fn _keep_imports(_c: Cursor<Vec<u8>>) {}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Smoke test: drive the parser against a real extracted Yahoo
    //! production directory.  We don't ship case data in the repo, so the
    //! test is gated on `YAHOO_TEST_SAMPLE_DIR` env var — if it's unset
    //! the test silently passes.  To run locally:
    //!
    //!   set YAHOO_TEST_SAMPLE_DIR=C:\path\to\YAHOO-11540
    //!   cargo test --features demo -p datapilot-scout -- yahoo::tests --nocapture

    use super::*;
    use std::env;
    use std::fs;

    #[test]
    fn end_to_end_against_sample_dir() {
        let sample_dir = match env::var("YAHOO_TEST_SAMPLE_DIR") {
            Ok(v) if !v.trim().is_empty() => std::path::PathBuf::from(v),
            _ => {
                eprintln!("[skip] YAHOO_TEST_SAMPLE_DIR not set; skipping smoke test");
                return;
            }
        };

        assert!(
            sample_dir.is_dir(),
            "YAHOO_TEST_SAMPLE_DIR must point at an extracted YAHOO-* directory: {}",
            sample_dir.display()
        );

        let parser = YahooWarrantParser;
        assert_eq!(parser.provider(), Provider::Yahoo);
        assert!(
            parser
                .accepts(&sample_dir)
                .expect("accepts() must not error"),
            "Yahoo parser failed to recognize a real production directory"
        );

        let tmp = env::temp_dir().join(format!("scout_yahoo_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create scratch media dir");

        let parsed = parser
            .parse(&sample_dir, &tmp)
            .expect("Yahoo parser must succeed on a well-formed production");

        eprintln!(
            "Yahoo parse complete: target={:?}  date_range={:?}  generated_at={:?}  items={}",
            parsed.case.target_account,
            parsed.case.date_range,
            parsed.case.generated_at_source,
            parsed.items.len()
        );

        let bio_items: Vec<_> =
            parsed.items.iter().filter(|i| i.section == "bio").collect();
        assert!(
            !bio_items.is_empty(),
            "expected at least one bio (subscriber details) item"
        );
        let bio = bio_items[0];
        eprintln!("bio summary: {:?}", bio.summary);
        let body = bio.body_text.as_deref().unwrap_or("");
        eprintln!(
            "bio body (first 800 chars):\n{}",
            body.chars().take(800).collect::<String>()
        );
        assert!(
            body.to_ascii_uppercase().contains("GUID"),
            "bio body should include the GUID field"
        );
        assert!(
            parsed.case.target_account.is_some(),
            "Yahoo case must extract a target_account"
        );
        assert!(
            parsed
                .default_buckets
                .iter()
                .any(|b| b.name == "CSAM"),
            "default buckets must include CSAM"
        );
    }

    /// Self-contained test (no external sample required): build a fake
    /// Yahoo production directory with a single subscriber-details HTML
    /// stub + a `.mbox` containing one synthetic message, then verify
    /// `parse()` walks the mbox path via mbox_lib and emits an `emails`
    /// section item with the correct envelope + body.
    #[test]
    fn synthetic_mbox_is_parsed_and_emitted() {
        let scratch = env::temp_dir()
            .join(format!("scout_yahoo_mbox_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);

        // Yahoo's accepts() looks for a subscriber_details file OR an
        // lt-activity OR the records-declaration PDF.  We satisfy it with
        // a tiny subscriber_details HTML stub.
        let yahoo_root = scratch
            .join("YAHOO-99999")
            .join("Production Files")
            .join("SUBSCRIBER_DETAILS_1")
            .join("synth_target@yahoo.com_1");
        fs::create_dir_all(&yahoo_root).expect("create yahoo subscriber dir");

        let stub_html = r#"<html><body><div class="userinfo">
            <div class="label">GUID</div>SYNTH-GUID-1234
            <div class="label">Target</div>synth_target@yahoo.com
        </div></body></html>"#;
        fs::write(
            yahoo_root.join("synth_target@yahoo.com-subscriber_details-01.01.2025.html"),
            stub_html,
        )
        .unwrap();

        // MAIL_* folder with a synthetic mbox.
        let mail_root = scratch
            .join("YAHOO-99999")
            .join("Production Files")
            .join("MAIL_1")
            .join("synth_target@yahoo.com_1");
        fs::create_dir_all(&mail_root).expect("create mail dir");

        // Real RFC822 — split_mbox keys on `From ` envelope lines.
        let mbox = "From MAILER-DAEMON Mon Jan 06 09:00:00 2025\r\n\
                    From: \"Alice\" <alice@yahoo.com>\r\n\
                    To: synth_target@yahoo.com\r\n\
                    Subject: Test Yahoo Mail\r\n\
                    Date: Mon, 06 Jan 2025 09:00:00 -0500\r\n\
                    Message-ID: <synth-001@yahoo.com>\r\n\
                    X-YMail-OSG: yahoo-folder-Inbox\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    \r\n\
                    Hello from a synthetic Yahoo mbox message.\r\n\
                    Line two of the body.\r\n";
        fs::write(mail_root.join("Inbox.mbox"), mbox).unwrap();

        // Parse.
        let parser = YahooWarrantParser;
        let media = scratch.join("media");
        fs::create_dir_all(&media).unwrap();
        let result = parser
            .parse(&scratch.join("YAHOO-99999"), &media)
            .expect("Yahoo parser should succeed on synthetic production");

        let emails: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.section == "emails")
            .collect();
        assert_eq!(
            emails.len(),
            1,
            "expected exactly one parsed mbox message, got {} (items={})",
            emails.len(),
            result.items.len(),
        );
        let m = emails[0];
        assert_eq!(m.author.as_deref(), Some("\"Alice\" <alice@yahoo.com>"));
        assert_eq!(m.recipient.as_deref(), Some("synth_target@yahoo.com"));
        assert!(m
            .summary
            .as_deref()
            .map(|s| s.contains("Test Yahoo Mail"))
            .unwrap_or(false));
        let body = m.body_text.as_deref().unwrap_or("");
        assert!(
            body.contains("synthetic Yahoo mbox message"),
            "body should include the message body, got: {:?}",
            body
        );
        let labels = m
            .raw_fields
            .get("labels")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            labels.contains("yahoo-folder-Inbox"),
            "X-YMail-OSG should land in labels, got: {:?}",
            labels
        );

        // Tidy.
        let _ = fs::remove_dir_all(&scratch);
    }
}
