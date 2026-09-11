//! AT&T warrant-return parser.
//!
//! Format reference
//! ----------------
//! AT&T (via Kodex or the Global Legal Demand Center) delivers a folder or
//! ZIP containing, per report, **two renderings of the same data**:
//!
//! ```text
//!   ReportCT_4691733.txt   <- fixed-width 76-column text
//!   ReportCT_4691733.pdf   <- same content, typeset
//! ```
//!
//! plus the legal request itself as a separate (usually scanned) PDF.
//!
//! We parse the **.txt** and deliberately ignore the PDFs.  This is not
//! laziness — the PDF text layer merges adjacent fixed-width columns and the
//! result is genuinely ambiguous:
//!
//! ```text
//!   .pdf  ->  "Photo ID Number: DOB:"                 <- which label owns the value?
//!   .txt  ->  "   Photo ID Number:            DOB:"   <- two empty fields, unambiguous
//!
//!   .pdf  ->  "AT&T Reseller Port-In 10/02/2025"      <- wrapped cell silently joined
//!   .txt  ->  "AT&T Reseller        10/02/2025"
//!             "Port-In"                                <- continuation row, recoverable
//! ```
//!
//! Any PDF that has **no** `.txt` counterpart is surfaced as a parser notice
//! rather than silently skipped, so the examiner always knows what was and
//! was not read.
//!
//! Grammar
//! -------
//! A report is a sequence of pages.  A page is anchored by a line whose
//! trimmed content is exactly `AT&T`, optionally preceded by an all-digit
//! report-id line:
//!
//! ```text
//!   4691733                        <- report id
//!                           AT&T   <- anchor
//!   09/04/2026                     <- report date
//!                  WIRELESS        <- division / line of business
//!            SUBSCRIBER INFORMATION <- report title
//!   ----------------------------   <- 76 dashes = block separator
//!   337257581571                   <- page key (account number)
//!   ----------------------------
//!   FINANCIAL LIABLE PARTY         <- section name (UPPERCASE at col 0)
//!         Name: US MOBILE, INC.    <- field line, label right-aligned
//!   Contact Home Phone: (000) 000-0000   Contact Work Phone: (202) 818-9310
//!   ----------------------------
//!   STATUS CHANGE HISTORY
//!   Status Change Reason                  Status Change Date  <- table header
//!   AT&T Reseller                             10/02/2025      <- row
//!   Port-In                                                   <- WRAPPED cell
//!                   AT&T PROPRIETARY                          <- footer, dropped
//! ```
//!
//! Everything hinges on one rule: **split each line on runs of 2+ spaces** and
//! keep each segment's start column.  A single space is data; two is a column
//! gap.  From there:
//!
//!   * segment containing `:`  -> new field (label before, value after)
//!   * segment without `:`     -> continuation, appended to the previous value.
//!     This is required, not theoretical: AT&T writes `Name:  US MOBILE, INC.`
//!     with *two* spaces after the colon, which would otherwise orphan the value.
//!   * a block whose first row contains no `:` at all -> **table**; column
//!     boundaries come from the header segments' start columns and each row
//!     cell is assigned to the nearest column.
//!   * a table row with only column 0 filled, following a row with more than
//!     one cell filled -> wrapped continuation of the previous row.
//!
//! Why this matters forensically
//! -----------------------------
//! The sample that prompted this parser came with the note *"the ability to
//! find the account owner and information would be nice — this particular
//! account was a tracphone which did not have actual owner information"*.
//!
//! That dead end is an artefact of reading only the first page.  AT&T emits
//! one page per account/window, newest first, and for an MVNO (reseller)
//! number the newest page names **the reseller**, not the human:
//!
//! ```text
//!   06/06/2026 - Current      US MOBILE, INC.   11 E 44TH ST, NEW YORK, NY
//!   10/02/2025 - 06/06/2026   JUSTIN D MOYER    14775 BUGLE CT, FONTANA, CA
//! ```
//!
//! The end user *is* in the return — one page down.  So this parser builds a
//! per-MSISDN timeline and emits an explicit [`SEC_OWNERSHIP`] item that flags
//! reseller-held numbers, names the human holder of any earlier window, and
//! states the follow-up step.  It hedges its language deliberately: an
//! organisation name can also be a legitimate corporate account.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use chrono::Utc;
use serde_json::{json, Map, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

// ─── Tunables ─────────────────────────────────────────────────────────────

/// How much of a candidate file we read when sniffing for the AT&T marker.
const MARKER_SNIFF_BYTES: usize = 256 * 1024;

/// Depth limit when walking a production folder.
const MAX_DIR_DEPTH: usize = 6;

/// Hard ceiling on rows lifted out of a single generic report.  AT&T call
/// detail files run to tens of thousands of lines (one observed return had a
/// 42,000-line usage report); without a ceiling a pathological return could
/// exhaust memory in the UI.  When we hit it we say so in a notice item —
/// never silently.
const MAX_ROWS_PER_REPORT: usize = 50_000;

// ─── Section ids ──────────────────────────────────────────────────────────

const SEC_SUBSCRIBER: &str = "subscriber";
const SEC_ACCOUNT: &str = "account_billing";
const SEC_STATUS: &str = "status_history";
const SEC_OWNERSHIP: &str = "ownership";
const SEC_NOTICES: &str = "notices";

pub struct AttWarrantParser;

impl WarrantParser for AttWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Att
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_att_format(path, 0));
        }
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if ext == "txt" {
            return Ok(file_has_att_marker(path));
        }
        if ext == "zip" {
            let file = File::open(path)?;
            let mut zip = match ZipArchive::new(file) {
                Ok(z) => z,
                Err(_) => return Ok(false),
            };
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i)?;
                if entry.is_dir() || !name_is_txt(entry.name()) {
                    continue;
                }
                let mut buf = Vec::new();
                let _ = entry
                    .by_ref()
                    .take(MARKER_SNIFF_BYTES as u64)
                    .read_to_end(&mut buf);
                if text_has_att_marker(&String::from_utf8_lossy(&buf)) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn parse(
        &self,
        path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        if !self.accepts(path)? {
            return Err(ParseError::WrongFormat);
        }
        // AT&T returns carry no media, but the registry contract expects the
        // directory to exist.
        fs::create_dir_all(media_extract_dir)?;

        let mut reports: Vec<(String, String)> = Vec::new(); // (display name, text)
        let mut pdf_stems: Vec<(String, String)> = Vec::new(); // (stem, display name)
        collect_reports(path, &mut reports, &mut pdf_stems)?;

        if reports.is_empty() {
            return Err(ParseError::WrongFormat);
        }
        // Stable order so item ids are reproducible across imports.
        reports.sort_by(|a, b| a.0.cmp(&b.0));

        let txt_stems: HashSet<String> = reports
            .iter()
            .map(|(n, _)| stem_of(n).to_lowercase())
            .collect();

        let mut ctx = Ctx::default();
        for (name, text) in &reports {
            ctx.ingest_report(name, text);
        }
        ctx.emit_ownership_analysis();

        // Only complain about PDFs that have no .txt twin — every AT&T *data*
        // report ships as both, so a paired PDF is genuinely redundant and
        // flagging it would be noise.
        let unpaired: Vec<String> = pdf_stems
            .iter()
            .filter(|(stem, _)| !txt_stems.contains(&stem.to_lowercase()))
            .map(|(_, name)| name.clone())
            .collect();
        if !unpaired.is_empty() {
            ctx.emit_unpaired_pdf_notice(&unpaired);
        }

        let source_filename = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let case = WarrantCase {
            case_id: Uuid::new_v4().to_string(),
            provider: Provider::Att,
            provider_display: "AT&T".into(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.target_account(),
            date_range: ctx.date_range(),
            generated_at_source: ctx.report_date.clone(),
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
                name: "Subscriber / Owner".into(),
                color: "#10b981".into(),
                description: Some("Identity, billing and account-holder records".into()),
            },
            BucketTemplate {
                name: "Call Activity".into(),
                color: "#5b8def".into(),
                description: Some("Voice, SMS and data usage detail".into()),
            },
            BucketTemplate {
                name: "Location / Tower".into(),
                color: "#8b5cf6".into(),
                description: Some("Cell site, sector and NELOS records".into()),
            },
            BucketTemplate {
                name: "Needs Subpoena".into(),
                color: "#f59e0b".into(),
                description: Some(
                    "Reseller / MVNO-held records — owner details sit with the reseller".into(),
                ),
            },
            BucketTemplate {
                name: "Unrelated".into(),
                color: "#6b7280".into(),
                description: None,
            },
            BucketTemplate {
                name: "Needs Follow-Up".into(),
                color: "#eab308".into(),
                description: None,
            },
        ]
    }
}

// ─── Detection ────────────────────────────────────────────────────────────

fn name_is_txt(name: &str) -> bool {
    name.to_lowercase().ends_with(".txt")
}

fn name_is_pdf(name: &str) -> bool {
    name.to_lowercase().ends_with(".pdf")
}

fn stem_of(name: &str) -> &str {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) => &base[..i],
        None => base,
    }
}

/// The `AT&T PROPRIETARY` footer is stamped on every page of every report and
/// is the single most reliable marker.  The title fallback covers reports
/// whose footer wording differs.
fn text_has_att_marker(text: &str) -> bool {
    let upper = text.to_uppercase();
    if upper.contains("AT&T PROPRIETARY") {
        return true;
    }
    upper.contains("AT&T")
        && (upper.contains("SUBSCRIBER INFORMATION")
            || upper.contains("SUBSCRIBER INFO")
            || upper.contains("USER INFORMATION")
            || upper.contains("STATUS CHANGE HISTORY"))
}

fn file_has_att_marker(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if f.by_ref()
        .take(MARKER_SNIFF_BYTES as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    text_has_att_marker(&String::from_utf8_lossy(&buf))
}

fn dir_has_att_format(dir: &Path, depth: usize) -> bool {
    if depth > MAX_DIR_DEPTH {
        return false;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if dir_has_att_format(&p, depth + 1) {
                return true;
            }
            continue;
        }
        let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        if name_is_txt(&name) && file_has_att_marker(&p) {
            return true;
        }
        // AT&T frequently nests each report in its own ZIP.
        if name.to_lowercase().ends_with(".zip") {
            if let Ok(file) = File::open(&p) {
                if let Ok(mut zip) = ZipArchive::new(file) {
                    for i in 0..zip.len() {
                        let Ok(mut e) = zip.by_index(i) else { continue };
                        if e.is_dir() || !name_is_txt(e.name()) {
                            continue;
                        }
                        let mut buf = Vec::new();
                        let _ = e.by_ref().take(MARKER_SNIFF_BYTES as u64).read_to_end(&mut buf);
                        if text_has_att_marker(&String::from_utf8_lossy(&buf)) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

// ─── Collection ───────────────────────────────────────────────────────────

/// Gather every `.txt` report (recursing into folders and one level into any
/// ZIP) plus the stems of every `.pdf` seen so we can report unpaired ones.
///
/// Text is decoded lossily on purpose: these files are ASCII with the
/// occasional Latin-1 byte in a street name, and a hard UTF-8 error would
/// abort an otherwise perfectly readable return.
fn collect_reports(
    path: &Path,
    reports: &mut Vec<(String, String)>,
    pdfs: &mut Vec<(String, String)>,
) -> Result<(), ParseError> {
    if path.is_dir() {
        collect_from_dir(path, 0, reports, pdfs)?;
    } else if path.extension().map(|e| e.to_string_lossy().to_lowercase()) == Some("zip".into()) {
        collect_from_zip(path, reports, pdfs)?;
    } else {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "report.txt".into());
        let bytes = fs::read(path)?;
        reports.push((name, String::from_utf8_lossy(&bytes).into_owned()));
    }
    Ok(())
}

fn collect_from_dir(
    dir: &Path,
    depth: usize,
    reports: &mut Vec<(String, String)>,
    pdfs: &mut Vec<(String, String)>,
) -> Result<(), ParseError> {
    if depth > MAX_DIR_DEPTH {
        return Ok(());
    }
    for entry in fs::read_dir(dir)?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_from_dir(&p, depth + 1, reports, pdfs)?;
            continue;
        }
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let lower = name.to_lowercase();
        if name_is_txt(&lower) {
            let bytes = fs::read(&p)?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if text_has_att_marker(&text) {
                reports.push((name, text));
            }
        } else if name_is_pdf(&lower) {
            pdfs.push((stem_of(&name).to_string(), name));
        } else if lower.ends_with(".zip") {
            collect_from_zip(&p, reports, pdfs)?;
        }
    }
    Ok(())
}

fn collect_from_zip(
    path: &Path,
    reports: &mut Vec<(String, String)>,
    pdfs: &mut Vec<(String, String)>,
) -> Result<(), ParseError> {
    let file = File::open(path)?;
    let mut zip = match ZipArchive::new(file) {
        Ok(z) => z,
        Err(_) => return Ok(()),
    };
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let raw = entry.name().to_string();
        let base = raw.rsplit(['/', '\\']).next().unwrap_or(&raw).to_string();
        let lower = base.to_lowercase();
        if name_is_txt(&lower) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let text = String::from_utf8_lossy(&buf).into_owned();
            if text_has_att_marker(&text) {
                reports.push((base, text));
            }
        } else if name_is_pdf(&lower) {
            pdfs.push((stem_of(&base).to_string(), base));
        }
    }
    Ok(())
}

// ─── Grammar: segments ────────────────────────────────────────────────────

/// One 2+-space-delimited run of text, with the column it starts at.
#[derive(Debug, Clone, PartialEq)]
struct Segment {
    col: usize,
    text: String,
}

/// Split a fixed-width line into column segments.
///
/// A **single** space is data (`US MOBILE, INC.`); **two or more** is a column
/// gap.  `col` is a character offset, which is what table-column alignment
/// needs.
fn segments(line: &str) -> Vec<Segment> {
    let chars: Vec<char> = line.chars().collect();
    let mut out: Vec<Segment> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if is_space(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i + 1; // exclusive index just past the last non-space
        let mut j = i + 1;
        while j < chars.len() {
            if is_space(chars[j]) {
                let mut k = j;
                while k < chars.len() && is_space(chars[k]) {
                    k += 1;
                }
                if k - j >= 2 {
                    break; // column gap — segment ends
                }
                j = k; // lone space inside the value
            } else {
                j += 1;
                end = j;
            }
        }
        let text: String = chars[start..end].iter().collect();
        if !text.trim().is_empty() {
            out.push(Segment { col: start, text });
        }
        i = end;
    }
    out
}

fn is_space(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn is_dash_rule(line: &str) -> bool {
    let t = line.trim();
    t.len() >= 10 && t.chars().all(|c| c == '-')
}

fn is_footer(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("AT&T PROPRIETARY")
        || t.starts_with("The information contained here")
        || t.starts_with("is not for general distribution")
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// `MM/DD/YYYY` (or `M/D/YY`) — AT&T's only date shape.
fn is_us_date(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    parts.len() == 3
        && parts.iter().all(|p| is_all_digits(p))
        && (parts[2].len() == 4 || parts[2].len() == 2)
}

/// Looks like a section heading: uppercase, no colon, at the left margin.
fn is_section_heading(s: &str) -> bool {
    !s.is_empty()
        && !s.contains(':')
        && s.chars().any(|c| c.is_ascii_alphabetic())
        && s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || " &/.-()".contains(c))
}

// ─── Grammar: blocks + pages ──────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Block {
    /// A lone value between two rules — the page's account/identifier key.
    Key(String),
    Fields {
        name: Option<String>,
        fields: Vec<(String, String)>,
    },
    Table {
        name: Option<String>,
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

#[derive(Debug, Clone, Default)]
struct Page {
    report_id: Option<String>,
    date: Option<String>,
    division: Option<String>,
    report: Option<String>,
    key: Option<String>,
    blocks: Vec<Block>,
}

/// Split a report into pages.
///
/// The anchor is a line reading exactly `AT&T` (right-aligned letterhead).
/// The all-digit report-id line immediately above it, when present, belongs
/// to the same page.  If a report has no letterhead at all we treat the whole
/// file as one page so the generic extractor still gets a shot at it.
fn split_pages(text: &str) -> Vec<Vec<String>> {
    let lines: Vec<String> = text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|s| s.to_string())
        .collect();

    let mut starts: Vec<usize> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == "AT&T" {
            let start = if i > 0 && is_all_digits(lines[i - 1].trim()) {
                i - 1
            } else {
                i
            };
            // Guard against two anchors collapsing onto the same start.
            if starts.last() != Some(&start) {
                starts.push(start);
            }
        }
    }
    if starts.is_empty() {
        return if lines.iter().any(|l| !l.trim().is_empty()) {
            vec![lines]
        } else {
            Vec::new()
        };
    }
    let mut pages = Vec::new();
    for k in 0..starts.len() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        pages.push(lines[starts[k]..end].to_vec());
    }
    pages
}

fn parse_page(page: &[String]) -> Page {
    let mut out = Page::default();

    // Header runs up to the first horizontal rule.
    let rule_at = page.iter().position(|l| is_dash_rule(l)).unwrap_or(0);
    let head: Vec<String> = page[..rule_at]
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut titles: Vec<String> = Vec::new();
    for h in &head {
        if h == "AT&T" {
            continue;
        }
        if out.report_id.is_none() && is_all_digits(h) {
            out.report_id = Some(h.clone());
            continue;
        }
        if out.date.is_none() && is_us_date(h) {
            out.date = Some(h.clone());
            continue;
        }
        titles.push(h.clone());
    }
    if !titles.is_empty() {
        out.division = Some(titles[0].clone());
        if titles.len() > 1 {
            out.report = Some(titles[1..].join(" "));
        }
    }

    // Body: strip the footer, then cut on horizontal rules.
    let mut current: Vec<String> = Vec::new();
    let mut raw_blocks: Vec<Vec<String>> = Vec::new();
    for l in page[rule_at..].iter() {
        if is_footer(l) {
            continue;
        }
        if is_dash_rule(l) {
            if current.iter().any(|x| !x.trim().is_empty()) {
                raw_blocks.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            continue;
        }
        current.push(l.clone());
    }
    if current.iter().any(|x| !x.trim().is_empty()) {
        raw_blocks.push(current);
    }

    for rb in &raw_blocks {
        if let Some(b) = parse_block(rb) {
            match b {
                Block::Key(k) if out.key.is_none() => out.key = Some(k),
                other => out.blocks.push(other),
            }
        }
    }
    out
}

fn parse_block(raw: &[String]) -> Option<Block> {
    let rows: Vec<Vec<Segment>> = raw
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| segments(l))
        .filter(|s| !s.is_empty())
        .collect();
    if rows.is_empty() {
        return None;
    }

    // A lone value on its own between rules is the page key.
    if rows.len() == 1 && rows[0].len() == 1 && !rows[0][0].text.contains(':') {
        return Some(Block::Key(rows[0][0].text.trim().to_string()));
    }

    let mut name: Option<String> = None;
    let mut body = &rows[..];
    if rows.len() > 1 && rows[0].len() == 1 && is_section_heading(rows[0][0].text.trim()) {
        name = Some(rows[0][0].text.trim().to_string());
        body = &rows[1..];
    }
    if body.is_empty() {
        return None;
    }

    // Field block vs table block is decided by the first body row: fields
    // always carry a colon, table headers never do.  Deciding on the *header*
    // rather than on the data keeps values containing colons (`12:34:56` in a
    // call detail record) from being misread as labels.
    if body[0].iter().any(|s| s.text.contains(':')) {
        let mut fields: Vec<(String, String)> = Vec::new();
        for row in body {
            for seg in row {
                match seg.text.split_once(':') {
                    Some((k, v)) => {
                        let key = k.trim();
                        if key.is_empty() {
                            continue;
                        }
                        fields.push((key.to_string(), v.trim().to_string()));
                    }
                    None => {
                        // Continuation of the previous value — AT&T writes
                        // `Name:  US MOBILE, INC.` with two spaces after the
                        // colon, which splits the value into its own segment.
                        if let Some(last) = fields.last_mut() {
                            if last.1.is_empty() {
                                last.1 = seg.text.trim().to_string();
                            } else {
                                last.1 = format!("{} {}", last.1, seg.text.trim());
                            }
                        }
                    }
                }
            }
        }
        if fields.is_empty() {
            return None;
        }
        return Some(Block::Fields { name, fields });
    }

    let cols: Vec<usize> = body[0].iter().map(|s| s.col).collect();
    let columns: Vec<String> = body[0].iter().map(|s| s.text.trim().to_string()).collect();
    let mut out_rows: Vec<Vec<String>> = Vec::new();
    for row in &body[1..] {
        let mut cells = vec![String::new(); cols.len()];
        for seg in row {
            let idx = nearest_column(&cols, seg.col);
            if cells[idx].is_empty() {
                cells[idx] = seg.text.trim().to_string();
            } else {
                cells[idx] = format!("{} {}", cells[idx], seg.text.trim());
            }
        }
        let filled: Vec<usize> = cells
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.is_empty())
            .map(|(i, _)| i)
            .collect();
        // Only the first column filled, and the previous row was a real
        // multi-column row -> this is a wrapped cell, not a new record.
        // `AT&T Reseller` / `Port-In` is one reason, rendered by AT&T's own
        // PDF as the single string "AT&T Reseller Port-In".
        if filled == [0] {
            if let Some(prev) = out_rows.last_mut() {
                if prev.iter().filter(|v| !v.is_empty()).count() > 1 {
                    prev[0] = format!("{} {}", prev[0], cells[0]).trim().to_string();
                    continue;
                }
            }
        }
        if filled.is_empty() {
            continue;
        }
        out_rows.push(cells);
    }
    Some(Block::Table {
        name,
        columns,
        rows: out_rows,
    })
}

fn nearest_column(cols: &[usize], col: usize) -> usize {
    let mut best = 0usize;
    let mut best_d = usize::MAX;
    for (i, c) in cols.iter().enumerate() {
        let d = c.abs_diff(col);
        if d < best_d {
            best_d = d;
            best = i;
        }
    }
    best
}

// ─── Helpers over parsed blocks ───────────────────────────────────────────

fn fget(fields: &[(String, String)], key: &str) -> Option<String> {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn fields_to_json(fields: &[(String, String)]) -> Value {
    let mut m = Map::new();
    for (k, v) in fields {
        m.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(m)
}

fn fields_to_body(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `MM/DD/YYYY` -> `YYYY-MM-DD`.
///
/// Normalised on purpose: the triage UI sorts timestamps as strings, and
/// `MM/DD/YYYY` does not sort chronologically.  The untouched original is
/// always kept in `raw_fields`.
fn iso_date(s: &str) -> Option<String> {
    let t = s.trim();
    let p: Vec<&str> = t.split('/').collect();
    if p.len() != 3 || !p.iter().all(|x| is_all_digits(x)) {
        return None;
    }
    let (m, d) = (p[0].parse::<u32>().ok()?, p[1].parse::<u32>().ok()?);
    let y = p[2].parse::<i32>().ok()?;
    let year = match p[2].len() {
        4 => y,
        2 => {
            if y <= 69 {
                2000 + y
            } else {
                1900 + y
            }
        }
        _ => return None,
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(format!("{:04}-{:02}-{:02}", year, m, d))
}

/// `MM/DD/YYYY HH:MM[:SS]` -> `YYYY-MM-DD HH:MM:SS`, date-only tolerated.
///
/// No timezone is applied: AT&T reports do not state one, and silently
/// stamping UTC onto a local-time record would be worse than leaving it bare.
fn iso_datetime(s: &str) -> Option<String> {
    let t = s.trim();
    let mut it = t.split_whitespace();
    let date = iso_date(it.next()?)?;
    match it.next() {
        None => Some(date),
        Some(time) => {
            let tp: Vec<&str> = time.split(':').collect();
            if tp.len() < 2 || !tp.iter().all(|x| is_all_digits(x)) {
                return Some(date);
            }
            let h: u32 = tp[0].parse().ok()?;
            let mi: u32 = tp[1].parse().ok()?;
            let se: u32 = tp.get(2).and_then(|x| x.parse().ok()).unwrap_or(0);
            if h > 23 || mi > 59 || se > 59 {
                return Some(date);
            }
            Some(format!("{} {:02}:{:02}:{:02}", date, h, mi, se))
        }
    }
}

/// `06/06/2026 - Current` -> (`06/06/2026`, `Current`).
fn split_window(v: &str) -> (Option<String>, Option<String>) {
    let parts: Vec<&str> = v.split(" - ").collect();
    if parts.len() == 2 {
        let a = parts[0].trim();
        let b = parts[1].trim();
        (
            (!a.is_empty()).then(|| a.to_string()),
            (!b.is_empty()).then(|| b.to_string()),
        )
    } else {
        let t = v.trim();
        ((!t.is_empty()).then(|| t.to_string()), None)
    }
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut prev_us = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_us = false;
        } else if !prev_us && !out.is_empty() {
            out.push('_');
            prev_us = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn title_case(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            let lower = w.to_lowercase();
            let mut c = lower.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── Identity classification ──────────────────────────────────────────────

/// Tokens that mark a name as an organisation rather than a person.
const ORG_TOKENS: &[&str] = &[
    "INC", "INC.", "LLC", "L.L.C.", "LLP", "LP", "CORP", "CORP.", "CORPORATION", "CO", "CO.",
    "COMPANY", "LTD", "LTD.", "PLC", "TRUST", "WIRELESS", "MOBILE", "TELECOM", "TELECOMM",
    "COMMUNICATIONS", "NETWORKS", "NETWORK", "SERVICES", "SOLUTIONS", "GROUP", "HOLDINGS",
    "TECHNOLOGIES", "TECHNOLOGY", "ENTERPRISES", "SYSTEMS", "DBA", "DEPT", "DEPARTMENT",
    "UNIVERSITY", "HOSPITAL", "SCHOOL", "CHURCH", "ASSOCIATION", "FOUNDATION",
];

/// Known AT&T-network resellers / MVNOs.  This is a *booster*, not the
/// primary signal — the list will always be incomplete, so the real test is
/// an organisation-shaped name plus a `Reseller` status-change entry.
const KNOWN_MVNOS: &[&str] = &[
    "US MOBILE", "TRACFONE", "STRAIGHT TALK", "NET10", "SIMPLE MOBILE", "H2O WIRELESS",
    "RED POCKET", "CONSUMER CELLULAR", "PURETALK", "PURE TALK", "PATRIOT MOBILE", "AIRVOICE",
    "TELCEL AMERICA", "LYCAMOBILE", "ULTRA MOBILE", "GEN MOBILE", "TELLO", "TEXTNOW",
    "EXCESS TELECOM", "GOOD2GO", "CRICKET", "AT&T PREPAID", "BOOST", "MINT MOBILE", "TING",
    "WING", "FREEDOMPOP", "SPEEDTALK", "PAGE PLUS", "TOTAL WIRELESS", "SELECTEL",
];

fn norm_name(s: &str) -> String {
    s.trim().to_uppercase()
}

fn is_placeholder_name(s: &str) -> bool {
    let n = norm_name(s);
    n.is_empty()
        || n == "UNKNOWN"
        || n == "UNKNOWN UNKNOWN"
        || n == "N/A"
        || n == "NA"
        || n == "NONE"
        || n == "NOT AVAILABLE"
        || n == "NOT PROVIDED"
        || n == "SUBSCRIBER"
}

fn looks_like_org(s: &str) -> bool {
    let n = norm_name(s);
    if n.is_empty() {
        return false;
    }
    n.split_whitespace()
        .any(|w| ORG_TOKENS.contains(&w.trim_matches(',')))
}

fn is_known_mvno(s: &str) -> bool {
    let n = norm_name(s);
    KNOWN_MVNOS.iter().any(|m| n.contains(m))
}

/// A person: not a placeholder, not organisation-shaped, and 2–5 name-like
/// tokens.  A single token ("MOYER") is too weak to claim as an identified
/// individual, so it is not treated as one.
fn looks_like_person(s: &str) -> bool {
    if is_placeholder_name(s) || looks_like_org(s) {
        return false;
    }
    let toks: Vec<&str> = s.split_whitespace().collect();
    (2..=5).contains(&toks.len())
        && toks
            .iter()
            .all(|t| t.chars().all(|c| c.is_ascii_alphabetic() || ".-'".contains(c)))
}

// ─── Parse context ────────────────────────────────────────────────────────

/// One `USER INFORMATION` block, kept for the per-MSISDN timeline.
#[derive(Debug, Clone)]
struct SubRecord {
    msisdn: String,
    name: Option<String>,
    address: Option<String>,
    window_start: Option<String>,
    window_end: Option<String>,
    account: Option<String>,
    liable_party: Option<String>,
    liable_contact: Option<String>,
    reseller_status: Vec<String>,
    item_id: String,
    has_identity_docs: bool,
}

#[derive(Default)]
struct Ctx {
    items: Vec<WarrantItem>,
    seq: HashMap<String, usize>,
    subs: Vec<SubRecord>,
    report_date: Option<String>,
    msisdn_counts: BTreeMap<String, usize>,
    date_min: Option<String>,
    date_max: Option<String>,
}

impl Ctx {
    fn next_id(&mut self, prefix: &str) -> String {
        let n = self.seq.entry(prefix.to_string()).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }

    fn push(&mut self, item: WarrantItem) {
        self.items.push(item);
    }

    fn note_date(&mut self, iso: &str) {
        if iso.is_empty() {
            return;
        }
        if self.date_min.as_deref().map_or(true, |d| iso < d) {
            self.date_min = Some(iso.to_string());
        }
        if self.date_max.as_deref().map_or(true, |d| iso > d) {
            self.date_max = Some(iso.to_string());
        }
    }

    fn target_account(&self) -> Option<String> {
        self.msisdn_counts
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(k, _)| k.clone())
    }

    fn date_range(&self) -> Option<String> {
        match (&self.date_min, &self.date_max) {
            (Some(a), Some(b)) if a != b => Some(format!("{} to {}", a, b)),
            (Some(a), _) => Some(a.clone()),
            _ => None,
        }
    }

    // ── Ingest ────────────────────────────────────────────────────────────

    fn ingest_report(&mut self, source: &str, text: &str) {
        let mut rows_emitted = 0usize;
        let mut truncated = false;
        for raw_page in split_pages(text) {
            let page = parse_page(&raw_page);
            if self.report_date.is_none() {
                self.report_date = page.date.clone();
            }
            let report = page.report.clone().unwrap_or_else(|| "REPORT".into());
            if report.to_uppercase().contains("SUBSCRIBER INFORMATION") {
                self.emit_subscriber_page(&page, source);
            } else {
                let (n, cut) = self.emit_generic_page(&page, source, rows_emitted);
                rows_emitted += n;
                truncated |= cut;
            }
        }
        if truncated {
            let id = self.next_id("notice");
            self.push(WarrantItem {
                id,
                section: SEC_NOTICES.into(),
                section_display: "Parser Notices".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text: Some(format!(
                    "Report '{}' contains more than {} rows. Only the first {} were imported \
                     to keep the case responsive. The source file is unmodified — re-run \
                     against a split copy if the remainder is needed.",
                    source, MAX_ROWS_PER_REPORT, MAX_ROWS_PER_REPORT
                )),
                summary: Some(format!("Row limit reached in {}", source)),
                raw_fields: json!({ "source": source, "rowLimit": MAX_ROWS_PER_REPORT }),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: true,
            });
        }
    }

    /// A `SUBSCRIBER INFORMATION` page: one account, one MSISDN window.
    fn emit_subscriber_page(&mut self, page: &Page, source: &str) {
        let mut liable: Option<&Vec<(String, String)>> = None;
        let mut billing: Option<&Vec<(String, String)>> = None;
        let mut user: Option<&Vec<(String, String)>> = None;
        let mut status: Vec<(&Vec<String>, &Vec<Vec<String>>)> = Vec::new();

        for b in &page.blocks {
            match b {
                Block::Fields { name, fields } => {
                    let n = name.as_deref().unwrap_or("").to_uppercase();
                    if n.contains("FINANCIAL LIABLE") {
                        liable = Some(fields);
                    } else if n.contains("BILLING PARTY") {
                        billing = Some(fields);
                    } else if n.contains("USER INFORMATION") {
                        user = Some(fields);
                    }
                }
                Block::Table {
                    name,
                    columns,
                    rows,
                } => {
                    let n = name.as_deref().unwrap_or("").to_uppercase();
                    if n.contains("STATUS CHANGE") {
                        status.push((columns, rows));
                    }
                }
                Block::Key(_) => {}
            }
        }

        let account = page
            .key
            .clone()
            .or_else(|| billing.and_then(|b| fget(b, "Account Number")));

        // Reasons mentioning a reseller are the hard signal for MVNO custody.
        let reseller_status: Vec<String> = status
            .iter()
            .flat_map(|(_, rows)| rows.iter())
            .filter(|r| {
                r.first()
                    .map(|c| {
                        let u = c.to_uppercase();
                        u.contains("RESELLER") || u.contains("PORT-IN") || u.contains("PORT IN")
                    })
                    .unwrap_or(false)
            })
            .map(|r| r.join(" — "))
            .collect();

        // ── Account / billing item ──
        if liable.is_some() || billing.is_some() {
            let mut merged: Vec<(String, String)> = Vec::new();
            if let Some(l) = liable {
                for (k, v) in l {
                    merged.push((format!("Financial Liable Party {}", k), v.clone()));
                }
            }
            if let Some(b) = billing {
                for (k, v) in b {
                    merged.push((format!("Billing Party {}", k), v.clone()));
                }
            }
            let id = self.next_id("acct");
            let holder = liable.and_then(|l| fget(l, "Name"));
            let since = liable.and_then(|l| fget(l, "Customer Since"));
            let ts = since.as_deref().and_then(iso_date);
            if let Some(t) = &ts {
                self.note_date(t);
            }
            let mut raw = fields_to_json(&merged);
            if let Some(o) = raw.as_object_mut() {
                o.insert("_source".into(), json!(source));
                if let Some(a) = &account {
                    o.insert("_account".into(), json!(a));
                }
            }
            self.push(WarrantItem {
                id,
                section: SEC_ACCOUNT.into(),
                section_display: "Account & Billing".into(),
                timestamp: ts,
                author: holder.clone(),
                recipient: account.clone(),
                body_text: Some(fields_to_body(&merged)),
                summary: Some(format!(
                    "Account {} — {}",
                    account.as_deref().unwrap_or("?"),
                    holder.as_deref().unwrap_or("unknown holder")
                )),
                raw_fields: raw,
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }

        // ── Subscriber (user information) item ──
        if let Some(u) = user {
            let msisdn = fget(u, "MSISDN").unwrap_or_else(|| "unknown".into());
            let name = fget(u, "Name");
            let address = fget(u, "User Address");
            let (ws, we) = fget(u, "MSISDN Active")
                .map(|v| split_window(&v))
                .unwrap_or((None, None));
            let ts = ws.as_deref().and_then(iso_date);
            if let Some(t) = &ts {
                self.note_date(t);
            }
            if let Some(t) = we.as_deref().and_then(iso_date) {
                self.note_date(&t);
            }
            *self.msisdn_counts.entry(msisdn.clone()).or_insert(0) += 1;

            // The exact condition that makes an MVNO return look empty: AT&T
            // holds no government-ID, DOB or SSN for the subscriber.
            let has_docs = ["Photo ID Type", "Photo ID Number", "DOB", "SSN"]
                .iter()
                .any(|k| liable.and_then(|l| fget(l, k)).is_some());

            let mut body = fields_to_body(u);
            if !has_docs {
                body.push_str(
                    "\n\n[No photo ID, DOB or SSN on file for this account — see Ownership Analysis]",
                );
            }
            let id = self.next_id("sub");
            let mut raw = fields_to_json(u);
            if let Some(o) = raw.as_object_mut() {
                o.insert("_source".into(), json!(source));
                if let Some(a) = &account {
                    o.insert("_account".into(), json!(a));
                }
                o.insert("_windowStart".into(), json!(ws));
                o.insert("_windowEnd".into(), json!(we));
            }
            let window = match (&ws, &we) {
                (Some(a), Some(b)) => format!("{} – {}", a, b),
                (Some(a), None) => a.clone(),
                _ => "window unknown".into(),
            };
            self.push(WarrantItem {
                id: id.clone(),
                section: SEC_SUBSCRIBER.into(),
                section_display: "Subscriber Records".into(),
                timestamp: ts,
                author: name.clone(),
                recipient: Some(msisdn.clone()),
                body_text: Some(body),
                summary: Some(format!(
                    "{} — {} ({})",
                    name.as_deref().unwrap_or("no name on file"),
                    msisdn,
                    window
                )),
                raw_fields: raw,
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });

            self.subs.push(SubRecord {
                msisdn,
                name,
                address,
                window_start: ws,
                window_end: we,
                account: account.clone(),
                liable_party: liable.and_then(|l| fget(l, "Name")),
                liable_contact: liable.and_then(|l| {
                    fget(l, "Contact Work Phone").or_else(|| fget(l, "Contact Home Phone"))
                }),
                reseller_status: reseller_status.clone(),
                item_id: id,
                has_identity_docs: has_docs,
            });
        }

        // ── Status change history ──
        for (columns, rows) in &status {
            for r in rows.iter() {
                let reason = r.first().cloned().unwrap_or_default();
                let when = r.get(1).cloned().unwrap_or_default();
                let ts = iso_date(&when);
                if let Some(t) = &ts {
                    self.note_date(t);
                }
                let id = self.next_id("status");
                let mut m = Map::new();
                for (i, c) in columns.iter().enumerate() {
                    m.insert(c.clone(), json!(r.get(i).cloned().unwrap_or_default()));
                }
                m.insert("_source".into(), json!(source));
                if let Some(a) = &account {
                    m.insert("_account".into(), json!(a));
                }
                self.push(WarrantItem {
                    id,
                    section: SEC_STATUS.into(),
                    section_display: "Status Changes".into(),
                    timestamp: ts,
                    author: None,
                    recipient: account.clone(),
                    body_text: Some(
                        columns
                            .iter()
                            .enumerate()
                            .map(|(i, c)| {
                                format!("{}: {}", c, r.get(i).cloned().unwrap_or_default())
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    summary: Some(if when.is_empty() {
                        reason.clone()
                    } else {
                        format!("{} — {}", when, reason)
                    }),
                    raw_fields: Value::Object(m),
                    attachments: Vec::new(),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    /// Any report we do not model by name.  Tables become one item per row,
    /// field blocks become one item each.
    ///
    /// AT&T's call-detail / usage / tower reports all use the same fixed-width
    /// table grammar, so they come through here as triageable rows even though
    /// their column semantics are not individually modelled yet.
    fn emit_generic_page(&mut self, page: &Page, source: &str, already: usize) -> (usize, bool) {
        let report = page.report.clone().unwrap_or_else(|| "Report".into());
        let section = {
            let s = slug(&report);
            if s.is_empty() {
                "att_report".to_string()
            } else {
                s
            }
        };
        let display = title_case(&report);
        let mut emitted = 0usize;
        let mut truncated = false;

        for b in &page.blocks {
            match b {
                Block::Fields { name, fields } => {
                    let id = self.next_id(&section);
                    let mut raw = fields_to_json(fields);
                    if let Some(o) = raw.as_object_mut() {
                        o.insert("_source".into(), json!(source));
                        o.insert("_block".into(), json!(name));
                    }
                    let ts = fields
                        .iter()
                        .find(|(k, _)| header_is_timestamp(k))
                        .and_then(|(_, v)| iso_datetime(v));
                    if let Some(t) = &ts {
                        self.note_date(t);
                    }
                    self.push(WarrantItem {
                        id,
                        section: section.clone(),
                        section_display: display.clone(),
                        timestamp: ts,
                        author: None,
                        recipient: page.key.clone(),
                        body_text: Some(fields_to_body(fields)),
                        summary: Some(
                            name.clone()
                                .unwrap_or_else(|| display.clone())
                                .to_string(),
                        ),
                        raw_fields: raw,
                        attachments: Vec::new(),
                        bucket: None,
                        note: None,
                        is_flagged: false,
                    });
                    emitted += 1;
                }
                Block::Table {
                    name,
                    columns,
                    rows,
                } => {
                    let ts_col = columns.iter().position(|c| header_is_timestamp(c));
                    let from_col = columns.iter().position(|c| header_is_originator(c));
                    let to_col = columns.iter().position(|c| header_is_recipient(c));
                    for r in rows {
                        if already + emitted >= MAX_ROWS_PER_REPORT {
                            truncated = true;
                            break;
                        }
                        let ts = ts_col
                            .and_then(|i| r.get(i))
                            .and_then(|v| iso_datetime(v));
                        if let Some(t) = &ts {
                            self.note_date(t);
                        }
                        let mut m = Map::new();
                        for (i, c) in columns.iter().enumerate() {
                            m.insert(c.clone(), json!(r.get(i).cloned().unwrap_or_default()));
                        }
                        m.insert("_source".into(), json!(source));
                        m.insert("_block".into(), json!(name));
                        let id = self.next_id(&section);
                        let body = columns
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| {
                                r.get(*i).map(|v| !v.trim().is_empty()).unwrap_or(false)
                            })
                            .map(|(i, c)| format!("{}: {}", c, r[i]))
                            .collect::<Vec<_>>()
                            .join("\n");
                        self.push(WarrantItem {
                            id,
                            section: section.clone(),
                            section_display: display.clone(),
                            timestamp: ts,
                            author: from_col.and_then(|i| r.get(i)).cloned().filter(|v| !v.is_empty()),
                            recipient: to_col
                                .and_then(|i| r.get(i))
                                .cloned()
                                .filter(|v| !v.is_empty())
                                .or_else(|| page.key.clone()),
                            body_text: Some(body),
                            summary: Some(
                                r.iter()
                                    .filter(|v| !v.trim().is_empty())
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join("  ")
                                    .chars()
                                    .take(160)
                                    .collect::<String>(),
                            ),
                            raw_fields: Value::Object(m),
                            attachments: Vec::new(),
                            bucket: None,
                            note: None,
                            is_flagged: false,
                        });
                        emitted += 1;
                    }
                }
                Block::Key(_) => {}
            }
            if truncated {
                break;
            }
        }
        (emitted, truncated)
    }

    // ── Ownership analysis ────────────────────────────────────────────────

    /// Build a per-MSISDN timeline and, where the number is held by a
    /// reseller, say so and point at the human-identified window.
    ///
    /// This exists because reading only page 1 of an MVNO return shows the
    /// reseller and no owner — the conclusion "no subscriber information
    /// available" that prompted this parser. The end user is usually one page
    /// further down.
    fn emit_ownership_analysis(&mut self) {
        if self.subs.is_empty() {
            return;
        }
        let mut by_number: BTreeMap<String, Vec<SubRecord>> = BTreeMap::new();
        for s in &self.subs {
            by_number
                .entry(s.msisdn.clone())
                .or_default()
                .push(s.clone());
        }

        for (msisdn, mut recs) in by_number {
            // Newest window first.
            recs.sort_by(|a, b| {
                let ka = a.window_start.as_deref().and_then(iso_date);
                let kb = b.window_start.as_deref().and_then(iso_date);
                kb.cmp(&ka)
            });

            let current = recs
                .iter()
                .find(|r| {
                    r.window_end
                        .as_deref()
                        .map(|e| e.eq_ignore_ascii_case("current"))
                        .unwrap_or(false)
                })
                .or_else(|| recs.first());

            let persons: Vec<&SubRecord> = recs
                .iter()
                .filter(|r| r.name.as_deref().map(looks_like_person).unwrap_or(false))
                .collect();

            let cur_name = current.and_then(|c| c.name.clone()).unwrap_or_default();
            let cur_is_org = looks_like_org(&cur_name);
            let cur_is_mvno = is_known_mvno(&cur_name);
            let has_reseller_event = recs.iter().any(|r| !r.reseller_status.is_empty());
            // Organisation-shaped current holder plus either a known MVNO name
            // or a reseller status event.  Requiring two signals keeps ordinary
            // corporate accounts from being mislabelled as resellers.
            let reseller_held = cur_is_org && (cur_is_mvno || has_reseller_event);

            let mut lines: Vec<String> = Vec::new();
            lines.push(format!("Number: {}", msisdn));
            lines.push(String::new());
            lines.push("Subscriber timeline (newest first):".into());
            for r in &recs {
                let window = match (&r.window_start, &r.window_end) {
                    (Some(a), Some(b)) => format!("{} – {}", a, b),
                    (Some(a), None) => a.clone(),
                    _ => "window unknown".into(),
                };
                lines.push(format!(
                    "  • {}  {}{}{}",
                    window,
                    r.name.as_deref().unwrap_or("(no name on file)"),
                    r.address
                        .as_deref()
                        .map(|a| format!("  [{}]", a))
                        .unwrap_or_default(),
                    r.account
                        .as_deref()
                        .map(|a| format!("  acct {}", a))
                        .unwrap_or_default(),
                ));
            }
            lines.push(String::new());

            let summary;
            let mut flagged = false;
            if reseller_held {
                flagged = true;
                summary = format!(
                    "{} — current subscriber of record is a reseller/MVNO ({})",
                    msisdn, cur_name
                );
                lines.push(format!(
                    "ASSESSMENT: the current subscriber of record is \"{}\", whose name and \
                     address are organisational rather than personal. This pattern is consistent \
                     with a reseller / MVNO holding the account on behalf of the end user, so \
                     AT&T's records name the reseller and not the person using the number.",
                    cur_name
                ));
                if !recs
                    .iter()
                    .any(|r| r.has_identity_docs)
                {
                    lines.push(
                        "No photo ID, DOB or SSN is held on any of these accounts, which is \
                         normal for reseller-held numbers — the reseller collects that data, \
                         not AT&T."
                            .into(),
                    );
                }
                if !persons.is_empty() {
                    lines.push(String::new());
                    lines.push(
                        "HOWEVER — AT&T retained an individually-named subscriber for an \
                         earlier window on this same number:"
                            .into(),
                    );
                    for p in &persons {
                        let window = match (&p.window_start, &p.window_end) {
                            (Some(a), Some(b)) => format!("{} – {}", a, b),
                            (Some(a), None) => a.clone(),
                            _ => "window unknown".into(),
                        };
                        lines.push(format!(
                            "  • {} — {}{}",
                            window,
                            p.name.as_deref().unwrap_or(""),
                            p.address
                                .as_deref()
                                .map(|a| format!(", {}", a))
                                .unwrap_or_default()
                        ));
                    }
                    lines.push(
                        "Check whether your offence window falls inside that period before \
                         treating this number as unattributed."
                            .into(),
                    );
                }
                lines.push(String::new());
                lines.push(format!(
                    "NEXT STEP: serve legal process on {} for subscriber details covering your \
                     date range.",
                    cur_name
                ));
                if let Some(phone) = current.and_then(|c| c.liable_contact.clone()) {
                    lines.push(format!(
                        "The return lists {} as a contact number for that party.",
                        phone
                    ));
                }
            } else if let Some(p) = persons.first() {
                summary = format!(
                    "{} — subscriber identified as {}",
                    msisdn,
                    p.name.as_deref().unwrap_or("")
                );
                lines.push(format!(
                    "ASSESSMENT: an individually-named subscriber is on file — {}{}.",
                    p.name.as_deref().unwrap_or(""),
                    p.address
                        .as_deref()
                        .map(|a| format!(", {}", a))
                        .unwrap_or_default()
                ));
            } else {
                summary = format!("{} — no individual subscriber identified", msisdn);
                lines.push(
                    "ASSESSMENT: no individually-named subscriber appears on any record for \
                     this number. Consider the billing party, dealer information and status \
                     history as leads."
                        .into(),
                );
            }

            let item_id = self.next_id("own");
            let timeline: Vec<Value> = recs
                .iter()
                .map(|r| {
                    json!({
                        "windowStart": r.window_start,
                        "windowEnd": r.window_end,
                        "name": r.name,
                        "address": r.address,
                        "account": r.account,
                        "liableParty": r.liable_party,
                        "statusEvents": r.reseller_status,
                        "itemId": r.item_id,
                        "nameLooksLikePerson": r.name.as_deref().map(looks_like_person).unwrap_or(false),
                        "nameLooksLikeOrg": r.name.as_deref().map(looks_like_org).unwrap_or(false),
                    })
                })
                .collect();

            self.push(WarrantItem {
                id: item_id,
                section: SEC_OWNERSHIP.into(),
                section_display: "Ownership Analysis".into(),
                timestamp: current.and_then(|c| c.window_start.as_deref().and_then(iso_date)),
                author: current.and_then(|c| c.name.clone()),
                recipient: Some(msisdn.clone()),
                body_text: Some(lines.join("\n")),
                summary: Some(summary),
                raw_fields: json!({
                    "msisdn": msisdn,
                    "resellerHeld": reseller_held,
                    "currentName": cur_name,
                    "knownMvno": cur_is_mvno,
                    "resellerStatusEvent": has_reseller_event,
                    "timeline": timeline,
                }),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: flagged,
            });
        }
    }

    fn emit_unpaired_pdf_notice(&mut self, unpaired: &[String]) {
        let id = self.next_id("notice");
        self.push(WarrantItem {
            id,
            section: SEC_NOTICES.into(),
            section_display: "Parser Notices".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(format!(
                "Not parsed — PDF with no matching .txt report:\n{}\n\nAT&T supplies each data \
                 report as both .pdf and .txt. Scout reads the .txt because the PDF text layer \
                 merges adjacent fixed-width columns (for example \"Photo ID Number: DOB:\", \
                 where the value cannot be attributed to a label). A PDF with no .txt twin is \
                 usually the legal request, a cover letter, or a scanned document — open it \
                 manually.",
                unpaired
                    .iter()
                    .map(|n| format!("  • {}", n))
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
            summary: Some(format!(
                "{} PDF{} not parsed (no .txt counterpart)",
                unpaired.len(),
                if unpaired.len() == 1 { "" } else { "s" }
            )),
            raw_fields: json!({ "files": unpaired }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── Column-header heuristics for unmodelled reports ──────────────────────

fn header_is_timestamp(h: &str) -> bool {
    let u = h.to_uppercase();
    (u.contains("DATE") || u.contains("TIME") || u.contains("TIMESTAMP"))
        && !u.contains("UPDATE")
        && !u.contains("CANDIDATE")
}

fn header_is_originator(h: &str) -> bool {
    let u = h.to_uppercase();
    u.contains("ORIGINATING")
        || u.contains("ORIG ")
        || u == "ORIG"
        || u.contains("CALLING")
        || u.contains("CALLER")
        || u.contains("FROM")
}

fn header_is_recipient(h: &str) -> bool {
    let u = h.to_uppercase();
    u.contains("TERMINATING")
        || u.contains("TERM ")
        || u == "TERM"
        || u.contains("CALLED")
        || u.contains("DIALED")
        || u.contains("DESTINATION")
        || u == "TO"
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the real `ReportCT_*.txt` layout, including the three traps:
    /// a double space after `Name:`, a two-column field line, and a wrapped
    /// table cell (`AT&T Reseller` / `Port-In`).
    const SAMPLE: &str = concat!(
        "4691733\r\n",
        "                                                                        AT&T\r\n",
        "09/04/2026\r\n",
        "                                  WIRELESS\r\n",
        "                           SUBSCRIBER INFORMATION\r\n",
        "----------------------------------------------------------------------------\r\n",
        "337246326085\r\n",
        "\r\n",
        "----------------------------------------------------------------------------\r\n",
        "FINANCIAL LIABLE PARTY\r\n",
        "\r\n",
        "              Name: US MOBILE, INC.\r\n",
        "    Credit Address: 11 E 44TH ST STE 200, NEW YORK, NY 10017\r\n",
        "    Customer Since: 09/17/2025\r\n",
        "     Photo ID Type:                                             Photo ID State:\r\n",
        "   Photo ID Number:\r\n",
        "               DOB:\r\n",
        "               SSN:                                                 TaxID/FEIN:\r\n",
        "\r\n",
        "      Contact Name:\r\n",
        "Contact Home Phone:                                         Contact Work Phone: (202) 818-9310\r\n",
        "\r\n",
        "----------------------------------------------------------------------------\r\n",
        "BILLING PARTY\r\n",
        "\r\n",
        "    Account Number: 337246326085\r\n",
        "              Name: US MOBILE, INC.\r\n",
        "    Account Status: Active                                       Billing Cycle: 14\r\n",
        "\r\n",
        "----------------------------------------------------------------------------\r\n",
        "USER INFORMATION\r\n",
        "\r\n",
        "            MSISDN: (909) 782-7571                                        IMSI: 310280197158828\r\n",
        "     MSISDN Active: 10/02/2025 - 06/06/2026\r\n",
        "              Name: JUSTIN D MOYER\r\n",
        "      User Address: 14775 BUGLE CT, FONTANA, CA 92336\r\n",
        "Service Start Date: 01/25/2009                                     Dealer Info: B3QN0\r\n",
        "      Payment Type: Postpaid\r\n",
        "\r\n",
        "----------------------------------------------------------------------------\r\n",
        "STATUS CHANGE HISTORY\r\n",
        "\r\n",
        "Status Change Reason                                    Status Change Date\r\n",
        "\r\n",
        "AT&T Reseller                                               10/02/2025\r\n",
        "Port-In\r\n",
        "\r\n",
        "                              AT&T PROPRIETARY\r\n",
        "  The information contained here is for use by authorized person only and\r\n",
        "                      is not for general distribution.\r\n",
    );

    /// Page 1 of the real return: the MVNO-held current window.  Combined with
    /// SAMPLE this is the two-window MVNO scenario.
    const SAMPLE_CURRENT: &str = concat!(
        "4691733\r\n",
        "                                                                        AT&T\r\n",
        "09/04/2026\r\n",
        "                                  WIRELESS\r\n",
        "                           SUBSCRIBER INFORMATION\r\n",
        "----------------------------------------------------------------------------\r\n",
        "337257581571\r\n",
        "----------------------------------------------------------------------------\r\n",
        "FINANCIAL LIABLE PARTY\r\n",
        "              Name: US MOBILE, INC.\r\n",
        "    Customer Since: 06/02/2026\r\n",
        "Contact Home Phone: (000) 000-0000                          Contact Work Phone: (202) 818-9310\r\n",
        "----------------------------------------------------------------------------\r\n",
        "USER INFORMATION\r\n",
        "            MSISDN: (909) 782-7571                                        IMSI: 310280243242850\r\n",
        "     MSISDN Active: 06/06/2026 - Current\r\n",
        "              Name:  US MOBILE, INC.\r\n",
        "      User Address: 11 E 44TH ST STE 200, NEW YORK, NY 10017\r\n",
        "      Payment Type: Postpaid\r\n",
        "----------------------------------------------------------------------------\r\n",
        "STATUS CHANGE HISTORY\r\n",
        "Status Change Reason                                    Status Change Date\r\n",
        "Win back activation                                         06/05/2026\r\n",
        "                              AT&T PROPRIETARY\r\n",
    );

    fn ingest(text: &str) -> Ctx {
        let mut ctx = Ctx::default();
        ctx.ingest_report("ReportCT_test.txt", text);
        ctx.emit_ownership_analysis();
        ctx
    }

    fn items_in(ctx: &Ctx, section: &str) -> Vec<WarrantItem> {
        ctx.items
            .iter()
            .filter(|i| i.section == section)
            .cloned()
            .collect()
    }

    // ── Segmentation ──

    #[test]
    fn segments_split_on_two_spaces_not_one() {
        let s = segments("              Name: US MOBILE, INC.");
        assert_eq!(s.len(), 1, "single spaces inside a value must not split it");
        assert_eq!(s[0].text, "Name: US MOBILE, INC.");
        assert_eq!(s[0].col, 14);
    }

    #[test]
    fn segments_split_two_column_field_line() {
        let s = segments(
            "Contact Home Phone: (000) 000-0000                          Contact Work Phone: (202) 818-9310",
        );
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].text, "Contact Home Phone: (000) 000-0000");
        assert_eq!(s[1].text, "Contact Work Phone: (202) 818-9310");
    }

    #[test]
    fn double_space_after_colon_keeps_the_value() {
        // `Name:  US MOBILE, INC.` has TWO spaces after the colon, so the
        // value lands in its own segment and must be re-joined.
        let b = parse_block(&[
            "USER INFORMATION".to_string(),
            "              Name:  US MOBILE, INC.".to_string(),
        ])
        .expect("block");
        match b {
            Block::Fields { fields, .. } => {
                assert_eq!(fget(&fields, "Name").as_deref(), Some("US MOBILE, INC."));
            }
            other => panic!("expected fields, got {:?}", other),
        }
    }

    #[test]
    fn paired_empty_fields_stay_separate() {
        // The case the PDF text layer cannot represent: two empty labels on
        // one line.  Both must exist, both empty.
        let b = parse_block(&[
            "FINANCIAL LIABLE PARTY".to_string(),
            "               SSN:                                                 TaxID/FEIN:"
                .to_string(),
        ])
        .expect("block");
        match b {
            Block::Fields { fields, .. } => {
                let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, vec!["SSN", "TaxID/FEIN"]);
                assert!(fields.iter().all(|(_, v)| v.is_empty()));
            }
            other => panic!("expected fields, got {:?}", other),
        }
    }

    // ── Tables ──

    #[test]
    fn wrapped_table_cell_rejoins_previous_row() {
        // AT&T's own PDF renders these two lines as "AT&T Reseller Port-In",
        // which is the oracle for this behaviour.
        let ctx = ingest(SAMPLE);
        let st = items_in(&ctx, SEC_STATUS);
        assert_eq!(st.len(), 1, "the wrapped line must not become a second row");
        assert_eq!(
            st[0].raw_fields["Status Change Reason"],
            json!("AT&T Reseller Port-In")
        );
        assert_eq!(st[0].timestamp.as_deref(), Some("2025-10-02"));
    }

    #[test]
    fn table_header_decides_columns() {
        let b = parse_block(&[
            "STATUS CHANGE HISTORY".to_string(),
            "Status Change Reason                                    Status Change Date"
                .to_string(),
            "Win back activation                                         06/05/2026".to_string(),
        ])
        .expect("block");
        match b {
            Block::Table { columns, rows, .. } => {
                assert_eq!(columns, vec!["Status Change Reason", "Status Change Date"]);
                assert_eq!(rows, vec![vec!["Win back activation", "06/05/2026"]]);
            }
            other => panic!("expected table, got {:?}", other),
        }
    }

    // ── Pages ──

    #[test]
    fn pages_split_on_the_letterhead_anchor() {
        let joined = format!("{}{}", SAMPLE, SAMPLE_CURRENT);
        assert_eq!(split_pages(&joined).len(), 2);
    }

    #[test]
    fn page_header_fields_are_read() {
        let pages = split_pages(SAMPLE);
        let p = parse_page(&pages[0]);
        assert_eq!(p.report_id.as_deref(), Some("4691733"));
        assert_eq!(p.date.as_deref(), Some("09/04/2026"));
        assert_eq!(p.division.as_deref(), Some("WIRELESS"));
        assert_eq!(p.report.as_deref(), Some("SUBSCRIBER INFORMATION"));
        assert_eq!(p.key.as_deref(), Some("337246326085"));
    }

    #[test]
    fn footer_is_not_parsed_as_data() {
        let ctx = ingest(SAMPLE);
        assert!(
            !ctx.items.iter().any(|i| i
                .body_text
                .as_deref()
                .unwrap_or("")
                .contains("AT&T PROPRIETARY")),
            "the proprietary footer must never reach an item body"
        );
    }

    // ── Subscriber extraction ──

    #[test]
    fn subscriber_record_is_extracted() {
        let ctx = ingest(SAMPLE);
        let subs = items_in(&ctx, SEC_SUBSCRIBER);
        assert_eq!(subs.len(), 1);
        let s = &subs[0];
        assert_eq!(s.author.as_deref(), Some("JUSTIN D MOYER"));
        assert_eq!(s.recipient.as_deref(), Some("(909) 782-7571"));
        assert_eq!(s.timestamp.as_deref(), Some("2025-10-02"));
        assert_eq!(
            s.raw_fields["User Address"],
            json!("14775 BUGLE CT, FONTANA, CA 92336")
        );
        assert_eq!(s.raw_fields["IMSI"], json!("310280197158828"));
    }

    #[test]
    fn missing_identity_documents_are_called_out() {
        let ctx = ingest(SAMPLE);
        let subs = items_in(&ctx, SEC_SUBSCRIBER);
        assert!(subs[0]
            .body_text
            .as_deref()
            .unwrap()
            .contains("No photo ID, DOB or SSN on file"));
    }

    #[test]
    fn account_and_billing_item_is_emitted() {
        let ctx = ingest(SAMPLE);
        let acct = items_in(&ctx, SEC_ACCOUNT);
        assert_eq!(acct.len(), 1);
        assert_eq!(
            acct[0].raw_fields["Financial Liable Party Credit Address"],
            json!("11 E 44TH ST STE 200, NEW YORK, NY 10017")
        );
        assert_eq!(acct[0].raw_fields["Billing Party Billing Cycle"], json!("14"));
    }

    // ── Ownership analysis ──

    #[test]
    fn reseller_held_number_is_flagged_and_points_at_the_person() {
        // The whole reason this parser exists: page 1 names the MVNO, page 2
        // names the human.  Reading page 1 alone looks like "no owner info".
        let joined = format!("{}{}", SAMPLE_CURRENT, SAMPLE);
        let ctx = ingest(&joined);
        let own = items_in(&ctx, SEC_OWNERSHIP);
        assert_eq!(own.len(), 1, "one analysis per MSISDN");
        let o = &own[0];
        assert!(o.is_flagged, "reseller-held numbers must be flagged");
        assert_eq!(o.raw_fields["resellerHeld"], json!(true));
        assert_eq!(o.raw_fields["knownMvno"], json!(true));
        let body = o.body_text.as_deref().unwrap();
        assert!(body.contains("JUSTIN D MOYER"), "must surface the person");
        assert!(body.contains("NEXT STEP"), "must state the follow-up");
        assert!(
            body.contains("10/02/2025 – 06/06/2026"),
            "must show the window the person held the number"
        );
        // Both windows present in the machine-readable timeline.
        assert_eq!(o.raw_fields["timeline"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn plain_person_account_is_not_flagged_as_reseller() {
        let ctx = ingest(SAMPLE);
        let own = items_in(&ctx, SEC_OWNERSHIP);
        assert_eq!(own.len(), 1);
        // The liable party is US MOBILE but the *current* user record names a
        // person, so this must not be reported as reseller-held.
        assert_eq!(own[0].raw_fields["resellerHeld"], json!(false));
        assert!(!own[0].is_flagged);
        assert!(own[0]
            .summary
            .as_deref()
            .unwrap()
            .contains("subscriber identified as JUSTIN D MOYER"));
    }

    #[test]
    fn corporate_account_without_reseller_signal_is_not_flagged() {
        // Two signals are required.  A company name alone — no MVNO match, no
        // reseller status event — is an ordinary business account.
        let text = concat!(
            "555\r\n",
            "                                    AT&T\r\n",
            "01/02/2026\r\n",
            "        WIRELESS\r\n",
            "   SUBSCRIBER INFORMATION\r\n",
            "--------------------------------------------------\r\n",
            "999\r\n",
            "--------------------------------------------------\r\n",
            "USER INFORMATION\r\n",
            "            MSISDN: (555) 111-2222\r\n",
            "     MSISDN Active: 01/01/2020 - Current\r\n",
            "              Name: ACME PLUMBING CO\r\n",
        );
        let ctx = ingest(text);
        let own = items_in(&ctx, SEC_OWNERSHIP);
        assert_eq!(own[0].raw_fields["resellerHeld"], json!(false));
    }

    // ── Generic fallback (activity logs) ──

    #[test]
    fn unmodelled_report_tables_become_rows() {
        // No call-detail sample on hand, so the generic path must carry them.
        let text = concat!(
            "777\r\n",
            "                                        AT&T\r\n",
            "03/04/2026\r\n",
            "          WIRELESS\r\n",
            "        VOICE USAGE DETAIL\r\n",
            "--------------------------------------------------------------\r\n",
            "(909) 782-7571\r\n",
            "--------------------------------------------------------------\r\n",
            "CALL DETAIL\r\n",
            "Date/Time            Originating Number  Terminating Number  Duration\r\n",
            "03/01/2026 14:22:05  9097827571          9095551212          00:03:11\r\n",
            "03/01/2026 15:40:00  9095559999          9097827571          00:00:45\r\n",
        );
        let ctx = ingest(text);
        let rows = items_in(&ctx, "voice_usage_detail");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].section_display, "Voice Usage Detail");
        assert_eq!(rows[0].timestamp.as_deref(), Some("2026-03-01 14:22:05"));
        assert_eq!(rows[0].author.as_deref(), Some("9097827571"));
        assert_eq!(rows[0].recipient.as_deref(), Some("9095551212"));
        assert_eq!(rows[1].author.as_deref(), Some("9095559999"));
    }

    // ── Normalisation ──

    #[test]
    fn dates_normalise_to_sortable_iso() {
        assert_eq!(iso_date("09/04/2026").as_deref(), Some("2026-09-04"));
        assert_eq!(iso_date("1/2/26").as_deref(), Some("2026-01-02"));
        assert_eq!(
            iso_datetime("03/01/2026 14:22:05").as_deref(),
            Some("2026-03-01 14:22:05")
        );
        assert_eq!(
            iso_datetime("03/01/2026 14:22").as_deref(),
            Some("2026-03-01 14:22:00")
        );
        // Garbage in must not produce a bogus timestamp.
        assert_eq!(iso_date("Current"), None);
        assert_eq!(iso_date("13/45/2026"), None);
    }

    #[test]
    fn window_splitting_handles_current() {
        assert_eq!(
            split_window("06/06/2026 - Current"),
            (Some("06/06/2026".into()), Some("Current".into()))
        );
        assert_eq!(
            split_window("10/02/2025 - 06/06/2026"),
            (Some("10/02/2025".into()), Some("06/06/2026".into()))
        );
    }

    #[test]
    fn name_classification() {
        assert!(looks_like_person("JUSTIN D MOYER"));
        assert!(!looks_like_person("US MOBILE, INC."));
        assert!(!looks_like_person("Unknown Unknown"));
        assert!(!looks_like_person("MOYER"), "one token is too weak to claim");
        assert!(looks_like_org("US MOBILE, INC."));
        assert!(looks_like_org("ACME PLUMBING CO"));
        assert!(is_known_mvno("US MOBILE, INC."));
        assert!(!is_known_mvno("ACME PLUMBING CO"));
    }

    // ── Detection ──

    #[test]
    fn marker_detects_att_text_and_rejects_others() {
        assert!(text_has_att_marker(SAMPLE));
        assert!(text_has_att_marker(SAMPLE_CURRENT));
        assert!(!text_has_att_marker("Verizon Wireless subscriber report"));
        assert!(!text_has_att_marker("just some notes"));
    }

    #[test]
    fn unpaired_pdf_notice_lists_the_file() {
        let mut ctx = Ctx::default();
        ctx.emit_unpaired_pdf_notice(&["Original-Kodex-ATT-64493.pdf".to_string()]);
        let n = items_in(&ctx, SEC_NOTICES);
        assert_eq!(n.len(), 1);
        assert!(n[0]
            .body_text
            .as_deref()
            .unwrap()
            .contains("Original-Kodex-ATT-64493.pdf"));
    }

    // ── End-to-end against the real return ──

    /// Runs only when the real production folder is present.
    #[test]
    fn parses_real_att_return() {
        let dir = Path::new(r"G:\att return");
        if !dir.exists() {
            eprintln!("skipping: {} not present", dir.display());
            return;
        }
        let parser = AttWarrantParser;
        assert!(parser.accepts(dir).unwrap(), "must accept the return folder");

        let tmp = std::env::temp_dir().join("scout_att_test_media");
        let parsed = parser.parse(dir, &tmp).expect("parse");

        assert_eq!(parsed.case.provider, Provider::Att);
        assert_eq!(parsed.case.target_account.as_deref(), Some("(909) 782-7571"));

        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for i in &parsed.items {
            *counts.entry(i.section.as_str()).or_insert(0) += 1;
        }
        eprintln!("=== AT&T parse breakdown ===");
        for (k, v) in &counts {
            eprintln!("  {:<20} {}", k, v);
        }
        eprintln!("target : {:?}", parsed.case.target_account);
        eprintln!("range  : {:?}", parsed.case.date_range);
        for i in parsed.items.iter().filter(|i| i.section == SEC_OWNERSHIP) {
            eprintln!("--- ownership ---\n{}", i.body_text.as_deref().unwrap_or(""));
        }

        // Two subscriber pages, one per account/window.
        assert_eq!(counts.get(SEC_SUBSCRIBER).copied(), Some(2));
        assert_eq!(counts.get(SEC_ACCOUNT).copied(), Some(2));
        assert_eq!(counts.get(SEC_STATUS).copied(), Some(2));
        // One MSISDN -> one ownership analysis.
        assert_eq!(counts.get(SEC_OWNERSHIP).copied(), Some(1));
        // The Kodex legal request has no .txt twin and must be reported.
        assert_eq!(counts.get(SEC_NOTICES).copied(), Some(1));

        let own = parsed
            .items
            .iter()
            .find(|i| i.section == SEC_OWNERSHIP)
            .unwrap();
        assert_eq!(own.raw_fields["resellerHeld"], json!(true));
        let body = own.body_text.as_deref().unwrap();
        assert!(body.contains("JUSTIN D MOYER"));
        assert!(body.contains("14775 BUGLE CT, FONTANA, CA 92336"));

        // Field-level parity with the Python/lxml prototype that was used to
        // decode this format.  The prototype read 13 fields from the real
        // `USER INFORMATION` block and 14 + 5 from `FINANCIAL LIABLE PARTY` +
        // `BILLING PARTY`.  Asserting the exact counts catches a segmenter
        // regression that drops or invents a field — which counting items
        // alone would not.
        let person = parsed
            .items
            .iter()
            .find(|i| i.section == SEC_SUBSCRIBER && i.author.as_deref() == Some("JUSTIN D MOYER"))
            .expect("the individually-named subscriber record");
        let user_keys: Vec<&String> = person
            .raw_fields
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| !k.starts_with('_'))
            .collect();
        assert_eq!(
            user_keys.len(),
            13,
            "USER INFORMATION field count drifted: {:?}",
            user_keys
        );
        let acct = parsed
            .items
            .iter()
            .find(|i| i.section == SEC_ACCOUNT)
            .unwrap();
        let acct_keys: Vec<&String> = acct
            .raw_fields
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| !k.starts_with('_'))
            .collect();
        assert_eq!(
            acct_keys.len(),
            19,
            "liable-party + billing field count drifted: {:?}",
            acct_keys
        );
        // Empty-but-present fields must survive: "AT&T holds no SSN" is a
        // finding, and it is only distinguishable from "we failed to parse
        // the SSN line" if the key exists with an empty value.
        assert_eq!(acct.raw_fields["Financial Liable Party SSN"], json!(""));
        assert_eq!(acct.raw_fields["Financial Liable Party TaxID/FEIN"], json!(""));

        // The wrapped status reason must match AT&T's own PDF rendering.
        assert!(
            parsed.items.iter().any(|i| i.section == SEC_STATUS
                && i.raw_fields["Status Change Reason"] == json!("AT&T Reseller Port-In")),
            "wrapped status reason should read 'AT&T Reseller Port-In'"
        );
    }
}
