//! WhatsApp warrant-return parser.
//!
//! Format reference
//! ----------------
//! WhatsApp productions arrive as a ZIP in Meta's "archive format":
//!   * `index.html`            — landing page: subscriber summary + links
//!   * `preservation-N.html`   — snapshot with the actual responsive records
//!   * `README.txt`            — boilerplate (ignored)
//!   * `linked_media/`         — media referenced by NCMEC reports, etc.
//!
//! Unlike the Facebook/Instagram Meta return (which renders each section
//! with `div.div_table[style="display:table"]`), the WhatsApp production
//! uses *real* HTML `<table><tr><th>KEY</th><td>VALUE</td></tr></table>`
//! markup.  Sections are `<div id="property-X" class="content-pane">`
//! (same envelope as Meta), plus a `<div id="home">` landing pane.
//!
//! WhatsApp is end-to-end encrypted, so there is no message *content*.
//! The high-value data is:
//!   * `ncmec_reports`    — NCMEC CyberTips + linked media (auto-CSAM)
//!   * `offline_log_info` — metadata of undelivered E2E messages
//!                          (timestamp / sender / media-or-text)
//!   * `connection_info` / `device_info` — device + registration details
//!   * `address_book_info` — symmetric contacts (phone numbers)
//!   * `offline_info`      — unviewed-message counts
//!
//! Because the title tag is literally "Facebook Legal Request" for *both*
//! Facebook and WhatsApp returns, detection keys on the `Service` value
//! (`WhatsApp`) / `WhatsAppUser` account type, which never appears in a
//! genuine Facebook/Instagram production.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use chrono::Utc;
use scraper::{ElementRef, Html, Selector};
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

pub struct WhatsAppWarrantParser;

impl WarrantParser for WhatsAppWarrantParser {
    fn provider(&self) -> Provider {
        Provider::WhatsApp
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_whatsapp(path, 0));
        }
        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let lower = entry.name().to_lowercase();
            let base = lower.rsplit('/').next().unwrap_or(&lower).to_string();
            if is_return_html(&base) {
                // Read only the head — the Service value sits at the very top.
                let mut head = String::new();
                let _ = entry.by_ref().take(16_384).read_to_string(&mut head);
                if head_is_whatsapp(&head) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn parse(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        if !self.accepts(archive_path)? {
            return Err(ParseError::WrongFormat);
        }
        fs::create_dir_all(media_extract_dir)?;

        // ── First pass: collect HTML files + extract linked_media ──
        let mut htmls: Vec<(String, String)> = Vec::new(); // (name, body)
        let mut media_on_disk: HashSet<String> = HashSet::new();

        if archive_path.is_dir() {
            collect_from_dir(archive_path, 0, media_extract_dir, &mut htmls, &mut media_on_disk)?;
        } else {
            let file = File::open(archive_path)?;
            let mut zip = ZipArchive::new(file)?;
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i)?;
                if entry.is_dir() {
                    continue;
                }
                let raw = entry.name().to_string();
                let lower = raw.to_lowercase();
                let base = lower.rsplit('/').next().unwrap_or(&lower).to_string();
                if is_return_html(&base) {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf)?;
                    htmls.push((base, buf));
                } else if lower.contains("linked_media/") {
                    if let Some(fname) = Path::new(&raw).file_name() {
                        let out = media_extract_dir.join(fname);
                        let mut f = File::create(&out)?;
                        std::io::copy(&mut entry, &mut f)?;
                        media_on_disk.insert(fname.to_string_lossy().into_owned());
                    }
                }
            }
        }

        if htmls.is_empty() {
            return Err(ParseError::WrongFormat);
        }

        // index.html first, then preservation-N in order — so subscriber
        // metadata prefers the landing page while records come from the
        // preservation snapshot.
        htmls.sort_by(|a, b| {
            let rank = |n: &str| if n.starts_with("index") { 0 } else { 1 };
            rank(&a.0).cmp(&rank(&b.0)).then(a.0.cmp(&b.0))
        });

        let mut ctx = Ctx::new();
        let sels = Sels::new();
        for (name, body) in &htmls {
            let source = Path::new(name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("record")
                .to_string();
            parse_html(&sels, body, &source, &mut ctx);
        }

        // Collapse cross-file duplicate summary sections (index vs preservation).
        ctx.dedupe();

        // Subscriber summary — one item accumulated across all files.
        ctx.emit_subscriber();

        // Media not referenced by any item → surface as standalone Media items.
        ctx.backfill_media(&media_on_disk);

        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let case = WarrantCase {
            case_id: Uuid::new_v4().to_string(),
            provider: Provider::WhatsApp,
            provider_display: "WhatsApp".into(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.account_id.clone(),
            date_range: ctx.date_range.clone(),
            generated_at_source: ctx.generated.clone(),
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
                description: Some(
                    "Child sexual abuse material — auto-seeded from NCMEC reports".into(),
                ),
            },
            BucketTemplate {
                name: "Communications".into(),
                color: "#5b8def".into(),
                description: Some("Undelivered / offline message logs".into()),
            },
            BucketTemplate {
                name: "Contacts of Interest".into(),
                color: "#8b5cf6".into(),
                description: Some("Address-book contacts".into()),
            },
            BucketTemplate {
                name: "Device / Account".into(),
                color: "#10b981".into(),
                description: Some("Device, connection and registration details".into()),
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

// ─── Selectors (built once per parse) ─────────────────────────────────────

struct Sels {
    property: Selector,
    home: Selector,
    tr: Selector,
    table: Selector,
}

impl Sels {
    fn new() -> Self {
        Self {
            property: Selector::parse(r#"div[id^="property-"]"#).unwrap(),
            home: Selector::parse(r#"div#home"#).unwrap(),
            tr: Selector::parse("tr").unwrap(),
            table: Selector::parse("table").unwrap(),
        }
    }
}

// ─── Parse context ─────────────────────────────────────────────────────────

struct Ctx {
    items: Vec<WarrantItem>,
    seq: HashMap<&'static str, usize>,
    service: String,
    account_id: Option<String>,
    account_type: Option<String>,
    generated: Option<String>,
    date_range: Option<String>,
    ticket: Option<String>,
    emails: Vec<String>,
    attached: HashSet<String>,
}

impl Ctx {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            seq: HashMap::new(),
            service: "WhatsApp".into(),
            account_id: None,
            account_type: None,
            generated: None,
            date_range: None,
            ticket: None,
            emails: Vec::new(),
            attached: HashSet::new(),
        }
    }

    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }

    fn emit_subscriber(&mut self) {
        // Only emit if we actually found identifying info.
        if self.account_id.is_none() && self.account_type.is_none() {
            return;
        }
        let id = self.next_id("sub");
        let mut obj = serde_json::Map::new();
        obj.insert("service".into(), Value::String(self.service.clone()));
        if let Some(v) = &self.account_id {
            obj.insert("accountIdentifier".into(), Value::String(v.clone()));
        }
        if let Some(v) = &self.account_type {
            obj.insert("accountType".into(), Value::String(v.clone()));
        }
        if let Some(v) = &self.ticket {
            obj.insert("internalTicketNumber".into(), Value::String(v.clone()));
        }
        if let Some(v) = &self.generated {
            obj.insert("generated".into(), Value::String(v.clone()));
        }
        if let Some(v) = &self.date_range {
            obj.insert("dateRange".into(), Value::String(v.clone()));
        }
        if !self.emails.is_empty() {
            obj.insert(
                "registeredEmails".into(),
                Value::Array(self.emails.iter().map(|e| Value::String(e.clone())).collect()),
            );
        }

        let summary = format!(
            "{} account {}",
            self.service,
            self.account_id.clone().unwrap_or_else(|| "(unknown)".into())
        );
        let mut body = Vec::new();
        if let Some(v) = &self.account_type {
            body.push(format!("Type: {}", v));
        }
        if let Some(v) = &self.date_range {
            body.push(format!("Date range: {}", v));
        }
        if let Some(v) = &self.generated {
            body.push(format!("Generated: {}", v));
        }

        self.items.insert(
            0,
            WarrantItem {
                id,
                section: "subscriber_info".into(),
                section_display: "Subscriber Info".into(),
                timestamp: self.generated.clone(),
                author: None,
                recipient: None,
                body_text: if body.is_empty() { None } else { Some(body.join("\n")) },
                summary: Some(summary),
                raw_fields: Value::Object(obj),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            },
        );
    }

    /// Collapse identical records that appear in both `index.html` and a
    /// `preservation-N.html` snapshot.  Signature = section + raw_fields
    /// (minus `_source`) + summary, so genuinely distinct rows — e.g. the
    /// thousands of offline messages, each with a unique `id` — survive.
    fn dedupe(&mut self) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut kept: Vec<WarrantItem> = Vec::with_capacity(self.items.len());
        for it in std::mem::take(&mut self.items) {
            let mut rf = it.raw_fields.clone();
            if let Value::Object(m) = &mut rf {
                m.remove("_source");
            }
            let sig = format!(
                "{}|{}|{}",
                it.section,
                it.summary.clone().unwrap_or_default(),
                rf
            );
            if seen.insert(sig) {
                kept.push(it);
            }
        }
        self.items = kept;
    }

    fn backfill_media(&mut self, on_disk: &HashSet<String>) {
        let mut orphans: Vec<String> = on_disk
            .iter()
            .filter(|f| !self.attached.contains(*f))
            .cloned()
            .collect();
        orphans.sort();
        for fname in orphans {
            let id = self.next_id("media");
            self.items.push(WarrantItem {
                id,
                section: "media".into(),
                section_display: "Media".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text: None,
                summary: Some(fname.clone()),
                raw_fields: json!({ "filename": fname }),
                attachments: vec![fname.clone()],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

// ─── KV extraction over real <table> markup ─────────────────────────────────

#[derive(Clone, Debug)]
struct Kv {
    key: String,
    value: String,
}

/// Collect leaf key/value pairs from a section: every `<tr>` whose `<td>`
/// contains no nested `<table>` (i.e. an innermost KV row), in document order.
fn leaf_kvs(sels: &Sels, section: ElementRef<'_>) -> Vec<Kv> {
    let mut out = Vec::new();
    for tr in section.select(&sels.tr) {
        let th = direct_child(tr, "th");
        let td = direct_child(tr, "td");
        let (Some(th), Some(td)) = (th, td) else {
            continue;
        };
        // Leaf only — skip wrapper rows whose value cell holds sub-tables.
        if td.select(&sels.table).next().is_some() {
            continue;
        }
        let key = clean_text(&th.text().collect::<String>());
        if key.is_empty() {
            continue;
        }
        let value = cell_text(td);
        out.push(Kv { key, value });
    }
    out
}

fn direct_child<'a>(el: ElementRef<'a>, name: &str) -> Option<ElementRef<'a>> {
    el.children()
        .filter_map(ElementRef::wrap)
        .find(|e| e.value().name() == name)
}

/// Text of a value cell, honoring `<br>` as line breaks.
fn cell_text(td: ElementRef<'_>) -> String {
    let raw = td.inner_html();
    html_to_text(&raw)
}

fn html_to_text(h: &str) -> String {
    let h = h
        .replace("<br>", "\n")
        .replace("<br/>", "\n")
        .replace("<br />", "\n");
    let mut out = String::new();
    let mut in_tag = false;
    for c in h.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let decoded = decode_entities(&out);
    // Trim each line, drop empties, rejoin.
    decoded
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn clean_text(s: &str) -> String {
    decode_entities(s).trim().to_string()
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&#039;", "'")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn is_definition(key: &str) -> bool {
    key.to_lowercase().ends_with("definition")
}

fn is_no_records(v: &str) -> bool {
    v.to_lowercase().contains("no responsive records")
}

/// Drop definition rows, "Additional Properties", and empty/no-record rows.
fn data_kvs(kvs: Vec<Kv>) -> Vec<Kv> {
    kvs.into_iter()
        .filter(|kv| {
            !is_definition(&kv.key)
                && !kv.key.eq_ignore_ascii_case("Additional Properties")
                && !kv.value.is_empty()
                && !is_no_records(&kv.value)
        })
        .collect()
}

fn split_records(kvs: &[Kv], boundary_keys: &[&str]) -> Vec<Vec<Kv>> {
    let mut recs = Vec::new();
    let mut cur: Vec<Kv> = Vec::new();
    for kv in kvs {
        if !cur.is_empty()
            && boundary_keys.iter().any(|b| kv.key.eq_ignore_ascii_case(b))
        {
            recs.push(std::mem::take(&mut cur));
        }
        cur.push(kv.clone());
    }
    if !cur.is_empty() {
        recs.push(cur);
    }
    recs
}

fn kvs_to_json(kvs: &[Kv]) -> Value {
    let mut map = serde_json::Map::new();
    for kv in kvs {
        let k = to_camel(&kv.key);
        map.entry(k).or_insert_with(|| Value::String(kv.value.clone()));
    }
    Value::Object(map)
}

fn to_camel(s: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in s.chars() {
        if c.is_alphanumeric() {
            if upper {
                out.extend(c.to_uppercase());
                upper = false;
            } else {
                out.extend(c.to_lowercase());
            }
        } else {
            if !out.is_empty() {
                upper = true;
            }
        }
    }
    out
}

fn media_basename(value: &str) -> Option<String> {
    // A leaf value like "linked_media/ncmec_reports_2724630461.mp4".
    for line in value.lines() {
        let l = line.trim();
        if let Some(idx) = l.to_lowercase().find("linked_media/") {
            let rest = &l[idx + "linked_media/".len()..];
            let base = rest.split(|c| c == ' ' || c == '\t').next().unwrap_or(rest);
            if !base.is_empty() {
                return Some(base.to_string());
            }
        }
    }
    None
}

// ─── Section dispatch ────────────────────────────────────────────────────────

fn parse_html(sels: &Sels, html: &str, source: &str, ctx: &mut Ctx) {
    let doc = Html::parse_document(html);

    if let Some(home) = doc.select(&sels.home).next() {
        parse_home(sels, home, ctx);
    }

    for section in doc.select(&sels.property) {
        let id = section.value().attr("id").unwrap_or("");
        match id {
            "property-ncmec_reports" => parse_ncmec(sels, section, source, ctx),
            "property-offline_log_info" => parse_offline_log(sels, section, source, ctx),
            "property-offline_info" => {
                parse_simple(sels, section, source, ctx, "offline_info", "Offline Info", "offinfo")
            }
            "property-connection_info" => parse_records(
                sels,
                section,
                source,
                ctx,
                "connection_info",
                "Connection Info",
                "conn",
                &["Connection Device Id", "Device Id", "Service start"],
                "Device / Account",
            ),
            "property-device_info" => parse_records(
                sels,
                section,
                source,
                ctx,
                "device_info",
                "Devices",
                "dev",
                &["Device Id"],
                "Device / Account",
            ),
            "property-registrations_info" => parse_records(
                sels,
                section,
                source,
                ctx,
                "registrations_info",
                "Registrations",
                "reg",
                &["Registration", "Time", "Registered"],
                "Device / Account",
            ),
            "property-address_book_info" => parse_address_book(sels, section, source, ctx),
            _ => parse_generic(sels, section, source, ctx, id),
        }
    }
}

fn parse_home(sels: &Sels, home: ElementRef<'_>, ctx: &mut Ctx) {
    for kv in leaf_kvs(sels, home) {
        if is_definition(&kv.key) || kv.key.eq_ignore_ascii_case("Additional Properties") {
            continue;
        }
        match kv.key.to_lowercase().as_str() {
            "service" => {
                if !kv.value.is_empty() {
                    ctx.service = kv.value.clone();
                }
            }
            "account identifier" => {
                ctx.account_id.get_or_insert(kv.value.clone());
            }
            "account type" => {
                ctx.account_type.get_or_insert(kv.value.clone());
            }
            "generated" => {
                ctx.generated.get_or_insert(kv.value.clone());
            }
            "date range" => {
                ctx.date_range.get_or_insert(kv.value.clone());
            }
            "internal ticket number" => {
                ctx.ticket.get_or_insert(kv.value.clone());
            }
            "registered email addresses" => {
                if !is_no_records(&kv.value) {
                    for line in kv.value.lines() {
                        let e = line.trim();
                        if e.contains('@') {
                            ctx.emails.push(e.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn parse_ncmec(sels: &Sels, section: ElementRef<'_>, source: &str, ctx: &mut Ctx) {
    let kvs = data_kvs(leaf_kvs(sels, section));
    if kvs.is_empty() {
        return;
    }
    for rec in split_records(&kvs, &["CyberTip ID", "Cybertip Id", "CyberTip Id"]) {
        let obj = kvs_to_json(&rec);
        let id = ctx.next_id("ncmec");
        let timestamp = rec
            .iter()
            .find(|k| k.key.eq_ignore_ascii_case("Time"))
            .map(|k| k.value.clone());
        let cyber = rec
            .iter()
            .find(|k| k.key.to_lowercase().starts_with("cybertip"))
            .map(|k| k.value.clone())
            .unwrap_or_else(|| "(no id)".into());

        // Collect any linked media referenced in this record.
        let mut attachments = Vec::new();
        for kv in &rec {
            if let Some(base) = media_basename(&kv.value) {
                attachments.push(base.clone());
                ctx.attached.insert(base);
            }
        }

        ctx.items.push(WarrantItem {
            id,
            section: "ncmec_reports".into(),
            section_display: "NCMEC Reports".into(),
            timestamp,
            author: None,
            recipient: None,
            body_text: Some(format!("CyberTip {}", cyber)),
            summary: Some(format!("CyberTip {}", cyber)),
            raw_fields: with_source(obj, source),
            attachments,
            bucket: Some("CSAM".into()),
            note: None,
            is_flagged: true,
        });
    }
}

fn parse_offline_log(sels: &Sels, section: ElementRef<'_>, source: &str, ctx: &mut Ctx) {
    let kvs = data_kvs(leaf_kvs(sels, section));
    if kvs.is_empty() {
        return;
    }
    for rec in split_records(&kvs, &["Timestamp"]) {
        let obj = kvs_to_json(&rec);
        let get = |name: &str| -> Option<String> {
            rec.iter()
                .find(|k| k.key.eq_ignore_ascii_case(name))
                .map(|k| k.value.clone())
        };
        let timestamp = get("Timestamp");
        let from = get("From");
        let event = get("Event").unwrap_or_default();
        let subtype = get("Subtype").filter(|s| !s.eq_ignore_ascii_case("undefined"));
        let content = get("Content").filter(|c| !is_no_records(c));

        let kind = match (event.as_str(), subtype.as_deref()) {
            (e, Some(st)) if !e.is_empty() => format!("{} ({})", e, st),
            (e, _) if !e.is_empty() => e.to_string(),
            _ => "message".into(),
        };
        let summary = match &from {
            Some(f) => format!("Undelivered {} from {}", kind, f),
            None => format!("Undelivered {}", kind),
        };

        let id = ctx.next_id("offmsg");
        ctx.items.push(WarrantItem {
            id,
            section: "offline_messages".into(),
            section_display: "Offline Message Logs".into(),
            timestamp,
            author: from,
            recipient: ctx.account_id.clone(),
            body_text: content,
            summary: Some(summary),
            raw_fields: with_source(obj, source),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn parse_address_book(sels: &Sels, section: ElementRef<'_>, source: &str, ctx: &mut Ctx) {
    let kvs = data_kvs(leaf_kvs(sels, section));
    for kv in &kvs {
        // Value looks like "33 Total\n<number>\n<number>...".
        let mut label = kv.key.clone();
        let mut count: Option<String> = None;
        let mut contacts: Vec<String> = Vec::new();
        for (i, line) in kv.value.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if i == 0 && t.to_lowercase().contains("total") {
                count = Some(t.to_string());
                continue;
            }
            // Phone-number-ish token.
            let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 7 {
                contacts.push(t.to_string());
            }
        }
        if contacts.is_empty() {
            continue;
        }
        if let Some(c) = &count {
            label = format!("{} — {}", kv.key, c);
        }
        for contact in contacts {
            let id = ctx.next_id("abk");
            ctx.items.push(WarrantItem {
                id,
                section: "address_book".into(),
                section_display: "Address Book".into(),
                timestamp: None,
                author: Some(contact.clone()),
                recipient: None,
                body_text: None,
                summary: Some(format!("Contact: {}", contact)),
                raw_fields: with_source(
                    json!({ "contact": contact, "group": label }),
                    source,
                ),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

/// Emit one item per record (grouped by boundary keys).
#[allow(clippy::too_many_arguments)]
fn parse_records(
    sels: &Sels,
    section: ElementRef<'_>,
    source: &str,
    ctx: &mut Ctx,
    sect: &str,
    display: &str,
    prefix: &'static str,
    boundary: &[&str],
    _bucket_hint: &str,
) {
    let kvs = data_kvs(leaf_kvs(sels, section));
    if kvs.is_empty() {
        return;
    }
    for rec in split_records(&kvs, boundary) {
        let obj = kvs_to_json(&rec);
        let summary = rec
            .iter()
            .take(2)
            .map(|k| format!("{}: {}", k.key, first_line(&k.value)))
            .collect::<Vec<_>>()
            .join(" · ");
        let body = rec
            .iter()
            .map(|k| format!("{}: {}", k.key, k.value.replace('\n', ", ")))
            .collect::<Vec<_>>()
            .join("\n");
        let id = ctx.next_id(prefix);
        ctx.items.push(WarrantItem {
            id,
            section: sect.into(),
            section_display: display.into(),
            timestamp: rec
                .iter()
                .find(|k| {
                    let lk = k.key.to_lowercase();
                    lk.contains("time") || lk.contains("service start")
                })
                .map(|k| k.value.clone()),
            author: None,
            recipient: None,
            body_text: Some(body),
            summary: Some(if summary.is_empty() { display.to_string() } else { summary }),
            raw_fields: with_source(obj, source),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

/// Emit a single info item for a section (no record boundaries).
fn parse_simple(
    sels: &Sels,
    section: ElementRef<'_>,
    source: &str,
    ctx: &mut Ctx,
    sect: &str,
    display: &str,
    prefix: &'static str,
) {
    let kvs = data_kvs(leaf_kvs(sels, section));
    if kvs.is_empty() {
        return;
    }
    let obj = kvs_to_json(&kvs);
    let body = kvs
        .iter()
        .map(|k| format!("{}: {}", k.key, k.value.replace('\n', ", ")))
        .collect::<Vec<_>>()
        .join("\n");
    let id = ctx.next_id(prefix);
    ctx.items.push(WarrantItem {
        id,
        section: sect.into(),
        section_display: display.into(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(body),
        summary: Some(display.to_string()),
        raw_fields: with_source(obj, source),
        attachments: Vec::new(),
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

/// Unknown / low-priority section — surface only if it has real records.
fn parse_generic(sels: &Sels, section: ElementRef<'_>, source: &str, ctx: &mut Ctx, id_attr: &str) {
    let kvs = data_kvs(leaf_kvs(sels, section));
    if kvs.is_empty() {
        return;
    }
    let sect = id_attr.strip_prefix("property-").unwrap_or(id_attr).to_string();
    let display = titleize(&sect);
    let obj = kvs_to_json(&kvs);

    // Media links inside generic sections still get surfaced.
    let mut attachments = Vec::new();
    for kv in &kvs {
        if let Some(base) = media_basename(&kv.value) {
            attachments.push(base.clone());
            ctx.attached.insert(base);
        }
    }

    let body = kvs
        .iter()
        .map(|k| format!("{}: {}", k.key, k.value.replace('\n', ", ")))
        .collect::<Vec<_>>()
        .join("\n");
    let id = ctx.next_id("info");
    ctx.items.push(WarrantItem {
        id,
        section: sect,
        section_display: display,
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(body),
        summary: kvs.first().map(|k| format!("{}: {}", k.key, first_line(&k.value))),
        raw_fields: with_source(obj, source),
        attachments,
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

fn titleize(s: &str) -> String {
    s.split('_')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn with_source(v: Value, source: &str) -> Value {
    let mut obj = match v {
        Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("value".into(), other);
            m
        }
    };
    obj.insert("_source".into(), Value::String(source.to_string()));
    Value::Object(obj)
}

// ─── Detection helpers ─────────────────────────────────────────────────────

fn is_return_html(base: &str) -> bool {
    base == "index.html"
        || (base.starts_with("preservation-") && base.ends_with(".html"))
        || base == "records.html"
}

fn head_is_whatsapp(head: &str) -> bool {
    let lower = head.to_lowercase();
    lower.contains("whatsappuser")
        || lower.contains(">whatsapp<")
        || (lower.contains("service") && lower.contains("whatsapp"))
        || lower.contains("property-offline_log_info")
        || lower.contains("property-connection_info")
}

fn dir_has_whatsapp(dir: &Path, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    let mut subdirs = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            subdirs.push(p);
            continue;
        }
        let base = p
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if is_return_html(&base) {
            if let Ok(mut f) = File::open(&p) {
                let mut head = String::new();
                let _ = f.by_ref().take(16_384).read_to_string(&mut head);
                if head_is_whatsapp(&head) {
                    return true;
                }
            }
        }
    }
    for sd in subdirs {
        if dir_has_whatsapp(&sd, depth + 1) {
            return true;
        }
    }
    false
}

fn collect_from_dir(
    dir: &Path,
    depth: usize,
    media_dir: &Path,
    htmls: &mut Vec<(String, String)>,
    media_on_disk: &mut HashSet<String>,
) -> Result<(), ParseError> {
    if depth > 6 {
        return Ok(());
    }
    for ent in fs::read_dir(dir)?.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_from_dir(&p, depth + 1, media_dir, htmls, media_on_disk)?;
            continue;
        }
        let base = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let lower_base = base.to_lowercase();
        let parent_is_media = p
            .parent()
            .and_then(|pp| pp.file_name())
            .map(|s| s.to_string_lossy().eq_ignore_ascii_case("linked_media"))
            .unwrap_or(false);
        if is_return_html(&lower_base) {
            let mut buf = String::new();
            File::open(&p)?.read_to_string(&mut buf)?;
            htmls.push((lower_base, buf));
        } else if parent_is_media {
            let out = media_dir.join(&base);
            fs::copy(&p, &out)?;
            media_on_disk.insert(base);
        }
    }
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const HOME: &str = r##"<div id="home" class="content-pane visible-content"><table><tr><th>Service</th><td>WhatsApp<br /></td></tr></table><table><tr><th>Internal Ticket Number</th><td>2491756<br /></td></tr></table><table><tr><th>Account Identifier</th><td>+19098270848<br /></td></tr></table><table><tr><th>Account Type</th><td>WhatsAppUser<br /></td></tr></table><table><tr><th>Generated</th><td>2023-06-01 15:18:32 UTC<br /></td></tr></table><table><tr><th>Date Range</th><td>2023-02-01 to 2023-05-30<br /></td></tr></table><table><tr><th>Additional Properties</th><td><a property="ncmec_reports" href="#">ncmec_reports</a><br /></td></tr></table></div>"##;

    const NCMEC: &str = r#"<div id="property-ncmec_reports" class="content-pane"><table><tr><th>Ncmec Reports Definition</th><td>NCMEC Reports: info<br /></td></tr></table><table><tr><th>NCMEC Cybertips</th><td><table><tr><th>CyberTip ID</th><td>159954830<br /></td></tr></table><table><tr><th>Time</th><td>2023-04-08 10:00:37 UTC<br /></td></tr></table><table><tr><th>Responsible Id</th><td>712125091<br /></td></tr></table><table><tr><th>Media uploaded in this cybertip</th><td><table><tr><th>Id</th><td>2724630461<br /></td></tr></table><table><tr><th>Ncmec File Id</th><td>bc8c3292<br /></td></tr></table><video controls="1"><source src="linked_media/ncmec_reports_2724630461.mp4" type="video/mp4" /></video><table><tr><th>Linked Media File:</th><td>linked_media/ncmec_reports_2724630461.mp4<br /></td></tr></table></td></tr></table></td></tr></table></div>"#;

    const OFFLINE_LOG: &str = r#"<div id="property-offline_log_info" class="content-pane"><table><tr><th>Offline Log Info Definition</th><td>logs<br /></td></tr></table><table><tr><th>Offline Message Logs</th><td><table><tr><th>Timestamp</th><td>2023-04-05 04:00:50 UTC<br /></td></tr></table><table><tr><th>ID</th><td>8EBA9935<br /></td></tr></table><table><tr><th>From</th><td>50585859530<br /></td></tr></table><table><tr><th>Event</th><td>media<br /></td></tr></table><table><tr><th>Subtype</th><td>video<br /></td></tr></table><table><tr><th>Content</th><td>No responsive records<br /></td></tr></table><table><tr><th>Timestamp</th><td>2023-04-05 04:07:40 UTC<br /></td></tr></table><table><tr><th>ID</th><td>52DC0F83<br /></td></tr></table><table><tr><th>From</th><td>50585859530<br /></td></tr></table><table><tr><th>Event</th><td>text<br /></td></tr></table><table><tr><th>Subtype</th><td>undefined<br /></td></tr></table><table><tr><th>Content</th><td>No responsive records<br /></td></tr></table></td></tr></table></div>"#;

    const ADDRESS_BOOK: &str = r#"<div id="property-address_book_info" class="content-pane"><table><tr><th>Address Book Info Definition</th><td>book<br /></td></tr></table><table><tr><th>Address Book</th><td><table><tr><th>Symmetric contacts</th><td>3 Total<br />13239065751<br />15023140800<br />15127404673<br /></td></tr></table></td></tr></table></div>"#;

    const DEVICE: &str = r#"<div id="property-device_info" class="content-pane"><table><tr><th>Device Info Definition</th><td>d<br /></td></tr></table><table><tr><th>Device Info</th><td><table><tr><th>Device Id</th><td>0<br /></td></tr></table><table><tr><th>App Version</th><td>iPhone-2.23.5.78<br /></td></tr></table><table><tr><th>Device Model</th><td>iPhone XS Max<br /></td></tr></table></td></tr></table></div>"#;

    fn full_doc(body: &str) -> String {
        format!(
            "<html><head><title>Facebook Legal Request</title></head><body>{}</body></html>",
            body
        )
    }

    #[test]
    fn parse_home_populates_case_metadata() {
        let sels = Sels::new();
        let mut ctx = Ctx::new();
        parse_html(&sels, &full_doc(HOME), "index", &mut ctx);
        assert_eq!(ctx.service, "WhatsApp");
        assert_eq!(ctx.account_id.as_deref(), Some("+19098270848"));
        assert_eq!(ctx.account_type.as_deref(), Some("WhatsAppUser"));
        assert_eq!(ctx.ticket.as_deref(), Some("2491756"));
        assert!(ctx.date_range.is_some());
    }

    #[test]
    fn ncmec_is_flagged_csam_with_media() {
        let sels = Sels::new();
        let mut ctx = Ctx::new();
        parse_html(&sels, &full_doc(NCMEC), "preservation-1", &mut ctx);
        let ncmec: Vec<_> = ctx
            .items
            .iter()
            .filter(|i| i.section == "ncmec_reports")
            .collect();
        assert_eq!(ncmec.len(), 1);
        let it = ncmec[0];
        assert!(it.is_flagged);
        assert_eq!(it.bucket.as_deref(), Some("CSAM"));
        assert_eq!(it.timestamp.as_deref(), Some("2023-04-08 10:00:37 UTC"));
        assert!(it.attachments.iter().any(|a| a == "ncmec_reports_2724630461.mp4"));
        assert!(ctx.attached.contains("ncmec_reports_2724630461.mp4"));
    }

    #[test]
    fn offline_log_splits_into_records() {
        let sels = Sels::new();
        let mut ctx = Ctx::new();
        ctx.account_id = Some("+19098270848".into());
        parse_html(&sels, &full_doc(OFFLINE_LOG), "preservation-1", &mut ctx);
        let msgs: Vec<_> = ctx
            .items
            .iter()
            .filter(|i| i.section == "offline_messages")
            .collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].author.as_deref(), Some("50585859530"));
        assert_eq!(msgs[0].recipient.as_deref(), Some("+19098270848"));
        assert!(msgs[0].summary.as_ref().unwrap().contains("media"));
        // Content was "No responsive records" → dropped to None.
        assert!(msgs[0].body_text.is_none());
    }

    #[test]
    fn address_book_one_item_per_contact() {
        let sels = Sels::new();
        let mut ctx = Ctx::new();
        parse_html(&sels, &full_doc(ADDRESS_BOOK), "preservation-1", &mut ctx);
        let contacts: Vec<_> = ctx
            .items
            .iter()
            .filter(|i| i.section == "address_book")
            .collect();
        assert_eq!(contacts.len(), 3);
        assert_eq!(contacts[0].author.as_deref(), Some("13239065751"));
    }

    #[test]
    fn device_info_becomes_record() {
        let sels = Sels::new();
        let mut ctx = Ctx::new();
        parse_html(&sels, &full_doc(DEVICE), "preservation-1", &mut ctx);
        let dev: Vec<_> = ctx.items.iter().filter(|i| i.section == "device_info").collect();
        assert_eq!(dev.len(), 1);
        assert!(dev[0].body_text.as_ref().unwrap().contains("iPhone XS Max"));
    }

    #[test]
    fn helpers_work() {
        assert_eq!(to_camel("CyberTip ID"), "cybertipId");
        assert_eq!(to_camel("Device OS Build Number"), "deviceOsBuildNumber");
        assert!(is_no_records("No responsive records located"));
        assert!(is_definition("Ncmec Reports Definition"));
        assert_eq!(
            media_basename("linked_media/ncmec_reports_1.mp4").as_deref(),
            Some("ncmec_reports_1.mp4")
        );
        assert_eq!(html_to_text("a<br />b<br />c"), "a\nb\nc");
        assert!(head_is_whatsapp("<th>Service</th><td>WhatsApp"));
        assert!(!head_is_whatsapp("<th>Service</th><td>Facebook"));
    }

    #[test]
    fn accepts_real_zip_shape() {
        // Build a minimal in-memory zip mirroring the production layout.
        let dir = std::env::temp_dir().join(format!("wa_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("case.zip");
        {
            let f = File::create(&zip_path).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            let opts = zip::write::FileOptions::default();
            zw.start_file("index.html", opts).unwrap();
            zw.write_all(full_doc(HOME).as_bytes()).unwrap();
            zw.start_file("preservation-1.html", opts).unwrap();
            zw.write_all(full_doc(&format!("{}{}", NCMEC, DEVICE)).as_bytes())
                .unwrap();
            zw.start_file("linked_media/ncmec_reports_2724630461.mp4", opts)
                .unwrap();
            zw.write_all(b"\x00\x00fakevideo").unwrap();
            zw.finish().unwrap();
        }

        let parser = WhatsAppWarrantParser;
        assert!(parser.accepts(&zip_path).unwrap());

        let media_dir = dir.join("media");
        let parsed = parser.parse(&zip_path, &media_dir).unwrap();
        assert_eq!(parsed.case.provider, Provider::WhatsApp);
        assert_eq!(parsed.case.target_account.as_deref(), Some("+19098270848"));
        assert!(parsed.items.iter().any(|i| i.section == "subscriber_info"));
        assert!(parsed
            .items
            .iter()
            .any(|i| i.section == "ncmec_reports" && i.is_flagged));
        assert!(parsed.items.iter().any(|i| i.section == "device_info"));
        // Media file extracted + linked to the NCMEC item (not orphaned).
        assert!(media_dir.join("ncmec_reports_2724630461.mp4").exists());
        let orphan_media = parsed
            .items
            .iter()
            .filter(|i| i.section == "media")
            .count();
        assert_eq!(orphan_media, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
