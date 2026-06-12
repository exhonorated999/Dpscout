//! Meta (Facebook / Instagram) warrant-return parser.
//!
//! Format reference
//! ----------------
//! Meta productions arrive as a ZIP with:
//!   * `records.html`         — primary data, 12 `<div id="property-X">` sections
//!   * `preservation-N.html`  — same format, snapshot from preservation order
//!   * `instructions.txt`     — ignored
//!   * `linked_media/`        — JPEGs referenced by photos / message attachments
//!
//! Each section uses nested `div.div_table` blocks with
//! `display:table` CSS, alternating bold-key cells and value cells.  Records
//! within a section are flat lists of KV pairs with a known "record-boundary"
//! key (e.g. `Author` for a message, `IP Address` for an IP event).
//!
//! This implementation is a port of the JS reference parser at
//! `C:\Users\JUSTI\Workspace\VIPER\modules\meta-warrant\meta-warrant-parser.js`.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;

use chrono::Utc;
use scraper::{ElementRef, Html, Selector};
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

pub struct MetaWarrantParser {
    // Selectors are expensive to construct; build once per parser instance.
    sel_property_section: Selector,
    sel_div_table_styled: Selector,
    sel_table_cell: Selector,
    sel_title: Selector,
}

impl MetaWarrantParser {
    pub fn new() -> Self {
        // Selector constructors below take &'static str and are infallible
        // for the literals we use, hence unwrap().
        Self {
            sel_property_section: Selector::parse(r#"div[id^="property-"]"#).unwrap(),
            sel_div_table_styled: Selector::parse(r#"div.div_table[style*="display:table"]"#)
                .unwrap(),
            sel_table_cell: Selector::parse(r#"div[style*="display:table-cell"]"#).unwrap(),
            sel_title: Selector::parse("title").unwrap(),
        }
    }
}

impl WarrantParser for MetaWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Meta
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        // Directory input — walk it looking for records.html (any depth)
        if path.is_dir() {
            return Ok(dir_has_meta_format(path) || dir_has_quest_format(path));
        }

        // Otherwise expect a zip file.
        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        let mut has_records = false;
        let mut has_linked_media = false;
        let mut has_preservation = false;
        let mut has_quest_index = false;
        let mut has_quest_folder = false;

        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            let lower = entry.name().to_lowercase();
            // basename comparison — file may be at zip root OR nested one
            // (or more) folders deep because Windows "Send to → Compressed
            // folder" wraps everything under the source folder name.
            let basename = lower.rsplit('/').next().unwrap_or(&lower);
            if basename == "records.html" {
                has_records = true;
            } else if basename.starts_with("preservation-") && basename.ends_with(".html") {
                has_preservation = true;
            }
            // linked_media: any segment named "linked_media/"
            if lower.contains("/linked_media/") || lower.starts_with("linked_media/") {
                has_linked_media = true;
            }

            // Quest export markers — `index.html` at root (or under a single
            // wrapper folder) plus at least one Quest-specific top-level dir.
            if basename == "index.html" {
                has_quest_index = true;
            }
            if lower.contains("meta_horizon_profile/")
                || lower.contains("your_apps_and_content/")
                || lower.contains("security_and_login_information/")
                || lower.contains("/worlds/")
                || lower.starts_with("worlds/")
            {
                has_quest_folder = true;
            }
        }

        let is_meta_records = has_records && (has_linked_media || has_preservation);
        let is_quest = has_quest_index && has_quest_folder;
        Ok(is_meta_records || is_quest)
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

        // Detect which Meta sub-format this is.  If we see records.html
        // anywhere in the input we take the official-LE-records path; if
        // not but we see index.html + Quest folders, we take the Quest
        // consumer-export path.
        let is_quest = is_quest_format(archive_path)?;
        if is_quest {
            return self.parse_quest_export(archive_path, media_extract_dir);
        }

        // ── First pass: collect HTML content + extract linked_media to disk.
        // Either walk a directory or iterate the zip — both paths populate
        // the same locals.
        let mut records_html: Option<String> = None;
        let mut preservation_htmls: Vec<(String, String)> = Vec::new();

        if archive_path.is_dir() {
            walk_dir_collect(
                archive_path,
                media_extract_dir,
                &mut records_html,
                &mut preservation_htmls,
            )?;
        } else {
            let file = File::open(archive_path)?;
            let mut zip = ZipArchive::new(file)?;

            for i in 0..zip.len() {
                let mut entry = zip.by_index(i)?;
                let raw_name = entry.name().to_string();
                if raw_name.ends_with('/') {
                    continue;
                }
                let lower = raw_name.to_lowercase();
                let basename = lower
                    .rsplit('/')
                    .next()
                    .unwrap_or(&lower)
                    .to_string();

                if basename == "records.html" {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf)?;
                    records_html = Some(buf);
                } else if basename.starts_with("preservation-") && basename.ends_with(".html")
                {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf)?;
                    preservation_htmls.push((raw_name.clone(), buf));
                } else if (lower.contains("/linked_media/") || lower.starts_with("linked_media/"))
                    && !raw_name.ends_with('/')
                {
                    // Extract to media dir, preserving filename only
                    // (drop everything up to and including linked_media/).
                    if let Some(filename) = Path::new(&raw_name).file_name() {
                        let out_path = media_extract_dir.join(filename);
                        let mut out = File::create(&out_path)?;
                        std::io::copy(&mut entry, &mut out)?;
                    }
                }
            }
        }

        let records_html = records_html.ok_or(ParseError::WrongFormat)?;

        // ── Parse records.html (primary) ──
        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let mut ctx = ParseCtx {
            items: Vec::new(),
            id_seq: HashMap::new(),
            service: "Facebook".to_string(),
            target_account: None,
            date_range: None,
            generated_at_source: None,
        };

        self.parse_html_file(&records_html, "records", &mut ctx)?;

        // ── Parse preservation files into separate items, tagged by source ──
        for (name, html) in &preservation_htmls {
            // Use the filename (without .html) as source tag — UI shows it
            let source_tag = Path::new(name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("preservation");
            self.parse_html_file(html, source_tag, &mut ctx)?;
        }

        // ── Backfill Photos with every media file on disk ──
        // Two cases this catches:
        //   1. Files in linked_media not referenced by any HTML record
        //      (e.g. test/staging images dropped into the folder, or
        //      media the provider attached without a matching record).
        //   2. Files attached to messages — surface them in Photos as a
        //      secondary card so triage doesn't require opening every
        //      message thread to eyeball the media.
        self.backfill_media_as_photos(media_extract_dir, &mut ctx);

        let case = WarrantCase {
            case_id,
            provider: Provider::Meta,
            provider_display: format!("Meta ({})", ctx.service),
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
        // Meta-specific seed: CSAM goes first because NCMEC reports get
        // auto-flagged into it during parse (see push_ncmec_reports).
        vec![
            BucketTemplate {
                name: "CSAM".into(),
                color: "#ef4444".into(),
                description: Some("Child sexual abuse material — auto-seeded from NCMEC reports".into()),
            },
            BucketTemplate {
                name: "Communications".into(),
                color: "#5b8def".into(),
                description: Some("Messages and chat content".into()),
            },
            BucketTemplate {
                name: "Contacts of Interest".into(),
                color: "#8b5cf6".into(),
                description: None,
            },
            BucketTemplate {
                name: "Drug Evidence".into(),
                color: "#10b981".into(),
                description: None,
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

// ─── Per-parse context ───────────────────────────────────────────────────

struct ParseCtx {
    items: Vec<WarrantItem>,
    /// Per-section running counter for stable IDs (e.g. msg-001, msg-002…).
    id_seq: HashMap<&'static str, usize>,
    service: String,
    target_account: Option<String>,
    date_range: Option<String>,
    generated_at_source: Option<String>,
}

impl ParseCtx {
    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }
}

// ─── KV-pair extraction helpers ──────────────────────────────────────────

#[derive(Debug, Clone)]
struct KvPair {
    key: String,
    value: String,
    images: Vec<String>,
}

impl MetaWarrantParser {
    fn parse_html_file(
        &self,
        html: &str,
        source: &str,
        ctx: &mut ParseCtx,
    ) -> Result<(), ParseError> {
        let doc = Html::parse_document(html);

        // Service detection from <title>
        if let Some(title_el) = doc.select(&self.sel_title).next() {
            let title = title_el.text().collect::<String>();
            if title.to_lowercase().contains("instagram") {
                ctx.service = "Instagram".into();
            } else if title.to_lowercase().contains("facebook") {
                ctx.service = "Facebook".into();
            }
        }

        // Dispatch each top-level property-X section
        for section in doc.select(&self.sel_property_section) {
            let id = section.value().attr("id").unwrap_or("");
            match id {
                "property-request_parameters" => self.parse_request_parameters(section, ctx),
                "property-ncmec_reports" => self.parse_ncmec_reports(section, source, ctx),
                "property-registration_ip" => self.parse_registration_ip(section, source, ctx),
                "property-ip_addresses" => self.parse_ip_addresses(section, source, ctx),
                "property-about_me" => self.parse_about_me(section, source, ctx),
                "property-bio" => self.parse_bio(section, source, ctx),
                "property-wallposts" => self.parse_wallposts(section, source, ctx),
                "property-status_updates" => self.parse_status_updates(section, source, ctx),
                "property-shares" => self.parse_shares(section, source, ctx),
                "property-photos" => self.parse_photos(section, source, ctx),
                "property-unified_messages" => self.parse_unified_messages(section, source, ctx),
                "property-posts_to_other_walls" => self.parse_posts_to_other_walls(section, source, ctx),
                _ => {
                    // Unknown section — surface a single "raw" item so it's visible
                    // in the triage UI rather than silently dropped.
                }
            }
        }

        Ok(())
    }

    /// Get the direct child `.div_table` elements of a section, skipping the
    /// "Definition" sub-section that Meta puts at the top of each block.
    fn data_divs<'a>(&self, section: ElementRef<'a>) -> Vec<ElementRef<'a>> {
        // scraper has no `:scope > .div_table` selector — emulate by walking
        // direct element children.
        let mut out = Vec::new();
        for child in section.children() {
            if let Some(el) = ElementRef::wrap(child) {
                if el
                    .value()
                    .attr("class")
                    .map(|c| c.contains("div_table"))
                    .unwrap_or(false)
                {
                    // Skip the Definition box: inner styled div_table's first
                    // text contains "Definition".
                    let inner = el.select(&self.sel_div_table_styled).next();
                    if let Some(inner_el) = inner {
                        let first_text = first_direct_text(inner_el);
                        if first_text.contains("Definition") {
                            continue;
                        }
                    }
                    out.push(el);
                }
            }
        }
        out
    }

    /// Walk every `.div_table[display:table]` under `container` and pull out
    /// the key (first text child) / value (table-cell > div) pairs.
    fn extract_kv_pairs<'a>(&self, container: ElementRef<'a>) -> Vec<KvPair> {
        let mut pairs = Vec::new();
        for dt in container.select(&self.sel_div_table_styled) {
            let key = first_direct_text(dt);
            if key.is_empty() {
                continue;
            }
            let Some(cell) = dt.select(&self.sel_table_cell).next() else {
                continue;
            };
            // First <div> child of the cell holds the actual value
            let Some(content_div) = cell
                .children()
                .filter_map(ElementRef::wrap)
                .find(|e| e.value().name() == "div")
            else {
                continue;
            };

            let value = content_div
                .text()
                .collect::<String>()
                .trim()
                .to_string();

            let images: Vec<String> = content_div
                .select(&Selector::parse("img").unwrap())
                .filter_map(|img| img.value().attr("src").map(|s| s.to_string()))
                .collect();

            pairs.push(KvPair {
                key: key.trim().to_string(),
                value,
                images,
            });
        }
        pairs
    }

    /// Group a flat list of KV pairs into "records" by re-starting whenever
    /// any of the `record_start_keys` appears.
    fn split_records(&self, kvs: &[KvPair], record_start_keys: &[&str]) -> Vec<Vec<KvPair>> {
        let mut records = Vec::new();
        let mut current: Vec<KvPair> = Vec::new();
        for kv in kvs {
            if record_start_keys.iter().any(|k| kv.key.eq_ignore_ascii_case(k))
                && !current.is_empty()
            {
                records.push(std::mem::take(&mut current));
            }
            current.push(kv.clone());
        }
        if !current.is_empty() {
            records.push(current);
        }
        records
    }

    fn kv_to_json(&self, kvs: &[KvPair]) -> Value {
        let mut map = serde_json::Map::new();
        for kv in kvs {
            let camel = to_camel_case(&kv.key);
            if !map.contains_key(&camel) {
                map.insert(camel.clone(), Value::String(kv.value.clone()));
                if !kv.images.is_empty() {
                    map.insert(
                        format!("{}Images", camel),
                        Value::Array(
                            kv.images.iter().map(|s| Value::String(s.clone())).collect(),
                        ),
                    );
                }
            }
        }
        Value::Object(map)
    }

    // ── Section parsers ──────────────────────────────────────────────────

    fn parse_request_parameters(&self, section: ElementRef<'_>, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            for kv in self.extract_kv_pairs(dd) {
                let k = kv.key.to_lowercase();
                match k.as_str() {
                    "target" => ctx.target_account.get_or_insert(kv.value.clone()),
                    "account identifier" => ctx.target_account.get_or_insert(kv.value.clone()),
                    "date range" => ctx.date_range.get_or_insert(kv.value.clone()),
                    "generated" => ctx.generated_at_source.get_or_insert(kv.value.clone()),
                    "service" => {
                        if !kv.value.is_empty() {
                            ctx.service = kv.value.clone();
                        }
                        continue;
                    }
                    _ => continue,
                };
            }
        }
    }

    fn parse_ncmec_reports(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            let records = self.split_records(&kvs, &["CyberTip ID", "Cybertip"]);
            for rec in records {
                let obj = self.kv_to_json(&rec);
                let id = ctx.next_id("ncmec");
                let timestamp = obj.get("time").and_then(|v| v.as_str()).map(String::from);
                let summary = format!(
                    "CyberTip {}",
                    obj.get("cyberTipId")
                        .or_else(|| obj.get("cybertip"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("(no id)")
                );

                ctx.items.push(WarrantItem {
                    id,
                    section: "ncmec_reports".into(),
                    section_display: "NCMEC Reports".into(),
                    timestamp,
                    author: None,
                    recipient: None,
                    body_text: obj.get("responsibleId").and_then(|v| v.as_str()).map(String::from),
                    summary: Some(summary),
                    raw_fields: with_source(obj, source),
                    attachments: Vec::new(),
                    // Auto-bucket: NCMEC reports are by definition CSAM.
                    bucket: Some("CSAM".into()),
                    note: None,
                    is_flagged: true,
                });
            }
        }
    }

    fn parse_registration_ip(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            let ip_value = kvs[0].value.clone();
            if ip_value.is_empty() {
                continue;
            }
            let id = ctx.next_id("regip");
            ctx.items.push(WarrantItem {
                id,
                section: "registration_ip".into(),
                section_display: "Registration IP".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text: Some(ip_value.clone()),
                summary: Some(format!("Registered from {}", ip_value)),
                raw_fields: with_source(json!({ "ip": ip_value }), source),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }

    fn parse_ip_addresses(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            let records = self.split_records(&kvs, &["IP Address"]);
            for rec in records {
                let obj = self.kv_to_json(&rec);
                let Some(ip) = obj.get("ipAddress").and_then(|v| v.as_str()) else {
                    continue;
                };
                if ip.is_empty() {
                    continue;
                }
                let time = obj.get("time").and_then(|v| v.as_str()).map(String::from);
                let id = ctx.next_id("ip");
                ctx.items.push(WarrantItem {
                    id,
                    section: "ip_addresses".into(),
                    section_display: "IP Addresses".into(),
                    timestamp: time,
                    author: None,
                    recipient: None,
                    body_text: Some(ip.to_string()),
                    summary: Some(format!("IP {}", ip)),
                    raw_fields: with_source(obj, source),
                    attachments: Vec::new(),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    fn parse_about_me(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        let text = self
            .data_divs(section)
            .into_iter()
            .flat_map(|dd| self.extract_kv_pairs(dd))
            .filter(|kv| !is_no_records(&kv.value))
            .map(|kv| kv.value)
            .collect::<Vec<_>>()
            .join(" ");
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        let id = ctx.next_id("about");
        ctx.items.push(WarrantItem {
            id,
            section: "about_me".into(),
            section_display: "About Me".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(trimmed.to_string()),
            summary: Some(truncate(trimmed, 80)),
            raw_fields: with_source(json!({ "text": trimmed }), source),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }

    fn parse_bio(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            let obj = self.kv_to_json(&kvs);
            let text = obj.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let creation = obj.get("creationTime").and_then(|v| v.as_str()).map(String::from);
            let id = ctx.next_id("bio");
            ctx.items.push(WarrantItem {
                id,
                section: "bio".into(),
                section_display: "Bio".into(),
                timestamp: creation,
                author: None,
                recipient: None,
                body_text: Some(text.into()),
                summary: Some(truncate(text, 80)),
                raw_fields: with_source(obj, source),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }

    fn parse_wallposts(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            for rec in self.split_records(&kvs, &["To", "Id"]) {
                let obj = self.kv_to_json(&rec);
                let id = ctx.next_id("post");
                let text = obj.get("text").and_then(|v| v.as_str()).map(String::from);
                ctx.items.push(WarrantItem {
                    id,
                    section: "wallposts".into(),
                    section_display: "Wall Posts".into(),
                    timestamp: obj.get("time").and_then(|v| v.as_str()).map(String::from),
                    author: obj.get("from").and_then(|v| v.as_str()).map(String::from),
                    recipient: obj.get("to").and_then(|v| v.as_str()).map(String::from),
                    body_text: text.clone(),
                    summary: text.map(|t| truncate(&t, 80)),
                    raw_fields: with_source(obj, source),
                    attachments: Vec::new(),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    fn parse_status_updates(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            for rec in self.split_records(&kvs, &["Posted"]) {
                let obj = self.kv_to_json(&rec);
                if obj.get("posted").and_then(|v| v.as_str()).is_none() {
                    continue;
                }
                let id = ctx.next_id("status");
                let status_text = obj.get("status").and_then(|v| v.as_str()).map(String::from);
                ctx.items.push(WarrantItem {
                    id,
                    section: "status_updates".into(),
                    section_display: "Status Updates".into(),
                    timestamp: obj.get("posted").and_then(|v| v.as_str()).map(String::from),
                    author: obj.get("author").and_then(|v| v.as_str()).map(String::from),
                    recipient: None,
                    body_text: status_text.clone(),
                    summary: status_text.map(|t| truncate(&t, 80)),
                    raw_fields: with_source(obj, source),
                    attachments: Vec::new(),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    fn parse_shares(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            for rec in self.split_records(&kvs, &["Date Created"]) {
                let obj = self.kv_to_json(&rec);
                let id = ctx.next_id("share");
                let title = obj.get("title").and_then(|v| v.as_str()).map(String::from);
                let summary = obj.get("summary").and_then(|v| v.as_str()).map(String::from);
                let display = title.clone().or(summary.clone()).unwrap_or_default();
                ctx.items.push(WarrantItem {
                    id,
                    section: "shares".into(),
                    section_display: "Shares".into(),
                    timestamp: obj.get("dateCreated").and_then(|v| v.as_str()).map(String::from),
                    author: None,
                    recipient: None,
                    body_text: summary.or(title),
                    summary: Some(truncate(&display, 80)),
                    raw_fields: with_source(obj, source),
                    attachments: Vec::new(),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    fn parse_photos(&self, section: ElementRef<'_>, source: &str, ctx: &mut ParseCtx) {
        for dd in self.data_divs(section) {
            let Some(inner) = dd.select(&self.sel_div_table_styled).next() else {
                continue;
            };
            let section_label = first_direct_text(inner);
            if is_no_records(&section_label) {
                continue;
            }
            let Some(cell) = inner.select(&self.sel_table_cell).next() else {
                continue;
            };
            let Some(content_div) = cell
                .children()
                .filter_map(ElementRef::wrap)
                .find(|e| e.value().name() == "div")
            else {
                continue;
            };

            let kvs = self.extract_kv_pairs(content_div);
            if kvs.is_empty() {
                continue;
            }

            let album_name = section_label
                .strip_prefix("Album:")
                .map(|s| s.trim().to_string())
                .unwrap_or(section_label.clone());

            let records = self.split_records(&kvs, &["Image", "Linked Media File:"]);
            for rec in records {
                let obj = self.kv_to_json(&rec);
                let image_file = first_image_filename(&obj);
                if image_file.is_none()
                    && obj.get("id").is_none()
                    && obj.get("title").is_none()
                {
                    continue;
                }
                let id = ctx.next_id("photo");
                let attachments: Vec<String> = image_file
                    .clone()
                    .map(|f| vec![f])
                    .unwrap_or_default();

                let title = obj.get("title").and_then(|v| v.as_str()).map(String::from);
                let summary = title
                    .clone()
                    .unwrap_or_else(|| format!("Photo in album '{}'", album_name));

                ctx.items.push(WarrantItem {
                    id,
                    section: "photos".into(),
                    section_display: "Photos".into(),
                    timestamp: obj.get("uploaded").and_then(|v| v.as_str()).map(String::from),
                    author: obj.get("author").and_then(|v| v.as_str()).map(String::from),
                    recipient: None,
                    body_text: title.clone(),
                    summary: Some(truncate(&summary, 80)),
                    raw_fields: with_source(
                        merge_album(&obj, &album_name),
                        source,
                    ),
                    attachments,
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    fn parse_unified_messages(
        &self,
        section: ElementRef<'_>,
        source: &str,
        ctx: &mut ParseCtx,
    ) {
        for dd in self.data_divs(section) {
            let Some(inner) = dd.select(&self.sel_div_table_styled).next() else {
                continue;
            };
            let section_label = first_direct_text(inner);
            if !(section_label.starts_with("Unified Messages")
                || section_label.starts_with("Thread"))
            {
                continue;
            }
            if is_no_records(&section_label) {
                continue;
            }
            let Some(cell) = inner.select(&self.sel_table_cell).next() else {
                continue;
            };
            let Some(content_div) = cell
                .children()
                .filter_map(ElementRef::wrap)
                .find(|e| e.value().name() == "div")
            else {
                continue;
            };

            self.parse_message_threads(content_div, source, ctx);
        }
    }

    fn parse_message_threads(
        &self,
        container: ElementRef<'_>,
        source: &str,
        ctx: &mut ParseCtx,
    ) {
        let kvs = self.extract_kv_pairs(container);
        if kvs.is_empty() {
            return;
        }

        let mut current_thread_id: Option<String> = None;
        let mut current_participants: Vec<String> = Vec::new();

        // Working message being assembled
        let mut msg_author: Option<String> = None;
        let mut msg_sent: Option<String> = None;
        let mut msg_body: Option<String> = None;
        let mut msg_attachments: Vec<String> = Vec::new();
        let mut msg_raw_attachment_meta: Vec<Value> = Vec::new();

        let flush_message = |ctx: &mut ParseCtx,
                             thread_id: &Option<String>,
                             participants: &[String],
                             author: &mut Option<String>,
                             sent: &mut Option<String>,
                             body: &mut Option<String>,
                             attachments: &mut Vec<String>,
                             attachment_meta: &mut Vec<Value>| {
            if author.is_none() && body.is_none() && attachments.is_empty() {
                return;
            }
            let id = ctx.next_id("msg");
            let body_text = body.take();
            let recipient = if participants.len() <= 1 {
                None
            } else {
                Some(
                    participants
                        .iter()
                        .filter(|p| Some(*p) != author.as_ref())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            };
            ctx.items.push(WarrantItem {
                id,
                section: "unified_messages".into(),
                section_display: "Messages".into(),
                timestamp: sent.clone(),
                author: author.clone(),
                recipient,
                body_text: body_text.clone(),
                summary: body_text.as_deref().map(|t| truncate(t, 80)),
                raw_fields: with_source(
                    json!({
                        "threadId": thread_id,
                        "participants": participants,
                        "author": author,
                        "sent": sent,
                        "body": body_text,
                        "attachmentMeta": attachment_meta.clone(),
                    }),
                    source,
                ),
                attachments: attachments.clone(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
            *author = None;
            *sent = None;
            attachments.clear();
            attachment_meta.clear();
        };

        for kv in &kvs {
            match kv.key.as_str() {
                "Thread" => {
                    // Flush any in-flight message before switching threads
                    flush_message(
                        ctx,
                        &current_thread_id,
                        &current_participants,
                        &mut msg_author,
                        &mut msg_sent,
                        &mut msg_body,
                        &mut msg_attachments,
                        &mut msg_raw_attachment_meta,
                    );
                    // Extract (digits) from "(1234567890)" if present
                    current_thread_id = extract_paren_number(&kv.value);
                    current_participants.clear();
                }
                "Current Participants" => {
                    // Value lines: first is a timestamp, rest are participant names
                    let lines: Vec<&str> = kv
                        .value
                        .lines()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if lines.len() > 1 {
                        for p in &lines[1..] {
                            current_participants.push((*p).to_string());
                        }
                    }
                }
                "Author" => {
                    // Starting a new message — flush previous first
                    flush_message(
                        ctx,
                        &current_thread_id,
                        &current_participants,
                        &mut msg_author,
                        &mut msg_sent,
                        &mut msg_body,
                        &mut msg_attachments,
                        &mut msg_raw_attachment_meta,
                    );
                    msg_author = Some(kv.value.clone());
                }
                "Sent" => msg_sent = Some(kv.value.clone()),
                "Body" => msg_body = Some(kv.value.clone()),
                "Attachments" => {
                    // Each "Attachments" line carries a description + may have
                    // <img src> entries pointing at linked_media filenames.
                    for img in &kv.images {
                        if let Some(name) = Path::new(img).file_name() {
                            msg_attachments.push(name.to_string_lossy().into_owned());
                        }
                    }
                    msg_raw_attachment_meta.push(json!({
                        "description": kv.value,
                        "images": kv.images,
                    }));
                }
                "Type" | "Size" | "URL" | "Linked Media File:" => {
                    // Attachment metadata for the last attachment record
                    if let Some(last) = msg_raw_attachment_meta.last_mut() {
                        if let Some(obj) = last.as_object_mut() {
                            obj.insert(to_camel_case(&kv.key), Value::String(kv.value.clone()));
                        }
                    }
                    // Linked Media File: directly names a file — capture it
                    if kv.key == "Linked Media File:" && !kv.value.is_empty() {
                        if let Some(name) = Path::new(&kv.value).file_name() {
                            msg_attachments.push(name.to_string_lossy().into_owned());
                        }
                    }
                }
                _ => {}
            }
        }

        // Final flush
        flush_message(
            ctx,
            &current_thread_id,
            &current_participants,
            &mut msg_author,
            &mut msg_sent,
            &mut msg_body,
            &mut msg_attachments,
            &mut msg_raw_attachment_meta,
        );
    }

    /// Walk the extracted `linked_media/` directory and add a Photos
    /// entry for every image/video file. Files already attached to a
    /// `photos`-section item are skipped (to avoid duplicating Album
    /// photos). Files attached to other items (most often Messages) get
    /// a backreference to that item; orphan files get an "Unreferenced"
    /// label. This is what makes the Photos tab a true media triage
    /// surface — the user sees everything that physically exists in the
    /// warrant return, not just things the provider chose to log.
    fn backfill_media_as_photos(&self, media_dir: &Path, ctx: &mut ParseCtx) {
        // Collect what's already in Photos so we don't double-emit album
        // entries — and a map of filename → source item for message etc.
        // backreferences.
        let mut already_in_photos: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut source_for: HashMap<String, (String, String)> = HashMap::new(); // name → (item_id, section_display)
        for item in &ctx.items {
            for att in &item.attachments {
                let key = att.to_ascii_lowercase();
                if item.section == "photos" {
                    already_in_photos.insert(key);
                } else {
                    source_for
                        .entry(key)
                        .or_insert_with(|| (item.id.clone(), item.section_display.clone()));
                }
            }
        }

        // Enumerate files on disk.
        let entries = match fs::read_dir(media_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        // Sort for stable IDs across re-imports.
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        files.sort();

        for path in files {
            let filename = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let lower = filename.to_ascii_lowercase();

            // Image / video only — keep the Photos grid renderable.
            let is_media = matches!(
                Path::new(&lower)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or(""),
                "jpg"
                    | "jpeg"
                    | "png"
                    | "gif"
                    | "webp"
                    | "bmp"
                    | "tif"
                    | "tiff"
                    | "heic"
                    | "heif"
                    | "mp4"
                    | "mov"
                    | "webm"
                    | "avi"
                    | "mkv"
                    | "m4v"
            );
            if !is_media {
                continue;
            }

            if already_in_photos.contains(&lower) {
                continue; // already shown via Photos album record
            }

            let id = ctx.next_id("photo");
            let (summary, raw, body_text) = if let Some((src_id, src_section)) =
                source_for.get(&lower)
            {
                let summary = format!("{} attachment · {}", src_section, filename);
                let raw = json!({
                    "filename": filename,
                    "sourceItemId": src_id,
                    "sourceSection": src_section,
                });
                (summary, raw, Some(format!("Attached to {} ({})", src_section, src_id)))
            } else {
                let summary = format!("Unreferenced media · {}", filename);
                let raw = json!({
                    "filename": filename,
                    "note": "Found in linked_media but not referenced by any HTML record",
                });
                (summary, raw, None)
            };

            ctx.items.push(WarrantItem {
                id,
                section: "photos".into(),
                section_display: "Photos".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text,
                summary: Some(truncate(&summary, 80)),
                raw_fields: with_source(raw, "media_scan"),
                attachments: vec![filename],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }

    fn parse_posts_to_other_walls(
        &self,
        section: ElementRef<'_>,
        source: &str,
        ctx: &mut ParseCtx,
    ) {
        for dd in self.data_divs(section) {
            let kvs = self.extract_kv_pairs(dd);
            if kvs.is_empty() || is_no_records(&kvs[0].value) {
                continue;
            }
            for rec in self.split_records(&kvs, &["Id"]) {
                let obj = self.kv_to_json(&rec);
                if obj.get("id").and_then(|v| v.as_str()).is_none() {
                    continue;
                }
                let id = ctx.next_id("otherpost");
                let post_text = obj.get("post").and_then(|v| v.as_str()).map(String::from);
                ctx.items.push(WarrantItem {
                    id,
                    section: "posts_to_other_walls".into(),
                    section_display: "Posts to Other Walls".into(),
                    timestamp: obj.get("time").and_then(|v| v.as_str()).map(String::from),
                    author: None,
                    recipient: obj.get("timelineOwner").and_then(|v| v.as_str()).map(String::from),
                    body_text: post_text.clone(),
                    summary: post_text.map(|t| truncate(&t, 80)),
                    raw_fields: with_source(obj, source),
                    attachments: Vec::new(),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    // ─── Quest export (consumer DYI) ─────────────────────────────────────
    //
    // The Meta Quest "Download Your Information" zip uses a *different* HTML
    // layout from the law-enforcement records.html: each top-level folder
    // contains one or more category HTML files, each with `<section>` blocks
    // wrapping `<table>` KV rows + a footer timestamp.  We walk every HTML
    // in the export, route by file path to a section label, and emit
    // WarrantItems.
    fn parse_quest_export(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        // (rel_path_normalised, html_content)
        let mut htmls: Vec<(String, String)> = Vec::new();

        if archive_path.is_dir() {
            walk_quest_dir(archive_path, media_extract_dir, &mut htmls)?;
        } else {
            let file = File::open(archive_path)?;
            let mut zip = ZipArchive::new(file)?;
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i)?;
                let raw_name = entry.name().to_string();
                if raw_name.ends_with('/') {
                    continue;
                }
                let lower = raw_name.to_lowercase();
                let rel = strip_zip_wrapper(&raw_name);
                let basename = lower.rsplit('/').next().unwrap_or(&lower).to_string();

                if is_media_extension(&basename) {
                    if let Some(filename) = Path::new(&raw_name).file_name() {
                        let out_path = media_extract_dir.join(filename);
                        let mut out = File::create(&out_path)?;
                        std::io::copy(&mut entry, &mut out)?;
                    }
                    continue;
                }

                if basename.ends_with(".html") {
                    let mut buf = String::new();
                    entry.read_to_string(&mut buf)?;
                    htmls.push((rel, buf));
                }
            }
        }

        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let mut ctx = ParseCtx {
            items: Vec::new(),
            id_seq: HashMap::new(),
            service: "Quest".to_string(),
            target_account: None,
            date_range: None,
            generated_at_source: None,
        };

        // Sort by path for deterministic output.
        htmls.sort_by(|a, b| a.0.cmp(&b.0));

        // Pull the target account / display name from profile_details.html
        // up front, before we parse the rest.
        for (rel, html) in &htmls {
            if rel.ends_with("meta_horizon_profile/profile_details.html") {
                self.parse_quest_profile(html, rel, &mut ctx);
            }
        }

        // Now parse every HTML file (profile included — it's idempotent).
        for (rel, html) in &htmls {
            // index.html is the landing page — purely navigation/no content
            if rel == "index.html" {
                continue;
            }
            // Skip Quest profile here; it was handled above and would
            // produce duplicates.
            if rel.ends_with("meta_horizon_profile/profile_details.html") {
                continue;
            }
            self.parse_quest_html(html, rel, &mut ctx);
        }

        // Backfill any leftover media (Quest's posts/media/your_posts/*.png
        // generally don't have a matching record HTML — they're world
        // thumbnails, screenshots, etc.).
        self.backfill_media_as_photos(media_extract_dir, &mut ctx);

        let case = WarrantCase {
            case_id,
            provider: Provider::Meta,
            provider_display: "Meta (Quest)".to_string(),
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

    /// Pull display name / username / horizon ID from profile_details.html
    /// into the case-level target_account.
    fn parse_quest_profile(&self, html: &str, source: &str, ctx: &mut ParseCtx) {
        let doc = Html::parse_document(html);
        let sel_section = Selector::parse(r#"main section.\_3-95.\_a6-g"#).unwrap();
        for sec in doc.select(&sel_section) {
            let pairs = quest_table_pairs(sec);
            if pairs.is_empty() {
                continue;
            }
            let obj = pairs_to_json(&pairs);
            let id = ctx.next_id("bio");
            let username = obj.get("username").and_then(|v| v.as_str()).map(String::from);
            let display_name = obj.get("displayName").and_then(|v| v.as_str()).map(String::from);
            let horizon_id = obj.get("metaHorizonProfileId").and_then(|v| v.as_str()).map(String::from);

            if ctx.target_account.is_none() {
                ctx.target_account = username
                    .clone()
                    .or_else(|| display_name.clone())
                    .or_else(|| horizon_id.clone());
            }

            let summary = display_name
                .clone()
                .or_else(|| username.clone())
                .unwrap_or_else(|| "Profile details".into());

            ctx.items.push(WarrantItem {
                id,
                section: "bio".into(),
                section_display: "Profile Details".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text: display_name.clone().or_else(|| username.clone()),
                summary: Some(summary),
                raw_fields: with_source(obj, source),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }

    /// Top-level Quest HTML router — dispatch on file path.
    fn parse_quest_html(&self, html: &str, rel_path: &str, ctx: &mut ParseCtx) {
        let lower = rel_path.to_lowercase();

        // Messages: each section inside a message_1.html is one message.
        if lower.contains("/inbox/") && lower.ends_with("message_1.html") {
            self.parse_quest_messages(html, rel_path, ctx);
            return;
        }

        // Friends/connections — flat list inside a single section.
        if lower.ends_with("friends/connections_details.html")
            || lower.ends_with("social_connections/connections_details.html")
        {
            self.parse_quest_friends(html, rel_path, ctx);
            return;
        }

        // Active sessions: IPs are nested inside divs, not a normal KV table.
        if lower.contains("security_and_login_information/active_sessions") {
            self.parse_quest_active_sessions(html, rel_path, ctx);
            return;
        }
        // Login history: standard KV table — keep in ip_addresses bucket.
        if lower.contains("security_and_login_information/login_history") {
            self.parse_quest_generic(html, rel_path, ctx, "ip_addresses", "Login History");
            return;
        }
        // Location history: own section so lat/long don't pollute IP filter.
        if lower.contains("security_and_login_information/location_history") {
            self.parse_quest_generic(html, rel_path, ctx, "location", "Location History");
            return;
        }

        // Everything else: generic table-of-records dispatch using a
        // path → (section, display) map.
        let (section_id, section_display) = quest_section_from_path(rel_path);
        self.parse_quest_generic(html, rel_path, ctx, &section_id, &section_display);
    }

    /// Walk every `<section class="_3-95 _a6-g">` and emit one WarrantItem
    /// per record (table block), using KV pairs as raw_fields and the
    /// `<div class="_a72d">` footer as the timestamp.
    fn parse_quest_generic(
        &self,
        html: &str,
        source: &str,
        ctx: &mut ParseCtx,
        section_id: &str,
        section_display: &str,
    ) {
        let doc = Html::parse_document(html);
        // Top-level record sections. Quest nests the actual content inside
        // a wrapper `_3-95 _a6-g` and again inside a child of the same
        // class; we look for any section whose immediate child contains
        // a `<table>` so we don't double-emit.
        let sel_section = Selector::parse(r#"section.\_3-95.\_a6-g"#).unwrap();

        // Per-section ID prefix.  Keep stable across re-imports.
        let prefix: &'static str = match section_id {
            "ip_addresses" => "ip",
            "bio" => "bio",
            "unified_messages" => "msg",
            "friends" => "friend",
            "social_connections" => "soc",
            "worlds_visited" => "world",
            "worlds_saved" => "saved",
            "worlds_progress" => "progress",
            "apps" => "app",
            "orders" => "order",
            "achievements" => "ach",
            "recently_viewed" => "viewed",
            "cloud_backups" => "backup",
            "watch_history" => "watch",
            "vr_sessions" => "vr",
            "location" => "loc",
            "settings" => "setting",
            "profile_photos" => "ppic",
            _ => "quest",
        };

        let mut emitted_any = false;
        for sec in doc.select(&sel_section) {
            // Skip the outermost wrapper — Quest layouts have an outer
            // `_3-95 _a6-g` that contains another `_3-95 _a6-g` with the
            // actual `<table>`.  We only parse the innermost level.
            let has_inner = sec.select(&sel_section).next().is_some();
            if has_inner {
                continue;
            }

            let pairs = quest_table_pairs(sec);
            if pairs.is_empty() {
                continue;
            }

            let timestamp = quest_section_timestamp(sec);
            let attachments = quest_section_attachments(sec);
            let obj = pairs_to_json(&pairs);

            // Build a sensible summary: prefer name-like fields (itemName,
            // name, title, displayName, ipAddress, world name) over the
            // first KV pair which is often a less-useful timestamp.
            const PREFERRED_KEYS: &[&str] = &[
                "item name",
                "name",
                "title",
                "display name",
                "world name",
                "destination",
                "ip address",
                "username",
                "email",
                "city",
                "country",
                "device name",
                "subject",
                "headset name",
                "app name",
                "achievement name",
            ];
            let lower_keys: Vec<String> =
                pairs.iter().map(|kv| kv.key.to_lowercase()).collect();
            let preferred_idx: Option<usize> = PREFERRED_KEYS
                .iter()
                .find_map(|target| lower_keys.iter().position(|k| k == target));
            let summary = if let Some(i) = preferred_idx {
                pairs[i].value.clone()
            } else {
                pairs
                    .iter()
                    .find(|kv| {
                        !kv.value.is_empty()
                            && !kv.value.eq_ignore_ascii_case("none")
                            && !kv.value.eq_ignore_ascii_case("n/a")
                    })
                    .map(|kv| format!("{}: {}", kv.key, kv.value))
                    .unwrap_or_else(|| section_display.to_string())
            };

            let body_text = pairs
                .iter()
                .map(|kv| format!("{}: {}", kv.key, kv.value))
                .collect::<Vec<_>>()
                .join("\n");

            // For IP/location records, lift the most meaningful field
            // into the summary + body so the list view reads naturally.
            let (final_body, final_summary) = match section_id {
                "ip_addresses" => {
                    let ip = obj.get("ipAddress").and_then(|v| v.as_str()).map(String::from);
                    let when = obj
                        .get("time")
                        .or_else(|| obj.get("timestamp"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| timestamp.clone());
                    let s = match (ip.as_ref(), when.as_ref()) {
                        (Some(i), Some(t)) => format!("IP {} · {}", i, t),
                        (Some(i), None) => format!("IP {}", i),
                        _ => summary.clone(),
                    };
                    let b = ip.clone().unwrap_or(body_text.clone());
                    (Some(b), Some(truncate(&s, 100)))
                }
                "location" => {
                    let lat = obj.get("latitude").and_then(|v| v.as_str()).map(String::from);
                    let lon = obj.get("longitude").and_then(|v| v.as_str()).map(String::from);
                    let s = match (lat.as_ref(), lon.as_ref()) {
                        (Some(la), Some(lo)) => format!("{}, {}", la, lo),
                        (Some(la), None) => format!("Lat {}", la),
                        _ => summary.clone(),
                    };
                    (Some(body_text.clone()), Some(truncate(&s, 100)))
                }
                _ => (Some(body_text.clone()), Some(truncate(&summary, 100))),
            };

            let id = ctx.next_id(prefix);
            ctx.items.push(WarrantItem {
                id,
                section: section_id.into(),
                section_display: section_display.into(),
                timestamp,
                author: None,
                recipient: None,
                body_text: final_body,
                summary: final_summary,
                raw_fields: with_source(obj, source),
                attachments,
                bucket: None,
                note: None,
                is_flagged: false,
            });
            emitted_any = true;
        }

        // Fallback: if the file has no inner sections (Quest sometimes
        // collapses single-record files), parse top-level tables directly.
        if !emitted_any {
            for sec in doc.select(&sel_section) {
                let pairs = quest_table_pairs(sec);
                if pairs.is_empty() {
                    continue;
                }
                let obj = pairs_to_json(&pairs);
                let id = ctx.next_id(prefix);
                let summary = pairs
                    .first()
                    .map(|kv| format!("{}: {}", kv.key, kv.value))
                    .unwrap_or_else(|| section_display.to_string());
                ctx.items.push(WarrantItem {
                    id,
                    section: section_id.into(),
                    section_display: section_display.into(),
                    timestamp: quest_section_timestamp(sec),
                    author: None,
                    recipient: None,
                    body_text: Some(
                        pairs
                            .iter()
                            .map(|kv| format!("{}: {}", kv.key, kv.value))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    summary: Some(truncate(&summary, 100)),
                    raw_fields: with_source(obj, source),
                    attachments: quest_section_attachments(sec),
                    bucket: None,
                    note: None,
                    is_flagged: false,
                });
            }
        }
    }

    /// Quest inbox: each `<section class="_a6-g">` directly inside `<main>`
    /// is ONE message — `<h2>` is the author, the body div holds text/links,
    /// and `<div class="_a72d">` is the timestamp.
    fn parse_quest_messages(&self, html: &str, source: &str, ctx: &mut ParseCtx) {
        let doc = Html::parse_document(html);
        let sel_thread_header = Selector::parse(r#"header._a709 h1"#).unwrap();
        let sel_section = Selector::parse(r#"main > section.\_a6-g, main > section._a6-g"#)
            .unwrap_or_else(|_| Selector::parse(r#"section._a6-g"#).unwrap());
        let sel_h2 = Selector::parse("h2").unwrap();
        let sel_body = Selector::parse(r#"div._a6-p"#).unwrap();
        let sel_time = Selector::parse(r#"div._a72d"#).unwrap();

        // Use thread header (other participant's display name) for context.
        let thread_with = doc
            .select(&sel_thread_header)
            .next()
            .map(|e| e.text().collect::<String>().trim().to_string())
            .unwrap_or_else(|| "Unknown".into());

        // Owner of the export (e.g. "Exhonorated") — needed to flip the
        // recipient field for outgoing messages.
        let owner = ctx.target_account.clone();

        for sec in doc.select(&sel_section) {
            let author = sec
                .select(&sel_h2)
                .next()
                .map(|e| e.text().collect::<String>().trim().to_string())
                .filter(|s| !s.is_empty());

            let body_text = sec
                .select(&sel_body)
                .next()
                .map(|e| e.text().collect::<String>().trim().to_string())
                .filter(|s| !s.is_empty());

            let timestamp = sec
                .select(&sel_time)
                .next()
                .map(|e| e.text().collect::<String>().trim().to_string())
                .filter(|s| !s.is_empty());

            if author.is_none() && body_text.is_none() && timestamp.is_none() {
                continue;
            }

            // Resolve recipient: if the author matches the export owner,
            // the other party is the thread name; otherwise the recipient
            // is the owner.  Outgoing flag drives chat-bubble alignment.
            let is_outgoing = match (&author, &owner) {
                (Some(a), Some(o)) => a.eq_ignore_ascii_case(o),
                _ => false,
            };
            let recipient = if is_outgoing {
                Some(thread_with.clone())
            } else {
                owner.clone().or_else(|| Some(thread_with.clone()))
            };

            let attachments = quest_section_attachments(sec);
            let id = ctx.next_id("msg");
            let summary = body_text
                .clone()
                .map(|t| truncate(&t, 100))
                .unwrap_or_else(|| {
                    if attachments.is_empty() {
                        "(empty message)".into()
                    } else {
                        format!("Attachment · {}", attachments[0])
                    }
                });

            let mut obj = serde_json::Map::new();
            if let Some(a) = &author {
                obj.insert("author".into(), Value::String(a.clone()));
            }
            obj.insert("threadWith".into(), Value::String(thread_with.clone()));
            if let Some(r) = &recipient {
                obj.insert("recipient".into(), Value::String(r.clone()));
            }
            obj.insert(
                "direction".into(),
                Value::String(if is_outgoing { "outgoing".into() } else { "incoming".into() }),
            );
            if let Some(b) = &body_text {
                obj.insert("body".into(), Value::String(b.clone()));
            }
            if let Some(t) = &timestamp {
                obj.insert("time".into(), Value::String(t.clone()));
            }
            if !attachments.is_empty() {
                obj.insert(
                    "attachments".into(),
                    Value::Array(attachments.iter().map(|s| Value::String(s.clone())).collect()),
                );
            }

            ctx.items.push(WarrantItem {
                id,
                section: "unified_messages".into(),
                section_display: "Messages".into(),
                timestamp,
                author,
                recipient,
                body_text,
                summary: Some(summary),
                raw_fields: with_source(Value::Object(obj), source),
                attachments,
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }

    /// `security_and_login_information/active_sessions.html` —
    /// IPs and timestamps are buried inside nested `<section class="_a6-g">`
    /// blocks containing strings like `47.152.61.26 (10/15/25, 7:23 PM (GMT))`.
    /// Emit one ip_addresses item per row.
    fn parse_quest_active_sessions(&self, html: &str, source: &str, ctx: &mut ParseCtx) {
        let doc = Html::parse_document(html);
        let sel_inner = Selector::parse(r#"section._a6-g div._2ph_._a6-p, section._a6-g div._a6-p"#)
            .unwrap_or_else(|_| Selector::parse("div").unwrap());
        for el in doc.select(&sel_inner) {
            let txt = el.text().collect::<String>().trim().to_string();
            if txt.is_empty() {
                continue;
            }
            // Pattern: "47.152.61.26 (10/15/25, 7:23 PM (GMT))"
            //  → split on the FIRST " (" so the inner "(GMT)" stays attached.
            let (ip, when): (String, Option<String>) = match txt.find(" (") {
                Some(idx) => {
                    let ip = txt[..idx].trim().to_string();
                    let rest = txt[idx + 2..].trim_end_matches(')').trim().to_string();
                    let rest = if rest.is_empty() { None } else { Some(rest) };
                    (ip, rest)
                }
                None => (txt.clone(), None),
            };
            if ip.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            obj.insert("ipAddress".into(), Value::String(ip.clone()));
            if let Some(t) = &when {
                obj.insert("time".into(), Value::String(t.clone()));
            }
            let summary = if let Some(t) = &when {
                format!("IP {} · {}", ip, t)
            } else {
                format!("IP {}", ip)
            };
            let body = if let Some(t) = &when {
                format!("{}\n{}", ip, t)
            } else {
                ip.clone()
            };
            let id = ctx.next_id("ip");
            ctx.items.push(WarrantItem {
                id,
                section: "ip_addresses".into(),
                section_display: "Active Sessions".into(),
                timestamp: when.clone(),
                author: None,
                recipient: None,
                body_text: Some(body),
                summary: Some(truncate(&summary, 100)),
                raw_fields: with_source(Value::Object(obj), source),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }

    /// `friends/connections_details.html` and `social_connections/...` —
    /// one big colspan=2 cell holding a list of friend names.
    fn parse_quest_friends(&self, html: &str, source: &str, ctx: &mut ParseCtx) {        let doc = Html::parse_document(html);
        let sel_section_a6g = Selector::parse(r#"section._a6-g"#).unwrap();
        let sel_inner_section = Selector::parse(r#"section._a6-g div._a6-p section._a6-g"#)
            .unwrap_or_else(|_| Selector::parse("section").unwrap());

        // Friends are inside nested sections inside the value cell.
        for sec in doc.select(&sel_inner_section) {
            let name = sec.text().collect::<String>().trim().to_string();
            if name.is_empty() {
                continue;
            }
            let id = ctx.next_id("friend");
            ctx.items.push(WarrantItem {
                id,
                section: "friends".into(),
                section_display: "Friends".into(),
                timestamp: None,
                author: None,
                recipient: None,
                body_text: Some(name.clone()),
                summary: Some(name.clone()),
                raw_fields: with_source(json!({ "name": name }), source),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }

        // Suppress unused-warning if no inner sections found.
        let _ = doc.select(&sel_section_a6g).count();
    }
}

// ─── Free helpers ────────────────────────────────────────────────────────

fn first_direct_text(el: ElementRef<'_>) -> String {
    for child in el.children() {
        if let Some(text) = child.value().as_text() {
            let t = text.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

fn is_no_records(s: &str) -> bool {
    s.contains("No responsive records")
}

fn to_camel_case(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c.is_ascii_whitespace() { c } else { ' ' })
        .collect();
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            out.push_str(&p.to_lowercase());
        } else {
            let mut chars = p.chars();
            if let Some(first) = chars.next() {
                out.push(first.to_ascii_uppercase());
                out.push_str(&chars.as_str().to_lowercase());
            }
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn extract_paren_number(s: &str) -> Option<String> {
    let start = s.find('(')?;
    let end = s[start + 1..].find(')')?;
    let inner = &s[start + 1..start + 1 + end];
    if inner.chars().all(|c| c.is_ascii_digit()) {
        Some(inner.to_string())
    } else {
        None
    }
}

fn first_image_filename(obj: &Value) -> Option<String> {
    // Look in `imageImages` (array from extract_kv_pairs) first, then
    // `linkedMediaFile`.
    if let Some(arr) = obj.get("imageImages").and_then(|v| v.as_array()) {
        if let Some(first) = arr.first().and_then(|v| v.as_str()) {
            if let Some(name) = Path::new(first).file_name() {
                return Some(name.to_string_lossy().into_owned());
            }
        }
    }
    obj.get("linkedMediaFile")
        .and_then(|v| v.as_str())
        .and_then(|s| Path::new(s).file_name().map(|n| n.to_string_lossy().into_owned()))
}

fn merge_album(obj: &Value, album: &str) -> Value {
    let mut clone = obj.clone();
    if let Some(map) = clone.as_object_mut() {
        map.insert("album".into(), Value::String(album.into()));
    }
    clone
}

fn with_source(mut obj: Value, source: &str) -> Value {
    if let Some(map) = obj.as_object_mut() {
        map.insert("__source".into(), Value::String(source.into()));
    } else {
        let mut new_obj = serde_json::Map::new();
        new_obj.insert("value".into(), obj.clone());
        new_obj.insert("__source".into(), Value::String(source.into()));
        return Value::Object(new_obj);
    }
    obj
}

// `Cursor`/`Read` imports are kept future-proof; presently we always read
// straight from the zip entry.
#[allow(dead_code)]
fn _readable_dummy() -> impl Read {
    Cursor::new(Vec::<u8>::new())
}

// ─── Folder-input helpers ────────────────────────────────────────────────

/// Recursive `is_dir` walk that returns true if a file named (case-insensitive)
/// `records.html` is anywhere under `dir` AND there's either a sibling/cousin
/// `linked_media` directory or a `preservation-*.html` file.
fn dir_has_meta_format(dir: &Path) -> bool {
    let mut has_records = false;
    let mut has_linked_media = false;
    let mut has_preservation = false;
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    // Depth-limit so we don't traverse pathological structures forever.
    let mut visited = 0usize;
    const MAX_VISITED: usize = 20_000;
    while let Some(p) = stack.pop() {
        visited += 1;
        if visited > MAX_VISITED {
            break;
        }
        let rd = match fs::read_dir(&p) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(f) => f,
                Err(_) => continue,
            };
            if ft.is_dir() {
                if path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("linked_media"))
                    .unwrap_or(false)
                {
                    has_linked_media = true;
                }
                stack.push(path);
            } else if ft.is_file() {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if name == "records.html" {
                    has_records = true;
                } else if name.starts_with("preservation-") && name.ends_with(".html") {
                    has_preservation = true;
                }
            }
            if has_records && (has_linked_media || has_preservation) {
                return true;
            }
        }
    }
    has_records && (has_linked_media || has_preservation)
}

/// Mirror of the zip-iteration first pass for a folder input. Reads
/// `records.html` + any `preservation-*.html` into memory, and copies
/// every file from any `linked_media` subdir into `media_extract_dir`.
fn walk_dir_collect(
    dir: &Path,
    media_extract_dir: &Path,
    records_html: &mut Option<String>,
    preservation_htmls: &mut Vec<(String, String)>,
) -> Result<(), ParseError> {
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let rd = match fs::read_dir(&p) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(f) => f,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let name_lower = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Treat files inside any "linked_media" parent as media.
            let in_linked_media = path.ancestors().any(|a| {
                a.file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("linked_media"))
                    .unwrap_or(false)
            });
            if in_linked_media {
                if let Some(filename) = path.file_name() {
                    let out_path = media_extract_dir.join(filename);
                    let mut input = File::open(&path)?;
                    let mut out = File::create(&out_path)?;
                    std::io::copy(&mut input, &mut out)?;
                }
                continue;
            }

            if name_lower == "records.html" {
                let mut buf = String::new();
                File::open(&path)?.read_to_string(&mut buf)?;
                *records_html = Some(buf);
            } else if name_lower.starts_with("preservation-") && name_lower.ends_with(".html") {
                let mut buf = String::new();
                File::open(&path)?.read_to_string(&mut buf)?;
                let display_name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("preservation.html")
                    .to_string();
                preservation_htmls.push((display_name, buf));
            }
        }
    }
    Ok(())
}

// ─── Quest export helpers ────────────────────────────────────────────────

/// Standard media extensions Quest's posts/media folder uses.
fn is_media_extension(name_lower: &str) -> bool {
    let exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff",
        ".heic", ".heif", ".mp4", ".mov", ".webm", ".avi", ".mkv", ".m4v",
        ".mp3", ".m4a", ".wav", ".ogg",
    ];
    exts.iter().any(|e| name_lower.ends_with(e))
}

/// Some users zip the export by selecting the unzipped folder + "Send to →
/// compressed", which wraps the whole thing inside `Some Folder/`. Detect
/// this and strip one level of wrapping so our path keys match what we'd
/// see in a "clean" zip rooted at index.html.
fn strip_zip_wrapper(raw: &str) -> String {
    // If the path starts with `<dir>/index.html`'s sibling, strip up to and
    // including the first slash.  Heuristic: if the first segment doesn't
    // match any known Quest top-level, treat it as a wrapper.
    let known = [
        "index.html",
        "approved_contacts/",
        "avatars_store/",
        "beat_saber/",
        "device_information/",
        "environmental_data/",
        "files/",
        "friends/",
        "meetings/",
        "messages/",
        "meta_account/",
        "meta_ai_app/",
        "meta_ai_profile/",
        "meta_credits/",
        "meta_horizon_home/",
        "meta_horizon_profile/",
        "other_activity/",
        "other_information_about_you/",
        "parental_approval/",
        "parental_supervision/",
        "posts/",
        "reports/",
        "security_and_login_information/",
        "social_connections/",
        "voice_activities/",
        "wit.ai_account_and_apps/",
        "workrooms/",
        "worlds/",
        "worlds_media_and_posts/",
        "your_apps_and_content/",
        "your_developer_organizations/",
        "your_media_from_meta_quest_media_studio/",
        "your_ratings_and_reviews/",
        "your_settings_and_preferences/",
    ];
    let lower = raw.to_lowercase();
    if known.iter().any(|k| lower.starts_with(k)) {
        return raw.to_string();
    }
    // Wrapper present — strip first segment.
    if let Some(idx) = raw.find('/') {
        let after = &raw[idx + 1..];
        // Only strip if what's left looks like a Quest entry.
        let after_lower = after.to_lowercase();
        if known.iter().any(|k| after_lower.starts_with(k)) {
            return after.to_string();
        }
    }
    raw.to_string()
}

/// Same `is_quest_format` check used by both zip + directory inputs.
fn is_quest_format(path: &Path) -> Result<bool, ParseError> {
    if path.is_dir() {
        return Ok(dir_has_quest_format(path));
    }
    let file = File::open(path)?;
    let mut zip = match ZipArchive::new(file) {
        Ok(z) => z,
        Err(_) => return Ok(false),
    };
    let mut has_records = false;
    let mut has_index = false;
    let mut has_quest_dir = false;
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let lower = entry.name().to_lowercase();
        let basename = lower.rsplit('/').next().unwrap_or(&lower);
        if basename == "records.html" {
            has_records = true;
        }
        if basename == "index.html" {
            has_index = true;
        }
        if lower.contains("meta_horizon_profile/")
            || lower.contains("your_apps_and_content/")
            || lower.contains("security_and_login_information/")
            || lower.contains("/worlds/")
            || lower.starts_with("worlds/")
        {
            has_quest_dir = true;
        }
    }
    // Quest format wins only when records.html is absent (records.html
    // exports always take priority because they're the LE format).
    Ok(!has_records && has_index && has_quest_dir)
}

fn dir_has_quest_format(dir: &Path) -> bool {
    let mut has_records = false;
    let mut has_index = false;
    let mut has_quest_dir = false;
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    let mut visited = 0usize;
    const MAX_VISITED: usize = 20_000;
    while let Some(p) = stack.pop() {
        visited += 1;
        if visited > MAX_VISITED {
            break;
        }
        let rd = match fs::read_dir(&p) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(f) => f,
                Err(_) => continue,
            };
            if ft.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if matches!(
                    name.as_str(),
                    "meta_horizon_profile"
                        | "your_apps_and_content"
                        | "security_and_login_information"
                        | "worlds"
                ) {
                    has_quest_dir = true;
                }
                stack.push(path);
            } else if ft.is_file() {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if name == "records.html" {
                    has_records = true;
                }
                if name == "index.html" {
                    has_index = true;
                }
            }
        }
    }
    !has_records && has_index && has_quest_dir
}

/// Walk a Quest extracted folder and collect every HTML file + extract
/// every media file into `media_extract_dir`.
fn walk_quest_dir(
    dir: &Path,
    media_extract_dir: &Path,
    htmls: &mut Vec<(String, String)>,
) -> Result<(), ParseError> {
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let rd = match fs::read_dir(&p) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(f) => f,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let name_lower = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            if is_media_extension(&name_lower) {
                if let Some(filename) = path.file_name() {
                    let out_path = media_extract_dir.join(filename);
                    let mut input = File::open(&path)?;
                    let mut out = File::create(&out_path)?;
                    std::io::copy(&mut input, &mut out)?;
                }
                continue;
            }
            if name_lower.ends_with(".html") {
                let rel = match path.strip_prefix(dir) {
                    Ok(r) => r.to_string_lossy().replace('\\', "/"),
                    Err(_) => path.to_string_lossy().replace('\\', "/"),
                };
                let mut buf = String::new();
                File::open(&path)?.read_to_string(&mut buf)?;
                htmls.push((rel, buf));
            }
        }
    }
    Ok(())
}

/// Map a Quest export path → (section_id, section_display).
fn quest_section_from_path(rel_path: &str) -> (String, String) {
    let lower = rel_path.to_lowercase();
    // Order matters — more-specific paths first.
    let table: &[(&str, &str, &str)] = &[
        ("meta_horizon_profile/profile_details", "bio", "Profile Details"),
        ("security_and_login_information/login_history", "ip_addresses", "Login History"),
        ("security_and_login_information/active_sessions", "ip_addresses", "Active Sessions"),
        ("security_and_login_information/location_history", "location", "Location History"),
        ("security_and_login_information/app_presence_activity", "app_presence", "App Presence"),
        ("your_apps_and_content/inbox/", "unified_messages", "Messages"),
        ("your_apps_and_content/apps.html", "apps", "Installed Apps"),
        ("your_apps_and_content/your_orders.html", "orders", "Orders"),
        ("your_apps_and_content/achievements.html", "achievements", "Achievements"),
        ("your_apps_and_content/recently_viewed_items.html", "recently_viewed", "Recently Viewed"),
        ("your_apps_and_content/cloud_backups.html", "cloud_backups", "Cloud Backups"),
        ("your_apps_and_content/in-app_entitlements", "entitlements", "In-App Entitlements"),
        ("your_apps_and_content/your_subscriptions.html", "subscriptions", "Subscriptions"),
        ("your_apps_and_content/sent_application_invites", "app_invites_sent", "App Invites Sent"),
        ("your_apps_and_content/received_application_invites", "app_invites_recv", "App Invites Received"),
        ("your_apps_and_content/sent_gifts.html", "gifts_sent", "Gifts Sent"),
        ("your_apps_and_content/group_chat_threads", "group_chats", "Group Chat Threads"),
        ("your_apps_and_content/subscribed_events", "events", "Subscribed Events"),
        ("your_apps_and_content/meta_quest_gallery_photos", "photos", "Photos"),
        ("worlds/worlds_visited", "worlds_visited", "Worlds Visited"),
        ("worlds/worlds_progress", "worlds_progress", "Worlds Progress"),
        ("worlds/worlds_saved", "worlds_saved", "Worlds Saved"),
        ("worlds/emotes", "emotes", "Emotes"),
        ("worlds/settings_details", "settings", "Worlds Settings"),
        ("worlds/worlds_privacy_settings", "settings", "Worlds Privacy Settings"),
        ("worlds/name_tag_frame", "settings", "Name Tag Frame"),
        ("friends/connections_details", "friends", "Friends"),
        ("social_connections/connections_details", "social_connections", "Social Connections"),
        ("other_activity/watch_history", "watch_history", "Watch History"),
        ("other_activity/your_vr_sessions", "vr_sessions", "VR Sessions"),
        ("other_information_about_you/current_and_past_profile_photos", "profile_photos", "Profile Photos"),
        ("other_information_about_you/emails_we_sent", "notification_emails", "Notification Emails"),
        ("meta_account/your_payment_methods", "payment_methods", "Payment Methods"),
        ("device_information/online_status_history", "device_info", "Online Status History"),
        ("device_information/vr_device_sync_data", "device_info", "VR Device Sync Data"),
        ("device_information/users_you", "device_info", "Users You're Sharing With"),
        ("device_information/device_promotions", "device_info", "Device Promotions"),
        ("device_information/wi-fi_signal_strength", "device_info", "Wi-Fi Signal Strength"),
        ("environmental_data/space_data", "environment", "Space Data"),
        ("your_ratings_and_reviews/", "reviews", "Ratings & Reviews"),
        ("your_settings_and_preferences/", "settings", "Settings & Preferences"),
        ("parental_supervision/", "parental", "Parental Supervision"),
    ];
    for (pat, sid, sdisp) in table {
        if lower.contains(pat) {
            return ((*sid).into(), (*sdisp).into());
        }
    }
    // Fallback: derive from first folder segment.
    let folder = lower.split('/').next().unwrap_or("misc").to_string();
    let display = folder
        .split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().chain(c).collect(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    (folder, display)
}

/// Extract every `<tr>` of every `<table>` directly inside this section
/// element as a flat list of KvPairs (key = first `_a6_q`, value = first
/// `_2piu _a6_r` text — and we also record image src basenames if any).
fn quest_table_pairs(section: ElementRef<'_>) -> Vec<KvPair> {
    let sel_tr = Selector::parse("table tr").unwrap();
    let sel_key = Selector::parse(r#"td.\_a6_q, td._a6_q"#).unwrap();
    let sel_val = Selector::parse(r#"td.\_2piu.\_a6_r, td._2piu._a6_r, td._a6_r"#).unwrap();
    let sel_img = Selector::parse("img").unwrap();
    let sel_a = Selector::parse("a").unwrap();

    let mut out: Vec<KvPair> = Vec::new();
    for tr in section.select(&sel_tr) {
        let key_el = tr.select(&sel_key).next();
        let key = key_el
            .map(|e| e.text().collect::<String>().trim().to_string())
            .unwrap_or_default();

        // Value cell — if it doesn't exist (colspan=2 key cells), reuse
        // the key cell's deeper content as the value.
        let val_el = tr.select(&sel_val).next();
        let value_text = match val_el {
            Some(v) => v.text().collect::<String>().trim().to_string(),
            None => {
                // For colspan rows, take everything in the key cell after
                // the leading bold text.
                if let Some(k) = key_el {
                    let full = k.text().collect::<String>();
                    let trimmed = full.trim();
                    // Strip the literal key prefix once if present.
                    trimmed
                        .strip_prefix(&*key)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| trimmed.to_string())
                } else {
                    String::new()
                }
            }
        };

        // Collect image src basenames + any URLs.
        let mut images: Vec<String> = Vec::new();
        let scan_el = val_el.or(key_el);
        if let Some(scan_root) = scan_el {
            for img in scan_root.select(&sel_img) {
                if let Some(src) = img.value().attr("src") {
                    // Skip data: URIs (inline icons)
                    if src.starts_with("data:") {
                        continue;
                    }
                    if let Some(name) = Path::new(src).file_name() {
                        images.push(name.to_string_lossy().into_owned());
                    }
                }
            }
            // Promote linked images via `<a href="posts/media/...">` too.
            for a in scan_root.select(&sel_a) {
                if let Some(href) = a.value().attr("href") {
                    let lower = href.to_lowercase();
                    if is_media_extension(&lower) {
                        if let Some(name) = Path::new(href).file_name() {
                            let n = name.to_string_lossy().into_owned();
                            if !images.contains(&n) {
                                images.push(n);
                            }
                        }
                    }
                }
            }
        }

        if key.is_empty() && value_text.is_empty() && images.is_empty() {
            continue;
        }
        out.push(KvPair {
            key,
            value: value_text,
            images,
        });
    }
    out
}

/// Pull the `<div class="_a72d">` timestamp out of a section's footer.
fn quest_section_timestamp(section: ElementRef<'_>) -> Option<String> {
    let sel = Selector::parse(r#"footer div._a72d, div._a72d"#).unwrap();
    section
        .select(&sel)
        .next()
        .map(|e| e.text().collect::<String>().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Walk a section for any image src / link href that points at a media
/// file and return the basenames.
fn quest_section_attachments(section: ElementRef<'_>) -> Vec<String> {
    let sel_img = Selector::parse("img").unwrap();
    let sel_a = Selector::parse("a").unwrap();
    let mut out: Vec<String> = Vec::new();
    for img in section.select(&sel_img) {
        if let Some(src) = img.value().attr("src") {
            if src.starts_with("data:") {
                continue;
            }
            if let Some(name) = Path::new(src).file_name() {
                let n = name.to_string_lossy().into_owned();
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    for a in section.select(&sel_a) {
        if let Some(href) = a.value().attr("href") {
            let lower = href.to_lowercase();
            if is_media_extension(&lower) {
                if let Some(name) = Path::new(href).file_name() {
                    let n = name.to_string_lossy().into_owned();
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
        }
    }
    out
}

/// Convert KvPairs to a serde JSON object using to_camel_case keys.
fn pairs_to_json(kvs: &[KvPair]) -> Value {
    let mut map = serde_json::Map::new();
    for kv in kvs {
        let camel = to_camel_case(&kv.key);
        if camel.is_empty() {
            continue;
        }
        if !map.contains_key(&camel) {
            map.insert(camel.clone(), Value::String(kv.value.clone()));
            if !kv.images.is_empty() {
                map.insert(
                    format!("{}Images", camel),
                    Value::Array(
                        kv.images.iter().map(|s| Value::String(s.clone())).collect(),
                    ),
                );
            }
        }
    }
    Value::Object(map)
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_zip() -> Option<PathBuf> {
        // The user-provided sample lives in their Downloads directory.
        let p = PathBuf::from(
            r"C:\Users\JUSTI\Downloads\26-123456_DA_Export_2026-05-28(2)\Warrants\Production\Clean Data Archive for Distribution[4] (1).zip",
        );
        if p.exists() {
            Some(p)
        } else {
            None
        }
    }

    #[test]
    fn meta_accepts_sample_zip() {
        let Some(p) = sample_zip() else {
            eprintln!("Sample zip not present — skipping");
            return;
        };
        let parser = MetaWarrantParser::new();
        assert!(parser.accepts(&p).unwrap(), "Meta parser should accept the sample zip");
    }

    #[test]
    fn meta_parses_sample_zip() {
        let Some(p) = sample_zip() else {
            eprintln!("Sample zip not present — skipping");
            return;
        };
        let tmp = std::env::temp_dir().join("scout_meta_test_extract");
        let _ = std::fs::remove_dir_all(&tmp);
        let parser = MetaWarrantParser::new();
        let parsed = parser.parse(&p, &tmp).expect("parse should succeed");

        // The known sample has 12 property sections, so we expect AT LEAST
        // one item across the canonical sections.  Without committing to
        // exact counts (depends on Meta's record shape), assert we found
        // SOME items.
        assert!(
            !parsed.items.is_empty(),
            "expected at least one parsed item from records.html"
        );

        // Print a section breakdown so we can eyeball coverage when this
        // test runs interactively.
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for it in &parsed.items {
            *counts.entry(it.section.clone()).or_insert(0) += 1;
        }
        eprintln!("=== Meta parse breakdown ===");
        for (k, v) in &counts {
            eprintln!("  {:32} {}", k, v);
        }
        eprintln!("Target account : {:?}", parsed.case.target_account);
        eprintln!("Date range     : {:?}", parsed.case.date_range);
        eprintln!("Service        : {}", parsed.case.provider_display);
    }

    // ── Quest export tests ───────────────────────────────────────────────

    fn quest_zip() -> Option<PathBuf> {
        let p = PathBuf::from(r"C:\Users\JUSTI\Downloads\Meta Quest Account Backup Data.zip");
        if p.exists() {
            Some(p)
        } else {
            None
        }
    }

    #[test]
    fn meta_accepts_quest_zip() {
        let Some(p) = quest_zip() else {
            eprintln!("Quest sample zip not present — skipping");
            return;
        };
        let parser = MetaWarrantParser::new();
        assert!(parser.accepts(&p).unwrap(), "Meta parser should accept the Quest backup zip");
        assert!(is_quest_format(&p).unwrap(), "is_quest_format should be true");
    }

    #[test]
    fn meta_parses_quest_zip() {
        let Some(p) = quest_zip() else {
            eprintln!("Quest sample zip not present — skipping");
            return;
        };
        let tmp = std::env::temp_dir().join("scout_quest_test_extract");
        let _ = std::fs::remove_dir_all(&tmp);
        let parser = MetaWarrantParser::new();
        let parsed = parser.parse(&p, &tmp).expect("parse should succeed");

        assert!(!parsed.items.is_empty(), "expected items from Quest export");
        assert_eq!(parsed.case.provider_display, "Meta (Quest)");

        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for it in &parsed.items {
            *counts.entry(it.section.clone()).or_insert(0) += 1;
        }
        eprintln!("=== Quest parse breakdown ===");
        for (k, v) in &counts {
            eprintln!("  {:32} {}", k, v);
        }
        eprintln!("Target account : {:?}", parsed.case.target_account);
        eprintln!("Service        : {}", parsed.case.provider_display);
        eprintln!("Total items    : {}", parsed.items.len());

        // Spot-check: we should have at least messages, friends, and bio
        // from this particular export.
        assert!(counts.contains_key("unified_messages"), "expected unified_messages");
        assert!(counts.contains_key("bio"), "expected bio");
    }
}
