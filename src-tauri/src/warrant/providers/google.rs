//! Google warrant-return parser (also accepts Google Takeout exports).
//!
//! Format reference
//! ----------------
//! Google law-enforcement responses ("LERS") come in one of two shapes:
//!
//! 1. **Warrant return** — a single outer ZIP containing many per-service
//!    inner ZIPs, named like:
//!
//!    ```text
//!    {accountEmail}.{accountId}.{Service}.{Resource}_001.zip
//!    ```
//!
//!    Inside each inner zip is a folder per service (`Google Account/`,
//!    `Google Play Store/`, `Mail/`, ...) holding HTML / CSV / JSON / MBOX
//!    files, plus a `*.ExportSummary.txt` cover sheet and (if empty) a
//!    `NoRecords.txt` sentinel.
//!
//!    The outer zip ALSO often contains a "master bundle" wrapper zip
//!    named `{caseNumber}-{date}-{N}.zip` that re-contains the inner zips
//!    — we recurse into it but dedupe by filename so the same service is
//!    not parsed twice.
//!
//! 2. **Google Takeout** — a user-initiated export.  Same per-service
//!    content but laid out as a single folder tree:
//!
//!    ```text
//!    Takeout/
//!      Google Account/           …SubscriberInfo.html, ChangeHistory.html
//!      Mail/                     All mail Including Spam and Trash.mbox
//!      Location History (Timeline)/  Records.json, Semantic Location History/
//!      Google Play Store/        Devices.csv, Installs.csv, Library.csv, …
//!      Hangouts/                 user_info.txt
//!      Google Chat/              UserInfo / Messages / Groups
//!      Access Log Activity/      *.html
//!      My Activity/              *.html (per-product activity logs)
//!      ...
//!    ```
//!
//! The parser auto-detects which shape it's looking at and walks the
//! file tree (zip or directory) accordingly.
//!
//! Sections emitted
//! ----------------
//! - `bio`               — subscriber info, Hangouts user_info, NoRecords list
//! - `ip_addresses`      — Subscriber IP Activity + AccessLog rows
//! - `change_history`    — Google Account change-history table
//! - `emails`            — every message in the .mbox (headers + body)
//! - `photos`            — attachments extracted from MIME bodies
//! - `device_info`       — Play Store device list
//! - `apps`              — Play Store installs + library entries
//! - `recently_viewed`   — Play Store User Activity HTML entries
//! - `settings`          — Play Store UserPreferences CSV
//! - `location`          — Location History records / semantic
//! - `unified_messages`  — Google Chat messages
//! - `friends`           — Google Chat UserInfo / GroupInfo
//! - `request_parameters`— Per-service ExportSummary rows
//!
//! Loose port of `VIPER/modules/google-warrant/google-warrant-parser.js`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use scraper::{Html, Selector};
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

pub struct GoogleWarrantParser;

// Filename → service identification pattern.
//
// Warrant return zips: `{email}.{accountId}.{Service}.{Resource}_001.zip`
//   e.g.  js7017987@gmail.com.838053527712.Mail.MessageContent_001.zip
//
// Takeout folder names map to "<Service>.<Resource>" via TAKEOUT_FOLDER_MAP.
const IMAGE_EXTS: &[&str] = &[".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp"];
const VIDEO_EXTS: &[&str] = &[".mp4", ".mov", ".webm", ".m4v", ".avi", ".mkv"];

/// Largest single file we will read fully into memory during collection.
/// Text/records/subscriber/mbox files are almost always well under this.
/// Multi-GB volumes (bulk media, giant mbox spills) above this are skipped
/// so a 300 GB+ return can never OOM the app.  Skipped files are recorded
/// via `ctx.skipped_large` and surfaced in the bio.
const MAX_INMEM_FILE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Per-return cap on bulk media (photos/videos) we extract to the case dir.
/// Beyond this we stop extracting media bytes but still count what was seen.
const MAX_MEDIA_EXTRACT: usize = 5_000;

// ─── WarrantParser impl ─────────────────────────────────────────────────

impl WarrantParser for GoogleWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Google
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_google_format(path));
        }

        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        // Warrant: contains *.ExportSummary.txt OR per-service inner zips
        // whose name matches the {email}.{accountId}.{Service}.{Resource}_NNN.zip pattern.
        // Large returns pack resources as DIRECTORIES inside master-bundle
        // volumes ({internalNumber}-{YYYYMMDD}-{N}.zip); detect those too.
        // Takeout: contains a top-level "Takeout/" directory.
        let mut found = false;
        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            let name = entry.name().to_string();
            let lower = name.to_lowercase();

            if lower.ends_with("/exportsummary.txt") || lower.ends_with(".exportsummary.txt") {
                found = true;
                break;
            }
            if name.contains("Takeout/") || name.starts_with("Takeout/") {
                found = true;
                break;
            }
            if is_lers_inner_zip(&name) {
                found = true;
                break;
            }
            // Master-bundle volume nested inside the picked zip, or the
            // resource-directory layout ({lers}_NNN/<files>).
            let first_seg = name.split('/').next().unwrap_or(&name);
            if is_master_bundle_filename(first_seg) || is_lers_dir_name(first_seg) {
                found = true;
                break;
            }
        }
        Ok(found)
    }

    fn parse(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        fs::create_dir_all(media_extract_dir)?;

        // Phase 1: gather every "category" (Service.Resource) → file list,
        // either by walking zips-of-zips or a Takeout folder.
        let mut ctx = ParseCtx::new(media_extract_dir);

        if archive_path.is_dir() {
            collect_from_dir(archive_path, &mut ctx)?;
        } else {
            collect_from_zip(archive_path, &mut ctx)?;
        }

        // Phase 2: dispatch each category to its handler.
        //
        // Use BTreeMap iteration so emit order is deterministic per run
        // (helps testing + makes the section sidebar feel stable).
        let mut categories: Vec<(String, Vec<CategoryFile>)> =
            std::mem::take(&mut ctx.categories).into_iter().collect();
        categories.sort_by(|a, b| a.0.cmp(&b.0));

        for (category, files) in categories {
            dispatch_category(&category, &files, &mut ctx);
        }

        // Phase 3: synthesize the bio (subscriber info + NoRecords + bundle
        // sources) once everything else has been emitted.
        emit_bio(&mut ctx);

        // Phase 4: emit unlinked media (mbox attachments not already tied
        // to an email item) as standalone photos so the gallery sees them.
        // Already handled inline by the mbox parser — see emit_email_item.

        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let case = WarrantCase {
            case_id: Uuid::new_v4().to_string(),
            provider: Provider::Google,
            provider_display: "Google".to_string(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.account_email.clone().or(ctx.account_id.clone()),
            date_range: ctx.date_range.clone(),
            generated_at_source: ctx.export_generated_at.clone(),
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
                name: "Email of Interest".into(),
                color: "#EA4335".into(),
                description: None,
            },
            BucketTemplate {
                name: "Search History".into(),
                color: "#4285F4".into(),
                description: None,
            },
            BucketTemplate {
                name: "Location".into(),
                color: "#34A853".into(),
                description: None,
            },
            BucketTemplate {
                name: "Drive Content".into(),
                color: "#FBBC04".into(),
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

// ─── Internal data model ────────────────────────────────────────────────

/// One file collected during phase 1.  We hold the bytes in memory for
/// small files and an absolute path for large ones (e.g. multi-GB mbox).
#[derive(Debug)]
struct CategoryFile {
    /// path relative to its inner-zip / Takeout-service root, e.g.
    /// `Google Account/SubscriberInfo.html`, `Mail/All mail.mbox`,
    /// `Records.json`.
    rel_path: String,
    bytes: Vec<u8>,
}

/// Accumulator passed through every parse phase.
struct ParseCtx {
    media_dir: PathBuf,
    items: Vec<WarrantItem>,
    id_seq: HashMap<&'static str, usize>,

    /// Service.Resource → list of files belonging to that category.
    /// Populated in phase 1 (collect_from_*).
    categories: BTreeMap<String, Vec<CategoryFile>>,

    /// Account identifiers parsed from inner-zip names or SubscriberInfo.
    account_email: Option<String>,
    account_id: Option<String>,

    /// Best-known date range string (from ExportSummary "End of date range").
    date_range: Option<String>,
    export_generated_at: Option<String>,

    /// Master-bundle filenames seen (for the bio).
    bundle_sources: Vec<String>,

    /// Services that returned `NoRecords.txt` — surfaced in the bio so the
    /// investigator can see "we asked Google for this and they returned
    /// nothing", which is forensically meaningful.
    no_records: Vec<String>,

    /// Files skipped during collection because they exceeded
    /// `MAX_INMEM_FILE_BYTES` (e.g. multi-GB media volumes on huge returns).
    /// Surfaced in the bio so the investigator knows they exist on disk.
    skipped_large: Vec<String>,

    /// Count of bulk media (photos/videos) written to the case media dir.
    /// Capped at `MAX_MEDIA_EXTRACT` so an enormous return can't fill disk.
    media_written: usize,

    /// Subscriber-info struct, populated as we encounter SubscriberInfo.html.
    /// Bio is emitted at the end so it lists no-records categories too.
    subscriber: Option<SubscriberInfo>,
    hangouts_user: Option<HangoutsUserInfo>,
    chat_user: Option<HashMap<String, String>>,
}

impl ParseCtx {
    fn new(media_dir: &Path) -> Self {
        Self {
            media_dir: media_dir.to_path_buf(),
            items: Vec::new(),
            id_seq: HashMap::new(),
            categories: BTreeMap::new(),
            account_email: None,
            account_id: None,
            date_range: None,
            export_generated_at: None,
            bundle_sources: Vec::new(),
            no_records: Vec::new(),
            skipped_large: Vec::new(),
            media_written: 0,
            subscriber: None,
            hangouts_user: None,
            chat_user: None,
        }
    }

    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:05}", prefix, *n)
    }

    fn push(&mut self, item: WarrantItem) {
        self.items.push(item);
    }

    /// Reserve one slot in the bulk-media budget.  Returns true if we may
    /// still write media to disk, false once the cap is reached.
    fn media_budget_ok(&mut self) -> bool {
        if self.media_written >= MAX_MEDIA_EXTRACT {
            return false;
        }
        self.media_written += 1;
        true
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriberInfo {
    account_id: Option<String>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    alternate_emails: Option<String>,
    created_on: Option<String>,
    tos_ip: Option<String>,
    tos_lang: Option<String>,
    birthday: Option<String>,
    services: Option<String>,
    unregistered_services: Option<String>,
    deletion_date: Option<String>,
    deletion_ip: Option<String>,
    end_of_service: Option<String>,
    status: Option<String>,
    last_updated: Option<String>,
    last_logins: Option<String>,
    contact_email: Option<String>,
    recovery_email: Option<String>,
    recovery_sms: Option<String>,
    user_phones: Option<String>,
    twostep_phones: Option<String>,
    /// Each entry: timestamp, ip, type, android_id, apple_idfv, user_agents
    ip_activity: Vec<IpActivityRow>,
    devices: Vec<HashMap<String, String>>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IpActivityRow {
    timestamp: Option<String>,
    ip: Option<String>,
    activity_type: Option<String>,
    android_id: Option<String>,
    apple_idfv: Option<String>,
    user_agents: Option<String>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HangoutsUserInfo {
    display_name: Option<String>,
    first_name: Option<String>,
    emails: Option<String>,
    location: Option<String>,
    organization: Option<String>,
    role: Option<String>,
    gender: Option<String>,
    photo_url: Option<String>,
    user_type: Option<String>,
    is_known_minor: Option<String>,
}

// ─── Phase 1: collect categories ────────────────────────────────────────

fn collect_from_zip(path: &Path, ctx: &mut ParseCtx) -> Result<(), ParseError> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;

    // Snapshot the top-level entries to find master-bundle WRAPPER zips
    // ({digits}-{date}-{N}.zip) that themselves contain the return.  All
    // other layouts (root-level per-service inner zips, resource DIRECTORIES,
    // Takeout tree) are handled by collect_bundle_archive below.
    let mut master_bundles: Vec<String> = Vec::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let basename = name.rsplit('/').next().unwrap_or(&name).to_string();
        if name.to_lowercase().ends_with(".zip") && is_master_bundle_filename(&basename) {
            master_bundles.push(name);
        }
    }

    let mut seen_inner: HashSet<String> = HashSet::new();

    // Root-level content first (per-service inner zips + resource directories
    // + Takeout tree), so it takes priority over duplicates inside bundles.
    collect_bundle_archive(&mut zip, ctx, &mut seen_inner)?;

    // Then any master-bundle wrapper zips.
    for nm in &master_bundles {
        let basename = nm.rsplit('/').next().unwrap_or(nm).to_string();
        ctx.bundle_sources
            .push(basename.trim_end_matches(".zip").to_string());
        if let Err(e) = process_master_bundle(&mut zip, nm, ctx, &mut seen_inner) {
            eprintln!("[google] master-bundle error {}: {}", nm, e);
        }
    }

    Ok(())
}

fn process_inner_zip<R: std::io::Read + std::io::Seek>(
    outer: &mut ZipArchive<R>,
    inner_name: &str,
    ctx: &mut ParseCtx,
) -> Result<(), ParseError> {
    // Reading a nested zip requires Seek, so we must buffer it in memory.
    // Guard against multi-GB volumes on huge returns — skip + record instead
    // of OOMing.  (The directory-in-bundle layout used by large returns does
    // not hit this path.)
    let inner_size = outer.by_name(inner_name).map(|e| e.size()).unwrap_or(0);
    if inner_size > MAX_INMEM_FILE_BYTES {
        ctx.skipped_large.push(inner_name.to_string());
        return Ok(());
    }
    // Read inner zip bytes from outer.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut entry = outer.by_name(inner_name)?;
        entry.read_to_end(&mut buf)?;
    }

    // Identify Service.Resource from filename.
    let basename = inner_name.rsplit('/').next().unwrap_or(inner_name);
    let (email, acct_id, category) = parse_lers_filename(basename).ok_or_else(|| {
        ParseError::Other(format!(
            "could not parse Service.Resource from inner zip name: {}",
            basename
        ))
    })?;
    if ctx.account_email.is_none() {
        ctx.account_email = Some(email.clone());
    }
    if ctx.account_id.is_none() {
        ctx.account_id = Some(acct_id.clone());
    }

    let inner_zip = ZipArchive::new(std::io::Cursor::new(buf));
    let mut inner_zip = match inner_zip {
        Ok(z) => z,
        Err(_) => return Ok(()),
    };

    let mut had_norecords = false;
    let mut files: Vec<CategoryFile> = Vec::new();
    for i in 0..inner_zip.len() {
        let mut e = inner_zip.by_index(i)?;
        if e.is_dir() {
            continue;
        }
        let name = e.name().to_string();
        let lower = name.to_lowercase();
        if lower.ends_with("norecords.txt") {
            had_norecords = true;
            continue;
        }
        if e.size() > MAX_INMEM_FILE_BYTES {
            if lower.ends_with(".mbox") {
                stream_mbox_reader(std::io::BufReader::new(e), ctx);
            } else {
                ctx.skipped_large.push(format!("{}/{}", basename, name));
            }
            continue;
        }
        let mut bytes = Vec::new();
        e.read_to_end(&mut bytes)?;

        if lower.ends_with("exportsummary.txt") {
            // Update date_range etc., do NOT push as a category file.
            if let Ok(s) = std::str::from_utf8(&bytes) {
                ingest_export_summary(s, ctx);
            }
            continue;
        }

        files.push(CategoryFile {
            rel_path: name,
            bytes,
        });
    }

    if had_norecords && files.is_empty() {
        if !ctx.no_records.contains(&category) {
            ctx.no_records.push(category);
        }
    } else if !files.is_empty() {
        ctx.categories.entry(category).or_default().extend(files);
    }

    Ok(())
}

fn process_master_bundle<R: std::io::Read + std::io::Seek>(
    outer: &mut ZipArchive<R>,
    bundle_name: &str,
    ctx: &mut ParseCtx,
    seen: &mut HashSet<String>,
) -> Result<(), ParseError> {
    // Read bundle bytes from outer.  (This variant only runs for a bundle
    // NESTED inside another picked zip — rare.  The common case, a folder of
    // bundle volumes on disk, is streamed from disk in collect_from_dir.)
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut entry = outer.by_name(bundle_name)?;
        entry.read_to_end(&mut buf)?;
    }
    let mut bundle = match ZipArchive::new(std::io::Cursor::new(buf)) {
        Ok(z) => z,
        Err(_) => return Ok(()),
    };
    collect_bundle_archive(&mut bundle, ctx, seen)
}

/// Commit a resource's collected files to ctx, applying NoRecords routing.
fn commit_resource(
    category: String,
    files: Vec<CategoryFile>,
    had_norecords: bool,
    ctx: &mut ParseCtx,
) {
    if had_norecords && files.is_empty() {
        if !ctx.no_records.contains(&category) {
            ctx.no_records.push(category);
        }
    } else if !files.is_empty() {
        ctx.categories.entry(category).or_default().extend(files);
    }
}

/// Process every entry inside a master-bundle archive.  Handles all three
/// on-the-wire layouts Google uses inside a `{num}-{date}-{N}.zip` volume:
///   1. nested per-service LERS zips     ({lers}_NNN.zip)
///   2. per-service resource DIRECTORIES  ({lers}_NNN/<service>/<files>)  ← large returns
///   3. a Takeout/ tree
/// Multi-GB leaf files (bulk media, giant mbox) above MAX_INMEM_FILE_BYTES
/// are skipped (recorded in ctx.skipped_large) so a 300 GB+ return can't OOM.
fn collect_bundle_archive<R: std::io::Read + std::io::Seek>(
    bundle: &mut ZipArchive<R>,
    ctx: &mut ParseCtx,
    seen: &mut HashSet<String>,
) -> Result<(), ParseError> {
    // Snapshot entry names up-front so we can group before reading bytes.
    let mut nested_zips: Vec<String> = Vec::new();
    let mut dir_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut takeout_files: Vec<String> = Vec::new();

    for i in 0..bundle.len() {
        let e = bundle.by_index(i)?;
        if e.is_dir() {
            continue;
        }
        let name = e.name().to_string();
        let lower = name.to_lowercase();

        if lower.ends_with(".zip") && is_lers_inner_zip(&name) {
            nested_zips.push(name);
            continue;
        }
        if name.contains("Takeout/") {
            takeout_files.push(name);
            continue;
        }
        let first_seg = name.split('/').next().unwrap_or(&name).to_string();
        if name.contains('/') && is_lers_dir_name(&first_seg) {
            dir_groups.entry(first_seg).or_default().push(name);
        }
    }

    // Layout 1 — nested LERS zips.
    for nm in &nested_zips {
        let basename = nm.rsplit('/').next().unwrap_or(nm).to_string();
        if !seen.insert(basename.clone()) {
            continue;
        }
        if let Err(e) = process_inner_zip(bundle, nm, ctx) {
            eprintln!("[google] bundle inner zip error {}: {}", nm, e);
        }
    }

    // Layout 2 — resource directories.
    for (seg, entries) in dir_groups {
        if !seen.insert(seg.clone()) {
            continue;
        }
        let (email, acct_id, category) = match parse_lers_name(&seg) {
            Some(t) => t,
            None => continue,
        };
        if ctx.account_email.is_none() {
            ctx.account_email = Some(email);
        }
        if ctx.account_id.is_none() {
            ctx.account_id = Some(acct_id);
        }
        let prefix = format!("{}/", seg);
        let mut files: Vec<CategoryFile> = Vec::new();
        let mut had_norecords = false;
        for nm in &entries {
            let rel = nm.strip_prefix(&prefix).unwrap_or(nm).to_string();
            let lower = rel.to_lowercase();
            if lower.ends_with("norecords.txt") {
                had_norecords = true;
                continue;
            }
            // Size-gate before reading so we never buffer a multi-GB volume.
            let size = bundle.by_name(nm).map(|e| e.size()).unwrap_or(0);
            if size > MAX_INMEM_FILE_BYTES {
                // A giant mbox is still evidence — stream it one message at a
                // time instead of skipping.  Other large binaries are skipped.
                if lower.ends_with(".mbox") {
                    if let Ok(entry) = bundle.by_name(nm) {
                        stream_mbox_reader(std::io::BufReader::new(entry), ctx);
                    }
                } else {
                    ctx.skipped_large.push(nm.clone());
                }
                continue;
            }
            let mut bytes = Vec::new();
            {
                let mut e = bundle.by_name(nm)?;
                e.read_to_end(&mut bytes)?;
            }
            if lower.ends_with("exportsummary.txt") {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    ingest_export_summary(s, ctx);
                }
                continue;
            }
            files.push(CategoryFile { rel_path: rel, bytes });
        }
        commit_resource(category, files, had_norecords, ctx);
    }

    // Layout 3 — Takeout tree inside the bundle.
    if !takeout_files.is_empty() {
        process_takeout_in_zip(bundle, &takeout_files, ctx)?;
    }

    Ok(())
}

/// Collect extracted resource directories ({lers}_NNN/) sitting directly
/// under `root` — i.e. a return that was already unzipped to a folder.
fn collect_extracted_resource_dirs(
    root: &Path,
    ctx: &mut ParseCtx,
    seen: &mut HashSet<String>,
) -> Result<(), ParseError> {
    let rd = match fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let dname = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !is_lers_dir_name(&dname) {
            continue;
        }
        if !seen.insert(dname.clone()) {
            continue;
        }
        let (email, acct_id, category) = match parse_lers_name(&dname) {
            Some(t) => t,
            None => continue,
        };
        if ctx.account_email.is_none() {
            ctx.account_email = Some(email);
        }
        if ctx.account_id.is_none() {
            ctx.account_id = Some(acct_id);
        }
        let mut files: Vec<CategoryFile> = Vec::new();
        let mut had_norecords = false;
        for f in walkdir_safe(&p, 8) {
            if !f.is_file() {
                continue;
            }
            let rel = f
                .strip_prefix(&p)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            let lower = rel.to_lowercase();
            if lower.ends_with("norecords.txt") {
                had_norecords = true;
                continue;
            }
            let size = fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
            if size > MAX_INMEM_FILE_BYTES {
                if lower.ends_with(".mbox") {
                    if let Ok(fh) = File::open(&f) {
                        stream_mbox_reader(std::io::BufReader::new(fh), ctx);
                    }
                } else {
                    ctx.skipped_large.push(rel);
                }
                continue;
            }
            let bytes = match fs::read(&f) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if lower.ends_with("exportsummary.txt") {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    ingest_export_summary(s, ctx);
                }
                continue;
            }
            files.push(CategoryFile { rel_path: rel, bytes });
        }
        commit_resource(category, files, had_norecords, ctx);
    }
    Ok(())
}



fn process_takeout_in_zip<R: std::io::Read + std::io::Seek>(
    outer: &mut ZipArchive<R>,
    names: &[String],
    ctx: &mut ParseCtx,
) -> Result<(), ParseError> {
    // Read each entry, route to a Service.Resource based on the Takeout
    // sub-folder name.
    for n in names {
        let mut entry = outer.by_name(n)?;
        if entry.is_dir() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        let category = takeout_category_from_path(n);
        if let Some(cat) = category {
            // rel_path = portion AFTER the Takeout/<Service>/ prefix.
            let rel = trim_takeout_prefix(n);
            ctx.categories.entry(cat).or_default().push(CategoryFile {
                rel_path: rel,
                bytes,
            });
        }
    }
    Ok(())
}

fn collect_from_dir(root: &Path, ctx: &mut ParseCtx) -> Result<(), ParseError> {
    // Two flavours of folder input:
    //  - a folder containing per-service inner zips (extracted warrant return)
    //  - a Takeout export folder ("Takeout/...")
    // We auto-detect.
    let mut takeout_root: Option<PathBuf> = None;
    for entry in walkdir_safe(root, 3) {
        let name_lower = entry
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if entry.is_dir() && name_lower == "takeout" {
            takeout_root = Some(entry.clone());
            break;
        }
    }

    if let Some(tk) = takeout_root {
        collect_takeout_dir(&tk, ctx)?;
        return Ok(());
    }

    // Else: walk for *.zip inner zips and process them like the in-zip case.
    let mut seen_inner: HashSet<String> = HashSet::new();

    // First, pick up any resource directories that were already extracted
    // directly under the folder ({lers}_NNN/<service>/<files>). This covers
    // a return the agency unzipped to disk before importing.
    collect_extracted_resource_dirs(root, ctx, &mut seen_inner)?;

    for entry in walkdir_safe(root, 4) {
        if !entry.is_file() {
            continue;
        }
        let name = entry.file_name().unwrap_or_default().to_string_lossy().to_string();
        let lower = name.to_lowercase();
        if !lower.ends_with(".zip") {
            continue;
        }
        if is_master_bundle_filename(&name) {
            // Open and recurse through bundle on disk (streamed, not buffered).
            let f = match File::open(&entry) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut bundle = match ZipArchive::new(f) {
                Ok(z) => z,
                Err(_) => continue,
            };
            ctx.bundle_sources.push(name.trim_end_matches(".zip").to_string());
            if let Err(e) = collect_bundle_archive(&mut bundle, ctx, &mut seen_inner) {
                eprintln!("[google] bundle-on-disk error {}: {}", name, e);
            }
            continue;
        }
        if !is_lers_inner_zip(&name) {
            continue;
        }
        if !seen_inner.insert(name.clone()) {
            continue;
        }

        // Process inner zip on disk.
        let f = match File::open(&entry) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut inner_zip = match ZipArchive::new(f) {
            Ok(z) => z,
            Err(_) => continue,
        };
        let (email, acct_id, category) = match parse_lers_filename(&name) {
            Some(t) => t,
            None => continue,
        };
        if ctx.account_email.is_none() {
            ctx.account_email = Some(email);
        }
        if ctx.account_id.is_none() {
            ctx.account_id = Some(acct_id);
        }

        let mut had_norecords = false;
        let mut files: Vec<CategoryFile> = Vec::new();
        for i in 0..inner_zip.len() {
            let mut e = inner_zip.by_index(i)?;
            if e.is_dir() {
                continue;
            }
            let rel = e.name().to_string();
            let lower2 = rel.to_lowercase();
            if lower2.ends_with("norecords.txt") {
                had_norecords = true;
                continue;
            }
            if e.size() > MAX_INMEM_FILE_BYTES {
                if lower2.ends_with(".mbox") {
                    stream_mbox_reader(std::io::BufReader::new(e), ctx);
                } else {
                    ctx.skipped_large.push(format!("{}/{}", name, rel));
                }
                continue;
            }
            let mut bytes = Vec::new();
            e.read_to_end(&mut bytes)?;
            if lower2.ends_with("exportsummary.txt") {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    ingest_export_summary(s, ctx);
                }
                continue;
            }
            files.push(CategoryFile { rel_path: rel, bytes });
        }

        if had_norecords && files.is_empty() {
            if !ctx.no_records.contains(&category) {
                ctx.no_records.push(category);
            }
        } else if !files.is_empty() {
            ctx.categories.entry(category).or_default().extend(files);
        }
    }

    Ok(())
}

fn collect_takeout_dir(root: &Path, ctx: &mut ParseCtx) -> Result<(), ParseError> {
    for entry in walkdir_safe(root, 8) {
        if !entry.is_file() {
            continue;
        }
        let rel = entry.strip_prefix(root).unwrap_or(&entry);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let category = match takeout_category_from_path(&rel_str) {
            Some(c) => c,
            None => continue,
        };
        let bytes = match fs::read(&entry) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let rel_after_service = trim_takeout_prefix(&rel_str);
        ctx.categories.entry(category).or_default().push(CategoryFile {
            rel_path: rel_after_service,
            bytes,
        });
    }
    Ok(())
}

fn walkdir_safe(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn recurse(p: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
        if depth > max_depth {
            return;
        }
        let rd = match fs::read_dir(p) {
            Ok(r) => r,
            Err(_) => return,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            out.push(path.clone());
            if path.is_dir() {
                recurse(&path, depth + 1, max_depth, out);
            }
        }
    }
    recurse(root, 0, max_depth, &mut out);
    out
}

// ─── Category dispatch ──────────────────────────────────────────────────

fn dispatch_category(category: &str, files: &[CategoryFile], ctx: &mut ParseCtx) {
    match category {
        "GoogleAccount.SubscriberInfo" => handle_subscriber_info(files, ctx),
        "GoogleAccount.ChangeHistory" => handle_change_history(files, ctx),
        "Mail.MessageContent" | "Mail.Messages" | "Gmail.Messages" => {
            handle_mbox(files, ctx);
        }
        "Mail.MessageInformation" => handle_mail_metadata(files, ctx),
        "Mail.UserSettings" => handle_generic_fallback(category, files, ctx),
        "LocationHistory.Records" => handle_location_records(files, ctx),
        "LocationHistory.SemanticLocationHistory" => handle_semantic_location(files, ctx),
        "LocationHistory.Tombstones" => handle_generic_fallback(category, files, ctx),
        "GooglePlayStore.Devices" => handle_play_devices(files, ctx),
        "GooglePlayStore.Installs" => handle_play_installs(files, ctx),
        "GooglePlayStore.Library" => handle_play_library(files, ctx),
        "GooglePlayStore.UserActivity" => handle_play_user_activity(files, ctx),
        "GooglePlayStore.UserPreferences" => handle_play_user_preferences(files, ctx),
        "GooglePlayStore.OrderHistory"
        | "GooglePlayStore.PurchaseHistory"
        | "GooglePlayStore.RefundRecords"
        | "GooglePlayStore.Subscription"
        | "GooglePlayStore.Loyalty"
        | "GooglePlayStore.PromotionHistory"
        | "GooglePlayStore.UserReviews" => handle_generic_fallback(category, files, ctx),
        "GoogleChat.Messages" => handle_chat_messages(files, ctx),
        "GoogleChat.UserInfo" => handle_chat_user_info(files, ctx),
        "GoogleChat.GroupInfo" => handle_chat_group_info(files, ctx),
        "GoogleChat.GroupTasks" => handle_generic_fallback(category, files, ctx),
        "Hangouts.ContentAndMetadata" => handle_hangouts(files, ctx),
        "AccessLogActivity.Activity"
        | "AccessLogActivity.Devices"
        | "AccessLogActivity.AggregatedActivities" => handle_access_log(category, files, ctx),
        _ => {
            // Catch-all for Google Photos / Drive (covers both LERS variants
            // like `GooglePhotos.Photos`, `Drive.Files`, `GoogleDrive.Files`
            // and Takeout `GooglePhotos.Takeout` / `Drive.Takeout`).
            if category.starts_with("GooglePhotos") {
                handle_google_photos(category, files, ctx);
            } else if category.starts_with("GoogleDrive") || category.starts_with("Drive") {
                handle_google_drive(category, files, ctx);
            } else {
                handle_generic_fallback(category, files, ctx);
            }
        }
    }
}

// ─── Subscriber Info ────────────────────────────────────────────────────

fn handle_subscriber_info(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".html") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let mut sub = parse_subscriber_html(&text);

        // Push the IP activity straight into items (`ip_addresses`).
        let rows = std::mem::take(&mut sub.ip_activity);
        for row in rows {
            let mut raw = serde_json::Map::new();
            if let Some(v) = &row.timestamp {
                raw.insert("timestamp".into(), Value::String(v.clone()));
            }
            if let Some(v) = &row.ip {
                raw.insert("ip".into(), Value::String(v.clone()));
            }
            if let Some(v) = &row.activity_type {
                raw.insert("activityType".into(), Value::String(v.clone()));
            }
            if let Some(v) = &row.android_id {
                raw.insert("androidId".into(), Value::String(v.clone()));
            }
            if let Some(v) = &row.apple_idfv {
                raw.insert("appleIdfv".into(), Value::String(v.clone()));
            }
            if let Some(v) = &row.user_agents {
                raw.insert("userAgents".into(), Value::String(v.clone()));
            }
            raw.insert("source".into(), json!("SubscriberInfo"));
            let id = ctx.next_id("ip");
            ctx.push(WarrantItem {
                id,
                section: "ip_addresses".into(),
                section_display: "IP Addresses".into(),
                timestamp: row.timestamp.clone(),
                author: row.activity_type.clone(),
                recipient: None,
                body_text: row.ip.clone(),
                summary: Some(format!(
                    "{} — {}",
                    row.activity_type.clone().unwrap_or_else(|| "Login".into()),
                    row.ip.clone().unwrap_or_default()
                )),
                raw_fields: Value::Object(raw),
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }

        // Subscriber struct lives in ctx; bio is emitted at the very end so
        // we can fold in NoRecords + bundle list.
        ctx.subscriber = Some(sub);
    }
}

fn parse_subscriber_html(html: &str) -> SubscriberInfo {
    let mut s = SubscriberInfo::default();
    let doc = Html::parse_document(html);

    // The Google SubscriberInfo file is a flat <li>label: value</li> list.
    let li_sel = Selector::parse("li").unwrap();
    for li in doc.select(&li_sel) {
        let text = li.text().collect::<Vec<_>>().join(" ").trim().to_string();
        if text.is_empty() {
            continue;
        }
        let (k, v) = match text.split_once(':') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => continue,
        };
        let kl = k.to_lowercase();
        let val = if v.is_empty() { None } else { Some(v) };
        match kl.as_str() {
            "google account id" => s.account_id = val,
            "name" => s.name = val,
            "given name" => s.given_name = val,
            "family name" => s.family_name = val,
            "e-mail" => s.email = val,
            "alternate e-mails" => s.alternate_emails = val,
            "created on" => s.created_on = val,
            "terms of service ip" => s.tos_ip = val,
            "terms of service language" => s.tos_lang = val,
            "birthday (month day, year)" => s.birthday = val,
            "services" => s.services = val,
            "unregistered services" => s.unregistered_services = val,
            "deletion date" => s.deletion_date = val,
            "deletion ip" => s.deletion_ip = val,
            "end of service date" => s.end_of_service = val,
            "status" => s.status = val,
            "last updated date" => s.last_updated = val,
            "last logins" => s.last_logins = val,
            "contact e-mail" => s.contact_email = val,
            "recovery e-mail" => s.recovery_email = val,
            "recovery sms" => s.recovery_sms = val,
            "user phone numbers" => s.user_phones = val,
            "2-step verification phone numbers" => s.twostep_phones = val,
            _ => {}
        }
    }

    // IP Activity table
    let table_sel = Selector::parse("table").unwrap();
    let tr_sel = Selector::parse("tr").unwrap();
    let th_sel = Selector::parse("th").unwrap();
    let td_sel = Selector::parse("td").unwrap();
    for table in doc.select(&table_sel) {
        let headers: Vec<String> = table
            .select(&th_sel)
            .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_lowercase())
            .collect();
        // Identify IP-activity table by its column names.
        let has_ip = headers
            .iter()
            .any(|h| h.contains("ip address") || h == "ip");
        let has_activity_type = headers.iter().any(|h| h.contains("activity type"));
        if !(has_ip && has_activity_type) {
            continue;
        }
        for tr in table.select(&tr_sel) {
            let tds: Vec<String> = tr
                .select(&td_sel)
                .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                .collect();
            if tds.is_empty() {
                continue;
            }
            let mut row = IpActivityRow::default();
            for (i, h) in headers.iter().enumerate() {
                let val = tds.get(i).cloned().unwrap_or_default();
                if val.is_empty() {
                    continue;
                }
                if h.contains("timestamp") {
                    row.timestamp = Some(val);
                } else if h.contains("ip") {
                    row.ip = Some(val);
                } else if h.contains("activity") {
                    row.activity_type = Some(val);
                } else if h.contains("android") {
                    row.android_id = Some(val);
                } else if h.contains("idfv") || h.contains("apple") {
                    row.apple_idfv = Some(val);
                } else if h.contains("user agent") {
                    row.user_agents = Some(val);
                }
            }
            if row.timestamp.is_some() || row.ip.is_some() {
                s.ip_activity.push(row);
            }
        }
    }

    s
}

// ─── Change History ─────────────────────────────────────────────────────

fn handle_change_history(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".html") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let rows = parse_change_history_html(&text);
        for r in rows {
            let id = ctx.next_id("chg");
            let ts = r.get("Timestamp").cloned();
            let change_type = r.get("Change Type").cloned();
            let new_val = r.get("New Value").cloned();
            let old_val = r.get("Old Value").cloned();
            let summary = format!(
                "{} {}",
                change_type.clone().unwrap_or_else(|| "Change".into()),
                new_val.clone().unwrap_or_default()
            );
            ctx.push(WarrantItem {
                id,
                section: "change_history".into(),
                section_display: "Account Change History".into(),
                timestamp: ts.clone(),
                author: change_type,
                recipient: None,
                body_text: Some(format!(
                    "Old: {}\nNew: {}",
                    old_val.clone().unwrap_or_default(),
                    new_val.clone().unwrap_or_default()
                )),
                summary: Some(summary),
                raw_fields: serde_json::to_value(&r).unwrap_or(Value::Null),
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn parse_change_history_html(html: &str) -> Vec<HashMap<String, String>> {
    parse_first_html_table(html)
}

// ─── Generic HTML table parser ──────────────────────────────────────────

fn parse_first_html_table(html: &str) -> Vec<HashMap<String, String>> {
    let doc = Html::parse_document(html);
    let table_sel = Selector::parse("table").unwrap();
    let tr_sel = Selector::parse("tr").unwrap();
    let th_sel = Selector::parse("th").unwrap();
    let td_sel = Selector::parse("td").unwrap();
    let mut out = Vec::new();
    for table in doc.select(&table_sel) {
        let headers: Vec<String> = table
            .select(&th_sel)
            .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
            .collect();
        if headers.is_empty() {
            continue;
        }
        for tr in table.select(&tr_sel) {
            let tds: Vec<String> = tr
                .select(&td_sel)
                .map(|el| el.text().collect::<Vec<_>>().join(" ").trim().to_string())
                .collect();
            if tds.is_empty() {
                continue;
            }
            let mut row = HashMap::new();
            for (i, h) in headers.iter().enumerate() {
                row.insert(h.clone(), tds.get(i).cloned().unwrap_or_default());
            }
            out.push(row);
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

// ─── MBOX ───────────────────────────────────────────────────────────────

fn handle_mbox(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".mbox") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes).into_owned();
        let raw_messages = split_mbox(&text);
        for raw in raw_messages {
            let parsed = parse_email_message(&raw);
            emit_email_item(parsed, ctx);
        }
    }
}

/// Stream an mbox from a reader, emitting one email item per message without
/// ever holding the whole mailbox in memory.  Used for multi-GB mbox spills
/// on very large returns where buffering the whole file would OOM.  Mirrors
/// `mbox_lib::split_mbox` semantics (envelope `From ` lines delimit messages).
fn stream_mbox_reader<R: std::io::BufRead>(reader: R, ctx: &mut ParseCtx) {
    let mut current = String::new();
    let mut started = false;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.starts_with("From ") {
            if started && !current.is_empty() {
                let parsed = parse_email_message(&current);
                emit_email_item(parsed, ctx);
                current.clear();
            }
            started = true;
            continue;
        }
        if started {
            current.push_str(&line);
            current.push('\n');
        }
    }
    if started && !current.is_empty() {
        let parsed = parse_email_message(&current);
        emit_email_item(parsed, ctx);
    }
}

// MBOX / RFC822 utilities (extracted to providers::mbox_lib so Yahoo
// — and any future email-bearing provider — can share the same parser).
use super::mbox_lib::{split_mbox, parse_email_message, EmailMsg};

fn emit_email_item(msg: EmailMsg, ctx: &mut ParseCtx) {
    let id = ctx.next_id("email");

    // Write attachments to media dir, return relative filenames.
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

                // Also emit images/videos as their own `photos` items so the
                // gallery sees them (the chip on the email tile still works).
                let lower = fname.to_lowercase();
                if IMAGE_EXTS.iter().any(|e| lower.ends_with(e))
                    || VIDEO_EXTS.iter().any(|e| lower.ends_with(e))
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

    let received_ips_clone = msg.received_ips.clone();
    let raw = json!({
        "from": msg.from,
        "to": msg.to,
        "cc": msg.cc,
        "bcc": msg.bcc,
        "subject": msg.subject,
        "date": msg.date,
        "messageId": msg.message_id,
        "labels": msg.labels,
        "receivedIps": received_ips_clone,
        "attachments": attachment_meta,
    });

    let summary = format!(
        "{} — {}",
        raw.get("from")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown sender)"),
        raw.get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("(no subject)"),
    );

    ctx.items.push(WarrantItem {
        id,
        section: "emails".into(),
        section_display: "Emails".into(),
        timestamp: raw.get("date").and_then(|v| v.as_str()).map(String::from),
        author: raw.get("from").and_then(|v| v.as_str()).map(String::from),
        recipient: raw.get("to").and_then(|v| v.as_str()).map(String::from),
        body_text: None, // populated below to avoid clone juggle
        summary: Some(summary),
        raw_fields: raw,
        attachments: attachment_files,
        bucket: None,
        note: None,
        is_flagged: false,
    });
    // Now set body separately so we don't have to clone msg above.
    if let Some(it) = ctx.items.last_mut() {
        it.body_text = msg.body_text;
    }
}

fn sanitize_filename(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.len() > 100 {
        out.truncate(100);
    }
    if out.is_empty() {
        out = "attachment.bin".to_string();
    }
    out
}

// ─── Mail.MessageInformation (per-message JSON) ─────────────────────────

fn handle_mail_metadata(files: &[CategoryFile], ctx: &mut ParseCtx) {
    // Per-message JSON files keyed by `item_key.server_id`.  We surface
    // them as a single rolled-up dump in raw_fields rather than spamming
    // the sidebar — investigators rarely care about the SMTP session IDs
    // for every message.
    let mut count = 0;
    let mut samples: Vec<Value> = Vec::new();
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".json") {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&f.bytes) {
            if let Ok(v) = serde_json::from_str::<Value>(s) {
                count += 1;
                if samples.len() < 20 {
                    samples.push(v);
                }
            }
        }
    }
    if count == 0 {
        return;
    }
    let id = ctx.next_id("mailmeta");
    ctx.push(WarrantItem {
        id,
        section: "request_parameters".into(),
        section_display: "Mail Metadata".into(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(format!(
            "{} Mail.MessageInformation JSON files in the production. \
             First 20 shown in rawFields.",
            count
        )),
        summary: Some(format!("Mail Metadata ({} files)", count)),
        raw_fields: json!({
            "totalFiles": count,
            "samples": samples,
        }),
        attachments: vec![],
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

// ─── Play Store CSVs ────────────────────────────────────────────────────

fn handle_play_devices(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".csv") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let rows = csv_rows(&text);
        for r in rows {
            let id = ctx.next_id("dev");
            let model = r.get("Device Attribute Model").cloned().or_else(|| {
                extract_kv_value(r.get("Hardware Info").cloned().unwrap_or_default(), "model_name")
            });
            let manufacturer = r
                .get("Device Attribute Manufacturer")
                .cloned()
                .or_else(|| {
                    extract_kv_value(
                        r.get("Most Recent Data").cloned().unwrap_or_default(),
                        "manufacturer",
                    )
                });
            let android_id = r.get("Android Id").cloned();
            let last_active = r.get("Last Time Device Active").cloned();
            let summary = format!(
                "{} {} (Android ID {})",
                manufacturer.clone().unwrap_or_default(),
                model.clone().unwrap_or_default(),
                android_id.clone().unwrap_or_default()
            );
            ctx.push(WarrantItem {
                id,
                section: "device_info".into(),
                section_display: "Devices".into(),
                timestamp: last_active,
                author: None,
                recipient: None,
                body_text: Some(format!(
                    "Most Recent Data:\n{}",
                    r.get("Most Recent Data").cloned().unwrap_or_default()
                )),
                summary: Some(summary),
                raw_fields: serde_json::to_value(&r).unwrap_or(Value::Null),
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

/// Truncate a string to at most `max_chars` characters, appending an
/// ellipsis when shortened.  Char-safe: never slices on a byte index, so it
/// cannot panic on multibyte UTF-8 (emoji / accented text).
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}

fn extract_kv_value(blob: String, key: &str) -> Option<String> {
    // Protobuf-text-ish blob:   `key: "value"`
    let needle = format!("{}: \"", key);
    if let Some(i) = blob.find(&needle) {
        let rest = &blob[i + needle.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn handle_play_installs(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".csv") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let rows = csv_rows(&text);
        for r in rows {
            let id = ctx.next_id("app");
            let title = r.get("Doc Title").cloned();
            let package = r
                .get("Package Name")
                .cloned()
                .or_else(|| r.get("Doc Backend Docid").cloned());
            let installed = r.get("First Installation Time").cloned();
            let device = r.get("Device Attribute Device Display Name").cloned();
            let summary = format!(
                "{} ({})",
                title.clone().unwrap_or_default(),
                package.clone().unwrap_or_default()
            );
            let mut raw = serde_json::to_value(&r).unwrap_or(Value::Null);
            if let Value::Object(ref mut m) = raw {
                m.insert("kind".into(), json!("install"));
            }
            ctx.push(WarrantItem {
                id,
                section: "apps".into(),
                section_display: "Apps".into(),
                timestamp: installed,
                author: device,
                recipient: None,
                body_text: package,
                summary: Some(summary),
                raw_fields: raw,
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn handle_play_library(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".csv") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let rows = csv_rows(&text);
        for r in rows {
            let id = ctx.next_id("lib");
            let title = r.get("Doc Title").cloned();
            let package = r.get("Doc Backend Docid").cloned();
            let acquisition = r.get("Acquisition Time").cloned();
            let summary = format!(
                "Library: {} ({})",
                title.clone().unwrap_or_default(),
                package.clone().unwrap_or_default()
            );
            let mut raw = serde_json::to_value(&r).unwrap_or(Value::Null);
            if let Value::Object(ref mut m) = raw {
                m.insert("kind".into(), json!("library"));
            }
            ctx.push(WarrantItem {
                id,
                section: "apps".into(),
                section_display: "Apps".into(),
                timestamp: acquisition,
                author: None,
                recipient: None,
                body_text: package,
                summary: Some(summary),
                raw_fields: raw,
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn handle_play_user_activity(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".html") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let entries = parse_my_activity_html(&text);
        for e in entries {
            let id = ctx.next_id("act");
            let summary = format!(
                "{} — {}",
                e.product.clone().unwrap_or_default(),
                e.title.clone().unwrap_or_default()
            );
            ctx.push(WarrantItem {
                id,
                section: "recently_viewed".into(),
                section_display: "Recently Viewed".into(),
                timestamp: e.when.clone(),
                author: e.product.clone(),
                recipient: None,
                body_text: e.url.clone(),
                summary: Some(summary),
                raw_fields: json!({
                    "product": e.product,
                    "title": e.title,
                    "url": e.url,
                    "timestamp": e.when,
                    "details": e.details,
                }),
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

#[derive(Debug, Default)]
struct ActivityEntry {
    product: Option<String>,
    title: Option<String>,
    url: Option<String>,
    when: Option<String>,
    details: Option<String>,
}

fn parse_my_activity_html(html: &str) -> Vec<ActivityEntry> {
    let doc = Html::parse_document(html);
    // Each activity is in `.outer-cell`.
    let cell_sel = Selector::parse(".outer-cell").unwrap();
    let mut out = Vec::new();
    for cell in doc.select(&cell_sel) {
        // Product header (e.g. "Google Play Store")
        let mut e = ActivityEntry::default();
        if let Some(h) = cell
            .select(&Selector::parse(".header-cell .mdl-typography--title").unwrap())
            .next()
        {
            e.product = Some(h.text().collect::<Vec<_>>().join(" ").trim().to_string());
        }
        // Body cells (multiple)
        let content_sel = Selector::parse(".content-cell.mdl-typography--body-1").unwrap();
        let mut body_texts: Vec<String> = Vec::new();
        let mut url: Option<String> = None;
        for content in cell.select(&content_sel) {
            let txt = content.text().collect::<Vec<_>>().join(" ").trim().to_string();
            body_texts.push(txt);
            if url.is_none() {
                if let Some(a) = content.select(&Selector::parse("a").unwrap()).next() {
                    if let Some(href) = a.value().attr("href") {
                        url = Some(href.to_string());
                    }
                }
            }
        }
        e.url = url;
        if let Some(b) = body_texts.first() {
            // First body cell usually contains "Installed <url>" + timestamp.
            // Split on "UTC" line for timestamp heuristic.
            let lines: Vec<&str> = b.split(|c| c == '\n' || c == '\r').collect();
            if !lines.is_empty() {
                e.title = Some(lines[0].trim().to_string());
            }
            // Search for timestamp pattern containing year
            for ln in &lines {
                if ln.contains("UTC") || ln.contains(", 20") {
                    e.when = Some(ln.trim().to_string());
                    break;
                }
            }
            // Fallback: regex-ish - look for "Sep 18, 2022, " inside the same string.
            if e.when.is_none() {
                if let Some(idx) = b.find(", 20") {
                    let start = b[..idx].rfind(|c: char| c == '\n' || c == ' ').unwrap_or(0);
                    e.when = Some(b[start..].trim().to_string());
                }
            }
        }
        let details_sel = Selector::parse(".content-cell.mdl-typography--caption").unwrap();
        let details = cell
            .select(&details_sel)
            .map(|c| c.text().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        if !details.is_empty() {
            e.details = Some(details);
        }
        if e.product.is_some() || e.title.is_some() {
            out.push(e);
        }
    }
    out
}

fn handle_play_user_preferences(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".csv") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let rows = csv_rows(&text);
        // UserPreferences.csv is a single very wide row of preference flags
        // — surface as one combined `settings` item.
        if rows.is_empty() {
            continue;
        }
        let id = ctx.next_id("pref");
        ctx.push(WarrantItem {
            id,
            section: "settings".into(),
            section_display: "Settings".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(format!("{} preference row(s) in Play Store UserPreferences.csv", rows.len())),
            summary: Some("Play Store User Preferences".into()),
            raw_fields: json!({ "rows": rows }),
            attachments: vec![],
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── Hangouts user_info.txt ─────────────────────────────────────────────

fn handle_hangouts(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        let lower = f.rel_path.to_lowercase();
        if !lower.ends_with("user_info.txt") {
            continue;
        }
        let text = String::from_utf8_lossy(&f.bytes);
        let info = parse_hangouts_user_info(&text);
        ctx.hangouts_user = Some(info);
    }
}

fn parse_hangouts_user_info(text: &str) -> HangoutsUserInfo {
    let mut info = HangoutsUserInfo::default();
    for line in text.lines() {
        let (k, v) = match line.split_once(':') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().to_string()),
            None => continue,
        };
        let val = if v.is_empty() { None } else { Some(v) };
        match k.as_str() {
            "display name" => info.display_name = val,
            "first name" => info.first_name = val,
            "emails" => info.emails = val,
            "user-set location (not from any location services)" => info.location = val,
            "user-set organization" => info.organization = val,
            "user-set role" => info.role = val,
            "gender" => info.gender = val,
            "photo url" => info.photo_url = val,
            "user type" => info.user_type = val,
            "is known minor" => info.is_known_minor = val,
            _ => {}
        }
    }
    info
}

// ─── Location ───────────────────────────────────────────────────────────

fn handle_location_records(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".json") {
            continue;
        }
        let s = match std::str::from_utf8(&f.bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let v: Value = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let arr = v
            .get("locations")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for loc in arr {
            let id = ctx.next_id("loc");
            let lat = loc.get("latitudeE7").and_then(|v| v.as_i64()).map(|i| i as f64 / 1e7);
            let lon = loc.get("longitudeE7").and_then(|v| v.as_i64()).map(|i| i as f64 / 1e7);
            let ts = loc.get("timestamp").and_then(|v| v.as_str()).map(String::from);
            let acc = loc.get("accuracy").and_then(|v| v.as_i64());
            let summary = format!(
                "{}, {} (±{} m)",
                lat.map(|x| format!("{:.5}", x)).unwrap_or_default(),
                lon.map(|x| format!("{:.5}", x)).unwrap_or_default(),
                acc.unwrap_or(0)
            );
            ctx.push(WarrantItem {
                id,
                section: "location".into(),
                section_display: "Location History".into(),
                timestamp: ts.clone(),
                author: None,
                recipient: None,
                body_text: None,
                summary: Some(summary),
                raw_fields: json!({
                    "latitude": lat,
                    "longitude": lon,
                    "timestamp": ts,
                    "accuracyMeters": acc,
                    "source": "LocationHistory.Records",
                }),
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn handle_semantic_location(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if !f.rel_path.to_lowercase().ends_with(".json") {
            continue;
        }
        let s = match std::str::from_utf8(&f.bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let v: Value = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let arr = v
            .get("timelineObjects")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for obj in arr {
            let id = ctx.next_id("semloc");
            let kind = if obj.get("placeVisit").is_some() {
                "placeVisit"
            } else if obj.get("activitySegment").is_some() {
                "activitySegment"
            } else {
                "unknown"
            };
            ctx.push(WarrantItem {
                id,
                section: "location".into(),
                section_display: "Location History".into(),
                timestamp: None,
                author: Some(kind.into()),
                recipient: None,
                body_text: None,
                summary: Some(format!("Semantic location ({})", kind)),
                raw_fields: obj,
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

// ─── Google Chat ────────────────────────────────────────────────────────

fn handle_chat_messages(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        let lower = f.rel_path.to_lowercase();
        if lower.ends_with(".json") {
            if let Ok(s) = std::str::from_utf8(&f.bytes) {
                if let Ok(v) = serde_json::from_str::<Value>(s) {
                    let arr = v
                        .get("messages")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_else(|| {
                            v.as_array().cloned().unwrap_or_default()
                        });
                    for m in arr {
                        let id = ctx.next_id("msg");
                        let author = m
                            .get("creator")
                            .and_then(|c| c.get("name"))
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| {
                                m.get("creator")
                                    .and_then(|c| c.get("email"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from)
                            });
                        let text = m
                            .get("text")
                            .or_else(|| m.get("message_text"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        let ts = m
                            .get("created_date")
                            .or_else(|| m.get("createdDate"))
                            .or_else(|| m.get("timestamp"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        let summary_text = text.clone().unwrap_or_default();
                        // Char-safe truncation: slicing on a fixed BYTE index
                        // (`[..80]`) panics when byte 80 lands mid-UTF-8-char
                        // (emoji / accented text is common in chat returns),
                        // which crashed the whole app. Truncate by chars.
                        let summary_short = truncate_chars(&summary_text, 80);
                        ctx.push(WarrantItem {
                            id,
                            section: "unified_messages".into(),
                            section_display: "Messages".into(),
                            timestamp: ts,
                            author,
                            recipient: None,
                            body_text: text,
                            summary: Some(summary_short),
                            raw_fields: m,
                            attachments: vec![],
                            bucket: None,
                            note: None,
                            is_flagged: false,
                        });
                    }
                }
            }
        }
    }
}

fn handle_chat_user_info(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if f.rel_path.to_lowercase().ends_with(".json") {
            if let Ok(s) = std::str::from_utf8(&f.bytes) {
                if let Ok(v) = serde_json::from_str::<Value>(s) {
                    let mut map = HashMap::new();
                    if let Value::Object(m) = v {
                        for (k, val) in m {
                            map.insert(k, val.to_string());
                        }
                    }
                    ctx.chat_user = Some(map);
                }
            }
        }
    }
}

fn handle_chat_group_info(files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        if f.rel_path.to_lowercase().ends_with(".json") {
            if let Ok(s) = std::str::from_utf8(&f.bytes) {
                if let Ok(v) = serde_json::from_str::<Value>(s) {
                    let arr = v
                        .get("groups")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_else(|| v.as_array().cloned().unwrap_or_default());
                    for g in arr {
                        let id = ctx.next_id("grp");
                        let name = g
                            .get("name")
                            .or_else(|| g.get("groupName"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        ctx.push(WarrantItem {
                            id,
                            section: "friends".into(),
                            section_display: "Chat Groups".into(),
                            timestamp: None,
                            author: name.clone(),
                            recipient: None,
                            body_text: None,
                            summary: name,
                            raw_fields: g,
                            attachments: vec![],
                            bucket: None,
                            note: None,
                            is_flagged: false,
                        });
                    }
                }
            }
        }
    }
}

// ─── Google Photos ──────────────────────────────────────────────────────
//
// LERS warrant bundles for Photos arrive under categories that start with
// `GooglePhotos.` and contain a flat list of media files (often alongside
// per-image JSON sidecars when shipped via Takeout).  We walk every file
// in the bundle, extract anything that looks like an image or video to
// the case media dir, and emit it as a `photos` item so it shows up in
// the gallery, the hash scanner, and keyword triage.

fn handle_google_photos(category: &str, files: &[CategoryFile], ctx: &mut ParseCtx) {
    use std::collections::HashMap;

    // First pass: index any `*.json` sidecars by their target filename
    // (Google Photos Takeout sidecar pattern: `IMG_1234.jpg.json` or
    // `IMG_1234.jpg.supplemental-metadata.json`).
    let mut sidecars: HashMap<String, Value> = HashMap::new();
    for f in files {
        let lower = f.rel_path.to_lowercase();
        if !lower.ends_with(".json") {
            continue;
        }
        let leaf = leaf_name(&f.rel_path);
        // Strip trailing `.json` (and optional `.supplemental-metadata`)
        let mut key = leaf.trim_end_matches(".json").to_string();
        if let Some(stripped) = key.strip_suffix(".supplemental-metadata") {
            key = stripped.to_string();
        }
        if let Ok(v) = serde_json::from_slice::<Value>(&f.bytes) {
            sidecars.insert(key.to_lowercase(), v);
        }
    }

    let mut emitted: usize = 0;
    for f in files {
        let lower = f.rel_path.to_lowercase();
        let is_image = IMAGE_EXTS.iter().any(|e| lower.ends_with(e));
        let is_video = VIDEO_EXTS.iter().any(|e| lower.ends_with(e));
        if !is_image && !is_video {
            continue;
        }

        let leaf = leaf_name(&f.rel_path);
        let id = ctx.next_id("photo");
        let safe = sanitize_filename(&leaf);
        let unique_name = format!("{}_{}", id, safe);
        if !ctx.media_budget_ok() {
            if !ctx.skipped_large.contains(&"(bulk media cap reached)".to_string()) {
                ctx.skipped_large.push("(bulk media cap reached)".to_string());
            }
            continue;
        }
        let out_path = ctx.media_dir.join(&unique_name);
        if let Ok(mut fh) = File::create(&out_path) {
            if fh.write_all(&f.bytes).is_err() {
                continue;
            }
        } else {
            continue;
        }

        // Pull metadata from the matching sidecar (if any).
        let sidecar = sidecars.get(&leaf.to_lowercase()).cloned();
        let (timestamp, geo, description) = extract_photos_meta(&sidecar);

        let mut raw = serde_json::Map::new();
        raw.insert("originalName".into(), Value::String(leaf.clone()));
        raw.insert("storedAs".into(), Value::String(unique_name.clone()));
        raw.insert("size".into(), json!(f.bytes.len()));
        raw.insert(
            "kind".into(),
            Value::String(if is_video { "video".into() } else { "image".into() }),
        );
        raw.insert("sourcePath".into(), Value::String(f.rel_path.clone()));
        raw.insert("category".into(), Value::String(category.to_string()));
        if let Some(s) = &sidecar {
            raw.insert("sidecar".into(), s.clone());
        }
        if let Some(g) = geo {
            raw.insert("geo".into(), g);
        }
        if let Some(d) = &description {
            raw.insert("description".into(), Value::String(d.clone()));
        }

        let summary = leaf.clone();
        ctx.items.push(WarrantItem {
            id,
            section: "photos".into(),
            section_display: "Photos".into(),
            timestamp,
            author: None,
            recipient: None,
            body_text: description,
            summary: Some(summary),
            raw_fields: Value::Object(raw),
            attachments: vec![unique_name],
            bucket: None,
            note: None,
            is_flagged: false,
        });
        emitted += 1;
    }

    // If the bundle had NO media at all, fall back to the generic
    // dump so the user still sees the raw files (e.g. albums JSON only).
    if emitted == 0 {
        handle_generic_fallback(category, files, ctx);
    }
}

fn extract_photos_meta(sidecar: &Option<Value>) -> (Option<String>, Option<Value>, Option<String>) {
    let s = match sidecar {
        Some(v) => v,
        None => return (None, None, None),
    };
    // photoTakenTime.formatted or .timestamp (unix seconds)
    let ts = s
        .get("photoTakenTime")
        .and_then(|v| {
            v.get("formatted")
                .and_then(|x| x.as_str())
                .map(|x| x.to_string())
                .or_else(|| {
                    v.get("timestamp")
                        .and_then(|x| x.as_str())
                        .map(|x| x.to_string())
                })
        })
        .or_else(|| {
            s.get("creationTime")
                .and_then(|v| v.get("formatted"))
                .and_then(|x| x.as_str())
                .map(|x| x.to_string())
        });
    let geo = s
        .get("geoData")
        .cloned()
        .or_else(|| s.get("geoDataExif").cloned())
        .filter(|v| {
            v.get("latitude")
                .and_then(|x| x.as_f64())
                .map(|n| n != 0.0)
                .unwrap_or(false)
                || v.get("longitude")
                    .and_then(|x| x.as_f64())
                    .map(|n| n != 0.0)
                    .unwrap_or(false)
        });
    let desc = s
        .get("description")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    (ts, geo, desc)
}

// ─── Google Drive ───────────────────────────────────────────────────────
//
// Drive returns can contain anything — images, video, PDFs, Office docs,
// plain text, etc.  We split the bundle:
//   * Media files (images/videos) → `photos` section (gallery + hash scan).
//   * Everything else → `drive_files` section (keyword-triageable).
//   * Per-file `*-info.json` / `*.metadata.json` sidecars are attached.

fn handle_google_drive(category: &str, files: &[CategoryFile], ctx: &mut ParseCtx) {
    use std::collections::HashMap;

    // Index sidecars (Drive ships `<filename>-info.json` or
    // `<filename>.metadata.json` patterns in some bundles).
    let mut sidecars: HashMap<String, Value> = HashMap::new();
    for f in files {
        let lower = f.rel_path.to_lowercase();
        if !lower.ends_with(".json") {
            continue;
        }
        let leaf = leaf_name(&f.rel_path).to_lowercase();
        let mut key = leaf.clone();
        for suffix in &["-info.json", ".metadata.json", ".json"] {
            if let Some(stripped) = key.strip_suffix(suffix) {
                key = stripped.to_string();
                break;
            }
        }
        if let Ok(v) = serde_json::from_slice::<Value>(&f.bytes) {
            sidecars.insert(key, v);
        }
    }

    let mut media_emitted = 0usize;
    let mut docs_emitted = 0usize;

    for f in files {
        let lower = f.rel_path.to_lowercase();
        // Skip the sidecars themselves — they're attached to the host file.
        if lower.ends_with(".json")
            && (sidecars.contains_key(
                leaf_name(&f.rel_path)
                    .to_lowercase()
                    .trim_end_matches(".json"),
            ) || lower.contains("-info.json")
                || lower.contains(".metadata.json"))
        {
            // Keep going only if this is actually a standalone document
            // (rare).  By default we skip JSON in Drive.
            continue;
        }

        let leaf = leaf_name(&f.rel_path);
        let safe = sanitize_filename(&leaf);
        let is_image = IMAGE_EXTS.iter().any(|e| lower.ends_with(e));
        let is_video = VIDEO_EXTS.iter().any(|e| lower.ends_with(e));

        // Pick section + id prefix
        let (section, section_display, id_prefix) = if is_image || is_video {
            ("photos", "Photos", "photo")
        } else {
            ("drive_files", "Drive Files", "drive")
        };
        let id = ctx.next_id(id_prefix);
        let unique_name = format!("{}_{}", id, safe);
        if (is_image || is_video) && !ctx.media_budget_ok() {
            if !ctx.skipped_large.contains(&"(bulk media cap reached)".to_string()) {
                ctx.skipped_large.push("(bulk media cap reached)".to_string());
            }
            continue;
        }
        let out_path = ctx.media_dir.join(&unique_name);
        if let Ok(mut fh) = File::create(&out_path) {
            if fh.write_all(&f.bytes).is_err() {
                continue;
            }
        } else {
            continue;
        }

        // Attach sidecar if present.
        let sidecar = sidecars
            .get(&leaf.to_lowercase())
            .cloned()
            .or_else(|| sidecars.get(lower.as_str()).cloned());

        let kind_str = if is_image {
            "image"
        } else if is_video {
            "video"
        } else {
            // Coarse classification for the UI.
            if lower.ends_with(".pdf") {
                "pdf"
            } else if lower.ends_with(".doc")
                || lower.ends_with(".docx")
                || lower.ends_with(".odt")
                || lower.ends_with(".rtf")
            {
                "document"
            } else if lower.ends_with(".xls")
                || lower.ends_with(".xlsx")
                || lower.ends_with(".csv")
                || lower.ends_with(".ods")
            {
                "spreadsheet"
            } else if lower.ends_with(".ppt") || lower.ends_with(".pptx") {
                "presentation"
            } else if lower.ends_with(".txt") || lower.ends_with(".md") {
                "text"
            } else if lower.ends_with(".zip")
                || lower.ends_with(".7z")
                || lower.ends_with(".rar")
                || lower.ends_with(".tar")
                || lower.ends_with(".gz")
            {
                "archive"
            } else {
                "other"
            }
        };

        // If it's plain text-ish, pull contents for keyword triage.
        let body_text = if matches!(kind_str, "text") {
            Some(String::from_utf8_lossy(&f.bytes).into_owned())
        } else {
            None
        };

        let mut raw = serde_json::Map::new();
        raw.insert("originalName".into(), Value::String(leaf.clone()));
        raw.insert("storedAs".into(), Value::String(unique_name.clone()));
        raw.insert("size".into(), json!(f.bytes.len()));
        raw.insert("kind".into(), Value::String(kind_str.into()));
        raw.insert("sourcePath".into(), Value::String(f.rel_path.clone()));
        raw.insert("category".into(), Value::String(category.to_string()));
        if let Some(s) = sidecar {
            raw.insert("sidecar".into(), s);
        }

        let summary = leaf.clone();
        ctx.items.push(WarrantItem {
            id,
            section: section.into(),
            section_display: section_display.into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text,
            summary: Some(summary),
            raw_fields: Value::Object(raw),
            attachments: vec![unique_name],
            bucket: None,
            note: None,
            is_flagged: false,
        });

        if is_image || is_video {
            media_emitted += 1;
        } else {
            docs_emitted += 1;
        }
    }

    if media_emitted == 0 && docs_emitted == 0 {
        handle_generic_fallback(category, files, ctx);
    }
}

fn leaf_name(rel: &str) -> String {
    rel.rsplit('/')
        .next()
        .unwrap_or(rel)
        .rsplit('\\')
        .next()
        .unwrap_or(rel)
        .to_string()
}

// ─── Access Log Activity ────────────────────────────────────────────────

fn handle_access_log(_category: &str, files: &[CategoryFile], ctx: &mut ParseCtx) {
    for f in files {
        let lower = f.rel_path.to_lowercase();
        if !lower.ends_with(".html") {
            continue;
        }
        let html = String::from_utf8_lossy(&f.bytes);
        let rows = parse_first_html_table(&html);
        for r in rows {
            let id = ctx.next_id("ip");
            let ts = r
                .get("Timestamp")
                .or_else(|| r.get("Date"))
                .cloned();
            let ip = r.get("IP Address").cloned().or_else(|| r.get("IP").cloned());
            let ua = r
                .get("User Agent")
                .or_else(|| r.get("Raw User Agents"))
                .cloned();
            let activity = r
                .get("Activity Type")
                .or_else(|| r.get("Type"))
                .cloned();
            let summary = format!(
                "{} — {}",
                activity.clone().unwrap_or_else(|| "Access".into()),
                ip.clone().unwrap_or_default()
            );
            let mut raw = serde_json::to_value(&r).unwrap_or(Value::Null);
            if let Value::Object(ref mut m) = raw {
                m.insert("source".into(), json!("AccessLogActivity"));
            }
            ctx.push(WarrantItem {
                id,
                section: "ip_addresses".into(),
                section_display: "IP Addresses".into(),
                timestamp: ts,
                author: activity,
                recipient: None,
                body_text: ua,
                summary: Some(summary),
                raw_fields: raw,
                attachments: vec![],
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

// ─── Generic fallback ───────────────────────────────────────────────────

fn handle_generic_fallback(category: &str, files: &[CategoryFile], ctx: &mut ParseCtx) {
    // Bundle into one `request_parameters` item per category so the data
    // is preserved without bloating the sidebar.
    if files.is_empty() {
        return;
    }
    let mut summaries: Vec<Value> = Vec::new();
    for f in files {
        let bytes = &f.bytes;
        let lower = f.rel_path.to_lowercase();
        let kind = if lower.ends_with(".html") {
            "html"
        } else if lower.ends_with(".csv") {
            "csv"
        } else if lower.ends_with(".json") {
            "json"
        } else if lower.ends_with(".txt") {
            "txt"
        } else {
            "other"
        };
        let entry = match kind {
            "html" => {
                let text = String::from_utf8_lossy(bytes);
                let rows = parse_first_html_table(&text);
                json!({
                    "name": f.rel_path,
                    "kind": kind,
                    "size": bytes.len(),
                    "rows": rows,
                })
            }
            "csv" => {
                let text = String::from_utf8_lossy(bytes);
                let rows = csv_rows(&text);
                json!({
                    "name": f.rel_path,
                    "kind": kind,
                    "size": bytes.len(),
                    "rows": rows,
                })
            }
            "json" => {
                let v: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
                json!({
                    "name": f.rel_path,
                    "kind": kind,
                    "size": bytes.len(),
                    "data": v,
                })
            }
            "txt" => {
                let s = String::from_utf8_lossy(bytes).into_owned();
                json!({
                    "name": f.rel_path,
                    "kind": kind,
                    "size": bytes.len(),
                    "text": s,
                })
            }
            _ => {
                json!({
                    "name": f.rel_path,
                    "kind": kind,
                    "size": bytes.len(),
                })
            }
        };
        summaries.push(entry);
    }

    let id = ctx.next_id("gen");
    ctx.push(WarrantItem {
        id,
        section: "request_parameters".into(),
        section_display: category.to_string(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(format!("{} file(s) in {}", files.len(), category)),
        summary: Some(format!("{} (raw)", category)),
        raw_fields: json!({
            "category": category,
            "files": summaries,
        }),
        attachments: vec![],
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

// ─── Bio (emitted last) ─────────────────────────────────────────────────

fn emit_bio(ctx: &mut ParseCtx) {
    // Structured field list — consumed by the React bio card.
    // Two shapes:
    //   {"section": "Subscriber Information"}   ← section header row
    //   {"label": "Name", "value": "Joe Smith"} ← key/value row
    let mut fields: Vec<Value> = Vec::new();
    let mut raw = serde_json::Map::new();

    let push_header = |fields: &mut Vec<Value>, title: &str| {
        let mut m = serde_json::Map::new();
        m.insert("section".into(), Value::String(title.into()));
        fields.push(Value::Object(m));
    };
    let push_kv = |fields: &mut Vec<Value>, label: &str, value: &str| {
        let mut m = serde_json::Map::new();
        m.insert("label".into(), Value::String(label.into()));
        m.insert("value".into(), Value::String(value.into()));
        fields.push(Value::Object(m));
    };

    if let Some(sub) = &ctx.subscriber {
        push_header(&mut fields, "Subscriber Information");
        let pairs: [(&str, &Option<String>); 20] = [
            ("Google Account ID", &sub.account_id),
            ("Name", &sub.name),
            ("Given Name", &sub.given_name),
            ("Family Name", &sub.family_name),
            ("e-Mail", &sub.email),
            ("Alternate e-Mails", &sub.alternate_emails),
            ("Created", &sub.created_on),
            ("Terms of Service IP", &sub.tos_ip),
            ("ToS Language", &sub.tos_lang),
            ("Birthday", &sub.birthday),
            ("Services", &sub.services),
            ("Unregistered Services", &sub.unregistered_services),
            ("Status", &sub.status),
            ("Last Updated", &sub.last_updated),
            ("Last Logins", &sub.last_logins),
            ("Contact e-Mail", &sub.contact_email),
            ("Recovery e-Mail", &sub.recovery_email),
            ("Recovery SMS", &sub.recovery_sms),
            ("User Phone Numbers", &sub.user_phones),
            ("2-Step Verification Phones", &sub.twostep_phones),
        ];
        for (k, v) in pairs.iter() {
            if let Some(val) = v {
                push_kv(&mut fields, k, val);
            }
        }
        raw.insert("subscriber".into(), serde_json::to_value(sub).unwrap_or(Value::Null));
    }

    if let Some(h) = &ctx.hangouts_user {
        push_header(&mut fields, "Hangouts User Info");
        let pairs: [(&str, &Option<String>); 10] = [
            ("Display Name", &h.display_name),
            ("First Name", &h.first_name),
            ("Emails", &h.emails),
            ("Photo URL", &h.photo_url),
            ("User Type", &h.user_type),
            ("Is Known Minor", &h.is_known_minor),
            ("Gender", &h.gender),
            ("User-Set Location", &h.location),
            ("Organization", &h.organization),
            ("Role", &h.role),
        ];
        for (k, v) in pairs.iter() {
            if let Some(val) = v {
                push_kv(&mut fields, k, val);
            }
        }
        raw.insert("hangouts".into(), serde_json::to_value(h).unwrap_or(Value::Null));
    }

    if let Some(cu) = &ctx.chat_user {
        push_header(&mut fields, "Google Chat User Info");
        let mut sorted: Vec<(&String, &String)> = cu.iter().collect();
        sorted.sort_by_key(|(k, _)| k.to_string());
        let mut simple_count = 0;
        for (k, v) in sorted.iter() {
            if !v.is_empty() {
                push_kv(&mut fields, k, v);
                simple_count += 1;
            }
        }
        if simple_count == 0 {
            push_kv(&mut fields, "Fields", &format!("{} structured field(s)", cu.len()));
        }
        raw.insert("chatUser".into(), serde_json::to_value(cu).unwrap_or(Value::Null));
    }

    if !ctx.no_records.is_empty() {
        push_header(&mut fields, "Categories With No Records Returned");
        let mut nr = ctx.no_records.clone();
        nr.sort();
        // Group into a single "value" so it lists nicely.  Renderer treats
        // newlines via white-space: pre-line.
        push_kv(&mut fields, &format!("{} categories", nr.len()), &nr.join("\n"));
        raw.insert("noRecords".into(), Value::Array(
            nr.into_iter().map(Value::String).collect(),
        ));
    }

    if !ctx.bundle_sources.is_empty() {
        push_header(&mut fields, "Imported From");
        push_kv(
            &mut fields,
            &format!("{} bundle(s)", ctx.bundle_sources.len()),
            &ctx.bundle_sources.join("\n"),
        );
        raw.insert(
            "bundleSources".into(),
            Value::Array(
                ctx.bundle_sources
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }

    if !ctx.skipped_large.is_empty() {
        push_header(&mut fields, "Large Files Not Loaded");
        let mut sl = ctx.skipped_large.clone();
        sl.sort();
        let shown: Vec<String> = sl.iter().take(50).cloned().collect();
        let mut note = shown.join("\n");
        if sl.len() > shown.len() {
            note.push_str(&format!("\n… and {} more", sl.len() - shown.len()));
        }
        push_kv(
            &mut fields,
            &format!("{} file(s) over size limit", sl.len()),
            &note,
        );
        raw.insert(
            "skippedLarge".into(),
            Value::Array(sl.into_iter().map(Value::String).collect()),
        );
    }

    if let Some(em) = &ctx.account_email {
        raw.insert("accountEmail".into(), Value::String(em.clone()));
    }
    if let Some(id) = &ctx.account_id {
        raw.insert("accountId".into(), Value::String(id.clone()));
    }
    if let Some(dr) = &ctx.date_range {
        raw.insert("dateRange".into(), Value::String(dr.clone()));
    }

    if fields.is_empty() && raw.is_empty() {
        return;
    }

    // Also build a plain-text body for the detail pane / export.
    let mut body_lines: Vec<String> = Vec::new();
    for f in fields.iter() {
        if let Some(obj) = f.as_object() {
            if let Some(s) = obj.get("section").and_then(|v| v.as_str()) {
                if !body_lines.is_empty() {
                    body_lines.push(String::new());
                }
                body_lines.push(format!("=== {} ===", s));
            } else if let (Some(l), Some(v)) = (
                obj.get("label").and_then(|v| v.as_str()),
                obj.get("value").and_then(|v| v.as_str()),
            ) {
                body_lines.push(format!("{}: {}", l, v));
            }
        }
    }

    raw.insert("fields".into(), Value::Array(fields));

    let id = ctx.next_id("bio");
    ctx.items.push(WarrantItem {
        id,
        section: "bio".into(),
        section_display: "Bio".into(),
        timestamp: None,
        author: ctx.account_email.clone(),
        recipient: None,
        body_text: if body_lines.is_empty() { None } else { Some(body_lines.join("\n")) },
        summary: Some(format!(
            "Google subscriber: {}",
            ctx.account_email.clone().unwrap_or_else(|| "(unknown)".into())
        )),
        raw_fields: Value::Object(raw),
        attachments: vec![],
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

// ─── Helpers: filename parsing + CSV + Takeout map ──────────────────────

fn is_lers_inner_zip(name: &str) -> bool {
    // {email}.{accountId}.{Service}.{Resource}_NNN.zip
    let basename = name.rsplit('/').next().unwrap_or(name);
    if !basename.to_lowercase().ends_with(".zip") {
        return false;
    }
    parse_lers_filename(basename).is_some()
}

fn parse_lers_filename(basename: &str) -> Option<(String, String, String)> {
    // Strip .zip extension, then parse the remaining stem.
    let stem = basename.strip_suffix(".zip").or_else(|| basename.strip_suffix(".ZIP"))?;
    parse_lers_stem(stem)
}

/// True when `name` (a bare directory name, no `.zip`) matches the LERS
/// per-service resource pattern `{email}.{accountId}.{Service}.{Resource}_NNN`.
/// Large Google returns pack each resource as a DIRECTORY (not a nested zip)
/// inside the master-bundle volumes.
fn is_lers_dir_name(name: &str) -> bool {
    let basename = name.trim_end_matches('/').rsplit('/').next().unwrap_or(name);
    // A resource directory has no file extension; guard against matching a
    // stray `.zip` (that path is handled by is_lers_inner_zip).
    if basename.to_lowercase().ends_with(".zip") {
        return false;
    }
    parse_lers_stem(basename).is_some()
}

/// Parse `{email}.{accountId}.{Service}.{Resource}[_NNN]` from a name that is
/// either a `.zip` basename (already stripped) or a bare resource-directory
/// name.  Returns (email, accountId, "Service.Resource").
fn parse_lers_name(name: &str) -> Option<(String, String, String)> {
    let basename = name.trim_end_matches('/').rsplit('/').next().unwrap_or(name);
    let stem = basename
        .strip_suffix(".zip")
        .or_else(|| basename.strip_suffix(".ZIP"))
        .unwrap_or(basename);
    parse_lers_stem(stem)
}

fn parse_lers_stem(stem: &str) -> Option<(String, String, String)> {
    // Expect at least 4 dot-separated chunks: email . accountId . Service . Resource_NNN
    let parts: Vec<&str> = stem.split('.').collect();
    if parts.len() < 4 {
        return None;
    }
    // Find the FIRST all-digit chunk after the first chunk — that's the account id.
    let mut acct_idx = None;
    for (i, p) in parts.iter().enumerate().skip(1) {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            acct_idx = Some(i);
            break;
        }
    }
    let acct_idx = acct_idx?;
    let email = parts[..acct_idx].join(".");
    let acct_id = parts[acct_idx].to_string();
    let svc_res_parts = &parts[acct_idx + 1..];
    if svc_res_parts.is_empty() {
        return None;
    }
    let svc_res = svc_res_parts.join(".");
    // Strip trailing _NNN
    let category = svc_res
        .rsplit_once('_')
        .map(|(a, b)| {
            if b.chars().all(|c| c.is_ascii_digit()) {
                a.to_string()
            } else {
                svc_res.clone()
            }
        })
        .unwrap_or(svc_res);
    Some((email, acct_id, category))
}

fn is_master_bundle_filename(basename: &str) -> bool {
    // {digits}-{YYYYMMDD}-{N}.zip
    let stem = match basename.strip_suffix(".zip").or_else(|| basename.strip_suffix(".ZIP")) {
        Some(s) => s,
        None => return false,
    };
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].len() == 8
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && !parts[2].is_empty()
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

/// Map a Takeout-relative path to a Service.Resource category.
fn takeout_category_from_path(rel: &str) -> Option<String> {
    // Find the segment AFTER "Takeout/"
    let lower = rel.to_lowercase();
    let after = if let Some(idx) = lower.find("takeout/") {
        &rel[idx + "takeout/".len()..]
    } else {
        return None;
    };
    let first = after.split('/').next()?;
    let cat = match first.to_lowercase().as_str() {
        "google account" => {
            // Sub-routing by leaf filename
            let leaf = after.rsplit('/').next().unwrap_or("").to_lowercase();
            if leaf.contains("subscriber") {
                "GoogleAccount.SubscriberInfo"
            } else if leaf.contains("changehistory") || leaf.contains("change history") {
                "GoogleAccount.ChangeHistory"
            } else {
                "GoogleAccount.Other"
            }
        }
        "mail" => "Mail.MessageContent",
        "location history (timeline)" | "location history" => {
            if after.to_lowercase().contains("semantic") {
                "LocationHistory.SemanticLocationHistory"
            } else if after.to_lowercase().contains("tombstone") {
                "LocationHistory.Tombstones"
            } else {
                "LocationHistory.Records"
            }
        }
        "google play store" => {
            let leaf = after.rsplit('/').next().unwrap_or("").to_lowercase();
            if leaf.starts_with("devices") {
                "GooglePlayStore.Devices"
            } else if leaf.starts_with("installs") {
                "GooglePlayStore.Installs"
            } else if leaf.starts_with("library") {
                "GooglePlayStore.Library"
            } else if leaf.starts_with("user activity") || leaf.starts_with("useractivity") {
                "GooglePlayStore.UserActivity"
            } else if leaf.starts_with("user preferences") || leaf.starts_with("userpreferences") {
                "GooglePlayStore.UserPreferences"
            } else {
                "GooglePlayStore.Other"
            }
        }
        "hangouts" => "Hangouts.ContentAndMetadata",
        "google photos" => "GooglePhotos.Takeout",
        "drive" => "GoogleDrive.Takeout",
        "google chat" => {
            let leaf = after.rsplit('/').next().unwrap_or("").to_lowercase();
            if leaf.contains("group") {
                "GoogleChat.GroupInfo"
            } else if leaf.contains("user") {
                "GoogleChat.UserInfo"
            } else if leaf.contains("messages") {
                "GoogleChat.Messages"
            } else {
                "GoogleChat.Other"
            }
        }
        "my activity" => "MyActivity.MyActivity",
        "access log activity" => "AccessLogActivity.Activity",
        _ => "Other.Other",
    };
    Some(cat.to_string())
}

fn trim_takeout_prefix(rel: &str) -> String {
    let lower = rel.to_lowercase();
    if let Some(idx) = lower.find("takeout/") {
        let after = &rel[idx + "takeout/".len()..];
        // Drop the first segment (service folder).
        match after.split_once('/') {
            Some((_, rest)) => rest.to_string(),
            None => after.to_string(),
        }
    } else {
        rel.to_string()
    }
}

fn ingest_export_summary(text: &str, ctx: &mut ParseCtx) {
    // Look for "End of date range: ..." line(s)
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("End of date range:") {
            let val = rest.trim().trim_end_matches('.').to_string();
            if !val.is_empty() && !val.eq_ignore_ascii_case("not specified") {
                ctx.date_range = Some(val);
            }
        }
        if let Some(rest) = t.strip_prefix("Resolved Identifier:") {
            // Capture the digits portion before "[Google Account ID]"
            let val = rest.trim();
            let digits: String = val.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() && ctx.account_id.is_none() {
                ctx.account_id = Some(digits);
            }
        }
    }
}

fn csv_rows(text: &str) -> Vec<HashMap<String, String>> {
    let rows = parse_csv(text);
    if rows.is_empty() {
        return Vec::new();
    }
    let headers = &rows[0];
    let mut out = Vec::with_capacity(rows.len().saturating_sub(1));
    for r in rows.iter().skip(1) {
        if r.iter().all(|f| f.is_empty()) {
            continue;
        }
        let mut m = HashMap::new();
        for (i, h) in headers.iter().enumerate() {
            m.insert(h.clone(), r.get(i).cloned().unwrap_or_default());
        }
        out.push(m);
    }
    out
}

fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if in_quotes {
            if ch == '"' {
                if i + 1 < chars.len() && chars[i + 1] == '"' {
                    field.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = false;
                i += 1;
                continue;
            }
            field.push(ch);
            i += 1;
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                i += 1;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                i += 1;
            }
            '\r' => {
                if i + 1 < chars.len() && chars[i + 1] == '\n' {
                    i += 1;
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                i += 1;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                i += 1;
            }
            _ => {
                field.push(ch);
                i += 1;
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

fn dir_has_google_format(path: &Path) -> bool {
    // Look for a Takeout folder, LERS-style inner zips, master-bundle volume
    // zips ({internalNumber}-{YYYYMMDD}-{N}.zip), or extracted resource
    // directories ({email}.{id}.{Service}.{Resource}_NNN/).
    for entry in walkdir_safe(path, 2) {
        let name = entry.file_name().unwrap_or_default().to_string_lossy().to_string();
        if entry.is_dir() {
            if name.to_lowercase() == "takeout" || is_lers_dir_name(&name) {
                return true;
            }
        }
        if entry.is_file() && (is_lers_inner_zip(&name) || is_master_bundle_filename(&name)) {
            return true;
        }
    }
    false
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ZIP: &str = r"D:\GOOGLE SW\GOOGLE SW.zip";

    fn sample_exists() -> bool {
        std::path::Path::new(SAMPLE_ZIP).exists()
    }

    #[test]
    fn truncate_chars_is_utf8_safe() {
        // Pure ASCII under the limit — unchanged.
        assert_eq!(truncate_chars("hello", 80), "hello");

        // A multibyte char (😀 = 4 bytes) sitting exactly across byte 80
        // would panic with the old `&s[..80]` byte-slice. 79 ASCII + emoji
        // = 80 chars but 83 bytes, so the old guard (`len() > 80`) fired and
        // sliced mid-char. Must not panic and must truncate by chars.
        let s = format!("{}{}", "a".repeat(79), "😀😀😀😀😀");
        let out = truncate_chars(&s, 80);
        assert!(out.ends_with('…'), "should be truncated with ellipsis");
        // 80 retained chars + the ellipsis char.
        assert_eq!(out.chars().count(), 81);

        // Emoji-heavy string shorter than the char limit but longer in bytes
        // — must be returned intact (this is the exact old crash case).
        let short_emoji = "👮‍♂️🚔🔍 evidence 📂";
        assert_eq!(truncate_chars(short_emoji, 80), short_emoji);
    }

    #[test]
    fn lers_filename_parses() {
        let r = parse_lers_filename(
            "js7017987@gmail.com.838053527712.Mail.MessageContent_001.zip",
        );
        assert!(r.is_some(), "should parse LERS filename");
        let (email, id, cat) = r.unwrap();
        assert_eq!(email, "js7017987@gmail.com");
        assert_eq!(id, "838053527712");
        assert_eq!(cat, "Mail.MessageContent");
    }

    #[test]
    fn master_bundle_filename_detected() {
        assert!(is_master_bundle_filename("26548003-20221112-1.zip"));
        assert!(!is_master_bundle_filename(
            "js7017987@gmail.com.838053527712.Mail.MessageContent_001.zip"
        ));
    }

    #[test]
    fn google_parser_accepts_sample_zip() {
        if !sample_exists() {
            eprintln!("skip: sample zip not present at {}", SAMPLE_ZIP);
            return;
        }
        let p = GoogleWarrantParser;
        let ok = p.accepts(std::path::Path::new(SAMPLE_ZIP)).unwrap_or(false);
        assert!(ok, "GoogleWarrantParser should accept the sample zip");
    }

    #[test]
    fn google_parser_parses_sample_zip() {
        if !sample_exists() {
            eprintln!("skip: sample zip not present at {}", SAMPLE_ZIP);
            return;
        }
        let media_dir = std::env::temp_dir().join(format!(
            "scout_google_test_{}",
            Uuid::new_v4()
        ));
        let p = GoogleWarrantParser;
        let result = p
            .parse(std::path::Path::new(SAMPLE_ZIP), &media_dir)
            .expect("parse should succeed");

        let bio = result.items.iter().filter(|i| i.section == "bio").count();
        let emails = result.items.iter().filter(|i| i.section == "emails").count();
        let devices = result
            .items
            .iter()
            .filter(|i| i.section == "device_info")
            .count();
        let apps = result.items.iter().filter(|i| i.section == "apps").count();
        let ips = result
            .items
            .iter()
            .filter(|i| i.section == "ip_addresses")
            .count();
        let change = result
            .items
            .iter()
            .filter(|i| i.section == "change_history")
            .count();
        let activity = result
            .items
            .iter()
            .filter(|i| i.section == "recently_viewed")
            .count();
        let photos = result.items.iter().filter(|i| i.section == "photos").count();

        eprintln!(
            "bio={} emails={} ip={} change={} dev={} apps={} act={} photos={} total={}",
            bio,
            emails,
            ips,
            change,
            devices,
            apps,
            activity,
            photos,
            result.items.len()
        );
        assert!(bio >= 1, "should emit at least one bio item");
        assert!(emails >= 1, "should emit at least one email item");
        assert!(devices >= 1, "should emit at least one device item");
        assert!(apps >= 1, "should emit at least one app item");
        assert!(ips >= 1, "should emit at least one ip item");
        assert!(change >= 1, "should emit at least one change-history item");
    }

    // ── Large multi-volume return: master-bundle zip whose per-service
    //    resources are DIRECTORIES (not nested zips).  This is the layout
    //    Google delivers for very large (100s of GB) returns and is the case
    //    that previously fell through to the generic catalog. ──────────────

    fn write_master_bundle_with_dirs(dir: &Path) -> PathBuf {
        use std::io::Write as _;
        use zip::write::FileOptions;

        let bundle_path = dir.join("26548003-20221112-1.zip");
        let f = File::create(&bundle_path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        let base = "js7017987@gmail.com.838053527712";

        // Subscriber info (directory layout: <res>_001/Google Account/<user>.SubscriberInfo.html)
        let sub_html = "<html><body><ul>\
            <li>Google Account ID: 838053527712</li>\
            <li>Name: Joe Sample</li>\
            <li>e-Mail: js7017987@gmail.com</li>\
            <li>Status: Enabled</li>\
            </ul></body></html>";
        zw.start_file(
            format!("{base}.GoogleAccount.SubscriberInfo_001/GoogleAccount.SubscriberInfo.ExportSummary.txt"),
            opts,
        ).unwrap();
        zw.write_all(b"End of date range: 2022/11/12.\n").unwrap();
        zw.start_file(
            format!("{base}.GoogleAccount.SubscriberInfo_001/Google Account/js7017987.SubscriberInfo.html"),
            opts,
        ).unwrap();
        zw.write_all(sub_html.as_bytes()).unwrap();

        // Mail (small mbox) — directory layout.
        let mbox = "From 1234@xxx Mon Jan 01 00:00:00 2022\r\n\
            From: alice@example.com\r\n\
            To: js7017987@gmail.com\r\n\
            Subject: Hello\r\n\
            Date: Mon, 01 Jan 2022 00:00:00 +0000\r\n\
            \r\n\
            Body text here.\r\n";
        zw.start_file(
            format!("{base}.Mail.MessageContent_001/Mail.MessageContent.ExportSummary.txt"),
            opts,
        ).unwrap();
        zw.write_all(b"End of date range: 2022/11/12.\n").unwrap();
        zw.start_file(
            format!("{base}.Mail.MessageContent_001/Mail/All mail Including Spam and Trash.mbox"),
            opts,
        ).unwrap();
        zw.write_all(mbox.as_bytes()).unwrap();

        // A NoRecords resource — directory layout.
        zw.start_file(
            format!("{base}.AccessLogActivity.Activity_001/AccessLogActivity.Activity.ExportSummary.txt"),
            opts,
        ).unwrap();
        zw.write_all(b"End of date range: 2022/11/12.\n").unwrap();
        zw.start_file(
            format!("{base}.AccessLogActivity.Activity_001/NoRecords.txt"),
            opts,
        ).unwrap();
        zw.write_all(b"No records").unwrap();

        zw.finish().unwrap();
        bundle_path
    }

    #[test]
    fn accepts_folder_of_master_bundles() {
        let tmp = std::env::temp_dir().join(format!("scout_g_bundle_acc_{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        write_master_bundle_with_dirs(&tmp);

        let p = GoogleWarrantParser;
        // Folder pick → must be recognised (previously returned false → generic).
        assert!(
            p.accepts(&tmp).unwrap_or(false),
            "folder of master-bundle volumes must be accepted as Google"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn accepts_single_master_bundle_zip() {
        let tmp = std::env::temp_dir().join(format!("scout_g_bundle_zip_{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let bundle = write_master_bundle_with_dirs(&tmp);

        let p = GoogleWarrantParser;
        assert!(
            p.accepts(&bundle).unwrap_or(false),
            "a directly-picked master-bundle zip must be accepted"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parses_directory_layout_bundle() {
        let tmp = std::env::temp_dir().join(format!("scout_g_bundle_parse_{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        write_master_bundle_with_dirs(&tmp);
        let media_dir = tmp.join("media");

        let p = GoogleWarrantParser;
        let result = p.parse(&tmp, &media_dir).expect("parse should succeed");

        let bio = result.items.iter().filter(|i| i.section == "bio").count();
        let emails = result.items.iter().filter(|i| i.section == "emails").count();
        assert!(bio >= 1, "should emit a bio from SubscriberInfo directory");
        assert!(emails >= 1, "should emit the mbox email from the directory layout");

        // Subscriber identity must be recovered from the HTML.
        assert_eq!(result.case.target_account.as_deref(), Some("js7017987@gmail.com"));

        // NoRecords category must be captured (surfaced in bio raw fields).
        let bio_item = result.items.iter().find(|i| i.section == "bio").unwrap();
        let raw = &bio_item.raw_fields;
        let nr = raw.get("noRecords").and_then(|v| v.as_array());
        assert!(
            nr.map(|a| a.iter().any(|x| x.as_str() == Some("AccessLogActivity.Activity"))).unwrap_or(false),
            "AccessLogActivity.Activity should be recorded as no-records"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stream_mbox_emits_each_message() {
        let tmp = std::env::temp_dir().join(format!("scout_g_streammbox_{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut ctx = ParseCtx::new(&tmp);
        let mbox = "From 1@x Mon Jan 01 00:00:00 2022\r\n\
            From: a@x\r\nTo: b@y\r\nSubject: One\r\n\r\nBody1\r\n\
            From 2@x Mon Jan 01 00:00:00 2022\r\n\
            From: c@x\r\nTo: d@y\r\nSubject: Two\r\n\r\nBody2\r\n";
        stream_mbox_reader(std::io::BufReader::new(std::io::Cursor::new(mbox)), &mut ctx);
        let emails = ctx.items.iter().filter(|i| i.section == "emails").count();
        assert_eq!(emails, 2, "streamed mbox should emit one item per message");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn extracts_media_from_directory_bundle() {
        use std::io::Write as _;
        use zip::write::FileOptions;

        let tmp = std::env::temp_dir().join(format!("scout_g_media_{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let base = "js7017987@gmail.com.838053527712";

        // Master-bundle volume containing a GooglePhotos resource DIRECTORY
        // with one image + its sidecar, plus a Mail resource with one email.
        let bundle_path = tmp.join("26548003-20221112-2.zip");
        {
            let f = File::create(&bundle_path).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            let opts = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

            // A real-ish JPEG (magic bytes; handler keys off extension).
            zw.start_file(
                format!("{base}.GooglePhotos.Photos_001/Google Photos/evidence.jpg"),
                opts,
            ).unwrap();
            zw.write_all(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x02, 0x03]).unwrap();
            zw.start_file(
                format!("{base}.GooglePhotos.Photos_001/Google Photos/evidence.jpg.supplemental-metadata.json"),
                opts,
            ).unwrap();
            zw.write_all(br#"{"photoTakenTime":{"timestamp":"1640995200"}}"#).unwrap();

            // An email with a small inline image attachment (base64 JPEG).
            let mbox = "From 1@x Mon Jan 01 00:00:00 2022\r\n\
                From: alice@example.com\r\nTo: js7017987@gmail.com\r\n\
                Subject: photo attached\r\n\
                MIME-Version: 1.0\r\n\
                Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n\
                --BND\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n\
                --BND\r\nContent-Type: image/jpeg\r\n\
                Content-Transfer-Encoding: base64\r\n\
                Content-Disposition: attachment; filename=\"a.jpg\"\r\n\r\n\
                /9j/4AAQSkZJRgAB\r\n--BND--\r\n";
            zw.start_file(
                format!("{base}.Mail.MessageContent_001/Mail/All mail Including Spam and Trash.mbox"),
                opts,
            ).unwrap();
            zw.write_all(mbox.as_bytes()).unwrap();

            zw.finish().unwrap();
        }

        let media_dir = tmp.join("media");
        let p = GoogleWarrantParser;
        let res = p.parse(&tmp, &media_dir).expect("parse");

        let photos = res.items.iter().filter(|i| i.section == "photos").count();
        let emails = res.items.iter().filter(|i| i.section == "emails").count();
        let media_files = std::fs::read_dir(&media_dir)
            .map(|rd| rd.flatten().count())
            .unwrap_or(0);
        eprintln!("media test: photos={} emails={} files_on_disk={}", photos, emails, media_files);

        assert!(emails >= 1, "should parse the email");
        assert!(photos >= 1, "should surface the GooglePhotos image as a photos item");
        assert!(media_files >= 1, "at least one media file must be written to disk");
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── Real-data smoke tests (gated on the operator's local sample, like
    //    SAMPLE_ZIP above).  These reproduce the exact failing user actions:
    //    picking the GOOGLE SW folder, and picking a master-bundle zip. ─────

    const SAMPLE_DIR: &str = r"D:\GOOGLE SW\GOOGLE SW";
    const SAMPLE_BUNDLE: &str = r"D:\GOOGLE SW\GOOGLE SW\26548003-20221112-1.zip";

    #[test]
    fn real_folder_pick_is_accepted_and_parses() {
        let dir = std::path::Path::new(SAMPLE_DIR);
        if !dir.exists() {
            eprintln!("skip: {} not present", SAMPLE_DIR);
            return;
        }
        let p = GoogleWarrantParser;
        assert!(
            p.accepts(dir).unwrap_or(false),
            "folder pick of a real Google return must be accepted (was falling to generic)"
        );
        let media = std::env::temp_dir().join(format!("scout_g_realdir_{}", Uuid::new_v4()));
        let res = p.parse(dir, &media).expect("folder parse must not error/OOM");
        let bio = res.items.iter().filter(|i| i.section == "bio").count();
        eprintln!("real folder: {} items, {} bio, target={:?}",
            res.items.len(), bio, res.case.target_account);
        assert!(res.items.len() > 0, "folder parse should yield items");
        let _ = fs::remove_dir_all(&media);
    }

    #[test]
    fn real_master_bundle_zip_is_accepted_and_parses() {
        let z = std::path::Path::new(SAMPLE_BUNDLE);
        if !z.exists() {
            eprintln!("skip: {} not present", SAMPLE_BUNDLE);
            return;
        }
        let p = GoogleWarrantParser;
        assert!(
            p.accepts(z).unwrap_or(false),
            "a directly-picked master-bundle zip must be accepted"
        );
        let media = std::env::temp_dir().join(format!("scout_g_realbundle_{}", Uuid::new_v4()));
        let res = p.parse(z, &media).expect("bundle parse must not error/OOM");
        eprintln!("real bundle: {} items, target={:?}",
            res.items.len(), res.case.target_account);
        assert!(res.items.len() > 0, "bundle parse should yield items");
        let _ = fs::remove_dir_all(&media);
    }
}
