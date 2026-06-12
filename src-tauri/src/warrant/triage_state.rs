//! On-disk persistence for a triage case.
//!
//! Layout
//! ------
//! Each imported warrant return becomes a case directory under
//! [`crate::warrant::cases_root`]:
//!
//! ```text
//! warrant_cases/
//! └── <case_id>/
//!     ├── case.json     # WarrantCase + triage state (buckets + per-item assignments)
//!     ├── parsed.json   # full ParsedReturn (items + metadata) — write-once
//!     └── media/        # extracted linked_media (parser writes here on import)
//! ```
//!
//! `case.json` is the only file mutated post-import.  Every triage action
//! ([`assign_bucket`], [`set_note`], [`create_bucket`], ...) rewrites it
//! atomically (write-then-rename).  We don't index per item — caseloads
//! are bounded (a single warrant return) so a full re-serialize is fine.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{BucketTemplate, ParsedReturn, WarrantCase, cases_root};

// ─── On-disk shapes ──────────────────────────────────────────────────────

/// One user-defined or seeded bucket.  `id` is opaque and stable; the user
/// edits `name`/`color` freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    pub id: String,
    pub name: String,
    pub color: String,
    pub description: Option<String>,
    /// True if seeded by the provider (e.g. Meta's "CSAM" bucket).  Used
    /// only as a hint to the UI — user can still rename or delete it.
    #[serde(default)]
    pub seeded: bool,
}

/// Lightweight per-item triage row stored in `case.json`.  We keep this
/// separate from [`ParsedReturn::items`] in `parsed.json` so the read-only
/// parse output never gets mutated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemTriage {
    /// Reference to `WarrantItem::id` from `parsed.json`.
    pub item_id: String,
    /// `Bucket::id` or None for unassigned.
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub is_flagged: bool,
}

/// The mutable file: `case.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseFile {
    pub case: WarrantCase,
    pub buckets: Vec<Bucket>,
    /// Sparse — only items the user has actually touched.
    pub triage: Vec<ItemTriage>,
    /// RFC3339; updated on every save.
    pub updated_at: String,
    /// Cached total item count from parsed.json.  Eliminates the need
    /// to re-parse the (potentially huge) parsed.json just to count
    /// rows for the list screen.  Backfilled lazily on first read of
    /// older case.json files.
    #[serde(default)]
    pub item_count: usize,
}

/// The shape returned to the frontend on load: parse output joined with
/// triage state.  Computed on the fly from `parsed.json` + `case.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseDetail {
    pub case: WarrantCase,
    pub items: Vec<super::WarrantItem>,
    pub buckets: Vec<Bucket>,
}

/// Compact summary for the case-list screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseSummary {
    pub case_id: String,
    pub provider: super::Provider,
    pub provider_display: String,
    pub source_filename: String,
    pub imported_at: String,
    pub updated_at: String,
    pub target_account: Option<String>,
    pub item_count: usize,
    pub flagged_count: usize,
    pub bucketed_count: usize,
}

// ─── Path helpers ────────────────────────────────────────────────────────

pub fn case_dir(case_id: &str) -> PathBuf {
    cases_root().join(case_id)
}

pub fn case_json_path(case_id: &str) -> PathBuf {
    case_dir(case_id).join("case.json")
}

pub fn parsed_json_path(case_id: &str) -> PathBuf {
    case_dir(case_id).join("parsed.json")
}

pub fn media_dir(case_id: &str) -> PathBuf {
    case_dir(case_id).join("media")
}

// ─── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotFound(String),
    Conflict(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Io(e) => write!(f, "I/O error: {}", e),
            StateError::Json(e) => write!(f, "JSON error: {}", e),
            StateError::NotFound(s) => write!(f, "not found: {}", s),
            StateError::Conflict(s) => write!(f, "conflict: {}", s),
        }
    }
}

impl std::error::Error for StateError {}

impl From<std::io::Error> for StateError {
    fn from(e: std::io::Error) -> Self {
        StateError::Io(e)
    }
}

impl From<serde_json::Error> for StateError {
    fn from(e: serde_json::Error) -> Self {
        StateError::Json(e)
    }
}

// ─── Create / load / save ────────────────────────────────────────────────

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    // On Windows `rename` fails if the dest exists, so remove first.
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path)
}

/// Persist a freshly parsed return to disk.  Writes `parsed.json` once,
/// then seeds `case.json` from the provider's default buckets.
pub fn create_case(parsed: &ParsedReturn) -> Result<CaseSummary, StateError> {
    let case_id = parsed.case.case_id.clone();
    let dir = case_dir(&case_id);
    // We allow the directory to exist (the parser typically writes
    // extracted media into media/ before create_case runs), but refuse
    // to overwrite an existing case.json.
    if case_json_path(&case_id).exists() {
        return Err(StateError::Conflict(format!(
            "case {} already exists",
            case_id
        )));
    }
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(media_dir(&case_id))?;

    // parsed.json — read-only after this
    let parsed_bytes = serde_json::to_vec_pretty(parsed)?;
    write_atomic(&parsed_json_path(&case_id), &parsed_bytes)?;

    // Seed buckets from provider defaults + auto-bucket flagged items
    let mut buckets: Vec<Bucket> = parsed
        .default_buckets
        .iter()
        .map(seeded_bucket_from_template)
        .collect();

    // Auto-bucket any items the parser already classified.  Right now Meta
    // is the only provider that does this (NCMEC → CSAM).
    let mut triage: Vec<ItemTriage> = Vec::new();
    for item in &parsed.items {
        if item.bucket.is_none() && !item.is_flagged && item.note.is_none() {
            continue;
        }
        // Resolve a parser-suggested bucket NAME (e.g. "CSAM") to one of
        // our seeded bucket IDs.
        let bucket_id = item.bucket.as_ref().and_then(|name| {
            buckets
                .iter()
                .find(|b| b.name.eq_ignore_ascii_case(name))
                .map(|b| b.id.clone())
                .or_else(|| {
                    // Parser suggested a bucket the provider didn't seed —
                    // create it on the fly so the user sees it.
                    let new_b = Bucket {
                        id: new_bucket_id(),
                        name: name.clone(),
                        color: "#64748b".into(),
                        description: None,
                        seeded: true,
                    };
                    let id = new_b.id.clone();
                    buckets.push(new_b);
                    Some(id)
                })
        });
        triage.push(ItemTriage {
            item_id: item.id.clone(),
            bucket: bucket_id,
            note: item.note.clone(),
            is_flagged: item.is_flagged,
        });
    }

    let case_file = CaseFile {
        case: parsed.case.clone(),
        buckets,
        triage,
        updated_at: now_rfc3339(),
        item_count: parsed.items.len(),
    };
    let case_bytes = serde_json::to_vec_pretty(&case_file)?;
    write_atomic(&case_json_path(&case_id), &case_bytes)?;

    Ok(summarize(&case_file, parsed.items.len()))
}

fn seeded_bucket_from_template(t: &BucketTemplate) -> Bucket {
    Bucket {
        id: new_bucket_id(),
        name: t.name.clone(),
        color: t.color.clone(),
        description: t.description.clone(),
        seeded: true,
    }
}

fn new_bucket_id() -> String {
    format!("b-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Read `case.json` for a case.
pub fn load_case_file(case_id: &str) -> Result<CaseFile, StateError> {
    let p = case_json_path(case_id);
    if !p.exists() {
        return Err(StateError::NotFound(case_id.to_string()));
    }
    let bytes = fs::read(&p)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Read `parsed.json` for a case.
pub fn load_parsed(case_id: &str) -> Result<ParsedReturn, StateError> {
    let p = parsed_json_path(case_id);
    if !p.exists() {
        return Err(StateError::NotFound(case_id.to_string()));
    }
    let bytes = fs::read(&p)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Write `case.json` back to disk, bumping `updated_at`.
fn save_case_file(case_file: &mut CaseFile) -> Result<(), StateError> {
    case_file.updated_at = now_rfc3339();
    let bytes = serde_json::to_vec_pretty(case_file)?;
    let case_id = case_file.case.case_id.clone();
    write_atomic(&case_json_path(&case_id), &bytes)?;
    Ok(())
}

/// Combine parsed.json items with case.json triage state and return what
/// the UI consumes.
pub fn load_case_detail(case_id: &str) -> Result<CaseDetail, StateError> {
    let parsed = load_parsed(case_id)?;
    let cf = load_case_file(case_id)?;

    // Build an item_id → triage map for O(n) merge.
    let mut by_id: std::collections::HashMap<&str, &ItemTriage> =
        std::collections::HashMap::with_capacity(cf.triage.len());
    for t in &cf.triage {
        by_id.insert(t.item_id.as_str(), t);
    }

    let items = parsed
        .items
        .into_iter()
        .map(|mut it| {
            if let Some(t) = by_id.get(it.id.as_str()) {
                it.bucket = t.bucket.clone();
                it.note = t.note.clone();
                it.is_flagged = t.is_flagged;
            } else {
                // Reset any parser-set state — case.json is the source of truth.
                it.bucket = None;
                it.note = None;
                it.is_flagged = false;
            }
            it
        })
        .collect();

    Ok(CaseDetail {
        case: cf.case,
        items,
        buckets: cf.buckets,
    })
}

fn summarize(cf: &CaseFile, item_count: usize) -> CaseSummary {
    let flagged_count = cf.triage.iter().filter(|t| t.is_flagged).count();
    let bucketed_count = cf.triage.iter().filter(|t| t.bucket.is_some()).count();
    CaseSummary {
        case_id: cf.case.case_id.clone(),
        provider: cf.case.provider,
        provider_display: cf.case.provider_display.clone(),
        source_filename: cf.case.source_filename.clone(),
        imported_at: cf.case.imported_at.clone(),
        updated_at: cf.updated_at.clone(),
        target_account: cf.case.target_account.clone(),
        item_count,
        flagged_count,
        bucketed_count,
    }
}

/// Scan the cases root and return a summary per case.  Silently skips
/// directories that don't have a valid `case.json`/`parsed.json` pair.
///
/// Performance: uses `cf.item_count` cached in case.json.  For legacy
/// case.json files written before that field existed, lazily backfills
/// by reading parsed.json once and rewriting case.json.
pub fn list_cases() -> Result<Vec<CaseSummary>, StateError> {
    let root = cases_root();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let mut cf = match load_case_file(&name) {
            Ok(cf) => cf,
            Err(_) => continue,
        };
        let item_count = if cf.item_count > 0 {
            cf.item_count
        } else {
            // Legacy file — backfill once.
            let n = load_parsed(&name).map(|p| p.items.len()).unwrap_or(0);
            if n > 0 {
                cf.item_count = n;
                let _ = save_case_file(&mut cf);
            }
            n
        };
        out.push(summarize(&cf, item_count));
    }
    // Newest first
    out.sort_by(|a, b| b.imported_at.cmp(&a.imported_at));
    Ok(out)
}

// ─── Mutations ───────────────────────────────────────────────────────────

fn upsert_triage<'a>(cf: &'a mut CaseFile, item_id: &str) -> &'a mut ItemTriage {
    if let Some(idx) = cf.triage.iter().position(|t| t.item_id == item_id) {
        &mut cf.triage[idx]
    } else {
        cf.triage.push(ItemTriage {
            item_id: item_id.to_string(),
            ..Default::default()
        });
        cf.triage.last_mut().unwrap()
    }
}

fn drop_if_empty(cf: &mut CaseFile, item_id: &str) {
    if let Some(idx) = cf.triage.iter().position(|t| t.item_id == item_id) {
        let t = &cf.triage[idx];
        if t.bucket.is_none() && t.note.is_none() && !t.is_flagged {
            cf.triage.remove(idx);
        }
    }
}

pub fn assign_bucket(
    case_id: &str,
    item_id: &str,
    bucket_id: Option<&str>,
) -> Result<(), StateError> {
    let mut cf = load_case_file(case_id)?;
    if let Some(bid) = bucket_id {
        if !cf.buckets.iter().any(|b| b.id == bid) {
            return Err(StateError::NotFound(format!("bucket {}", bid)));
        }
    }
    {
        let t = upsert_triage(&mut cf, item_id);
        t.bucket = bucket_id.map(|s| s.to_string());
    }
    drop_if_empty(&mut cf, item_id);
    save_case_file(&mut cf)
}

pub fn set_note(case_id: &str, item_id: &str, note: Option<&str>) -> Result<(), StateError> {
    let mut cf = load_case_file(case_id)?;
    {
        let t = upsert_triage(&mut cf, item_id);
        t.note = note
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }
    drop_if_empty(&mut cf, item_id);
    save_case_file(&mut cf)
}

pub fn set_flag(case_id: &str, item_id: &str, flagged: bool) -> Result<(), StateError> {
    let mut cf = load_case_file(case_id)?;
    {
        let t = upsert_triage(&mut cf, item_id);
        t.is_flagged = flagged;
    }
    drop_if_empty(&mut cf, item_id);
    save_case_file(&mut cf)
}

pub fn create_bucket(
    case_id: &str,
    name: &str,
    color: &str,
    description: Option<&str>,
) -> Result<Bucket, StateError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(StateError::Conflict("bucket name cannot be empty".into()));
    }
    let mut cf = load_case_file(case_id)?;
    if cf.buckets.iter().any(|b| b.name.eq_ignore_ascii_case(name)) {
        return Err(StateError::Conflict(format!(
            "bucket named {:?} already exists",
            name
        )));
    }
    let new_b = Bucket {
        id: new_bucket_id(),
        name: name.to_string(),
        color: color.to_string(),
        description: description.map(|s| s.to_string()),
        seeded: false,
    };
    let out = new_b.clone();
    cf.buckets.push(new_b);
    save_case_file(&mut cf)?;
    Ok(out)
}

pub fn rename_bucket(case_id: &str, bucket_id: &str, name: &str) -> Result<(), StateError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(StateError::Conflict("bucket name cannot be empty".into()));
    }
    let mut cf = load_case_file(case_id)?;
    if cf
        .buckets
        .iter()
        .any(|b| b.id != bucket_id && b.name.eq_ignore_ascii_case(name))
    {
        return Err(StateError::Conflict(format!(
            "bucket named {:?} already exists",
            name
        )));
    }
    let b = cf
        .buckets
        .iter_mut()
        .find(|b| b.id == bucket_id)
        .ok_or_else(|| StateError::NotFound(format!("bucket {}", bucket_id)))?;
    b.name = name.to_string();
    save_case_file(&mut cf)
}

pub fn delete_bucket(case_id: &str, bucket_id: &str) -> Result<(), StateError> {
    let mut cf = load_case_file(case_id)?;
    let before = cf.buckets.len();
    cf.buckets.retain(|b| b.id != bucket_id);
    if cf.buckets.len() == before {
        return Err(StateError::NotFound(format!("bucket {}", bucket_id)));
    }
    // Unassign any items pointing at this bucket
    for t in cf.triage.iter_mut() {
        if t.bucket.as_deref() == Some(bucket_id) {
            t.bucket = None;
        }
    }
    // Drop now-empty triage rows
    cf.triage
        .retain(|t| t.bucket.is_some() || t.note.is_some() || t.is_flagged);
    save_case_file(&mut cf)
}

pub fn delete_case(case_id: &str) -> Result<(), StateError> {
    let dir = case_dir(case_id);
    if !dir.exists() {
        return Err(StateError::NotFound(case_id.to_string()));
    }
    fs::remove_dir_all(&dir)?;
    Ok(())
}
