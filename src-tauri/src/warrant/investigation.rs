//! Multi-return investigations.
//!
//! An **Investigation** is the detective-facing wrapper around one or
//! more parsed warrant **Returns**.  Each Return is still an independent
//! on-disk case under [`super::cases_root`] with its own triage state;
//! the Investigation is just a manifest that names a group of returns
//! and orders them for a combined HTML report.
//!
//! Layout
//! ------
//!
//! ```text
//! investigations/
//! └── <investigation_id>/
//!     └── investigation.json
//! ```
//!
//! No media, no parsed data — the Investigation just points at returns
//! by `case_id`.  A return belongs to at most one investigation (strict
//! 1:1).
//!
//! ```text
//! investigation.json
//! {
//!   "investigationId": "inv-1234abcd",
//!   "name": "State v. Doe",
//!   "agencyCaseNumber": "2025-001234",
//!   "notes": "...",
//!   "createdAt": "RFC3339",
//!   "updatedAt": "RFC3339",
//!   "returns": [
//!     { "caseId": "w-aaaaaaaa", "label": "Suspect — John Doe" },
//!     { "caseId": "w-bbbbbbbb", "label": "Victim — J. Roe"  }
//!   ]
//! }
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::cases_root;
use super::triage_state::{self, CaseSummary, StateError};

// ─── On-disk shapes ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnRef {
    pub case_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub investigation_id: String,
    pub name: String,
    #[serde(default)]
    pub agency_case_number: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub returns: Vec<ReturnRef>,
}

/// Lightweight row for the landing-screen list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationSummary {
    pub investigation_id: String,
    pub name: String,
    pub agency_case_number: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub return_count: usize,
    pub total_items: usize,
    pub total_flagged: usize,
    pub total_bucketed: usize,
}

/// Full detail returned when the user opens an investigation.  Joins
/// each return ref with its current [`CaseSummary`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationDetail {
    pub investigation: Investigation,
    pub returns: Vec<ReturnDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnDetail {
    pub label: String,
    pub summary: CaseSummary,
}

// ─── Path helpers ────────────────────────────────────────────────────────

pub fn investigations_root() -> PathBuf {
    // Sits beside `warrant_cases/` — under DatapilotScout on desktop,
    // under ScoutData on the USB for portable builds.
    crate::app_paths::investigations_root()
}

pub fn investigation_dir(id: &str) -> PathBuf {
    investigations_root().join(id)
}

pub fn investigation_json_path(id: &str) -> PathBuf {
    investigation_dir(id).join("investigation.json")
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn new_investigation_id() -> String {
    format!("inv-{}", &uuid::Uuid::new_v4().to_string()[..8])
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
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path)
}

// ─── CRUD ────────────────────────────────────────────────────────────────

pub fn create(
    name: &str,
    agency_case_number: Option<&str>,
    notes: Option<&str>,
) -> Result<Investigation, StateError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(StateError::Conflict("investigation name is required".into()));
    }

    let now = now_rfc3339();
    let inv = Investigation {
        investigation_id: new_investigation_id(),
        name: name.to_string(),
        agency_case_number: agency_case_number
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        notes: notes
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        created_at: now.clone(),
        updated_at: now,
        returns: Vec::new(),
    };

    let bytes = serde_json::to_vec_pretty(&inv)?;
    write_atomic(&investigation_json_path(&inv.investigation_id), &bytes)?;
    Ok(inv)
}

pub fn load(id: &str) -> Result<Investigation, StateError> {
    let p = investigation_json_path(id);
    if !p.exists() {
        return Err(StateError::NotFound(id.to_string()));
    }
    let bytes = fs::read(&p)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn save(inv: &mut Investigation) -> Result<(), StateError> {
    inv.updated_at = now_rfc3339();
    let bytes = serde_json::to_vec_pretty(inv)?;
    write_atomic(&investigation_json_path(&inv.investigation_id), &bytes)?;
    Ok(())
}

pub fn update_meta(
    id: &str,
    name: Option<&str>,
    agency_case_number: Option<Option<&str>>,
    notes: Option<Option<&str>>,
) -> Result<Investigation, StateError> {
    let mut inv = load(id)?;
    if let Some(n) = name {
        let n = n.trim();
        if n.is_empty() {
            return Err(StateError::Conflict("name cannot be empty".into()));
        }
        inv.name = n.to_string();
    }
    if let Some(maybe) = agency_case_number {
        inv.agency_case_number = maybe
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
    }
    if let Some(maybe) = notes {
        inv.notes = maybe
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
    }
    save(&mut inv)?;
    Ok(inv)
}

/// Attach a return to an investigation.  Fails if the return is already
/// linked to a different investigation (strict 1:1).
pub fn add_return(
    investigation_id: &str,
    case_id: &str,
    label: &str,
) -> Result<Investigation, StateError> {
    // Reject if already in some other investigation.
    if let Some(existing) = find_investigation_for_return(case_id)? {
        if existing != investigation_id {
            return Err(StateError::Conflict(format!(
                "return {} is already in investigation {}",
                case_id, existing
            )));
        }
    }

    let mut inv = load(investigation_id)?;
    let label = label.trim();
    let label = if label.is_empty() {
        case_id.to_string()
    } else {
        label.to_string()
    };

    // Replace if already present, else append.
    if let Some(slot) = inv.returns.iter_mut().find(|r| r.case_id == case_id) {
        slot.label = label;
    } else {
        inv.returns.push(ReturnRef {
            case_id: case_id.to_string(),
            label,
        });
    }
    save(&mut inv)?;
    Ok(inv)
}

pub fn rename_return(
    investigation_id: &str,
    case_id: &str,
    new_label: &str,
) -> Result<Investigation, StateError> {
    let mut inv = load(investigation_id)?;
    let label = new_label.trim();
    if label.is_empty() {
        return Err(StateError::Conflict("label cannot be empty".into()));
    }
    let slot = inv
        .returns
        .iter_mut()
        .find(|r| r.case_id == case_id)
        .ok_or_else(|| {
            StateError::NotFound(format!(
                "return {} not in investigation {}",
                case_id, investigation_id
            ))
        })?;
    slot.label = label.to_string();
    save(&mut inv)?;
    Ok(inv)
}

pub fn remove_return(
    investigation_id: &str,
    case_id: &str,
) -> Result<Investigation, StateError> {
    let mut inv = load(investigation_id)?;
    let before = inv.returns.len();
    inv.returns.retain(|r| r.case_id != case_id);
    if inv.returns.len() == before {
        return Err(StateError::NotFound(format!(
            "return {} not in investigation {}",
            case_id, investigation_id
        )));
    }
    save(&mut inv)?;
    Ok(inv)
}

/// Delete the investigation.  If `delete_returns` is true, also delete
/// every referenced return on disk (calls `triage_state::delete_case`).
/// Otherwise the returns become orphans (no investigation parent).
pub fn delete(id: &str, delete_returns: bool) -> Result<(), StateError> {
    let inv = load(id)?;
    if delete_returns {
        for r in &inv.returns {
            let _ = triage_state::delete_case(&r.case_id);
        }
    }
    let dir = investigation_dir(id);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

// ─── List + lookup ───────────────────────────────────────────────────────

/// Load every investigation manifest in one pass.  Used by `list()`,
/// `find_investigation_for_return()` and `migrate_orphan_returns_if_any()`
/// to avoid O(n*m) directory walks.
fn load_all_investigations() -> Result<Vec<Investigation>, StateError> {
    let root = investigations_root();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if let Ok(inv) = load(&id) {
            out.push(inv);
        }
    }
    Ok(out)
}

/// Scan `investigations/` and return one summary per investigation.
/// Silently skips dirs missing investigation.json.
///
/// Performance: calls `triage_state::list_cases()` ONCE and reuses its
/// cached item/flagged/bucketed counts instead of re-parsing parsed.json
/// for every return.
pub fn list() -> Result<Vec<InvestigationSummary>, StateError> {
    let investigations = load_all_investigations()?;
    if investigations.is_empty() {
        return Ok(Vec::new());
    }

    // One disk pass for all cases, indexed by case_id.
    use std::collections::HashMap;
    let case_summaries = triage_state::list_cases().unwrap_or_default();
    let case_index: HashMap<&str, &CaseSummary> = case_summaries
        .iter()
        .map(|cs| (cs.case_id.as_str(), cs))
        .collect();

    let mut out: Vec<InvestigationSummary> = investigations
        .iter()
        .map(|inv| build_summary_with_index(inv, &case_index))
        .collect();
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(out)
}

fn build_summary_with_index(
    inv: &Investigation,
    case_index: &std::collections::HashMap<&str, &CaseSummary>,
) -> InvestigationSummary {
    let mut total_items = 0usize;
    let mut total_flagged = 0usize;
    let mut total_bucketed = 0usize;
    for r in &inv.returns {
        if let Some(cs) = case_index.get(r.case_id.as_str()) {
            total_items += cs.item_count;
            total_flagged += cs.flagged_count;
            total_bucketed += cs.bucketed_count;
        }
    }
    InvestigationSummary {
        investigation_id: inv.investigation_id.clone(),
        name: inv.name.clone(),
        agency_case_number: inv.agency_case_number.clone(),
        created_at: inv.created_at.clone(),
        updated_at: inv.updated_at.clone(),
        return_count: inv.returns.len(),
        total_items,
        total_flagged,
        total_bucketed,
    }
}

fn build_summary(inv: &Investigation) -> InvestigationSummary {
    let mut total_items = 0usize;
    let mut total_flagged = 0usize;
    let mut total_bucketed = 0usize;
    for r in &inv.returns {
        if let Ok(cf) = triage_state::load_case_file(&r.case_id) {
            // We need item_count; recompute by reading parsed.json.
            let item_count = triage_state::load_parsed(&r.case_id)
                .map(|p| p.items.len())
                .unwrap_or(0);
            total_items += item_count;
            total_flagged += cf.triage.iter().filter(|t| t.is_flagged).count();
            total_bucketed += cf.triage.iter().filter(|t| t.bucket.is_some()).count();
        }
    }
    InvestigationSummary {
        investigation_id: inv.investigation_id.clone(),
        name: inv.name.clone(),
        agency_case_number: inv.agency_case_number.clone(),
        created_at: inv.created_at.clone(),
        updated_at: inv.updated_at.clone(),
        return_count: inv.returns.len(),
        total_items,
        total_flagged,
        total_bucketed,
    }
}

/// Load full detail (investigation + joined CaseSummary per return).
pub fn load_detail(id: &str) -> Result<InvestigationDetail, StateError> {
    let inv = load(id)?;
    let mut returns: Vec<ReturnDetail> = Vec::with_capacity(inv.returns.len());
    for r in &inv.returns {
        // Skip refs whose return has been deleted off-disk.
        let cf = match triage_state::load_case_file(&r.case_id) {
            Ok(cf) => cf,
            Err(_) => continue,
        };
        // Use cached item_count from case.json (backfilled by list_cases
        // for legacy files); fall back to parsed.json only if empty.
        let item_count = if cf.item_count > 0 {
            cf.item_count
        } else {
            triage_state::load_parsed(&r.case_id)
                .map(|p| p.items.len())
                .unwrap_or(0)
        };
        returns.push(ReturnDetail {
            label: r.label.clone(),
            summary: case_summary_from_file(&cf, item_count),
        });
    }
    Ok(InvestigationDetail { investigation: inv, returns })
}

fn case_summary_from_file(cf: &super::triage_state::CaseFile, item_count: usize) -> CaseSummary {
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

/// Return the investigation id that owns the given `case_id`, if any.
/// O(n_investigations) but n is bounded (one detective, dozens of cases).
pub fn find_investigation_for_return(case_id: &str) -> Result<Option<String>, StateError> {
    let investigations = load_all_investigations()?;
    for inv in investigations {
        if inv.returns.iter().any(|r| r.case_id == case_id) {
            return Ok(Some(inv.investigation_id));
        }
    }
    Ok(None)
}

/// One-time migration: if there are returns on disk that don't belong
/// to any investigation, sweep them into a single auto-created "Legacy
/// Returns" investigation.  Idempotent — no-op if every existing return
/// is already attached somewhere.
///
/// Performance: builds the attached-set in one pass over investigations,
/// then does O(1) HashSet lookups per case.
pub fn migrate_orphan_returns_if_any() -> Result<Option<String>, StateError> {
    let case_summaries = match triage_state::list_cases() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if case_summaries.is_empty() {
        return Ok(None);
    }

    // Build the set of already-attached case_ids in ONE pass.
    use std::collections::HashSet;
    let investigations = load_all_investigations()?;
    let attached: HashSet<String> = investigations
        .iter()
        .flat_map(|inv| inv.returns.iter().map(|r| r.case_id.clone()))
        .collect();

    let orphans: Vec<&CaseSummary> = case_summaries
        .iter()
        .filter(|s| !attached.contains(&s.case_id))
        .collect();
    if orphans.is_empty() {
        return Ok(None);
    }

    let inv = create(
        "Legacy Returns",
        None,
        Some("Auto-created on upgrade — contains returns imported before multi-return support."),
    )?;
    let inv_id = inv.investigation_id.clone();
    for s in orphans {
        let label = s
            .target_account
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| s.provider_display.clone());
        let _ = add_return(&inv_id, &s.case_id, &label);
    }
    Ok(Some(inv_id))
}

/// Marker used by the on-disk `cases_root` keep-in-sync: ensures
/// `investigations_root()` exists.
pub fn ensure_root() {
    let _ = fs::create_dir_all(investigations_root());
    let _ = fs::create_dir_all(cases_root());
}
