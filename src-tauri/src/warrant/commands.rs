//! Tauri commands for the Warrant Triage feature.
//!
//! All commands return `Result<T, String>` so the frontend gets a clean
//! error string via `invoke().catch()`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use super::triage_state::{
    self, Bucket, CaseDetail, CaseSummary,
};
use super::{cases_root, registry, Provider};

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ─── Import ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub case_id: String,
    pub summary: CaseSummary,
}

/// Parse a warrant return archive for the given provider, create a new
/// on-disk case, extract its linked_media to that case's media/ dir, and
/// return a summary the UI can route to.
#[tauri::command]
pub fn warrant_import(
    provider: Provider,
    archive_path: String,
    allow_generic: Option<bool>,
) -> Result<ImportResult, String> {
    let archive = PathBuf::from(&archive_path);
    if !archive.exists() {
        return Err(format!("file not found: {}", archive_path));
    }

    // Pick a stable case_id up-front so we can use it as the media dir
    // BEFORE the case file is created.  The parser will overwrite case.case_id
    // with its own uuid, but we then rewrite it to ours below.
    let case_id = format!("w-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let media_dir = cases_root().join(&case_id).join("media");
    std::fs::create_dir_all(&media_dir).map_err(map_err)?;

    let parser = registry::for_provider(provider)
        .ok_or_else(|| "unknown provider".to_string())?;

    let mut parsed = if parser.accepts(&archive).unwrap_or(false) {
        parser.parse(&archive, &media_dir).map_err(map_err)?
    } else if allow_generic.unwrap_or(false) {
        // Operator consented to a degraded import after being warned the
        // format wasn't recognized — build a generic media/document/manifest
        // catalog so the return is never a dead-end.
        super::providers::generic::catalog(&archive, &media_dir, provider).map_err(map_err)?
    } else {
        // Not recognized and no consent yet.  Emit a machine-readable signal
        // (prefix `UNSUPPORTED_FORMAT|`) so the UI can offer a generic import
        // instead of treating this like a hard failure.  Clean up first.
        let _ = std::fs::remove_dir_all(cases_root().join(&case_id));
        return Err(format!(
            "UNSUPPORTED_FORMAT|{}",
            parser.provider().display_name()
        ));
    };

    // Force the case_id we already committed to on disk
    parsed.case.case_id = case_id.clone();
    parsed.case.media_root = Some("media".to_string());
    parsed.case.source_filename = archive
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| archive_path.clone());
    if parsed.default_buckets.is_empty() {
        parsed.default_buckets = parser.default_buckets();
    }

    let summary = triage_state::create_case(&parsed).map_err(map_err)?;
    Ok(ImportResult { case_id, summary })
}

// ─── Read ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn warrant_list_cases() -> Result<Vec<CaseSummary>, String> {
    triage_state::list_cases().map_err(map_err)
}

#[tauri::command]
pub fn warrant_load_case(case_id: String) -> Result<CaseDetail, String> {
    triage_state::load_case_detail(&case_id).map_err(map_err)
}

// ─── Mutations ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn warrant_assign_bucket(
    case_id: String,
    item_id: String,
    bucket_id: Option<String>,
) -> Result<(), String> {
    triage_state::assign_bucket(&case_id, &item_id, bucket_id.as_deref()).map_err(map_err)
}

#[tauri::command]
pub fn warrant_set_note(
    case_id: String,
    item_id: String,
    note: Option<String>,
) -> Result<(), String> {
    triage_state::set_note(&case_id, &item_id, note.as_deref()).map_err(map_err)
}

#[tauri::command]
pub fn warrant_set_flag(case_id: String, item_id: String, flagged: bool) -> Result<(), String> {
    triage_state::set_flag(&case_id, &item_id, flagged).map_err(map_err)
}

#[tauri::command]
pub fn warrant_create_bucket(
    case_id: String,
    name: String,
    color: String,
    description: Option<String>,
) -> Result<Bucket, String> {
    triage_state::create_bucket(&case_id, &name, &color, description.as_deref()).map_err(map_err)
}

#[tauri::command]
pub fn warrant_rename_bucket(
    case_id: String,
    bucket_id: String,
    name: String,
) -> Result<(), String> {
    triage_state::rename_bucket(&case_id, &bucket_id, &name).map_err(map_err)
}

#[tauri::command]
pub fn warrant_delete_bucket(case_id: String, bucket_id: String) -> Result<(), String> {
    triage_state::delete_bucket(&case_id, &bucket_id).map_err(map_err)
}

#[tauri::command]
pub fn warrant_delete_case(case_id: String) -> Result<(), String> {
    triage_state::delete_case(&case_id).map_err(map_err)
}

// ─── Export report ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    /// Absolute path to the created report folder.
    pub report_dir: String,
}

/// Build a self-contained interactive HTML report for `case_id` inside
/// `dest_dir`.  Returns the absolute path to the created
/// `<case_id>_warrant_report/` directory.  Detective receives the folder
/// (typically on the USB they brought) and opens `index.html`.
#[tauri::command]
pub fn warrant_export_report(case_id: String, dest_dir: String) -> Result<ExportResult, String> {
    let dest = PathBuf::from(&dest_dir);
    let folder = super::report::export_report(&case_id, &dest).map_err(map_err)?;
    Ok(ExportResult {
        report_dir: folder.to_string_lossy().to_string(),
    })
}

// ─── Media open ──────────────────────────────────────────────────────────

/// Generate (or fetch a cached) 200px JPEG thumbnail for a media file in
/// the case's media/ dir.  Returns a `data:image/jpeg;base64,...` URL the
/// frontend can stuff straight into an `<img src>`.  Returns `Ok(None)`
/// if the file isn't an image we can decode (audio, video, doc, etc.).
#[tauri::command]
pub fn warrant_get_thumbnail(case_id: String, filename: String) -> Result<Option<String>, String> {
    let media_root = triage_state::media_dir(&case_id);
    let media_root_canon = std::fs::canonicalize(&media_root)
        .map_err(|e| format!("media dir not found: {}", e))?;

    let candidate = media_root.join(&filename);
    let resolved = std::fs::canonicalize(&candidate)
        .map_err(|e| format!("media file not found: {}", e))?;

    if !resolved.starts_with(&media_root_canon) {
        return Err("path traversal rejected".into());
    }

    // Decide whether to *attempt* a thumbnail. The decoder
    // (`generate_thumb_data_url`) guesses the format from the file's magic
    // bytes, so a correct extension is NOT required — this matters for the
    // generic catalog, which extracts content-sniffed media that may have no
    // extension (e.g. Discord `attachments/…/file_0007`) or an exotic one.
    //
    // Rather than allow-listing image extensions (which silently blanked
    // those tiles), we *deny-list* the extensions that are clearly NOT
    // decodable stills — video, audio, documents, archives. Everything else
    // (known image extensions, unknown extensions, and no extension at all)
    // gets a decode attempt; failures fall through to `Ok(None)` and the UI
    // shows its placeholder. The image crate can't decode heic/heif/avif/svg,
    // so those still return None gracefully.
    let ext = resolved
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let is_non_image = matches!(
        ext.as_str(),
        // video
        "mp4" | "m4v" | "mov" | "mkv" | "avi" | "wmv" | "webm" | "flv"
        | "3gp" | "3g2" | "mpg" | "mpeg"
        // audio
        | "mp3" | "m4a" | "wav" | "aac" | "ogg" | "opus" | "flac" | "wma" | "amr"
        // documents / data / archives
        | "pdf" | "doc" | "docx" | "odt" | "rtf" | "xls" | "xlsx" | "xlsm"
        | "xlsb" | "ods" | "ppt" | "pptx" | "odp" | "csv" | "tsv" | "json"
        | "xml" | "html" | "htm" | "txt" | "log" | "md" | "eml" | "msg"
        | "mbox" | "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "tgz"
    );
    if is_non_image {
        return Ok(None);
    }

    match super::report::generate_thumb_data_url(&resolved) {
        Ok(url) => Ok(Some(url)),
        Err(_) => Ok(None), // decode failures (non-image / unsupported codec) shouldn't break the UI
    }
}



/// Open a linked_media file for a case using the OS default viewer.
/// `filename` is the bare filename as stored in `WarrantItem::attachments`.
/// We resolve it relative to the case's media/ dir and reject anything
/// that escapes the dir (defense against `..` in path).
#[tauri::command]
pub fn warrant_open_media(case_id: String, filename: String) -> Result<(), String> {
    let media_root = triage_state::media_dir(&case_id);
    let media_root_canon = std::fs::canonicalize(&media_root)
        .map_err(|e| format!("media dir not found: {}", e))?;

    let candidate = media_root.join(&filename);
    let resolved = std::fs::canonicalize(&candidate)
        .map_err(|e| format!("media file not found: {}", e))?;

    if !resolved.starts_with(&media_root_canon) {
        return Err("path traversal rejected".into());
    }

    open_with_default(&resolved)
}

#[cfg(target_os = "windows")]
fn open_with_default(path: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW = 0x08000000
    std::process::Command::new("cmd")
        .creation_flags(0x0800_0000)
        .args(["/C", "start", "", path.to_string_lossy().as_ref()])
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("failed to open: {}", e))
}

#[cfg(target_os = "macos")]
fn open_with_default(path: &std::path::Path) -> Result<(), String> {
    std::process::Command::new("open")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("failed to open: {}", e))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_with_default(path: &std::path::Path) -> Result<(), String> {
    std::process::Command::new("xdg-open")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("failed to open: {}", e))
}


// ─── Scan: Hash + Keyword (ephemeral, in-memory) ─────────────────────────

use super::scan;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordListSummary {
    pub name: String,
    pub keyword_count: usize,
}

/// List keyword lists available on this machine (mirrors the lists the
/// phone/PC scans see).  Used by the dropdown in the warrant UI.
#[tauri::command]
pub fn warrant_list_keyword_lists() -> Result<Vec<KeywordListSummary>, String> {
    use crate::scanner::keyword::load_keyword_lists_from_dir;
    let dir = crate::get_keyword_lists_dir()?;
    let lists = load_keyword_lists_from_dir(&dir).map_err(map_err)?;
    Ok(lists
        .into_iter()
        .map(|l| KeywordListSummary {
            keyword_count: l.keywords.len(),
            name: l.name,
        })
        .collect())
}

/// Run a SHA-1 hash scan against every media file in the case folder,
/// using every loaded hash database list (Project VIC + imports).
/// Result is stored in the in-memory cache for this case until app exit.
#[tauri::command]
pub async fn warrant_run_hash_scan(
    case_id: String,
    list_names: Option<Vec<String>>,
) -> Result<scan::HashScanResult, String> {
    tauri::async_runtime::spawn_blocking(move || scan::run_hash_scan(&case_id, list_names.as_deref()))
        .await
        .map_err(|e| format!("scan thread failed: {}", e))?
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashListSummary {
    pub name: String,
    pub source: String,
    pub hash_count: u64,
}

/// List hash lists currently loaded in the local hash DB (Project VIC + imports).
/// Used by the warrant UI to populate the hash-scan multi-select picker.
#[tauri::command]
pub fn warrant_list_hash_lists() -> Result<Vec<HashListSummary>, String> {
    let db = crate::hash_db::HashDatabase::new()?;
    let lists = db.get_lists()?;
    Ok(lists
        .into_iter()
        .map(|l| HashListSummary {
            name: l.name,
            source: l.source,
            hash_count: l.hash_count,
        })
        .collect())
}

/// Run a keyword scan over the textual fields of every item in the case
/// using the named keyword lists (selected from the same dir as phone scans).
#[tauri::command]
pub async fn warrant_run_keyword_scan(
    case_id: String,
    list_names: Vec<String>,
) -> Result<scan::KeywordScanResult, String> {
    let dir = crate::get_keyword_lists_dir()?;
    tauri::async_runtime::spawn_blocking(move || scan::run_keyword_scan(&case_id, &list_names, &dir))
        .await
        .map_err(|e| format!("scan thread failed: {}", e))?
}

/// Read the cached scan results for a case.  Empty if no scan ran this session.
#[tauri::command]
pub fn warrant_get_scan_results(case_id: String) -> Result<scan::CaseScanResults, String> {
    Ok(scan::get_results(&case_id))
}

/// Clear cached scan results for a case.  `scan_type` is `"hash"`,
/// `"keyword"`, or anything else for both.
#[tauri::command]
pub fn warrant_clear_scan(case_id: String, scan_type: String) -> Result<(), String> {
    scan::clear(&case_id, &scan_type);
    Ok(())
}

// ─── Investigations (multi-return wrappers) ──────────────────────────────

use super::investigation::{self, Investigation, InvestigationDetail, InvestigationSummary};

/// Create a new investigation.  Name is required; agency case number and
/// notes are optional (empty string treated as not provided).
#[tauri::command]
pub fn warrant_create_investigation(
    name: String,
    agency_case_number: Option<String>,
    notes: Option<String>,
) -> Result<Investigation, String> {
    investigation::create(
        &name,
        agency_case_number.as_deref(),
        notes.as_deref(),
    )
    .map_err(map_err)
}

/// List all investigations (newest-updated first).  Also lazily migrates
/// any orphan returns (returns on disk not linked to any investigation)
/// into a single "Legacy Returns" investigation on first call.
#[tauri::command]
pub fn warrant_list_investigations() -> Result<Vec<InvestigationSummary>, String> {
    investigation::ensure_root();
    let _ = investigation::migrate_orphan_returns_if_any();
    investigation::list().map_err(map_err)
}

/// Load full detail for an investigation: metadata + every linked return
/// joined with its current CaseSummary.
#[tauri::command]
pub fn warrant_load_investigation(
    investigation_id: String,
) -> Result<InvestigationDetail, String> {
    investigation::load_detail(&investigation_id).map_err(map_err)
}

/// Update investigation metadata.  Any field set to `None` is left
/// untouched; an explicit empty string clears the field (for
/// agencyCaseNumber / notes).
#[tauri::command]
pub fn warrant_update_investigation(
    investigation_id: String,
    name: Option<String>,
    agency_case_number: Option<String>,
    notes: Option<String>,
) -> Result<Investigation, String> {
    // Translate to update_meta's "Option<Option<&str>>" semantics:
    //   missing key  → don't touch
    //   present any  → set (empty string clears agency/notes; empty name rejected)
    let agency = agency_case_number.as_ref().map(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    });
    let notes_arg = notes.as_ref().map(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    });
    investigation::update_meta(
        &investigation_id,
        name.as_deref(),
        agency,
        notes_arg,
    )
    .map_err(map_err)
}

/// Attach a parsed return (`case_id`) to an investigation with the given
/// display label.  Strict 1:1 — fails if the return is already in a
/// different investigation.
#[tauri::command]
pub fn warrant_add_return_to_investigation(
    investigation_id: String,
    case_id: String,
    label: String,
) -> Result<Investigation, String> {
    investigation::add_return(&investigation_id, &case_id, &label).map_err(map_err)
}

/// Rename a return's display label within an investigation.
#[tauri::command]
pub fn warrant_rename_return_in_investigation(
    investigation_id: String,
    case_id: String,
    label: String,
) -> Result<Investigation, String> {
    investigation::rename_return(&investigation_id, &case_id, &label).map_err(map_err)
}

/// Detach a return from an investigation.  Does NOT delete the underlying
/// return data — caller can re-attach to a different investigation.
#[tauri::command]
pub fn warrant_remove_return_from_investigation(
    investigation_id: String,
    case_id: String,
) -> Result<Investigation, String> {
    investigation::remove_return(&investigation_id, &case_id).map_err(map_err)
}

/// Delete an investigation.  If `delete_returns` is true, also wipes
/// every linked return off disk; otherwise the returns become orphans
/// (will be re-swept into "Legacy Returns" on next list call).
#[tauri::command]
pub fn warrant_delete_investigation(
    investigation_id: String,
    delete_returns: bool,
) -> Result<(), String> {
    investigation::delete(&investigation_id, delete_returns).map_err(map_err)
}

/// Find which investigation (if any) currently owns a return.  Used by
/// the frontend to render the "← Investigation" breadcrumb when opening
/// a return's triage UI.
#[tauri::command]
pub fn warrant_find_investigation_for_return(
    case_id: String,
) -> Result<Option<String>, String> {
    investigation::find_investigation_for_return(&case_id).map_err(map_err)
}

/// Build the combined investigation-level HTML report inside `dest_dir`.
/// Produces `Scout_Investigation_<NAME>_<YYYYMMDD_HHMMSS>/` with a
/// cover-page `index.html` and one numbered subfolder per return.
///
/// Emits `warrant_export_progress` events on `app` while running, so
/// the UI can show a progress bar / ETA without blocking.  The command
/// itself is `async` so the work runs on a worker thread and the
/// frontend stays responsive.
#[tauri::command]
pub async fn warrant_export_investigation_report(
    app: AppHandle,
    investigation_id: String,
    dest_dir: String,
) -> Result<ExportResult, String> {
    let dest = PathBuf::from(&dest_dir);
    let app_for_cb = app.clone();
    let emit_cb = move |p: super::report_investigation::ExportProgress| {
        let _ = app_for_cb.emit("warrant_export_progress", p);
    };
    // Run the (sync, disk-heavy) export on a blocking worker so the
    // command future doesn't park the main runtime.
    let folder = tauri::async_runtime::spawn_blocking(move || {
        super::report_investigation::export_investigation_report(
            &investigation_id,
            &dest,
            &emit_cb,
        )
    })
    .await
    .map_err(|e| format!("export task join error: {}", e))?
    .map_err(map_err)?;

    // Final "done" event so the UI can flip into success state.
    let _ = app.emit(
        "warrant_export_progress",
        super::report_investigation::ExportProgress {
            stage: "done".to_string(),
            index: 0,
            total: 0,
            label: folder.to_string_lossy().to_string(),
        },
    );

    Ok(ExportResult {
        report_dir: folder.to_string_lossy().to_string(),
    })
}

// ─── Parser submission: structural sample ────────────────────────────────
//
// The user picks an unsupported warrant return; we build a JSON
// "structural fingerprint" envelope describing its shape *without* any
// case content, then POST it to the admin server so the parser author
// can build a real parser from real shape data.  See
// `src/warrant/sample/mod.rs` for the privacy model.

const SAMPLE_SUBMIT_DEFAULT_URL: &str =
    "https://scout-server-production-1d65.up.railway.app/api/parser-submission";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildSampleArgs {
    /// Path to a folder OR a `.zip` warrant return.
    pub root_path: String,
    /// Free-text provider hint typed by the user ("KIK return", "T-Mobile CDR",
    /// "Apple iCloud zip", etc.).  Empty string is allowed.
    #[serde(default)]
    pub provider_hint: String,
    /// Submitter contact info — frontend pre-fills from cached registration.
    #[serde(default)]
    pub submitter_email: String,
    #[serde(default)]
    pub agency_name: String,
    /// Free-text notes from the submitter.
    #[serde(default)]
    pub submitter_notes: String,
    /// Last-4 of the active license key (for audit), if any.
    #[serde(default)]
    pub license_key_last4: String,
}

#[tauri::command]
pub async fn warrant_build_sample_envelope(
    args: BuildSampleArgs,
) -> Result<serde_json::Value, String> {
    let root = PathBuf::from(&args.root_path);
    if !root.exists() {
        return Err(format!("path does not exist: {}", args.root_path));
    }

    // Heavy I/O — run on a blocking worker so the UI stays responsive.
    let envelope = tauri::async_runtime::spawn_blocking(move || {
        super::sample::build_envelope(
            &root,
            super::sample::BuildOptions {
                provider_hint: args.provider_hint,
                submitter_email: args.submitter_email,
                submitter_notes: args.submitter_notes,
                agency_name: args.agency_name,
                license_key_last4: args.license_key_last4,
            },
        )
    })
    .await
    .map_err(|e| format!("sample task join error: {}", e))?
    .map_err(|e| e.to_string())?;

    serde_json::to_value(&envelope)
        .map_err(|e| format!("envelope serialization failed: {}", e))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitSampleArgs {
    /// The envelope built by `warrant_build_sample_envelope`, passed
    /// through verbatim.  We accept a raw JSON Value here so the
    /// frontend can show / edit / save it before submitting and we
    /// don't reject extra fields the user might add later.
    pub envelope: serde_json::Value,
    /// Override the default endpoint (useful for staging / self-host).
    /// Empty string falls back to `SAMPLE_SUBMIT_DEFAULT_URL`.
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubmitSampleResponse {
    pub status: u16,
    pub body: String,
    /// `endpoint` that was actually used (after default fallback).
    pub endpoint: String,
}

#[tauri::command]
pub async fn warrant_submit_sample_envelope(
    args: SubmitSampleArgs,
) -> Result<SubmitSampleResponse, String> {
    let endpoint = if args.endpoint.trim().is_empty() {
        SAMPLE_SUBMIT_DEFAULT_URL.to_string()
    } else {
        args.endpoint.clone()
    };

    // The server expects `{ envelope: {...}, submitter: {...} }`. The
    // envelope itself already carries the submitter fields (the builder
    // stamped them in), so we lift them into a top-level submitter block
    // without round-tripping through the UI. machine_id + platform come
    // from the licensing module so the server can attribute the row to
    // an Agency without trusting client-supplied claims.
    fn pick_str(env: &serde_json::Value, key: &str) -> String {
        env.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
    let scout_version = {
        let from_env = pick_str(&args.envelope, "scout_version");
        if from_env.is_empty() {
            env!("CARGO_PKG_VERSION").to_string()
        } else {
            from_env
        }
    };
    let submitter = serde_json::json!({
        "machine_id": crate::licensing::get_machine_id().unwrap_or_default(),
        "platform": crate::licensing::get_platform(),
        "scout_version": scout_version,
        "provider_hint":      pick_str(&args.envelope, "provider_hint"),
        "submitter_email":    pick_str(&args.envelope, "submitter_email"),
        "submitter_notes":    pick_str(&args.envelope, "submitter_notes"),
        "agency_name":        pick_str(&args.envelope, "agency_name"),
        "license_key_last4":  pick_str(&args.envelope, "license_key_last4"),
    });
    let wrapped = serde_json::json!({
        "envelope": &args.envelope,
        "submitter": submitter,
    });

    let body = serde_json::to_string(&wrapped)
        .map_err(|e| format!("envelope serialization failed: {}", e))?;

    let endpoint_for_call = endpoint.clone();
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<SubmitSampleResponse, String> {
        match ureq::post(&endpoint_for_call)
            .timeout(std::time::Duration::from_secs(60))
            .set("Content-Type", "application/json")
            .set("User-Agent", concat!("DatapilotScout/", env!("CARGO_PKG_VERSION")))
            .send_string(&body)
        {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().unwrap_or_default();
                Ok(SubmitSampleResponse { status, body, endpoint: endpoint_for_call })
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok(SubmitSampleResponse { status, body, endpoint: endpoint_for_call })
            }
            Err(e) => Err(format!("submission failed: {}", e)),
        }
    })
    .await
    .map_err(|e| format!("submit task join error: {}", e))??;

    Ok(result)
}
