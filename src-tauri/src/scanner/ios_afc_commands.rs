//! Tauri command surface for the iOS AFC live-triage backend.
//!
//! Talks to the `IosAfcBackend` (currently `PythonSidecar`) and forwards
//! its streaming events into Tauri event channels the frontend listens
//! on:
//!
//!   ios:walk_progress  -> { filesDone, bytesDone, elapsedSec }
//!   ios:file_hash      -> { path, name, size, sha256, sha1?, md5?, mtime? }
//!   ios:hash_match     -> { path, name, size, sha256, match: HashMatch }
//!   ios:walk_warn      -> { path, error }
//!   ios:walk_complete  -> { filesDone, bytesDone, elapsedSec }
//!   ios:walk_stopped   -> { filesDone, bytesDone, elapsedSec }

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tauri::{AppHandle, Emitter};

use crate::hash_db;
use crate::scanner::ios_afc_sidecar::{
    self as sidecar, AfcEntry, AfcWalkRequest, IosAfcBackend,
};

/// Per-scan counter so we can rate-limit the per-file hash-lookup
/// diagnostics that fire from the daemon event sink. Reset at the
/// start of every triage call.
static DIAG_LOOKUPS_PRINTED: AtomicUsize = AtomicUsize::new(0);
const DIAG_LOOKUP_BUDGET: usize = 5;

// ---------------------------------------------------------------------------
// Request/response types exposed to JS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IosLiveTriageOptions {
    /// AFC roots to walk. Defaults to `["/DCIM", "/Downloads", "/Recordings"]`.
    #[serde(default)]
    pub roots: Option<Vec<String>>,
    /// Hash algorithms to compute. Defaults to `["sha256"]`.
    #[serde(default)]
    pub algos: Option<Vec<String>>,
    /// Skip files smaller than this. Default 0.
    #[serde(default)]
    pub min_bytes: Option<u64>,
    /// Optional extension filter, lowercase with leading dot.
    #[serde(default)]
    pub extensions: Option<Vec<String>>,
    /// Hash list IDs to match against. Empty = no matching.
    #[serde(default)]
    pub hash_lists: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IosAfcSmokeResult {
    pub udid: String,
    pub dcim_folder_count: usize,
    pub sample_paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// Smoke: spawn → open → list /DCIM → return.
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn ios_afc_smoke(udid: Option<String>) -> Result<IosAfcSmokeResult, String> {
    let udid_for_thread = udid;
    tauri::async_runtime::spawn_blocking(move || -> Result<IosAfcSmokeResult, String> {
        let backend = sidecar::get_or_spawn_backend()?;
        let opened_udid = backend.open(udid_for_thread.as_deref())?;
        let entries = backend.list_dir("/DCIM")?;
        let sample = entries
            .iter()
            .take(5)
            .map(|e| e.path.clone())
            .collect::<Vec<_>>();
        Ok(IosAfcSmokeResult {
            udid: opened_udid,
            dcim_folder_count: entries.len(),
            sample_paths: sample,
        })
    })
    .await
    .map_err(|e| format!("smoke thread: {e}"))?
}

// ---------------------------------------------------------------------------
// Live triage: walk + stream hash + match against hash DB.
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn start_ios_live_triage_afc(
    app: AppHandle,
    udid: Option<String>,
    options: Option<IosLiveTriageOptions>,
) -> Result<(), String> {
    let opts = options.unwrap_or_default();
    let roots = opts
        .roots
        .unwrap_or_else(|| vec![
            "/DCIM".to_string(),
            "/Downloads".to_string(),
            "/Recordings".to_string(),
        ]);
    let algos = opts.algos.unwrap_or_else(|| vec!["sha256".to_string()]);
    let min_bytes = opts.min_bytes.unwrap_or(0);
    let extensions = opts.extensions;
    let hash_list_ids = opts.hash_lists.unwrap_or_default();

    let udid_for_thread = udid;

    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        // Always start a fresh daemon for a new scan. This ensures any
        // edits to `ios_afc_daemon.py` (e.g. new RPC commands) are
        // picked up without requiring a full app restart, and clears
        // any lingering state from a prior incomplete walk.
        sidecar::shutdown_backend();
        // Reset per-scan lookup-diagnostic budget so we get fresh
        // [iOS AFC] lookup … lines for this scan.
        DIAG_LOOKUPS_PRINTED.store(0, Ordering::Relaxed);
        let backend = sidecar::get_or_spawn_backend()?;
        backend.open(udid_for_thread.as_deref())?;

        // Open the hash DB once and share it with the sink. If it fails
        // we still proceed — matching is best-effort, walk_hash itself
        // must always work for triage.
        let hash_db_opt: Option<Arc<hash_db::HashDatabase>> =
            match hash_db::HashDatabase::new() {
                Ok(db) => Some(Arc::new(db)),
                Err(e) => {
                    eprintln!("[iOS AFC] hash DB unavailable for matching: {e}");
                    None
                }
            };

        let app_for_sink = app.clone();
        let hash_db_for_sink = hash_db_opt.clone();
        let lists_for_sink = hash_list_ids.clone();

        // One-shot diagnostic: confirm the DB has hashes of the kind we
        // will be checking, and that the list-name filter resolves. Helps
        // diagnose "scan completed, zero hits" — almost always one of:
        //   - selected list names don't match DB hash_lists.name rows
        //   - DB has MD5/SHA1 only but we're hashing SHA256
        //   - DB is empty
        if let Some(db) = hash_db_opt.as_ref() {
            let types: Vec<String> = db
                .get_hash_types()
                .into_iter()
                .collect();
            eprintln!(
                "[iOS AFC] hash DB ready. Types in DB: {:?}. Selected list names: {:?}",
                types, hash_list_ids
            );
            // Try a no-op query to confirm name filter doesn't return zero
            // rows due to typo: count hashes per requested list.
            if !hash_list_ids.is_empty() {
                for name in &hash_list_ids {
                    // Direct SQL probe — using check_hash_filtered with a
                    // sentinel hash that won't match; the SQL still runs
                    // and the prepare-fail surfaces a name-mismatch.
                    let probe = db.check_hash_filtered(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "SHA256",
                        &[name.clone()],
                    );
                    eprintln!(
                        "[iOS AFC] probe list_name='{}' SHA256 sentinel → {:?}",
                        name,
                        probe.as_ref().map(|o| o.is_some()).unwrap_or(false)
                    );
                }
            }
        }

        backend.set_event_sink(Box::new(move |ev: Value| {
            handle_event(
                &app_for_sink,
                hash_db_for_sink.as_ref(),
                &lists_for_sink,
                ev,
            );
        }));

        backend.start_walk_hash(&AfcWalkRequest {
            roots,
            algos,
            min_bytes,
            extensions,
        })?;
        Ok(())
    })
    .await
    .map_err(|e| format!("live triage thread: {e}"))?
}

#[tauri::command]
pub async fn stop_ios_live_triage_afc() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| -> Result<(), String> {
        let backend = sidecar::get_or_spawn_backend()?;
        backend.stop_walk()?;
        backend.clear_event_sink();
        Ok(())
    })
    .await
    .map_err(|e| format!("stop triage thread: {e}"))?
}

#[tauri::command]
pub async fn list_ios_afc_dir(
    udid: Option<String>,
    path: String,
) -> Result<Vec<AfcEntry>, String> {
    tauri::async_runtime::spawn_blocking(move || -> Result<Vec<AfcEntry>, String> {
        let backend = sidecar::get_or_spawn_backend()?;
        backend.open(udid.as_deref())?;
        backend.list_dir(&path)
    })
    .await
    .map_err(|e| format!("list dir thread: {e}"))?
}

#[tauri::command]
pub async fn pull_ios_afc_file(
    udid: Option<String>,
    path: String,
    dest: String,
) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || -> Result<u64, String> {
        let backend = sidecar::get_or_spawn_backend()?;
        backend.open(udid.as_deref())?;
        backend.pull(&path, &dest)
    })
    .await
    .map_err(|e| format!("pull thread: {e}"))?
}

/// Stream `path` via AFC and return a JPEG data URL (base64). Never
/// persists the source bytes. Intended for lazy viewport-triggered
/// thumbnail rendering in the Media Files panel.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IosAfcThumbnail {
    pub path: String,
    pub data_url: String,
    pub src_bytes: u64,
}

#[tauri::command]
pub async fn get_ios_afc_thumbnail(
    udid: Option<String>,
    path: String,
    max_dim: Option<u32>,
) -> Result<IosAfcThumbnail, String> {
    let dim = max_dim.unwrap_or(256);
    let p_for_thread = path.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<IosAfcThumbnail, String> {
        let backend = sidecar::get_or_spawn_backend()?;
        backend.open(udid.as_deref())?;
        let (data_url, src_bytes) = backend.thumbnail(&p_for_thread, dim)?;
        Ok(IosAfcThumbnail {
            path: p_for_thread,
            data_url,
            src_bytes,
        })
    })
    .await
    .map_err(|e| format!("thumbnail thread: {e}"))?
}

#[tauri::command]
pub async fn shutdown_ios_afc() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| {
        sidecar::shutdown_backend();
    })
    .await
    .map_err(|e| format!("shutdown thread: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Video thumbnail (daemon pipes AFC bytes through ffmpeg, returns JPEG b64).
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_ios_afc_video_thumbnail(
    udid: Option<String>,
    path: String,
    max_dim: Option<u32>,
) -> Result<IosAfcThumbnail, String> {
    let dim = max_dim.unwrap_or(320);
    let p_for_thread = path.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<IosAfcThumbnail, String> {
        let backend = sidecar::get_or_spawn_backend()?;
        backend.open(udid.as_deref())?;
        let (data_url, src_bytes) = backend.video_thumbnail(&p_for_thread, dim)?;
        Ok(IosAfcThumbnail {
            path: p_for_thread,
            data_url,
            src_bytes,
        })
    })
    .await
    .map_err(|e| format!("video thumbnail thread: {e}"))?
}

// ---------------------------------------------------------------------------
// scout-afc:// URI scheme — proxies HTTP Range requests to AFC.
// ---------------------------------------------------------------------------

use tauri::http::{header, Request, Response, StatusCode};

fn afc_mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "mov" => "video/quicktime",
        "mp4" | "m4v" => "video/mp4",
        "3gp" => "video/3gpp",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "heic" | "heif" => "image/heic",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        _ => "application/octet-stream",
    }
}

/// Parse an HTTP `Range: bytes=start-end` header. Mirrors the
/// permissive behavior of the local media_server parser.
fn parse_afc_range(header_val: &str, file_size: u64) -> Option<(u64, u64)> {
    let stripped = header_val.trim().strip_prefix("bytes=").unwrap_or(header_val);
    let parts: Vec<&str> = stripped.split('-').collect();
    if file_size == 0 {
        return None;
    }
    let last = file_size - 1;
    match parts.as_slice() {
        [s, e] if !s.is_empty() && !e.is_empty() => {
            let start = s.parse::<u64>().ok()?;
            let end = e.parse::<u64>().ok()?.min(last);
            if start > end {
                return None;
            }
            Some((start, end))
        }
        [s, ""] if !s.is_empty() => {
            let start = s.parse::<u64>().ok()?;
            if start > last {
                return None;
            }
            Some((start, last))
        }
        ["", e] if !e.is_empty() => {
            let suffix = e.parse::<u64>().ok()?;
            let start = file_size.saturating_sub(suffix);
            Some((start, last))
        }
        _ => None,
    }
}

/// Hard cap on bytes returned per Range request so a misbehaving
/// client can't ask us to copy a 4 GB video into a single response.
/// HTML5 video readers always re-issue small subsequent ranges.
const AFC_MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;

/// Resolve `scout-afc://...` requests by pulling bytes off the live
/// AFC connection. Path format:
///
/// ```text
///   scout-afc://afc/DCIM/106APPLE/IMG_6785.MOV
/// ```
///
/// The host portion (`afc`) is ignored. The path portion is treated
/// as the absolute AFC path. UDID is taken from the currently-open
/// device on the singleton backend; the caller is expected to have
/// already issued `open()` (which the live-triage flow does).
pub fn handle_afc_request(
    request: &Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let uri = request.uri();
    let raw_path = uri.path();
    let range_hdr_dbg = request
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    eprintln!(
        "[scout-afc] REQ uri='{}' path='{}' range='{}'",
        uri,
        raw_path,
        range_hdr_dbg,
    );
    let decoded = urlencoding::decode(raw_path)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| raw_path.to_string());

    // `convertFileSrc(path, 'scout-afc')` does encodeURIComponent on the
    // whole AFC path including the leading `/`, which produces a URL
    // like `http://scout-afc.localhost/%2FDCIM/...`. After decoding the
    // path component we end up with `//DCIM/...`. Collapse any number of
    // leading slashes back to exactly one so AFC stat() doesn't choke.
    let trimmed = decoded.trim_start_matches('/');
    let afc_path = format!("/{trimmed}");
    let mime = afc_mime_for(&afc_path);

    let backend = match sidecar::get_or_spawn_backend() {
        Ok(b) => b,
        Err(e) => return afc_error(StatusCode::SERVICE_UNAVAILABLE, e),
    };

    // We require the device to already be open (live-triage opens it).
    // Stat'ing tells us the total size for Content-Range and confirms
    // the path is reachable.
    let entry = match backend.stat(&afc_path) {
        Ok(e) => e,
        Err(e) => return afc_error(StatusCode::NOT_FOUND, e),
    };
    let total = entry.size;

    let range_hdr = request
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok());

    if let Some(rh) = range_hdr {
        if let Some((start, end_requested)) = parse_afc_range(rh, total) {
            // Cap the served slice; the client will follow up with
            // another Range starting at end+1 if it needs more.
            let max_end = start
                .saturating_add(AFC_MAX_RANGE_BYTES)
                .saturating_sub(1)
                .min(end_requested);
            let length = max_end.saturating_sub(start).saturating_add(1);

            let bytes = match backend.read_range(&afc_path, start, length) {
                Ok(b) => b,
                Err(e) => return afc_error(StatusCode::INTERNAL_SERVER_ERROR, e),
            };

            // Recompute end from the bytes we actually got (in case of
            // short read near EOF).
            let actual_end = start + (bytes.len() as u64).saturating_sub(1);
            return Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CONTENT_LENGTH, bytes.len().to_string())
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, actual_end, total),
                )
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(bytes)
                .unwrap();
        }
    }

    // No (or unparseable) Range — serve the first slice and let the
    // <video> element issue follow-up Range requests for the rest.
    let length = total.min(AFC_MAX_RANGE_BYTES);
    let bytes = match backend.read_range(&afc_path, 0, length) {
        Ok(b) => b,
        Err(e) => return afc_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let actual_end = (bytes.len() as u64).saturating_sub(1);

    // If the file is bigger than what we served, advertise partial
    // content so the browser knows to ask for more via Range.
    if total > bytes.len() as u64 {
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, bytes.len().to_string())
            .header(
                header::CONTENT_RANGE,
                format!("bytes 0-{}/{}", actual_end, total),
            )
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(bytes)
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, bytes.len().to_string())
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(bytes)
            .unwrap()
    }
}

fn afc_error(status: StatusCode, msg: String) -> Response<Vec<u8>> {
    eprintln!("[scout-afc] {} — {}", status, msg);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(msg.into_bytes())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Sink: classify each daemon event and bridge it onto Tauri channels.
// ---------------------------------------------------------------------------

fn handle_event(
    app: &AppHandle,
    hash_db: Option<&Arc<hash_db::HashDatabase>>,
    hash_lists: &[String],
    ev: Value,
) {
    let name = ev.get("event").and_then(|n| n.as_str()).unwrap_or("");
    match name {
        "file_hash" => {
            let path = ev.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let size = ev.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let sha256 = ev.get("sha256").and_then(|v| v.as_str());
            let sha1 = ev.get("sha1").and_then(|v| v.as_str());
            let md5 = ev.get("md5").and_then(|v| v.as_str());
            let name_only = path.rsplit('/').next().unwrap_or("").to_string();
            let mtime = ev
                .get("mtime")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let file_payload = json!({
                "path": path,
                "name": name_only,
                "size": size,
                "sha256": sha256,
                "sha1": sha1,
                "md5": md5,
                "mtime": mtime,
            });
            let _ = app.emit("ios:file_hash", &file_payload);

            // Hash matching — best-effort.
            if let Some(db) = hash_db {
                let diag_left = DIAG_LOOKUPS_PRINTED
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        if n < DIAG_LOOKUP_BUDGET { Some(n + 1) } else { None }
                    })
                    .is_ok();
                for (hex, kind) in [
                    (sha256, "SHA256"),
                    (sha1, "SHA1"),
                    (md5, "MD5"),
                ] {
                    if let Some(h) = hex {
                        let matched = if hash_lists.is_empty() {
                            db.check_hash(h, kind).unwrap_or(None)
                        } else {
                            db.check_hash_filtered(h, kind, hash_lists)
                                .unwrap_or(None)
                        };
                        if diag_left {
                            eprintln!(
                                "[iOS AFC] lookup {} hash={} (lists={}) → match={}",
                                kind,
                                h,
                                if hash_lists.is_empty() { "ALL".to_string() } else { format!("{:?}", hash_lists) },
                                matched.is_some()
                            );
                        }
                        if let Some(m) = matched {
                            // Emit a payload matching the AndroidHashMatch
                            // camelCase shape that UnifiedDashboard renders,
                            // so iOS hits show file path, size, hash, and
                            // source instead of NaN MB / blanks.
                            let payload = json!({
                                "filePath": path,
                                "fileName": name_only,
                                "fileSize": size,
                                "md5Hash": md5.unwrap_or(""),
                                "sha256Hash": sha256.unwrap_or(""),
                                "matchedHash": h,
                                "hashType": kind,
                                "listName": m.list_name,
                                "listSource": m.source,
                                "description": m.description,
                                "severity": "Critical",
                            });
                            let _ = app.emit("ios:hash_match", &payload);
                            break; // one match per file is enough
                        }
                    }
                }
            }
        }
        "progress" => {
            let _ = app.emit(
                "ios:walk_progress",
                &json!({
                    "filesDone": ev.get("files_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "bytesDone": ev.get("bytes_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "elapsedSec": ev.get("elapsed_s").and_then(|v| v.as_f64()).unwrap_or(0.0),
                }),
            );
        }
        "walk_warn" => {
            let _ = app.emit(
                "ios:walk_warn",
                &json!({
                    "path": ev.get("path"),
                    "error": ev.get("error"),
                }),
            );
        }
        "phase_started" => {
            let _ = app.emit(
                "ios:walk_phase",
                &json!({
                    "phase": ev.get("phase").and_then(|v| v.as_str()).unwrap_or(""),
                    "state": "started",
                }),
            );
        }
        "phase_complete" => {
            let _ = app.emit(
                "ios:walk_phase",
                &json!({
                    "phase": ev.get("phase").and_then(|v| v.as_str()).unwrap_or(""),
                    "state": "complete",
                    "filesDone": ev.get("files_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "bytesDone": ev.get("bytes_done").and_then(|v| v.as_u64()).unwrap_or(0),
                }),
            );
        }
        "complete" => {
            let _ = app.emit(
                "ios:walk_complete",
                &json!({
                    "filesDone": ev.get("files_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "bytesDone": ev.get("bytes_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "elapsedSec": ev.get("elapsed_s").and_then(|v| v.as_f64()).unwrap_or(0.0),
                }),
            );
        }
        "stopped" => {
            let _ = app.emit(
                "ios:walk_stopped",
                &json!({
                    "filesDone": ev.get("files_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "bytesDone": ev.get("bytes_done").and_then(|v| v.as_u64()).unwrap_or(0),
                    "elapsedSec": ev.get("elapsed_s").and_then(|v| v.as_f64()).unwrap_or(0.0),
                }),
            );
        }
        "afc_reconnect" => {
            // Daemon is tearing down a dead AFC connection and rebuilding.
            // Surface to the UI so the operator knows the next op may be slow.
            eprintln!(
                "[iOS AFC] reconnect (attempt {}): {}",
                ev.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0),
                ev.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
            );
            let _ = app.emit(
                "ios:afc_reconnect",
                &json!({
                    "udid": ev.get("udid"),
                    "attempt": ev.get("attempt"),
                    "reason": ev.get("reason"),
                }),
            );
        }
        "afc_reconnected" => {
            eprintln!(
                "[iOS AFC] reconnected (attempt {})",
                ev.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0),
            );
            let _ = app.emit(
                "ios:afc_reconnected",
                &json!({
                    "udid": ev.get("udid"),
                    "attempt": ev.get("attempt"),
                }),
            );
        }
        _ => {
            // Unknown streaming event; surface for debugging.
            eprintln!("[iOS AFC] sink: unhandled event {ev}");
        }
    }
}
