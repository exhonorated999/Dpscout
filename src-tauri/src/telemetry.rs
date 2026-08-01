// telemetry.rs
//
// Lightweight, privacy-respecting usage analytics.
//
// What we send:
//   - machine_id (SHA-256 fingerprint, same value used for licensing)
//   - platform   ("desktop" or "portable")
//   - app_version (from CARGO_PKG_VERSION)
//   - events    { event_name: count_increment }
//
// What we DO NOT send: case data, file paths, hashes, user identity,
// agency name, badge number, scan results — anything besides the
// event counter map above.
//
// Wire model:
//   - Counts accumulate in a JSON file at %APPDATA%\Hindsight\telemetry.json
//   - On app launch we attempt one flush (best-effort). After a successful
//     POST, the local counters are cleared.
//   - If the server is unreachable, counters stay on disk and re-flush
//     on the next launch.
//
// Opt-out:
//   - A small flag file at %APPDATA%\Hindsight\telemetry_disabled is the
//     single source of truth. Default is OPT-IN (no file present).
//   - When the flag is present we never record and never flush.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

const TELEMETRY_ENDPOINT: &str =
    "https://scout-server-production-1d65.up.railway.app/api/telemetry";

/// Allow-list of events that the desktop is permitted to record.
/// Anything outside this set is silently dropped client-side so a typo
/// in a call site never leaks an unintended name.
pub const ALLOWED_EVENTS: &[&str] = &[
    "app_launched",
    "warrant_triage_opened",
    "hash_scan_run",
    "intrusion_scan_run",
    "ios_triage_opened",
    "android_triage_opened",
    "deleted_media_scan_run",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TelemetryStore {
    /// event_name → pending count to flush
    #[serde(default)]
    events: HashMap<String, u64>,
}

// One in-memory copy of the counter store. Persists to disk on every
// mutation so we don't lose counts if the process is killed.
static STORE: Mutex<Option<TelemetryStore>> = Mutex::new(None);

// ---------- path helpers ----------

fn telemetry_file_path() -> Result<PathBuf, String> {
    let mut p = crate::settings::get_base_dir()?;
    p.push("telemetry.json");
    Ok(p)
}

fn opt_out_flag_path() -> Result<PathBuf, String> {
    let mut p = crate::settings::get_base_dir()?;
    p.push("telemetry_disabled");
    Ok(p)
}

/// Returns true if telemetry is currently enabled (default = ON).
pub fn is_enabled() -> bool {
    match opt_out_flag_path() {
        Ok(p) => !p.exists(),
        Err(_) => true,
    }
}

/// Toggle telemetry. `enabled = false` writes the opt-out flag and
/// clears any pending counters so nothing already buffered is sent.
pub fn set_enabled(enabled: bool) -> Result<(), String> {
    let flag = opt_out_flag_path()?;
    if enabled {
        if flag.exists() {
            let _ = fs::remove_file(&flag);
        }
    } else {
        // Make sure parent dir exists
        if let Some(parent) = flag.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&flag, b"disabled")
            .map_err(|e| format!("failed to write opt-out flag: {}", e))?;
        // Drop anything already buffered.
        let mut guard = STORE.lock().map_err(|_| "store lock poisoned".to_string())?;
        *guard = Some(TelemetryStore::default());
        let path = telemetry_file_path()?;
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

// ---------- disk I/O ----------

fn load_from_disk() -> TelemetryStore {
    let path = match telemetry_file_path() {
        Ok(p) => p,
        Err(_) => return TelemetryStore::default(),
    };
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return TelemetryStore::default(),
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_to_disk(store: &TelemetryStore) {
    let path = match telemetry_file_path() {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string(store) {
        let _ = fs::write(&path, json);
    }
}

fn ensure_loaded(guard: &mut std::sync::MutexGuard<'_, Option<TelemetryStore>>) {
    if guard.is_none() {
        **guard = Some(load_from_disk());
    }
}

// ---------- public API ----------

/// Record a single occurrence of `event_name`. Cheap, non-blocking,
/// and silently no-ops if telemetry is disabled or the event isn't
/// on the allow-list.
pub fn record(event_name: &str) {
    if !is_enabled() {
        return;
    }
    if !ALLOWED_EVENTS.contains(&event_name) {
        eprintln!("[telemetry] dropping unknown event: {}", event_name);
        return;
    }
    let mut guard = match STORE.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    ensure_loaded(&mut guard);
    if let Some(store) = guard.as_mut() {
        let entry = store.events.entry(event_name.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
        save_to_disk(store);
    }
}

#[derive(Debug, Serialize)]
struct FlushPayload {
    machine_id: String,
    platform: String,
    app_version: String,
    events: HashMap<String, u64>,
}

/// Synchronously POST any buffered counters. Returns Ok(true) if a
/// payload was actually sent, Ok(false) if there was nothing to send,
/// Err(_) on network failure. On success the local store is cleared.
fn flush_blocking() -> Result<bool, String> {
    if !is_enabled() {
        return Ok(false);
    }

    // Pull the current snapshot under lock; release before HTTP.
    let snapshot = {
        let mut guard = STORE.lock().map_err(|_| "store lock poisoned".to_string())?;
        ensure_loaded(&mut guard);
        let store = guard.as_mut().ok_or_else(|| "store empty".to_string())?;
        if store.events.is_empty() {
            return Ok(false);
        }
        store.events.clone()
    };

    let machine_id = crate::licensing::get_machine_id()
        .unwrap_or_else(|_| "unknown".to_string());
    let payload = FlushPayload {
        machine_id,
        platform: crate::licensing::get_platform().to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        events: snapshot.clone(),
    };

    let body = serde_json::to_string(&payload)
        .map_err(|e| format!("serialize: {}", e))?;

    let resp = ureq::post(TELEMETRY_ENDPOINT)
        .timeout(std::time::Duration::from_secs(15))
        .set("Content-Type", "application/json")
        .set(
            "User-Agent",
            concat!("DatapilotScout/", env!("CARGO_PKG_VERSION")),
        )
        .send_string(&body);

    match resp {
        Ok(r) if r.status() < 500 => {
            // Server accepted (it always returns 200 anyway). Clear
            // exactly the events we shipped so any concurrent writes
            // that arrived after the snapshot are preserved.
            let mut guard = STORE.lock().map_err(|_| "store lock poisoned".to_string())?;
            if let Some(store) = guard.as_mut() {
                for (k, v) in snapshot.iter() {
                    if let Some(cur) = store.events.get_mut(k) {
                        *cur = cur.saturating_sub(*v);
                        if *cur == 0 {
                            store.events.remove(k);
                        }
                    }
                }
                save_to_disk(store);
            }
            Ok(true)
        }
        Ok(r) => Err(format!("server error {}", r.status())),
        Err(ureq::Error::Status(code, _)) => Err(format!("status {}", code)),
        Err(e) => Err(format!("network: {}", e)),
    }
}

/// Best-effort background flush. Spawns a thread; never blocks the caller.
pub fn flush_in_background() {
    if !is_enabled() {
        return;
    }
    std::thread::spawn(|| {
        if let Err(e) = flush_blocking() {
            eprintln!("[telemetry] flush failed: {}", e);
        }
    });
}

// ---------- Tauri commands ----------

#[tauri::command]
pub fn telemetry_track_event(event_name: String) -> Result<(), String> {
    record(&event_name);
    Ok(())
}

#[tauri::command]
pub fn telemetry_get_enabled() -> bool {
    is_enabled()
}

#[tauri::command]
pub fn telemetry_set_enabled(enabled: bool) -> Result<(), String> {
    set_enabled(enabled)
}
