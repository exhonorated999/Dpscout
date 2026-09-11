use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const SERVER_URL: &str = "https://scout-server-production-1d65.up.railway.app";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationData {
    pub agency_name: String,
    pub contact_name: String,
    pub contact_email: String,
    pub agency_address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub zip_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub registered: bool,
    pub agency_name: Option<String>,
    pub plan: Option<String>,       // trial | annual | perpetual
    pub status: Option<String>,     // active | expired
    pub expires_at: Option<String>,
    pub days_remaining: i64,
    pub is_expired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub agency_id: Option<i64>,
    pub trial_expires_at: Option<String>,
    pub trial_days: Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateResponse {
    pub success: bool,
    pub plan: Option<String>,
    pub expires_at: Option<String>,
    pub days_remaining: Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub update_available: bool,
    pub latest_version: Option<String>,
    pub download_url: Option<String>,
    pub current_version: Option<String>,
}

/// What support needs to rebind a machine whose ID changed underneath it.
///
/// The `wmic` removal in Windows 11 24H2 silently dropped the motherboard
/// serial out of the desktop fingerprint, so anyone who registered while
/// running a build that used `wmic` is on the server under `legacy_machine_id`
/// rather than `machine_id`. There is no safe automatic fallback — the server
/// authorizes on the raw hash, and the legacy hash is guessable — so the user
/// reads both values off this panel and support repoints the record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseDiagnostics {
    /// The ID this install reports today.
    pub machine_id: String,
    /// The ID this install reported while the motherboard serial was being
    /// silently dropped. `None` when there is no distinct legacy identity.
    pub legacy_machine_id: Option<String>,
    /// "desktop" or "portable".
    pub platform: String,
    pub app_version: String,
    /// Whether a server-confirmed registration is saved locally.
    pub registered_locally: bool,
    /// Set when the motherboard serial could not be read at all, which means
    /// the fingerprint is running on COMPUTERNAME + USERNAME alone.
    pub fingerprint_warning: Option<String>,
}

// ---------------------------------------------------------------------------
// Machine ID — unique fingerprint for this installation
// ---------------------------------------------------------------------------

/// Returns "portable" when built with the `portable` feature, else "desktop".
pub fn get_platform() -> &'static str {
    if cfg!(feature = "portable") { "portable" } else { "desktop" }
}

/// The COMPUTERNAME + USERNAME part of the desktop fingerprint. Always
/// available on Windows, which is why `get_machine_id` can never fail there.
#[cfg(not(feature = "portable"))]
fn base_identity_components() -> Vec<String> {
    let mut components = Vec::new();
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        components.push(name);
    }
    if let Ok(user) = std::env::var("USERNAME") {
        components.push(user);
    }
    components
}

#[cfg(not(feature = "portable"))]
fn hash_components(components: &[String]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(components.join("|").as_bytes());
    hex::encode(hasher.finalize())
}

/// Read `Win32_BaseBoard.SerialNumber` via WMI.
///
/// This replaces `wmic baseboard get serialnumber`. `wmic` was demoted to a
/// disabled-by-default Feature-on-Demand and is simply ABSENT on Windows 11
/// 24H2 (build 26100) and later — the process spawn fails outright. The old
/// code swallowed that with `if let Ok(..)`, so the motherboard serial
/// silently vanished from the fingerprint and the machine ID changed the
/// moment a user took the 24H2 update. That looks exactly like "Machine not
/// registered" on a machine that registered fine a month earlier.
///
/// `wmic baseboard get serialnumber` was only ever printing this WMI property,
/// so reading it directly returns a byte-identical string and therefore an
/// identical hash on machines where `wmic` used to work. No re-registration.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn baseboard_serial() -> Option<String> {
    use wmi::{COMLibrary, WMIConnection, Variant};
    use std::collections::HashMap;

    let com = COMLibrary::new().ok()?;
    let conn = WMIConnection::new(com).ok()?;
    let rows: Vec<HashMap<String, Variant>> = conn
        .raw_query("SELECT SerialNumber FROM Win32_BaseBoard")
        .ok()?;

    for row in rows {
        if let Some(Variant::String(serial)) = row.get("SerialNumber") {
            let trimmed = serial.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Legacy `wmic` path, kept only as a fallback for Windows builds old enough
/// that WMI access could fail while `wmic` still shipped. Produces the same
/// string as `baseboard_serial` when both work.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn baseboard_serial_via_wmic() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let output = std::process::Command::new("wmic")
        .args(["baseboard", "get", "serialnumber"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Read `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
///
/// Used ONLY when no motherboard serial can be read. Some machines genuinely
/// cannot supply one — VMs, OEMs that leave the field blank or set it to
/// "Default string", and boxes with a damaged WMI repository — which used to
/// leave the fingerprint running on COMPUTERNAME + USERNAME alone. That is
/// both guessable and collision-prone: image two workstations from the same
/// template and give them the same local username and they share an identity.
///
/// MachineGuid is generated at Windows install time, is stable across reboots,
/// BIOS updates and hardware swaps, and is readable by any user without
/// elevation. It changes only on a Windows reinstall/re-image.
///
/// Note this is read under HKEY_LOCAL_MACHINE with a 64-bit view: the key
/// lives in the shared (non-redirected) part of the registry, but being
/// explicit avoids surprises if this ever runs as a 32-bit process under
/// WOW64 redirection.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn machine_guid() -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .ok()?;
    let guid: String = key.get_value("MachineGuid").ok()?;
    let trimmed = guid.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// Some OEMs ship placeholder serials. Treating those as real would make every
/// machine from that vendor share one identity, which is worse than having no
/// serial at all — so reject them and let MachineGuid take over.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn is_usable_serial(serial: &str) -> bool {
    let s = serial.trim();
    if s.len() < 3 {
        return false;
    }
    const PLACEHOLDERS: [&str; 8] = [
        "default string",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "none",
        "n/a",
        "not applicable",
        "system serial number",
        "0123456789",
    ];
    let lower = s.to_ascii_lowercase();
    if PLACEHOLDERS.contains(&lower.as_str()) {
        return false;
    }
    // All-zero / all-same-character serials carry no information.
    !s.chars().all(|c| c == s.chars().next().unwrap())
}

pub fn get_machine_id() -> Result<String, String> {
    // Portable build: derive identity from the USB drive serial number
    #[cfg(feature = "portable")]
    {
        use sha2::{Sha256, Digest};
        let serial = get_usb_drive_serial()?;
        let mut hasher = Sha256::new();
        hasher.update(serial.as_bytes());
        let result = hasher.finalize();
        return Ok(hex::encode(result));
    }

    // Desktop build: hardware fingerprint (motherboard + user)
    #[cfg(not(feature = "portable"))]
    {
        let mut components = base_identity_components();

        #[cfg(target_os = "windows")]
        {
            // Order matters. A usable motherboard serial keeps the hash
            // byte-identical to every previous build, so machines that can
            // read one never re-register. MachineGuid is only consulted when
            // there is no usable serial — those machines were otherwise
            // running on COMPUTERNAME + USERNAME alone, which collides across
            // identically-imaged workstations.
            let serial = baseboard_serial()
                .or_else(baseboard_serial_via_wmic)
                .filter(|s| is_usable_serial(s));

            match serial {
                Some(serial) => components.push(serial),
                None => match machine_guid() {
                    Some(guid) => {
                        eprintln!(
                            "[Licensing] No usable motherboard serial; \
                             using registry MachineGuid for machine identity"
                        );
                        components.push(guid);
                    }
                    None => eprintln!(
                        "[Licensing] Neither motherboard serial nor MachineGuid \
                         could be read; machine ID falls back to name+user only"
                    ),
                },
            }
        }

        if components.is_empty() {
            return Err("Cannot determine machine identity".to_string());
        }

        Ok(hash_components(&components))
    }
}

/// The machine ID this install would have reported while the motherboard
/// serial was being silently dropped (see `baseboard_serial`). Anyone who
/// registered during that window is on the server under THIS id, not the one
/// `get_machine_id()` now returns.
///
/// Deliberately NOT used as an automatic licensing fallback. The server treats
/// `machine_id` as an unauthenticated bearer identity — it looks an agency up
/// by the hash and nothing else. Accepting a name+user-only hash would mean
/// anyone who sets COMPUTERNAME and USERNAME to a licensed agency's values
/// collides with them and is served their license. A motherboard serial is at
/// least not guessable; `DESK-PD01` + `jsmith` very much is.
///
/// So affected installs are rebound by support instead: read this value and
/// the current one out of the diagnostics, then repoint the server record.
/// Closing this properly needs a real credential (a per-install secret issued
/// at activation and proven on later requests) rather than a fingerprint.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
pub fn get_legacy_machine_id() -> Option<String> {
    let base = base_identity_components();
    if base.is_empty() {
        return None;
    }
    let legacy = hash_components(&base);
    // Only meaningful when it actually differs — i.e. a serial is readable now.
    match get_machine_id() {
        Ok(current) if current != legacy => Some(legacy),
        _ => None,
    }
}

/// Get the volume serial number of the drive this exe is running from.
/// Used as the stable USB identity for portable licensing.
#[cfg(feature = "portable")]
fn get_usb_drive_serial() -> Result<String, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Cannot find exe path: {}", e))?;
    let drive_root = exe_path
        .components()
        .next()
        .ok_or_else(|| "Cannot determine drive letter".to_string())?
        .as_os_str()
        .to_string_lossy()
        .to_string();
    // Ensure it ends with backslash (e.g. "E:\")
    let root = if drive_root.ends_with('\\') {
        drive_root
    } else {
        format!("{}\\", drive_root)
    };

    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = OsStr::new(&root)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut serial: u32 = 0;
        let ok = unsafe {
            winapi::um::fileapi::GetVolumeInformationW(
                wide.as_ptr(),
                std::ptr::null_mut(), 0,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(), 0,
            )
        };
        if ok == 0 {
            return Err(format!("GetVolumeInformationW failed for {}", root));
        }
        Ok(format!("USB-VOL-{:08X}", serial))
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Portable USB serial only supported on Windows".to_string())
    }
}

// ---------------------------------------------------------------------------
// Local license cache (SQLite)
// ---------------------------------------------------------------------------

fn get_license_db_path() -> Result<PathBuf, String> {
    // Portable: <usb>\ScoutData\scout_license.db — same root every other
    // subsystem now resolves through, so the stick holds one self-contained
    // data folder.
    #[cfg(feature = "portable")]
    {
        return crate::app_paths::license_db_path();
    }

    // Desktop: store in %APPDATA%\Hindsight\ so it survives installer updates
    #[cfg(not(feature = "portable"))]
    let new_path = crate::app_paths::license_db_path()?;

    // Migrate from old location (next to exe) if new doesn't exist yet
    #[cfg(not(feature = "portable"))]
    if !new_path.exists() {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let old_path = exe_dir.join("scout_license.db");
                if old_path.exists() {
                    eprintln!("[License] Migrating license DB from {:?} to {:?}", old_path, new_path);
                    if let Err(e) = std::fs::copy(&old_path, &new_path) {
                        eprintln!("[License] Migration copy failed: {}", e);
                    } else {
                        let _ = std::fs::remove_file(&old_path);
                        eprintln!("[License] ✓ License DB migrated successfully");
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "portable"))]
    return Ok(new_path);
}

fn init_license_db() -> Result<rusqlite::Connection, String> {
    let path = get_license_db_path()?;
    let conn = rusqlite::Connection::open(&path)
        .map_err(|e| format!("Failed to open license DB: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS license_cache (
            id INTEGER PRIMARY KEY,
            registered INTEGER DEFAULT 0,
            agency_name TEXT,
            plan TEXT,
            status TEXT,
            expires_at TEXT,
            days_remaining INTEGER DEFAULT 0,
            is_expired INTEGER DEFAULT 1,
            last_check TEXT,
            machine_id TEXT
        )", [],
    ).map_err(|e| format!("Failed to create license_cache: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS registration_info (
            id INTEGER PRIMARY KEY,
            agency_name TEXT,
            contact_name TEXT,
            contact_email TEXT,
            agency_address TEXT,
            city TEXT,
            state TEXT,
            zip_code TEXT,
            registered_at TEXT
        )", [],
    ).map_err(|e| format!("Failed to create registration_info: {}", e))?;

    Ok(conn)
}

fn cache_license(info: &LicenseInfo) -> Result<(), String> {
    let conn = init_license_db()?;
    let machine_id = get_machine_id().unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute("DELETE FROM license_cache", [])
        .map_err(|e| format!("Failed to clear cache: {}", e))?;

    conn.execute(
        "INSERT INTO license_cache (registered, agency_name, plan, status, expires_at, days_remaining, is_expired, last_check, machine_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            info.registered as i32,
            info.agency_name,
            info.plan,
            info.status,
            info.expires_at,
            info.days_remaining,
            info.is_expired as i32,
            now,
            machine_id,
        ],
    ).map_err(|e| format!("Failed to cache license: {}", e))?;

    Ok(())
}

pub(crate) fn load_cached_license() -> Result<Option<LicenseInfo>, String> {
    let conn = init_license_db()?;

    let result = conn.query_row(
        "SELECT registered, agency_name, plan, status, expires_at, days_remaining, is_expired FROM license_cache LIMIT 1",
        [],
        |row| {
            Ok(LicenseInfo {
                registered: row.get::<_, i32>(0).unwrap_or(0) != 0,
                agency_name: row.get(1).ok(),
                plan: row.get(2).ok(),
                status: row.get(3).ok(),
                expires_at: row.get(4).ok(),
                days_remaining: row.get::<_, i64>(5).unwrap_or(0),
                is_expired: row.get::<_, i32>(6).unwrap_or(1) != 0,
            })
        },
    );

    match result {
        Ok(info) => Ok(Some(info)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to load cached license: {}", e)),
    }
}

pub fn is_registration_saved() -> bool {
    if let Ok(conn) = init_license_db() {
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM registration_info", [], |row| row.get(0)
        ).unwrap_or(0);
        count > 0
    } else {
        false
    }
}

fn save_registration(data: &RegistrationData) -> Result<(), String> {
    let conn = init_license_db()?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute("DELETE FROM registration_info", [])
        .map_err(|e| format!("Failed to clear registration: {}", e))?;
    conn.execute(
        "INSERT INTO registration_info (agency_name, contact_name, contact_email, agency_address, city, state, zip_code, registered_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            data.agency_name, data.contact_name, data.contact_email,
            data.agency_address, data.city, data.state, data.zip_code, now
        ],
    ).map_err(|e| format!("Failed to save registration: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API — Tauri commands
// ---------------------------------------------------------------------------

/// Check if the app has been registered with the server
pub fn check_is_registered_with_server() -> Result<bool, String> {
    Ok(is_registration_saved())
}

/// Register agency with the server (first-time setup)
/// Turn a failed `ureq` request into a human-readable message.
///
/// On a non-2xx HTTP status, `ureq` returns `Error::Status(code, response)`
/// and the server's JSON body carries the real reason in `{"detail": "..."}`.
/// Surface that message so the user sees e.g. "This license key is not
/// assigned to your agency." instead of a bare "status code 403".
fn ureq_error_message(context: &str, err: ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, response) => {
            let body = response.into_string().unwrap_or_default();
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("detail")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string())
                });
            match detail {
                Some(msg) if !msg.trim().is_empty() => msg,
                _ => format!("{}: server returned status {}", context, code),
            }
        }
        ureq::Error::Transport(t) => format!("{}: {}", context, t),
    }
}

pub fn register_agency(data: RegistrationData) -> Result<RegisterResponse, String> {
    let machine_id = get_machine_id()?;
    let app_version = env!("CARGO_PKG_VERSION").to_string();

    let body = serde_json::json!({
        "agency_name": data.agency_name,
        "contact_name": data.contact_name,
        "contact_email": data.contact_email,
        "agency_address": data.agency_address,
        "city": data.city,
        "state": data.state,
        "zip_code": data.zip_code,
        "machine_id": machine_id,
        "app_version": app_version,
        "platform": get_platform(),
    });

    let resp = ureq::post(&format!("{}/api/register", SERVER_URL))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| ureq_error_message("Registration failed", e))?;

    let text = resp.into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let reg: RegisterResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if reg.success {
        // Save registration locally
        save_registration(&data)?;

        // Cache the initial trial license
        let info = LicenseInfo {
            registered: true,
            agency_name: Some(data.agency_name),
            plan: Some("trial".to_string()),
            status: Some("active".to_string()),
            expires_at: reg.trial_expires_at.clone(),
            days_remaining: reg.trial_days.unwrap_or(30),
            is_expired: false,
        };
        cache_license(&info)?;
    }

    Ok(reg)
}

/// Check license status (online with offline fallback).
///
/// A debug build is never license-gated. `debug_assertions` is on for
/// `cargo build` / `tauri dev` and off for every release bundle, so the
/// override below is compiled out of anything `npx tauri build` produces —
/// it cannot escape into a shipped installer.
///
/// The real check still runs first, so the cache stays truthful and Settings
/// keeps showing the machine's actual agency/plan. Only the fields that can
/// lock the UI are overridden, and `days_remaining` is set to an absurd value
/// so a developer can tell at a glance that they are looking at the override
/// and not a real license.
pub fn get_license_status() -> Result<LicenseInfo, String> {
    let real = check_license_with_server();

    #[cfg(debug_assertions)]
    {
        let mut info = real.unwrap_or_else(|e| {
            eprintln!("[Licensing] debug build: status check failed ({}), continuing anyway", e);
            LicenseInfo {
                registered: false,
                agency_name: None,
                plan: None,
                status: None,
                expires_at: None,
                days_remaining: 0,
                is_expired: true,
            }
        });

        if !info.registered || info.is_expired {
            eprintln!(
                "[Licensing] debug build: server says registered={} expired={} — \
                 bypassing the license gate (this override does not exist in release builds)",
                info.registered, info.is_expired
            );
        }

        info.registered = true;
        info.is_expired = false;
        info.days_remaining = DEV_LICENSE_DAYS;
        if info.plan.is_none() {
            info.plan = Some("developer".to_string());
        }
        if info.status.is_none() {
            info.status = Some("active".to_string());
        }
        if info.agency_name.is_none() {
            info.agency_name = Some("DEVELOPER BUILD (unlicensed)".to_string());
        }
        return Ok(info);
    }

    #[cfg(not(debug_assertions))]
    real
}

/// Obvious-on-sight stand-in for a real remaining-days count in debug builds.
#[cfg(debug_assertions)]
const DEV_LICENSE_DAYS: i64 = 9999;

fn check_license_with_server() -> Result<LicenseInfo, String> {
    let machine_id = get_machine_id()?;

    // Try online check first
    let body = serde_json::json!({ "machine_id": machine_id, "platform": get_platform() });

    match ureq::post(&format!("{}/api/license/status", SERVER_URL))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(resp) => {
            let text = resp.into_string()
                .map_err(|e| format!("Failed to read response: {}", e))?;
            let info: LicenseInfo = serde_json::from_str(&text)
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            // Cache for offline use
            let _ = cache_license(&info);
            Ok(info)
        }
        Err(_) => {
            // Offline fallback — use cached data
            eprintln!("[Licensing] Server unreachable, using cached license data");
            match load_cached_license()? {
                Some(cached) => Ok(cached),
                None => Ok(LicenseInfo {
                    registered: is_registration_saved(),
                    agency_name: None,
                    plan: None,
                    status: None,
                    expires_at: None,
                    days_remaining: 0,
                    is_expired: true,
                }),
            }
        }
    }
}

/// Activate a license key
pub fn activate_license_key(license_key: String) -> Result<ActivateResponse, String> {
    let machine_id = get_machine_id()?;

    let body = serde_json::json!({
        "license_key": license_key,
        "machine_id": machine_id,
        "platform": get_platform(),
    });

    let resp = ureq::post(&format!("{}/api/license/activate", SERVER_URL))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| ureq_error_message("License activation failed", e))?;

    let text = resp.into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let act: ActivateResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if act.success {
        // Refresh the cached license info
        let _ = get_license_status();
    }

    Ok(act)
}

/// Gather the identity values support needs to rebind a stranded install.
/// Never fails hard — a diagnostics panel that errors out is useless.
pub fn get_license_diagnostics() -> LicenseDiagnostics {
    let machine_id = get_machine_id().unwrap_or_else(|e| format!("UNAVAILABLE: {}", e));

    #[cfg(all(not(feature = "portable"), target_os = "windows"))]
    let legacy_machine_id = get_legacy_machine_id();
    #[cfg(not(all(not(feature = "portable"), target_os = "windows")))]
    let legacy_machine_id: Option<String> = None;

    // Only a desktop Windows build folds in a motherboard serial, so only it
    // can lose one. A missing serial is no longer worth reporting on its own —
    // MachineGuid covers it and the resulting ID is stable. Warn only when
    // BOTH are unavailable, which is the genuinely weak case.
    #[cfg(all(not(feature = "portable"), target_os = "windows"))]
    let fingerprint_warning = {
        let has_serial = baseboard_serial()
            .or_else(baseboard_serial_via_wmic)
            .filter(|s| is_usable_serial(s))
            .is_some();
        if has_serial || machine_guid().is_some() {
            None
        } else {
            Some(
                "Neither the motherboard serial nor the Windows MachineGuid could be \
                 read, so this machine's ID is based on computer name and user name \
                 only. Report this to support — the ID may collide with another \
                 machine."
                    .to_string(),
            )
        }
    };
    #[cfg(not(all(not(feature = "portable"), target_os = "windows")))]
    let fingerprint_warning: Option<String> = None;

    LicenseDiagnostics {
        machine_id,
        legacy_machine_id,
        platform: get_platform().to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        registered_locally: is_registration_saved(),
        fingerprint_warning,
    }
}

/// Check for software updates
pub fn check_for_updates() -> Result<UpdateInfo, String> {    let current = env!("CARGO_PKG_VERSION");

    let url = format!("{}/api/updates/check?current_version={}", SERVER_URL, current);

    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("Update check failed: {}", e))?;

    let text = resp.into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let info: UpdateInfo = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(info)
}

// ---------------------------------------------------------------------------
// Bug Reports
// ---------------------------------------------------------------------------

const INTELLECT_API: &str = "https://intellect-unified-dashboard-production.up.railway.app/api/bug-reports";
const INTELLECT_API_KEY: &str = "INT-KEDG-I69Q-OD2C-Z0HX";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugReportData {
    pub title: String,
    pub description: String,
    /// Optional absolute file paths to image attachments (PNG/JPG/JPEG/WEBP).
    /// Server caps at 3 images, 5 MB each. Older callers may omit this field.
    #[serde(default)]
    pub attachment_paths: Option<Vec<String>>,
}

const MAX_ATTACHMENTS: usize = 3;
const MAX_ATTACHMENT_BYTES: u64 = 5 * 1024 * 1024;

/// Guess a sensible content-type from a file extension. Falls back to
/// `application/octet-stream` — server will reject anything not `image/*`.
fn guess_image_mime(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        _ => "application/octet-stream",
    }
}

/// Build a multipart/form-data body. Returns (body_bytes, content_type_header).
/// `text_fields`: list of (field_name, value).
/// `files`: list of (field_name, filename, content_type, bytes).
fn build_multipart_body(
    text_fields: &[(&str, &str)],
    files: &[(String, String, String, Vec<u8>)],
) -> (Vec<u8>, String) {
    // Boundary: random-ish but deterministic per call. ureq has no built-in
    // multipart helper, so we hand-roll the body. Boundary must not appear
    // inside any field value or file content; using a long random hex prefix
    // keeps the collision probability negligible.
    let boundary = format!(
        "----ScoutBugReportBoundary{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let mut body: Vec<u8> = Vec::new();
    let crlf = b"\r\n";

    for (name, value) in text_fields {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(crlf);
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(crlf);
    }

    for (field, filename, ctype, bytes) in files {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(crlf);
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                field, filename
            )
            .as_bytes(),
        );
        body.extend_from_slice(
            format!("Content-Type: {}\r\n\r\n", ctype).as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(crlf);
    }

    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");

    let content_type = format!("multipart/form-data; boundary={}", boundary);
    (body, content_type)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugReportResponse {
    pub ok: bool,
    pub bug_id: Option<i64>,
    pub intellect_id: Option<String>,
    pub message: Option<String>,
}

/// Submit bug report to both Scout server and Intellect LE Command Center.
pub fn submit_bug_report(data: BugReportData) -> Result<BugReportResponse, String> {
    let machine_id = get_machine_id().unwrap_or_default();
    let app_version = env!("CARGO_PKG_VERSION").to_string();

    // Load saved registration for reporter info
    let (reporter_name, reporter_email) = match init_license_db() {
        Ok(conn) => {
            conn.query_row(
                "SELECT contact_name, contact_email FROM registration_info LIMIT 1",
                [],
                |row| Ok((
                    row.get::<_, String>(0).unwrap_or_else(|_| "Unknown".to_string()),
                    row.get::<_, String>(1).unwrap_or_else(|_| String::new()),
                )),
            ).unwrap_or_else(|_| ("Unknown".to_string(), String::new()))
        }
        Err(_) => ("Unknown".to_string(), String::new()),
    };

    // 1. Submit to Scout server.
    // If there are attachments, send multipart. Otherwise send JSON (legacy path).
    // Both paths POST to the same endpoint — server detects content-type.
    let attachment_paths = data.attachment_paths.clone().unwrap_or_default();

    // Read + validate attachment files up front so we can refuse with a clear
    // error before contacting the server.
    let mut prepared_files: Vec<(String, String, String, Vec<u8>)> = Vec::new();
    if !attachment_paths.is_empty() {
        if attachment_paths.len() > MAX_ATTACHMENTS {
            return Err(format!(
                "Too many attachments: {} provided, max is {}",
                attachment_paths.len(),
                MAX_ATTACHMENTS
            ));
        }
        for path_str in &attachment_paths {
            let path = std::path::Path::new(path_str);
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    return Err(format!("Attachment '{}' not readable: {}", path_str, e));
                }
            };
            if meta.len() > MAX_ATTACHMENT_BYTES {
                return Err(format!(
                    "Attachment '{}' is too large ({} bytes, max {})",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or(path_str),
                    meta.len(),
                    MAX_ATTACHMENT_BYTES
                ));
            }
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => return Err(format!("Failed to read '{}': {}", path_str, e)),
            };
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("attachment")
                .to_string();
            let ctype = guess_image_mime(path).to_string();
            if !ctype.starts_with("image/") {
                return Err(format!("Attachment '{}' is not an image", filename));
            }
            prepared_files.push(("files".to_string(), filename, ctype, bytes));
        }
    }

    let scout_result = if prepared_files.is_empty() {
        // Legacy JSON path — keeps compatibility with older server builds.
        let scout_body = serde_json::json!({
            "title": data.title,
            "description": data.description,
            "reporter_name": reporter_name,
            "reporter_email": reporter_email,
            "app_version": app_version,
            "platform": get_platform(),
            "machine_id": machine_id,
        });
        ureq::post(&format!("{}/api/bug-report", SERVER_URL))
            .set("Content-Type", "application/json")
            .send_string(&scout_body.to_string())
    } else {
        // Multipart path — used when there are screenshots to upload.
        let platform_str: &str = get_platform();
        let text_fields: Vec<(&str, &str)> = vec![
            ("title", data.title.as_str()),
            ("description", data.description.as_str()),
            ("reporter_name", reporter_name.as_str()),
            ("reporter_email", reporter_email.as_str()),
            ("app_version", app_version.as_str()),
            ("platform", platform_str),
            ("machine_id", machine_id.as_str()),
        ];
        let (body, content_type) = build_multipart_body(&text_fields, &prepared_files);
        ureq::post(&format!("{}/api/bug-report", SERVER_URL))
            .set("Content-Type", &content_type)
            .send_bytes(&body)
    };

    let bug_id = match scout_result {
        Ok(resp) => {
            resp.into_string().ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|v| v.get("bug_id").and_then(|id| id.as_i64()))
        }
        Err(e) => {
            eprintln!("Scout server bug report failed: {}", e);
            None
        }
    };

    // 2. Submit to Intellect LE Command Center (best-effort, don't fail if unavailable)
    let intellect_body = serde_json::json!({
        "title": data.title,
        "description": data.description,
        "product_slug": "dp-scout",
        "reporter_name": reporter_name,
        "reporter_email": reporter_email,
        "app_version": app_version,
        "severity": "medium",
    });

    let intellect_id = match ureq::post(INTELLECT_API)
        .set("Content-Type", "application/json")
        .set("X-API-Key", INTELLECT_API_KEY)
        .send_string(&intellect_body.to_string())
    {
        Ok(resp) => {
            resp.into_string().ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|v| v.get("bug_id").map(|id| id.to_string()))
        }
        Err(e) => {
            eprintln!("Intellect LE bug report failed (non-fatal): {}", e);
            None
        }
    };

    if bug_id.is_none() && intellect_id.is_none() {
        return Err("Failed to submit bug report to any server".to_string());
    }

    Ok(BugReportResponse {
        ok: true,
        bug_id,
        intellect_id,
        message: Some("Bug report submitted successfully".to_string()),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, not(feature = "portable")))]
mod tests {
    use super::*;

    /// The fingerprint must stay a plain SHA-256 of the `|`-joined components.
    /// Any change here silently invalidates every machine ID on the server, so
    /// pin the exact algorithm rather than trusting it not to drift.
    #[test]
    fn hash_is_sha256_of_pipe_joined_components() {
        use sha2::{Sha256, Digest};
        let components = vec![
            "OFFICE".to_string(),
            "JUSTI".to_string(),
            "07E4112_P31B737304".to_string(),
        ];
        let mut h = Sha256::new();
        h.update(b"OFFICE|JUSTI|07E4112_P31B737304");
        assert_eq!(hash_components(&components), hex::encode(h.finalize()));
    }

    #[test]
    fn machine_id_is_stable_across_calls() {
        let a = get_machine_id().expect("machine id must resolve on this host");
        let b = get_machine_id().expect("machine id must resolve on this host");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "SHA-256 hex is 64 chars");
    }

    /// The legacy ID is a SUPPORT DIAGNOSTIC, never a licensing fallback. It
    /// must not be sent to `/api/license/status` or `/api/license/activate`:
    /// `SHA256(COMPUTERNAME|USERNAME)` is guessable, and the server authorizes
    /// on the hash alone, so accepting it would let anyone who sets those two
    /// env vars impersonate a licensed agency.
    #[cfg(target_os = "windows")]
    #[test]
    fn legacy_id_is_reported_only_when_it_differs_from_current() {
        let current = get_machine_id().unwrap();
        match get_legacy_machine_id() {
            Some(legacy) => {
                assert_ne!(legacy, current, "a legacy ID equal to current is noise");
                assert_eq!(legacy.len(), 64);
                assert_eq!(legacy, hash_components(&base_identity_components()));
                // A distinct legacy ID implies SOMETHING is folded in now --
                // either a usable serial or the MachineGuid fallback.
                let has_serial = baseboard_serial()
                    .or_else(baseboard_serial_via_wmic)
                    .filter(|x| is_usable_serial(x))
                    .is_some();
                assert!(has_serial || machine_guid().is_some());
            }
            None => {
                // Nothing extra readable, so the current ID already IS the
                // name+user hash and there is no separate legacy identity.
                assert_eq!(current, hash_components(&base_identity_components()));
            }
        }
    }

    /// The whole point of moving off `wmic`: WMI must produce the serial
    /// without it.
    #[cfg(target_os = "windows")]
    #[test]
    fn wmi_reads_baseboard_serial() {
        assert!(
            baseboard_serial().is_some(),
            "WMI could not read Win32_BaseBoard.SerialNumber on this host"
        );
    }

    /// Diagnostics must never fail — a support panel that errors out is
    /// useless precisely when it is needed.
    #[test]
    fn diagnostics_always_produce_a_usable_machine_id() {
        let d = get_license_diagnostics();
        assert!(!d.machine_id.starts_with("UNAVAILABLE"), "got {}", d.machine_id);
        assert_eq!(d.machine_id.len(), 64);
        assert_eq!(d.platform, "desktop");
        assert!(!d.app_version.is_empty());
        // The warning fires only when NEITHER identifier is readable.
        #[cfg(target_os = "windows")]
        {
            let has_serial = baseboard_serial()
                .or_else(baseboard_serial_via_wmic)
                .filter(|x| is_usable_serial(x))
                .is_some();
            assert_eq!(
                d.fingerprint_warning.is_none(),
                has_serial || machine_guid().is_some()
            );
        }
        // The legacy ID, when present, must differ from the live one.
        if let Some(legacy) = d.legacy_machine_id {
            assert_ne!(legacy, d.machine_id);
        }
    }

    /// A debug build must never be gated by licensing, whatever the server
    /// says about this machine. Regressing this strands every developer whose
    /// machine ID has drifted out of the server's records.
    ///
    /// Network-independent: the offline fallback and the error path both end
    /// in the debug override, so this holds on a disconnected machine too.
    #[cfg(debug_assertions)]
    #[test]
    fn debug_builds_are_never_license_gated() {
        let info = get_license_status().expect("debug build must not fail the license check");
        assert!(info.registered, "debug build reported as unregistered");
        assert!(!info.is_expired, "debug build reported as expired");
        assert_eq!(info.days_remaining, DEV_LICENSE_DAYS);
        assert!(info.plan.is_some() && info.status.is_some());
    }

    /// MachineGuid must be readable without elevation. It is the only thing
    /// standing between a serial-less machine and a name+user-only ID.
    #[cfg(target_os = "windows")]
    #[test]
    fn machine_guid_is_readable_unelevated() {
        let guid = machine_guid().expect("HKLM\\...\\Cryptography\\MachineGuid unreadable");
        assert!(guid.len() >= 32, "unexpected MachineGuid shape: {}", guid);
        // Stable across calls — it is a registry read, not a generated value.
        assert_eq!(Some(guid), machine_guid());
    }

    /// The critical no-regression guarantee: adding the MachineGuid fallback
    /// must NOT change the ID of any machine that can read a usable serial.
    /// If this breaks, every such install re-registers on update.
    #[cfg(target_os = "windows")]
    #[test]
    fn serial_machines_keep_their_existing_id() {
        let serial = baseboard_serial()
            .or_else(baseboard_serial_via_wmic)
            .filter(|s| is_usable_serial(s));
        let Some(serial) = serial else {
            // Host has no usable serial; nothing to assert about that path.
            return;
        };
        let mut expected = base_identity_components();
        expected.push(serial);
        assert_eq!(
            get_machine_id().unwrap(),
            hash_components(&expected),
            "ID for a serial-readable machine must be name|user|serial and nothing else"
        );
        // MachineGuid must NOT be folded in when a serial exists.
        if let Some(guid) = machine_guid() {
            let mut with_guid = base_identity_components();
            with_guid.push(guid);
            assert_ne!(get_machine_id().unwrap(), hash_components(&with_guid));
        }
    }

    /// Placeholder serials carry no entropy — every machine from that vendor
    /// would share one. They must be rejected so MachineGuid takes over.
    #[cfg(target_os = "windows")]
    #[test]
    fn placeholder_serials_are_rejected() {
        for bad in [
            "Default string",
            "DEFAULT STRING",
            "To Be Filled By O.E.M.",
            "None",
            "N/A",
            "0000000000",
            "...",
            "",
            "  ",
            "aa",
        ] {
            assert!(!is_usable_serial(bad), "{:?} must not be treated as a serial", bad);
        }
        for good in ["07E4112_P31B737304", "PF0ABCDE", "5CD1234XYZ"] {
            assert!(is_usable_serial(good), "{:?} is a real serial", good);
        }
    }
}
