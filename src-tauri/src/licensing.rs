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

// ---------------------------------------------------------------------------
// Machine ID — unique fingerprint for this installation
// ---------------------------------------------------------------------------

/// Returns "portable" when built with the `portable` feature, else "desktop".
fn get_platform() -> &'static str {
    if cfg!(feature = "portable") { "portable" } else { "desktop" }
}

fn get_machine_id() -> Result<String, String> {
    use sha2::{Sha256, Digest};

    // Portable build: derive identity from the USB drive serial number
    #[cfg(feature = "portable")]
    {
        let serial = get_usb_drive_serial()?;
        let mut hasher = Sha256::new();
        hasher.update(serial.as_bytes());
        let result = hasher.finalize();
        return Ok(hex::encode(result));
    }

    // Desktop build: hardware fingerprint (motherboard + user)
    #[cfg(not(feature = "portable"))]
    {
        let mut components = Vec::new();

        if let Ok(name) = std::env::var("COMPUTERNAME") {
            components.push(name);
        }
        if let Ok(user) = std::env::var("USERNAME") {
            components.push(user);
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("wmic")
                .args(["baseboard", "get", "serialnumber"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(1) {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        components.push(trimmed.to_string());
                        break;
                    }
                }
            }
        }

        if components.is_empty() {
            return Err("Cannot determine machine identity".to_string());
        }

        let combined = components.join("|");
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        Ok(hex::encode(result))
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
    // Portable: store next to the exe on the USB drive
    #[cfg(feature = "portable")]
    {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Cannot find exe path: {}", e))?;
        let exe_dir = exe_path.parent()
            .ok_or_else(|| "Cannot find exe directory".to_string())?;
        let data_dir = exe_dir.join("ScoutData");
        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir)
                .map_err(|e| format!("Failed to create ScoutData directory: {}", e))?;
        }
        return Ok(data_dir.join("scout_license.db"));
    }

    // Desktop: store in %APPDATA%\Hindsight\ so it survives installer updates
    #[cfg(not(feature = "portable"))]
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "Could not find APPDATA directory".to_string())?;
    #[cfg(not(feature = "portable"))]
    let hindsight_dir = PathBuf::from(&app_data).join("Hindsight");
    #[cfg(not(feature = "portable"))]
    if !hindsight_dir.exists() {
        std::fs::create_dir_all(&hindsight_dir)
            .map_err(|e| format!("Failed to create Hindsight directory: {}", e))?;
    }
    #[cfg(not(feature = "portable"))]
    let new_path = hindsight_dir.join("scout_license.db");

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
        .map_err(|e| format!("Registration failed: {}", e))?;

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
            days_remaining: reg.trial_days.unwrap_or(60),
            is_expired: false,
        };
        cache_license(&info)?;
    }

    Ok(reg)
}

/// Check license status (online with offline fallback)
pub fn get_license_status() -> Result<LicenseInfo, String> {
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
        .map_err(|e| format!("License activation failed: {}", e))?;

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

/// Check for software updates
pub fn check_for_updates() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION");

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
