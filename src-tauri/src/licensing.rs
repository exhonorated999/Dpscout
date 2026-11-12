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

/// Read `Win32_BaseBoard.SerialNumber` via WMI **on the calling thread**.
///
/// Do not call this from licensing code directly — use [`baseboard_serial_mta`].
/// `COMLibrary::new()` asks for a multithreaded apartment, and every
/// licensing command is a sync `#[tauri::command]`, which Tauri runs on the
/// UI thread — already a single-threaded apartment (tao calls
/// `OleInitialize`). `CoInitializeEx` fails there with RPC_E_CHANGED_MODE, so
/// in the shipped app this has ALWAYS returned None (verified: the installed
/// 1.1.5 caches the MachineGuid-variant ID on a machine with a readable
/// serial). It only ever worked in `cargo test`, whose threads have no
/// apartment yet. That gap is why the machine ID drifted between builds.
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

/// The motherboard serial read on a fresh worker thread, so it works no
/// matter which COM apartment the caller is in. Raw (unfiltered) value,
/// cached for the life of the process.
///
/// NOT part of the canonical fingerprint (see [`fingerprint_serial`]) — the
/// shipped app never managed to fold this in, so doing it now would move
/// every install onto a new ID. Used for previous-ID candidates and
/// diagnostics only.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn baseboard_serial_mta() -> Option<String> {
    use std::sync::OnceLock;
    static SERIAL: OnceLock<Option<String>> = OnceLock::new();
    SERIAL
        .get_or_init(|| {
            std::thread::Builder::new()
                .name("scout-wmi-serial".into())
                .spawn(baseboard_serial)
                .ok()
                .and_then(|h| h.join().ok())
                .flatten()
        })
        .clone()
}

/// The serial the canonical machine ID folds in: `wmic`'s answer, usable
/// values only. This is byte-for-byte what every shipped build actually used
/// (the in-app WMI read never worked — see [`baseboard_serial`]), so it keeps
/// existing IDs unchanged, and it no longer depends on which thread asks.
/// Where `wmic` is gone (Windows 11 24H2+) MachineGuid takes over, exactly as
/// it already did in 1.1.2–1.1.5.
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn fingerprint_serial() -> Option<String> {
    baseboard_serial_via_wmic().filter(|s| is_usable_serial(s))
}

/// Legacy `wmic` path, kept only as a fallback for Windows builds old enough
/// that WMI access could fail while `wmic` still shipped. Produces the same
/// string as `baseboard_serial` when both work. Raw value, cached for the life
/// of the process (spawning wmic costs ~100 ms and the answer cannot change).
#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn baseboard_serial_via_wmic() -> Option<String> {
    use std::sync::OnceLock;
    static SERIAL: OnceLock<Option<String>> = OnceLock::new();
    SERIAL.get_or_init(read_wmic_serial).clone()
}

#[cfg(all(not(feature = "portable"), target_os = "windows"))]
fn read_wmic_serial() -> Option<String> {
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

    // Desktop build: the ID the server last confirmed for this Windows
    // install + user; else the ID the previous release was actually using
    // (if this machine can still derive it); else the hardware fingerprint.
    #[cfg(not(feature = "portable"))]
    {
        if let Some(pinned) = pinned_machine_id() {
            return Ok(pinned);
        }
        if let Some(adopted) = adopted_cached_machine_id() {
            return Ok(adopted);
        }
        fingerprint_machine_id()
    }
}

/// The desktop hardware fingerprint: COMPUTERNAME | USERNAME | serial-or-guid.
///
/// Deliberately COM-free, so it returns the same value on every thread (see
/// [`baseboard_serial`] for why the WMI read made the old ID depend on which
/// thread asked). It reproduces what the shipped app actually computed.
///
/// On its own this still moves when the inputs move (wmic removed by a
/// Windows update, a rename), which is why `get_machine_id` prefers the
/// server-confirmed pin and the previous release's cached ID.
#[cfg(not(feature = "portable"))]
fn fingerprint_machine_id() -> Result<String, String> {
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
            match fingerprint_serial() {
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

// ---------------------------------------------------------------------------
// Identity continuity (desktop): pinned ID, history, previous-ID candidates
// ---------------------------------------------------------------------------
//
// The desktop fingerprint has drifted between releases (name|user in <=1.1.1,
// name|user|MachineGuid from 1.1.2 wherever wmic is gone), and every drift
// stranded the agency's licence on the old hash. What stops that:
//
// * Pin — once the server confirms an ID for this install, `get_machine_id`
//   keeps returning it even if the fingerprint inputs later change.
// * Adoption — before any pin exists, the ID the previous release cached in
//   `license_cache` is kept, provided this machine can still derive it from
//   its own inputs. An update therefore never changes the ID the server
//   knows. Purely local: the server is not asked to move anything.
// * Previous IDs — for installs that already drifted, the licence ACTIVATION
//   request carries the IDs this install may have been known by. The server
//   only acts on them together with that agency's own valid paid licence key
//   (scout-server `app/identity.py`).
//
//   SECURITY: a machine ID is an unauthenticated bearer value and the old
//   name|user variant is guessable, so an old ID (plus a contact email, which
//   is often public) is never proof of ownership. Never send previous IDs on
//   status or registration, and never ask the server to move an agency on
//   anything weaker than the licence key.
// * Anchor — pins and history are keyed by hash(name|user|MachineGuid). The
//   DB lives in %APPDATA% (Roaming), so on a roaming profile two machines can
//   share it; the anchor keeps each machine to its own pin.

/// Most previous IDs worth sending; the server ignores anything beyond 8.
#[cfg(not(feature = "portable"))]
const MAX_PREVIOUS_IDS: usize = 8;

/// How many server-confirmed IDs from this install's history to send.
#[cfg(not(feature = "portable"))]
const HISTORY_CANDIDATES: usize = 3;

/// Identifies "this Windows install + this user" for keying the pin. Never
/// sent anywhere; the domain prefix keeps it from ever equalling a machine ID.
#[cfg(not(feature = "portable"))]
fn identity_anchor() -> Option<String> {
    let mut components = base_identity_components();
    if components.is_empty() {
        return None;
    }
    #[cfg(target_os = "windows")]
    if let Some(guid) = machine_guid() {
        components.push(guid);
    }
    components.insert(0, "scout-identity-anchor-v1".to_string());
    Some(hash_components(&components))
}

/// A machine ID is a lowercase-or-uppercase SHA-256 hex string.
#[cfg(not(feature = "portable"))]
fn is_machine_id_shape(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(not(feature = "portable"))]
fn init_identity_tables(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_identity (
            anchor TEXT PRIMARY KEY,
            machine_id TEXT NOT NULL,
            pinned_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS identity_history (
            anchor TEXT NOT NULL,
            machine_id TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (anchor, machine_id)
        );",
    )
    .map_err(|e| format!("Failed to create identity tables: {}", e))
}

#[cfg(not(feature = "portable"))]
fn read_pin(conn: &rusqlite::Connection, anchor: &str) -> Option<String> {
    conn.query_row(
        "SELECT machine_id FROM machine_identity WHERE anchor = ?1",
        [anchor],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .filter(|id| is_machine_id_shape(id))
}

#[cfg(not(feature = "portable"))]
fn write_pin(conn: &rusqlite::Connection, anchor: &str, machine_id: &str, now: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO machine_identity (anchor, machine_id, pinned_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(anchor) DO UPDATE SET machine_id = excluded.machine_id, pinned_at = excluded.pinned_at
         WHERE machine_identity.machine_id <> excluded.machine_id",
        rusqlite::params![anchor, machine_id, now],
    )
    .map(|_| ())
    .map_err(|e| format!("Failed to pin machine ID: {}", e))
}

#[cfg(not(feature = "portable"))]
fn record_history(conn: &rusqlite::Connection, anchor: &str, machine_id: &str, now: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO identity_history (anchor, machine_id, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(anchor, machine_id) DO UPDATE SET last_seen = excluded.last_seen",
        rusqlite::params![anchor, machine_id, now],
    )
    .map(|_| ())
    .map_err(|e| format!("Failed to record machine ID history: {}", e))
}

/// Server-confirmed IDs for this anchor, most recently seen first.
#[cfg(not(feature = "portable"))]
fn read_history(conn: &rusqlite::Connection, anchor: &str, limit: usize) -> Vec<String> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT machine_id FROM identity_history WHERE anchor = ?1
         ORDER BY last_seen DESC, first_seen DESC LIMIT ?2",
    ) else {
        return Vec::new();
    };
    stmt.query_map(rusqlite::params![anchor, limit as i64], |row| row.get::<_, String>(0))
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
}

/// Whether any install has ever pinned an ID in this DB.
#[cfg(not(feature = "portable"))]
fn any_pin_exists(conn: &rusqlite::Connection) -> bool {
    conn.query_row("SELECT COUNT(*) FROM machine_identity", [], |row| row.get::<_, i64>(0))
        .map(|n| n > 0)
        .unwrap_or(false)
}

/// The ID the last status check ran under (written by every release).
#[cfg(not(feature = "portable"))]
fn read_cached_machine_id(conn: &rusqlite::Connection) -> Option<String> {
    conn.query_row("SELECT machine_id FROM license_cache LIMIT 1", [], |row| {
        row.get::<_, Option<String>>(0)
    })
    .ok()
    .flatten()
}

/// The cached ID, if it is one this machine derives itself. Comparing against
/// local derivations only means a roaming profile's cache from another
/// machine is never adopted.
#[cfg(not(feature = "portable"))]
fn adoptable_cached_id(cached: Option<String>, derived: &[Option<String>]) -> Option<String> {
    let cached = cached?.trim().to_string();
    if !is_machine_id_shape(&cached) {
        return None;
    }
    derived
        .iter()
        .flatten()
        .any(|d| d.eq_ignore_ascii_case(&cached))
        .then_some(cached)
}

/// The ID the previous release was running under, while this install has no
/// pin yet.
#[cfg(not(feature = "portable"))]
fn adopted_cached_machine_id() -> Option<String> {
    let conn = init_license_db().ok()?;
    let cached = read_cached_machine_id(&conn)?;
    adoptable_cached_id(Some(cached), &derived_identity_candidates())
}

/// Shape-filter, drop the current ID, de-duplicate case-insensitively, cap.
/// Input order is priority order.
#[cfg(not(feature = "portable"))]
fn assemble_previous_ids<I>(current: &str, candidates: I) -> Vec<String>
where
    I: IntoIterator<Item = Option<String>>,
{
    let mut seen = std::collections::HashSet::new();
    seen.insert(current.to_ascii_lowercase());
    let mut out = Vec::new();
    for candidate in candidates.into_iter().flatten() {
        let candidate = candidate.trim().to_string();
        if !is_machine_id_shape(&candidate) {
            continue;
        }
        if seen.insert(candidate.to_ascii_lowercase()) {
            out.push(candidate);
            if out.len() >= MAX_PREVIOUS_IDS {
                break;
            }
        }
    }
    out
}

/// Every fingerprint variant a shipped release could have computed on this
/// machine, from this machine's own inputs (so never another machine's ID).
#[cfg(not(feature = "portable"))]
fn derived_identity_candidates() -> Vec<Option<String>> {
    let base = base_identity_components();
    if base.is_empty() {
        return Vec::new();
    }
    #[cfg(target_os = "windows")]
    let with = |extra: Option<String>| {
        extra.map(|e| {
            let mut c = base.clone();
            c.push(e);
            hash_components(&c)
        })
    };

    // <= 1.1.1 on a machine without a serial: name|user only.
    let mut out = vec![Some(hash_components(&base))];
    #[cfg(target_os = "windows")]
    {
        // 1.1.2 - 1.1.5 without wmic.
        out.push(with(machine_guid()));
        // Unfiltered serials: <= 1.1.1 accepted placeholder values, and code
        // running off the UI thread could read the serial over WMI.
        out.push(with(baseboard_serial_mta()));
        out.push(with(baseboard_serial_via_wmic()));
    }
    out.push(fingerprint_machine_id().ok());
    out
}

/// The server-confirmed ID for this install, if any.
#[cfg(not(feature = "portable"))]
fn pinned_machine_id() -> Option<String> {
    let anchor = identity_anchor()?;
    let conn = init_license_db().ok()?;
    read_pin(&conn, &anchor)
}

/// Candidate IDs this install may be registered under on the server.
#[cfg(not(feature = "portable"))]
fn previous_machine_ids(current: &str) -> Vec<String> {
    let anchor = identity_anchor();
    let mut candidates: Vec<Option<String>> = Vec::new();
    if let Ok(conn) = init_license_db() {
        if let Some(anchor) = anchor.as_deref() {
            candidates.extend(read_history(&conn, anchor, HISTORY_CANDIDATES).into_iter().map(Some));
        }
        // The cached ID is only trusted until some install has pinned in this
        // DB — after that it may belong to another machine on the same
        // roaming profile, and sending it would hand that machine's agency
        // over to this one.
        if !any_pin_exists(&conn) {
            candidates.push(read_cached_machine_id(&conn));
        }
    }
    candidates.extend(derived_identity_candidates());
    assemble_previous_ids(current, candidates)
}

/// Previous IDs for a licence ACTIVATION request only (see the security note
/// above). Portable IDs come from the stick and do not drift, so portable
/// sends none.
fn activation_previous_ids(current: &str) -> Vec<String> {
    #[cfg(feature = "portable")]
    {
        let _ = current;
        Vec::new()
    }
    #[cfg(not(feature = "portable"))]
    {
        previous_machine_ids(current)
    }
}

/// Record that the server accepted `machine_id` for this install. Best effort:
/// a failure here only means the next request sends candidates again.
fn confirm_identity(machine_id: &str) {
    #[cfg(feature = "portable")]
    let _ = machine_id;
    #[cfg(not(feature = "portable"))]
    {
        if !is_machine_id_shape(machine_id) {
            return;
        }
        let Some(anchor) = identity_anchor() else { return };
        let result = init_license_db().and_then(|conn| {
            let now = chrono::Utc::now().to_rfc3339();
            write_pin(&conn, &anchor, machine_id, &now)?;
            record_history(&conn, &anchor, machine_id, &now)
        });
        if let Err(e) = result {
            eprintln!("[Licensing] Could not record confirmed machine ID: {}", e);
        }
    }
}

/// The name|user-only hash that builds up to 1.1.1 reported on machines with
/// no readable serial. Shown in diagnostics for support.
///
/// Not used to look a licence up directly: the server treats `machine_id` as
/// an unauthenticated bearer identity, and `DESK-PD01` + `jsmith` is
/// guessable. It IS sent as one of `previous_machine_ids` on licence
/// activation, which the server only acts on together with that agency's own
/// valid paid licence key.
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

    #[cfg(not(feature = "portable"))]
    init_identity_tables(&conn)?;

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
        confirm_identity(&machine_id);

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
    let body = serde_json::json!({
        "machine_id": machine_id,
        "platform": get_platform(),
    });

    match ureq::post(&format!("{}/api/license/status", SERVER_URL))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(resp) => {
            let text = resp.into_string()
                .map_err(|e| format!("Failed to read response: {}", e))?;
            let info: LicenseInfo = serde_json::from_str(&text)
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            if info.registered {
                confirm_identity(&machine_id);
            }

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
    // Only honoured by the server together with this agency's paid key.
    let previous_machine_ids = activation_previous_ids(&machine_id);

    let body = serde_json::json!({
        "license_key": license_key,
        "machine_id": machine_id,
        "platform": get_platform(),
        "previous_machine_ids": previous_machine_ids,
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
        confirm_identity(&machine_id);
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
        let has_serial = baseboard_serial_mta()
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

    /// The legacy ID is never looked up as `machine_id` (it is guessable). It
    /// only travels as a `previous_machine_ids` candidate on activation, which
    /// the server acts on solely together with the agency's paid licence key.
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
                let has_serial = fingerprint_serial().is_some();
                assert!(has_serial || machine_guid().is_some());
            }
            None => {
                // Nothing extra readable, so the current ID already IS the
                // name+user hash and there is no separate legacy identity.
                assert_eq!(current, hash_components(&base_identity_components()));
            }
        }
    }

    /// The WMI read itself must work when run off the UI apartment.
    #[cfg(target_os = "windows")]
    #[test]
    fn wmi_reads_baseboard_serial() {
        assert!(
            baseboard_serial_mta().is_some(),
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
            let has_serial = baseboard_serial_mta()
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
        let Some(serial) = fingerprint_serial() else {
            // Host has no usable serial; nothing to assert about that path.
            return;
        };
        let mut expected = base_identity_components();
        expected.push(serial);
        assert_eq!(
            fingerprint_machine_id().unwrap(),
            hash_components(&expected),
            "ID for a serial-readable machine must be name|user|serial and nothing else"
        );
        // MachineGuid must NOT be folded in when a serial exists.
        if let Some(guid) = machine_guid() {
            let mut with_guid = base_identity_components();
            with_guid.push(guid);
            assert_ne!(fingerprint_machine_id().unwrap(), hash_components(&with_guid));
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

    // --- STA regression -----------------------------------------------------

    #[cfg(target_os = "windows")]
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut std::ffi::c_void, coinit: u32) -> i32;
        fn CoUninitialize();
    }

    /// Run `f` on a fresh thread that has entered a single-threaded apartment,
    /// like Tauri's UI thread (where every sync licensing command runs).
    #[cfg(target_os = "windows")]
    fn on_sta_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(move || {
            const COINIT_APARTMENTTHREADED: u32 = 0x2;
            let hr = unsafe { CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED) };
            assert!(hr >= 0, "CoInitializeEx(STA) failed: {:#x}", hr);
            let out = f();
            unsafe { CoUninitialize() };
            out
        })
        .join()
        .expect("STA thread panicked")
    }

    /// The bug behind the Derry Township ticket: the ID depended on the COM
    /// apartment of the calling thread. It must not, any more.
    #[cfg(target_os = "windows")]
    #[test]
    fn fingerprint_is_the_same_on_sta_and_mta_threads() {
        let here = fingerprint_machine_id().unwrap();
        let sta = on_sta_thread(|| fingerprint_machine_id().unwrap());
        assert_eq!(here, sta, "fingerprint must not depend on the COM apartment");
    }

    /// Documents WHY: the in-thread WMI read fails in an STA, the worker-thread
    /// read does not.
    #[cfg(target_os = "windows")]
    #[test]
    fn wmi_serial_fails_in_sta_but_not_via_worker_thread() {
        let (direct, via_worker) = on_sta_thread(|| (baseboard_serial(), baseboard_serial_mta()));
        assert!(direct.is_none(), "in-thread WMI unexpectedly worked inside an STA");
        assert_eq!(via_worker, baseboard_serial_mta());
    }

    // --- pin / history / candidates -----------------------------------------

    fn id(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    fn memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE license_cache (id INTEGER PRIMARY KEY, machine_id TEXT);
             CREATE TABLE registration_info (id INTEGER PRIMARY KEY, contact_email TEXT);",
        )
        .unwrap();
        init_identity_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn pin_is_per_anchor_and_replaceable() {
        let conn = memory_db();
        assert_eq!(read_pin(&conn, "A"), None);
        assert!(!any_pin_exists(&conn));

        write_pin(&conn, "A", &id('a'), "2026-01-01").unwrap();
        write_pin(&conn, "B", &id('b'), "2026-01-01").unwrap();
        assert_eq!(read_pin(&conn, "A"), Some(id('a')));
        assert_eq!(read_pin(&conn, "B"), Some(id('b')), "a roaming twin keeps its own pin");
        assert!(any_pin_exists(&conn));

        write_pin(&conn, "A", &id('c'), "2026-02-01").unwrap();
        assert_eq!(read_pin(&conn, "A"), Some(id('c')));
        assert_eq!(read_pin(&conn, "B"), Some(id('b')));
    }

    #[test]
    fn malformed_pin_is_ignored() {
        let conn = memory_db();
        conn.execute(
            "INSERT INTO machine_identity (anchor, machine_id, pinned_at) VALUES ('A', 'junk', 'x')",
            [],
        )
        .unwrap();
        assert_eq!(read_pin(&conn, "A"), None);
    }

    #[test]
    fn history_is_most_recent_first_and_per_anchor() {
        let conn = memory_db();
        record_history(&conn, "A", &id('1'), "2026-01-01").unwrap();
        record_history(&conn, "A", &id('2'), "2026-02-01").unwrap();
        record_history(&conn, "B", &id('9'), "2026-03-01").unwrap();
        record_history(&conn, "A", &id('1'), "2026-04-01").unwrap(); // seen again
        assert_eq!(read_history(&conn, "A", 10), vec![id('1'), id('2')]);
        assert_eq!(read_history(&conn, "A", 1), vec![id('1')]);
        assert_eq!(read_history(&conn, "B", 10), vec![id('9')]);
    }

    #[test]
    fn cached_id_is_read_back() {
        let conn = memory_db();
        assert_eq!(read_cached_machine_id(&conn), None);
        conn.execute("INSERT INTO license_cache (machine_id) VALUES (?1)", [id('e')]).unwrap();
        assert_eq!(read_cached_machine_id(&conn), Some(id('e')));
    }

    /// An update must keep the ID the previous release used, but only an ID
    /// this machine can derive itself — never one from another machine that
    /// shares the roaming profile, and never garbage.
    #[test]
    fn cached_id_is_adopted_only_if_locally_derivable() {
        let derived = vec![None, Some(id('a')), Some(id('b'))];
        assert_eq!(adoptable_cached_id(Some(id('a')), &derived), Some(id('a')));
        assert_eq!(
            adoptable_cached_id(Some(format!(" {} ", id('B'))), &derived),
            Some(id('B')),
            "case/whitespace-insensitive match keeps the cached spelling"
        );
        assert_eq!(adoptable_cached_id(Some(id('c')), &derived), None, "foreign ID");
        assert_eq!(adoptable_cached_id(Some("nope".into()), &derived), None);
        assert_eq!(adoptable_cached_id(None, &derived), None);
        assert_eq!(adoptable_cached_id(Some(id('a')), &[]), None);
    }

    /// Kevin's path: a <= 1.1.1 install cached name|user; after updating, the
    /// fingerprint is name|user|guid but the ID must stay name|user.
    #[cfg(target_os = "windows")]
    #[test]
    fn legacy_cached_id_survives_the_update() {
        let legacy = hash_components(&base_identity_components());
        assert_eq!(
            adoptable_cached_id(Some(legacy.clone()), &derived_identity_candidates()),
            Some(legacy)
        );
    }

    #[test]
    fn previous_ids_are_filtered_deduped_and_capped() {
        let current = id('a');
        let out = assemble_previous_ids(
            &current,
            vec![
                None,
                Some(current.to_uppercase()), // current, other case
                Some(id('b')),
                Some("not-a-hash".to_string()),
                Some(id('B')), // duplicate of b, other case
                Some(format!(" {} ", id('c'))),
                Some(id('g')), // not hex
            ],
        );
        assert_eq!(out, vec![id('b'), id('c')]);

        let many = (0..20).map(|i| Some(format!("{:064x}", i + 1)));
        assert_eq!(assemble_previous_ids(&current, many).len(), MAX_PREVIOUS_IDS);
    }

    /// Kevin's case: registered on 1.0.6 under name|user, now running under
    /// name|user|MachineGuid. The old ID must be among the candidates, and
    /// the guid variant too (for wmic machines that lose wmic later).
    #[cfg(target_os = "windows")]
    #[test]
    fn derived_candidates_cover_every_shipped_variant() {
        let base = base_identity_components();
        let derived: Vec<String> = derived_identity_candidates().into_iter().flatten().collect();
        assert!(derived.contains(&hash_components(&base)), "name|user (<= 1.1.1) missing");
        if let Some(guid) = machine_guid() {
            let mut c = base.clone();
            c.push(guid);
            assert!(derived.contains(&hash_components(&c)), "name|user|guid (1.1.2+) missing");
        }
        if let Some(serial) = baseboard_serial_mta() {
            let mut c = base.clone();
            c.push(serial);
            assert!(derived.contains(&hash_components(&c)), "name|user|serial missing");
        }
        assert!(derived.contains(&fingerprint_machine_id().unwrap()));
        // The anchor must never be mistaken for (or sent as) a machine ID.
        let anchor = identity_anchor().unwrap();
        assert!(!derived.contains(&anchor));
        // And the current ID is never sent back as a "previous" one.
        let current = fingerprint_machine_id().unwrap();
        assert!(!assemble_previous_ids(&current, derived_identity_candidates()).contains(&current));
    }
}
