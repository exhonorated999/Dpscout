//! iOS live device detection and triage.
//!
//! All detection now delegates to pymobiledevice3 via the Python bridge
//! (`ios_python.rs`). The old libimobiledevice CLI approach is removed
//! because the required executables (idevice_id, ideviceinfo, etc.) were
//! never bundled correctly and are unreliable on modern Windows + iOS.

use serde::{Deserialize, Serialize};

use super::ios_python;

// ---------------------------------------------------------------------------
// Type definitions – kept for backward compatibility with lib.rs / frontend
// ---------------------------------------------------------------------------

/// Live iOS device information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveIosDevice {
    pub udid: String,
    pub device_name: String,
    pub device_model: String,
    pub product_type: String,
    pub ios_version: String,
    pub is_trusted: bool,
    pub connection_type: String,
    pub serial_number: String,
    pub imei: String,
    pub phone_number: String,
    pub wifi_address: String,
    pub bluetooth_address: String,
    pub build_version: String,
    pub hardware_model: String,
    pub device_color: String,
    pub battery_level: String,
    pub total_capacity: String,
    pub available_capacity: String,
}

/// Triage results from device scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosLiveTriageResults {
    pub device_info: LiveIosDevice,
    pub apps_found: Vec<IosAppInfo>,
    pub browser_history: Vec<IosBrowserEntry>,
    pub keyword_matches: Vec<IosKeywordMatch>,
    pub hash_matches: Vec<IosHashMatch>,
    pub suspicious_apps: Vec<String>,
    pub total_files_scanned: u64,
    pub total_photos: u64,
    pub total_videos: u64,
    pub scan_duration_secs: u64,
}

/// Browser history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosBrowserEntry {
    pub url: String,
    pub title: String,
    pub visit_count: u32,
    pub last_visit: String,
}

/// App information from device
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosAppInfo {
    pub bundle_id: String,
    pub app_name: String,
    pub version: String,
    pub is_system_app: bool,
    pub category: String,
}

/// Keyword match found during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosKeywordMatch {
    pub keyword: String,
    pub file_name: String,
    pub file_path: String,
    pub file_type: String,
    pub match_context: String,
    pub timestamp: String,
}

/// Hash match for known contraband
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosHashMatch {
    pub file_hash: String,
    pub hash_type: String,
    pub file_name: String,
    pub file_path: String,
    pub file_size: u64,
    pub match_category: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Public API – every function delegates to pymobiledevice3 via ios_python
// ---------------------------------------------------------------------------

/// Check if iOS scanning tools are available.
/// Returns true when Python + pymobiledevice3 are installed.
/// (Name kept for backward-compat with existing Tauri command.)
pub fn check_libimobiledevice_available() -> Result<bool, String> {
    match ios_python::check_ios_python_available() {
        Ok(available) => {
            if available {
                eprintln!("[iOS] pymobiledevice3 available — iOS scanning supported");
            } else {
                eprintln!("[iOS] pymobiledevice3 NOT installed — run scripts\\setup_ios_environment.ps1");
            }
            Ok(available)
        }
        Err(e) => {
            eprintln!("[iOS] Failed to check Python availability: {}", e);
            Ok(false)
        }
    }
}

/// Detect connected iOS devices via pymobiledevice3.
pub fn detect_live_ios_devices() -> Result<Vec<LiveIosDevice>, String> {
    eprintln!("[iOS] Detecting devices via pymobiledevice3...");

    let python_devices = ios_python::detect_ios_devices_python().map_err(|e| {
        format!(
            "iOS device detection failed.\n\n\
             Ensure Python and pymobiledevice3 are installed:\n  \
             Run: scripts\\setup_ios_environment.ps1\n\n\
             Details: {}",
            e
        )
    })?;

    if python_devices.is_empty() {
        eprintln!("[iOS] No devices found");
        return Ok(Vec::new());
    }

    let devices: Vec<LiveIosDevice> = python_devices
        .into_iter()
        .map(|pd| LiveIosDevice {
            udid: pd.udid,
            device_name: pd.device_name,
            device_model: pd.device_model,
            product_type: pd.product_type,
            ios_version: pd.ios_version,
            is_trusted: pd.is_trusted,
            connection_type: pd.connection_type,
            serial_number: pd.serial_number,
            imei: pd.imei,
            phone_number: pd.phone_number,
            wifi_address: pd.wifi_address,
            bluetooth_address: pd.bluetooth_address,
            build_version: pd.build_version,
            hardware_model: pd.hardware_model,
            device_color: pd.device_color,
            battery_level: pd.battery_level,
            total_capacity: pd.total_capacity,
            available_capacity: pd.available_capacity,
        })
        .collect();

    eprintln!("[iOS] Found {} device(s)", devices.len());
    Ok(devices)
}

/// Verify trust / pairing for a device.
/// With pymobiledevice3, pairing happens when creating a lockdown client.
pub fn request_device_trust(udid: &str) -> Result<bool, String> {
    eprintln!("[iOS] Verifying trust for device {}...", udid);
    match ios_python::get_ios_device_info_python(udid) {
        Ok(info) => {
            if info.is_trusted {
                eprintln!("[iOS] Device {} is trusted", udid);
                Ok(true)
            } else {
                Err(
                    "Device not trusted. Please unlock your iPhone and tap 'Trust' when prompted."
                        .to_string(),
                )
            }
        }
        Err(e) => Err(format!(
            "Cannot verify trust for device {}.\n\
             Please ensure the device is unlocked and connected via USB.\n\
             Details: {}",
            udid, e
        )),
    }
}

/// List installed apps on a live device.
/// Modern iOS does not allow reliable live app listing without a backup.
/// Returns empty — callers should use `get_ios_apps_from_backup` instead.
pub fn list_installed_apps(_udid: &str) -> Result<Vec<String>, String> {
    eprintln!("[iOS] Live app listing not supported — use backup-based extraction");
    Ok(Vec::new())
}

/// Perform triage scan on an iOS device.
///
/// True live forensic triage of iOS is extremely limited without a jailbreak.
/// The correct workflow is:
///   1. Create a backup via pymobiledevice3  (`start_ios_backup_python`)
///   2. Parse the backup with Rust parsers    (`analyze_ios_backup`, etc.)
///
/// This function returns minimal results (device info only) so the frontend
/// does not crash, but real analysis must go through the backup path.
pub fn perform_live_triage(
    udid: &str,
    _keyword_lists: Vec<String>,
    _hash_lists: Vec<String>,
) -> Result<IosLiveTriageResults, String> {
    let start = std::time::Instant::now();
    eprintln!("[iOS] perform_live_triage called for {}", udid);
    eprintln!("[iOS] NOTE: Use backup-based scanning for full results.");

    let pd = ios_python::get_ios_device_info_python(udid)
        .map_err(|e| format!("Cannot connect to device: {}", e))?;

    let device_info = LiveIosDevice {
        udid: pd.udid,
        device_name: pd.device_name,
        device_model: pd.device_model,
        product_type: pd.product_type,
        ios_version: pd.ios_version,
        is_trusted: pd.is_trusted,
        connection_type: pd.connection_type,
        serial_number: pd.serial_number,
        imei: pd.imei,
        phone_number: pd.phone_number,
        wifi_address: pd.wifi_address,
        bluetooth_address: pd.bluetooth_address,
        build_version: pd.build_version,
        hardware_model: pd.hardware_model,
        device_color: pd.device_color,
        battery_level: pd.battery_level,
        total_capacity: pd.total_capacity,
        available_capacity: pd.available_capacity,
    };

    Ok(IosLiveTriageResults {
        device_info,
        apps_found: Vec::new(),
        browser_history: Vec::new(),
        keyword_matches: Vec::new(),
        hash_matches: Vec::new(),
        suspicious_apps: Vec::new(),
        total_files_scanned: 0,
        total_photos: 0,
        total_videos: 0,
        scan_duration_secs: start.elapsed().as_secs(),
    })
}
