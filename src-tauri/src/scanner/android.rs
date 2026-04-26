use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;
use tauri::Manager;
use sha2::{Sha256, Digest};
use md5::Md5;
use chrono::{DateTime, Utc, NaiveDateTime};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a Command that runs without showing a window on Windows
pub fn create_hidden_command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    cmd
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDevice {
    pub serial: String,
    pub model: String,
    pub manufacturer: String,
    pub android_version: String,
    pub device_name: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidApp {
    pub package_name: String,
    pub app_name: String,
    pub version: String,
    pub install_time: String,
    pub is_system_app: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidBrowserData {
    pub browser_name: String,
    pub package_name: String,
    pub history: Vec<AndroidHistoryEntry>,
    pub bookmarks: Vec<AndroidBookmarkEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i32,
    pub last_visit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidBookmarkEntry {
    pub url: String,
    pub title: String,
    pub folder: String,
}

/// Get path to bundled ADB executable
pub fn get_bundled_adb_path(app_handle: &tauri::AppHandle) -> PathBuf {
    let resource_path = app_handle.path()
        .resource_dir()
        .expect("Failed to get resource directory");
    
    #[cfg(target_os = "windows")]
    let adb_path = resource_path.join("_up_/external/platform-tools/adb.exe");
    
    #[cfg(not(target_os = "windows"))]
    let adb_path = resource_path.join("_up_/external/platform-tools/adb");
    
    adb_path
}

/// Check if bundled ADB is available
pub fn check_adb_available(app_handle: &tauri::AppHandle) -> Result<bool, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    if !adb_path.exists() {
        return Err(format!("Bundled ADB not found at {:?}. Please ensure ADB platform tools are bundled with the application.", adb_path));
    }
    
    match create_hidden_command(&adb_path).arg("version").output() {
        Ok(output) => Ok(output.status.success()),
        Err(e) => Err(format!("Failed to execute ADB: {}", e))
    }
}

/// Get list of connected Android devices using bundled ADB
pub fn get_connected_devices(app_handle: &tauri::AppHandle) -> Result<Vec<AndroidDevice>, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    // Kill and restart ADB server to refresh device list
    let _ = create_hidden_command(&adb_path).arg("kill-server").output();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = create_hidden_command(&adb_path).arg("start-server").output();
    std::thread::sleep(std::time::Duration::from_millis(1000));
    
    let output = create_hidden_command(&adb_path)
        .args(&["devices", "-l"])
        .output()
        .map_err(|e| format!("Failed to execute adb: {}", e))?;

    if !output.status.success() {
        return Err("ADB command failed".to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    for line in output_str.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let serial = parts[0].to_string();
        let state = parts[1].to_string();
        
        // Skip unauthorized or offline devices
        if state != "device" {
            eprintln!("Device {} is {}, skipping", serial, state);
            continue;
        }
        
        // Get device details
        if let Ok(device_info) = get_device_info(&adb_path, &serial) {
            devices.push(device_info);
        }
    }

    Ok(devices)
}

/// Get detailed information about a specific device
fn get_device_info(adb_path: &Path, serial: &str) -> Result<AndroidDevice, String> {
    let model = get_device_property(adb_path, serial, "ro.product.model")
        .unwrap_or_else(|_| "Unknown".to_string());
    let manufacturer = get_device_property(adb_path, serial, "ro.product.manufacturer")
        .unwrap_or_else(|_| "Unknown".to_string());
    let android_version = get_device_property(adb_path, serial, "ro.build.version.release")
        .unwrap_or_else(|_| "Unknown".to_string());
    let device_name = format!("{} {}", manufacturer, model);

    Ok(AndroidDevice {
        serial: serial.to_string(),
        model,
        manufacturer,
        android_version,
        device_name,
        state: "device".to_string(),
    })
}

/// Get a property from the device using getprop
fn get_device_property(adb_path: &Path, serial: &str, property: &str) -> Result<String, String> {
    let output = create_hidden_command(adb_path)
        .args(&["-s", serial, "shell", "getprop", property])
        .output()
        .map_err(|e| format!("Failed to get property: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get list of installed apps on device
pub fn get_installed_apps(app_handle: &tauri::AppHandle, serial: &str) -> Result<Vec<AndroidApp>, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    // Use -3 flag to only get third-party (user-installed) apps
    let output = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "pm", "list", "packages", "-3", "-f"])
        .output()
        .map_err(|e| format!("Failed to list packages: {}", e))?;

    if !output.status.success() {
        return Err("Failed to get package list".to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut apps = Vec::new();

    eprintln!("ADB output for packages:");
    eprintln!("{}", output_str);

    for line in output_str.lines() {
        if line.starts_with("package:") {
            eprintln!("Parsing line: {}", line);
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() >= 2 {
                // The package name is the LAST part after the last '='
                let empty_str = "";
                let package_name = parts.last().unwrap_or(&empty_str).trim().to_string();
                
                if package_name.is_empty() {
                    eprintln!("WARNING: Empty package name from line: {}", line);
                    continue;
                }
                
                // Skip system overlays and generated packages
                if package_name.contains("auto_generated_rro_") 
                    || package_name.contains(".overlay.")
                    || package_name.starts_with("com.android.theme.")
                    || package_name.starts_with("android.auto_generated_") {
                    continue;
                }
                
                let is_system = parts[0].contains("/system/");
                
                // Use package name as app name for speed
                // Extract just the last part of package name for readability
                let package_name_ref = package_name.as_str();
                let app_name = package_name.split('.').last()
                    .unwrap_or(&package_name_ref)
                    .to_string();

                eprintln!("Adding app: {} -> {}", package_name, app_name);

                apps.push(AndroidApp {
                    package_name: package_name.clone(),
                    app_name,
                    version: "Unknown".to_string(),
                    install_time: "Unknown".to_string(),
                    is_system_app: is_system,
                });
            } else {
                eprintln!("WARNING: Could not parse line (no = found): {}", line);
            }
        }
    }
    
    // Sort apps alphabetically by app name
    apps.sort_by(|a, b| a.app_name.to_lowercase().cmp(&b.app_name.to_lowercase()));

    Ok(apps)
}

/// Get app label (display name)
fn get_app_label(adb_path: &Path, serial: &str, package: &str) -> Result<String, String> {
    let output = create_hidden_command(adb_path)
        .args(&["-s", serial, "shell", "pm", "dump", package])
        .output()
        .map_err(|e| format!("Failed to get app info: {}", e))?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // Look for application label
    for line in output_str.lines() {
        if line.contains("applicationInfo") || line.contains("label") {
            // This is simplified - real implementation would parse dumpsys output better
            return Ok(package.split('.').last().unwrap_or(package).to_string());
        }
    }

    Ok(package.to_string())
}

/// Pull Chrome browser history from device
pub fn get_chrome_history(app_handle: &tauri::AppHandle, serial: &str) -> Result<AndroidBrowserData, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    // First, check if Chrome is installed
    eprintln!("[Android Browser] Checking if Chrome is installed...");
    let package_check = create_hidden_command(&adb_path)
        .args(&[
            "-s", serial,
            "shell",
            "pm list packages | grep com.android.chrome"
        ])
        .output();
    
    match package_check {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains("com.android.chrome") {
                return Err("Chrome is not installed on this device".to_string());
            }
            eprintln!("[Android Browser] Chrome is installed");
        }
        Err(e) => {
            eprintln!("[Android Browser] Failed to check for Chrome: {}", e);
        }
    }
    
    // Chrome database path on Android
    let db_path = "/data/data/com.android.chrome/app_chrome/Default/History";
    let temp_dir = std::env::temp_dir();
    let local_db = temp_dir.join(format!("chrome_history_{}.db", serial));

    // Try to pull the database file using run-as (works on non-rooted devices)
    eprintln!("[Android Browser] Attempting to access Chrome history database...");
    
    // First try: direct pull (works on some devices with root or special permissions)
    eprintln!("[Android Browser] Method 1: Attempting direct pull...");
    let mut output = create_hidden_command(&adb_path)
        .args(&[
            "-s", serial,
            "pull",
            db_path,
            local_db.to_str().unwrap()
        ])
        .output()
        .map_err(|e| format!("Failed to pull Chrome history: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("[Android Browser] Direct pull failed: {}", stderr);
    }

    // If direct pull failed, try using run-as
    if !output.status.success() {
        eprintln!("[Android Browser] Method 2: Attempting run-as method...");
        
        // Create temp location on device
        let device_temp = format!("/sdcard/chrome_history_temp_{}.db", serial);
        
        // Try to copy database to accessible location using run-as
        // Method 2a: Try with sh -c for proper shell handling
        let copy_result = create_hidden_command(&adb_path)
            .args(&[
                "-s", serial,
                "shell",
                "sh", "-c",
                &format!("run-as com.android.chrome cat app_chrome/Default/History > {}", device_temp)
            ])
            .output();
        
        let mut run_as_success = false;
        if let Ok(copy_output) = copy_result {
            if copy_output.status.success() {
                run_as_success = true;
                eprintln!("[Android Browser] Run-as copy successful");
            } else {
                let stderr = String::from_utf8_lossy(&copy_output.stderr);
                eprintln!("[Android Browser] Run-as method failed: {}", stderr);
                
                // Method 2b: Try alternative run-as approach
                if !run_as_success {
                    eprintln!("[Android Browser] Method 3: Trying alternative run-as approach...");
                    let alt_result = create_hidden_command(&adb_path)
                        .args(&[
                            "-s", serial,
                            "shell",
                            "run-as", "com.android.chrome",
                            "cat", "app_chrome/Default/History"
                        ])
                        .output();
                    
                    if let Ok(alt_output) = alt_result {
                        if alt_output.status.success() && !alt_output.stdout.is_empty() {
                            // Write stdout directly to local file
                            if std::fs::write(&local_db, &alt_output.stdout).is_ok() {
                                eprintln!("[Android Browser] Alternative run-as method successful (direct pipe)");
                                run_as_success = true;
                            }
                        }
                    }
                }
            }
        }
        
        if run_as_success {
            // Pull from accessible location (if using temp file method)
            if std::fs::metadata(&device_temp).is_ok() {
                output = create_hidden_command(&adb_path)
                    .args(&[
                        "-s", serial,
                        "pull",
                        &device_temp,
                        local_db.to_str().unwrap()
                    ])
                    .output()
                    .map_err(|e| format!("Failed to pull Chrome history: {}", e))?;
                
                // Clean up temp file on device
                let _ = create_hidden_command(&adb_path)
                    .args(&["-s", serial, "shell", "rm", &device_temp])
                    .output();
            }
        }
    }

    if !output.status.success() || !local_db.exists() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let error_msg = if stderr.contains("Permission denied") {
            "Chrome data is protected on Android. This requires either:\n\
             1. Root access on the device\n\
             2. Chrome must be debuggable (not the production version)\n\
             3. Android version must be older (before Android 10's scoped storage)"
        } else if stderr.contains("does not exist") || stderr.contains("No such file") {
            "Chrome history database not found. Chrome may not have been used yet, or the database path may be different on this device."
        } else {
            "Failed to access Chrome history. USB debugging must be enabled and authorized."
        };
        
        eprintln!("[Android Browser] Final error: {}", error_msg);
        eprintln!("[Android Browser] Technical details: {}", stderr);
        return Err(error_msg.to_string());
    }

    eprintln!("[Android Browser] Successfully pulled Chrome history database");

    // Parse the database
    let history = match parse_chrome_database(&local_db) {
        Ok(h) => h,
        Err(e) => {
            // Clean up failed database file
            let _ = std::fs::remove_file(&local_db);
            return Err(format!("Failed to parse Chrome database: {}", e));
        }
    };

    // Clean up local database file
    let _ = std::fs::remove_file(local_db);

    eprintln!("[Android Browser] Successfully parsed {} history entries", history.len());

    Ok(AndroidBrowserData {
        browser_name: "Chrome".to_string(),
        package_name: "com.android.chrome".to_string(),
        history,
        bookmarks: Vec::new(),
    })
}

/// Parse Chrome history database
fn parse_chrome_database(db_path: &PathBuf) -> Result<Vec<AndroidHistoryEntry>, String> {
    use rusqlite::Connection;

    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time, typed_count FROM urls ORDER BY last_visit_time DESC LIMIT 1000"
    ).map_err(|e| format!("Failed to prepare statement: {}", e))?;

    let entries = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1).unwrap_or_else(|_| String::new());
        let visit_count: i32 = row.get(2)?;
        let last_visit_time: i64 = row.get(3)?;
        let typed_count: i32 = row.get(4).unwrap_or(0);

        // Convert Chrome timestamp (microseconds since 1601-01-01) to readable format
        let last_visit = if last_visit_time > 0 {
            convert_chrome_timestamp(last_visit_time)
        } else {
            "Unknown".to_string()
        };

        Ok(AndroidHistoryEntry {
            url,
            title,
            visit_count,
            last_visit,
        })
    }).map_err(|e| format!("Query failed: {}", e))?
    .filter_map(|e| e.ok())
    .collect();

    Ok(entries)
}

/// Convert Chrome timestamp to readable format
fn convert_chrome_timestamp(timestamp: i64) -> String {
    // Chrome uses microseconds since January 1, 1601 UTC
    const EPOCH_DIFF: i64 = 11644473600; // Seconds between 1601 and 1970
    
    if timestamp == 0 {
        return "Unknown".to_string();
    }
    
    // Convert microseconds to seconds
    let unix_seconds = (timestamp / 1_000_000) - EPOCH_DIFF;
    
    if unix_seconds < 0 {
        return "Unknown".to_string();
    }
    
    // Convert to chrono DateTime
    if let Some(naive) = NaiveDateTime::from_timestamp_opt(unix_seconds, 0) {
        let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
        datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Scan Android browsers and return in Windows-compatible BrowserData format
pub fn scan_android_browsers(app_handle: &tauri::AppHandle, serial: &str) -> Result<Vec<serde_json::Value>, String> {
    eprintln!("[Android Browser] Starting browser scan for device {}", serial);
    
    let mut browsers = Vec::new();
    let mut last_error: Option<String> = None;
    
    // Try to get Chrome history
    match get_chrome_history(app_handle, serial) {
        Ok(android_browser_data) => {
            eprintln!("[Android Browser] Successfully scanned Chrome: {} history entries", 
                android_browser_data.history.len());
            
            // Convert to Windows BrowserData format
            let mut browser_map = serde_json::Map::new();
            browser_map.insert("browserType".to_string(), serde_json::Value::String("Chrome".to_string()));
            browser_map.insert("browserName".to_string(), serde_json::Value::String("Chrome (Android)".to_string()));
            browser_map.insert("profileName".to_string(), serde_json::Value::String("Default".to_string()));
            browser_map.insert("installPath".to_string(), serde_json::Value::String(android_browser_data.package_name.clone()));
            browser_map.insert("profilePath".to_string(), serde_json::Value::String("/data/data/com.android.chrome".to_string()));
            
            // Convert history entries to Windows format
            let history_entries: Vec<serde_json::Value> = android_browser_data.history.iter().map(|entry| {
                let mut hist_map = serde_json::Map::new();
                hist_map.insert("url".to_string(), serde_json::Value::String(entry.url.clone()));
                hist_map.insert("title".to_string(), serde_json::Value::String(entry.title.clone()));
                hist_map.insert("visitCount".to_string(), serde_json::Value::Number(entry.visit_count.into()));
                hist_map.insert("lastVisit".to_string(), serde_json::Value::String(entry.last_visit.clone()));
                hist_map.insert("typedCount".to_string(), serde_json::Value::Number(0.into()));
                serde_json::Value::Object(hist_map)
            }).collect();
            
            browser_map.insert("history".to_string(), serde_json::Value::Array(history_entries));
            browser_map.insert("bookmarks".to_string(), serde_json::Value::Array(Vec::new()));
            browser_map.insert("credentials".to_string(), serde_json::Value::Array(Vec::new()));
            browser_map.insert("downloads".to_string(), serde_json::Value::Array(Vec::new()));
            
            browsers.push(serde_json::Value::Object(browser_map));
        }
        Err(e) => {
            eprintln!("[Android Browser] Failed to scan Chrome: {}", e);
            // Store the error to return to UI
            last_error = Some(e);
        }
    }
    
    // Could add more browsers here (Firefox, Samsung Internet, etc.)
    
    if browsers.is_empty() {
        // Return the specific error from Chrome, or a generic error if none
        return Err(last_error.unwrap_or_else(|| 
            "No browser data could be accessed. This typically requires USB debugging and may need additional permissions or root access on newer Android versions.".to_string()
        ));
    }
    
    eprintln!("[Android Browser] Browser scan complete: {} browser(s) scanned", browsers.len());
    Ok(browsers)
}

/// Pull files from Android device to local temp directory for scanning
pub fn pull_files_for_scanning(app_handle: &tauri::AppHandle, serial: &str, paths: Vec<String>) -> Result<PathBuf, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    let temp_dir = std::env::temp_dir().join(format!("android_scan_{}", serial));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;

    let temp_dir_str = temp_dir.to_str().unwrap();
    for path in paths {
        let output = create_hidden_command(&adb_path)
            .args(&["-s", serial, "pull", &path, temp_dir_str])
            .output()
            .map_err(|e| format!("Failed to pull files: {}", e))?;

        if !output.status.success() {
            eprintln!("Warning: Failed to pull {}", path);
        }
    }

    Ok(temp_dir)
}

/// Pull a single Android file to local cache and return the local path
pub fn pull_single_file(app_handle: &tauri::AppHandle, serial: &str, android_path: &str) -> Result<PathBuf, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    // Create cache directory for this device
    let cache_dir = std::env::temp_dir()
        .join("datapilot_scout")
        .join("android_media_cache")
        .join(serial);
    
    // Create directory structure matching Android path
    let android_path_buf = PathBuf::from(android_path);
    let filename = android_path_buf.file_name()
        .ok_or_else(|| "Invalid file path".to_string())?;
    
    // Create parent directories
    if let Some(parent) = android_path_buf.parent() {
        let local_parent = cache_dir.join(parent.strip_prefix("/").unwrap_or(parent));
        std::fs::create_dir_all(&local_parent)
            .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    }
    
    // Determine local cache path
    let android_path_ref = android_path_buf.as_path();
    let local_path = cache_dir.join(android_path_buf.strip_prefix("/").unwrap_or(&android_path_ref));
    
    // Check if file already cached
    if local_path.exists() {
        return Ok(local_path);
    }
    
    // Pull file from Android device
    let local_path_str = local_path.to_str().unwrap();
    let output = create_hidden_command(&adb_path)
        .args(&["-s", serial, "pull", android_path, local_path_str])
        .output()
        .map_err(|e| format!("Failed to pull file: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ADB pull failed: {}", stderr));
    }

    Ok(local_path)
}

/// Get common Android paths for scanning
pub fn get_android_scan_paths() -> Vec<String> {
    vec![
        "/sdcard/Download".to_string(),
        "/sdcard/DCIM".to_string(),
        "/sdcard/Pictures".to_string(),
        "/sdcard/Documents".to_string(),
        "/sdcard/WhatsApp".to_string(),
        "/sdcard/Telegram".to_string(),
    ]
}

/// Check if device has USB debugging enabled
pub fn check_device_ready(app_handle: &tauri::AppHandle, serial: &str) -> Result<bool, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    let output = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "echo", "ready"])
        .output()
        .map_err(|e| format!("Failed to check device: {}", e))?;

    Ok(output.status.success())
}

/// Check if device is rooted
pub fn check_root_status(app_handle: &tauri::AppHandle, serial: &str) -> Result<bool, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    // Try to execute 'su' command
    let output = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "su", "-c", "id"])
        .output()
        .map_err(|e| format!("Failed to check root: {}", e))?;
    
    // If 'uid=0(root)' appears, device is rooted
    let output_str = String::from_utf8_lossy(&output.stdout);
    Ok(output_str.contains("uid=0") || output_str.contains("root"))
}

/// Get detailed Android device information
pub fn get_android_device_info(app_handle: &tauri::AppHandle, serial: &str) -> Result<serde_json::Value, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    let mut info = serde_json::Map::new();
    
    // Basic device properties (removed "device" codename)
    let properties = vec![
        ("manufacturer", "ro.product.manufacturer"),
        ("model", "ro.product.model"),
        ("androidVersion", "ro.build.version.release"),
        ("sdkVersion", "ro.build.version.sdk"),
        ("buildId", "ro.build.id"),
        ("serialNumber", "ro.serialno"),
    ];
    
    for (key, prop) in properties {
        if let Ok(value) = get_device_property(&adb_path, serial, prop) {
            if !value.is_empty() {
                info.insert(key.to_string(), serde_json::Value::String(value));
            }
        }
    }
    
    // Create deviceName from manufacturer and model
    let manufacturer = info.get("manufacturer")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let model = info.get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    info.insert("deviceName".to_string(), serde_json::Value::String(format!("{} {}", manufacturer, model)));
    
    // Get storage information
    // Try dumpsys diskstats first (gives nicely formatted MB values)
    if let Ok(output) = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "dumpsys", "diskstats"])
        .output()
    {
        let diskstats_output = String::from_utf8_lossy(&output.stdout);
        for line in diskstats_output.lines() {
            if line.contains("Data-Free:") {
                if let Some(free_str) = line.split(':').nth(1) {
                    let free_trimmed = free_str.trim().replace("MB", "");
                    let free = free_trimmed.trim();
                    if let Ok(free_mb) = free.parse::<f64>() {
                        info.insert("storageFree".to_string(), serde_json::Value::String(format!("{:.1} GB", free_mb / 1024.0)));
                    }
                }
            } else if line.contains("Data-Used:") {
                if let Some(used_str) = line.split(':').nth(1) {
                    let used_trimmed = used_str.trim().replace("MB", "");
                    let used = used_trimmed.trim();
                    if let Ok(used_mb) = used.parse::<f64>() {
                        info.insert("storageUsed".to_string(), serde_json::Value::String(format!("{:.1} GB", used_mb / 1024.0)));
                    }
                }
            }
        }
    }
    
    // Fallback: try df command (returns values in KB on most devices)
    if !info.contains_key("storageUsed") {
        if let Ok(output) = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "df", "/data"])
            .output()
        {
            let storage_output = String::from_utf8_lossy(&output.stdout);
            // Parse df output - typically format: Filesystem Size Used Avail Use% Mounted
            for line in storage_output.lines().skip(1) { // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    // df usually returns KB (1K-blocks), convert to human readable
                    if let Ok(used_kb) = parts[2].parse::<u64>() {
                        let used_gb = used_kb as f64 / 1024.0 / 1024.0;
                        info.insert("storageUsed".to_string(), serde_json::Value::String(format!("{:.1} GB", used_gb)));
                    }
                    if let Ok(total_kb) = parts[1].parse::<u64>() {
                        let total_gb = total_kb as f64 / 1024.0 / 1024.0;
                        info.insert("storageTotal".to_string(), serde_json::Value::String(format!("{:.1} GB", total_gb)));
                    }
                    if let Ok(avail_kb) = parts[3].parse::<u64>() {
                        let avail_gb = avail_kb as f64 / 1024.0 / 1024.0;
                        info.insert("storageAvailable".to_string(), serde_json::Value::String(format!("{:.1} GB", avail_gb)));
                    }
                    break;
                }
            }
        }
    }
    
    // Try to get IMEI (may require permissions)
    if let Ok(output) = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "service", "call", "iphonesubinfo", "1"])
        .output()
    {
        let imei_output = String::from_utf8_lossy(&output.stdout);
        // Parse IMEI from output if available
        if !imei_output.contains("SecurityException") && !imei_output.is_empty() {
            info.insert("imei".to_string(), serde_json::Value::String("Available (protected)".to_string()));
        }
    }
    
    // Get battery info
    if let Ok(output) = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "dumpsys", "battery"])
        .output()
    {
        let battery_output = String::from_utf8_lossy(&output.stdout);
        for line in battery_output.lines() {
            if line.contains("level:") {
                if let Some(level) = line.split(':').nth(1) {
                    info.insert("batteryLevel".to_string(), serde_json::Value::String(level.trim().to_string() + "%"));
                }
            }
        }
    }
    
    // Try to get phone number (requires permissions)
    // Method 1: Using service call
    if let Ok(output) = create_hidden_command(&adb_path)
        .args(&["-s", serial, "shell", "service", "call", "iphonesubinfo", "4"])
        .output()
    {
        let phone_output = String::from_utf8_lossy(&output.stdout);
        if !phone_output.contains("SecurityException") && !phone_output.trim().is_empty() {
            // Parse the hex-encoded phone number from service call output
            // Format is typically: Result: Parcel(HEXVALUE 'phonenumber')
            if let Some(start) = phone_output.find('\'') {
                if let Some(end) = phone_output[start+1..].find('\'') {
                    let phone_number = &phone_output[start+1..start+1+end];
                    if !phone_number.is_empty() && phone_number.chars().any(|c| c.is_digit(10)) {
                        info.insert("phoneNumber".to_string(), serde_json::Value::String(phone_number.to_string()));
                    }
                }
            }
        }
    }
    
    // Method 2: Try dumpsys telephony.registry (fallback)
    if !info.contains_key("phoneNumber") {
        if let Ok(output) = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "dumpsys", "telephony.registry"])
            .output()
        {
            let telephony_output = String::from_utf8_lossy(&output.stdout);
            for line in telephony_output.lines() {
                if line.contains("mCallIncomingNumber=") {
                    if let Some(number_str) = line.split("mCallIncomingNumber=").nth(1) {
                        let number = number_str.trim();
                        if !number.is_empty() && number != "null" {
                            info.insert("phoneNumber".to_string(), serde_json::Value::String(number.to_string()));
                            break;
                        }
                    }
                }
            }
        }
    }
    
    // Method 3: Check if SIM is present (even if we can't get the number)
    if !info.contains_key("phoneNumber") {
        if let Ok(output) = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "getprop", "gsm.sim.state"])
            .output()
        {
            let sim_state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if sim_state == "READY" {
                info.insert("phoneNumber".to_string(), serde_json::Value::String("SIM Present (Number Protected)".to_string()));
            } else if !sim_state.is_empty() {
                info.insert("phoneNumber".to_string(), serde_json::Value::String(format!("SIM: {}", sim_state)));
            }
        }
    }
    
    Ok(serde_json::Value::Object(info))
}

/// Scan Android device for media files (images and videos)
pub fn scan_android_media(app_handle: &tauri::AppHandle, serial: &str) -> Result<Vec<serde_json::Value>, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    
    // Define common Android media paths
    let media_paths = vec![
        "/sdcard/DCIM",
        "/sdcard/Camera",
        "/sdcard/Pictures",
        "/sdcard/Download",
        "/sdcard/Downloads",
        "/sdcard/Movies",
        "/sdcard/Video",
        "/sdcard/WhatsApp/Media/WhatsApp Images",
        "/sdcard/WhatsApp/Media/WhatsApp Video",
    ];
    
    let mut all_media_files = Vec::new();
    
    // Media file extensions we're looking for
    let image_extensions = vec!["jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "heif"];
    let video_extensions = vec!["mp4", "avi", "mov", "mkv", "3gp", "m4v", "wmv", "flv"];
    
    for base_path in media_paths {
        // Check if path exists
        let check_output = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "test", "-d", base_path, "&&", "echo", "exists"])
            .output();
        
        if let Ok(output) = check_output {
            if !String::from_utf8_lossy(&output.stdout).contains("exists") {
                continue; // Path doesn't exist, skip
            }
        } else {
            continue;
        }
        
        // Find all files in this directory (recursive)
        let find_output = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "find", base_path, "-type", "f"])
            .output();
        
        if let Ok(output) = find_output {
            if !output.status.success() {
                eprintln!("Warning: Failed to scan {}", base_path);
                continue;
            }
            
            let file_list = String::from_utf8_lossy(&output.stdout);
            
            for file_path in file_list.lines() {
                let file_path = file_path.trim();
                
                if file_path.is_empty() {
                    continue;
                }
                
                // Check if file has media extension
                let file_lower = file_path.to_lowercase();
                let is_image = image_extensions.iter().any(|ext| {
                    let ext_with_dot = format!(".{}", ext);
                    file_lower.ends_with(&ext_with_dot)
                });
                let is_video = video_extensions.iter().any(|ext| {
                    let ext_with_dot = format!(".{}", ext);
                    file_lower.ends_with(&ext_with_dot)
                });
                
                if !is_image && !is_video {
                    continue;
                }
                
                // Get file size using stat (quote path to handle spaces in filenames)
                let stat_cmd = format!("stat -c %s '{}'", file_path.replace("'", "'\\''"));
                let stat_output = create_hidden_command(&adb_path)
                    .args(&["-s", serial, "shell", &stat_cmd])
                    .output();
                
                let file_size = if let Ok(output) = stat_output {
                    String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(0)
                } else {
                    0
                };
                
                // Extract filename
                let filename = file_path.split('/').last().unwrap_or("unknown").to_string();
                
                // Create media file entry
                let mut media_file = serde_json::Map::new();
                media_file.insert("path".to_string(), serde_json::Value::String(file_path.to_string()));
                media_file.insert("filename".to_string(), serde_json::Value::String(filename));
                media_file.insert("sizeBytes".to_string(), serde_json::Value::Number(file_size.into()));
                media_file.insert("fileType".to_string(), serde_json::Value::String(
                    if is_image { "Image" } else { "Video" }.to_string()
                ));
                media_file.insert("createdDate".to_string(), serde_json::Value::String("Unknown".to_string()));
                media_file.insert("modifiedDate".to_string(), serde_json::Value::String("Unknown".to_string()));
                
                all_media_files.push(serde_json::Value::Object(media_file));
                
                // Limit to prevent overwhelming the system
                if all_media_files.len() >= 10000 {
                    eprintln!("Warning: Reached 10,000 file limit, stopping scan");
                    return Ok(all_media_files);
                }
            }
        }
    }
    
    Ok(all_media_files)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidHashMatch {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub md5_hash: String,
    pub sha256_hash: String,
    pub matched_hash: String,
    pub hash_type: String,
    pub list_name: String,
    pub list_source: String,
    pub description: Option<String>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidHashScanProgress {
    pub status: String,
    pub current_file: String,
    pub files_scanned: usize,
    pub total_files: usize,
    pub matches_found: usize,
}

/// Scan Android media files for known hashes
/// This function pulls files from the device, computes hashes, and checks against the hash database
pub fn scan_android_media_hashes(
    app_handle: &tauri::AppHandle,
    serial: &str,
    progress_callback: Option<Box<dyn Fn(AndroidHashScanProgress) + Send>>,
    selected_hash_list_ids: Option<Vec<String>>
) -> Result<Vec<AndroidHashMatch>, String> {
    use tauri::Emitter;
    
    eprintln!("[Android Hash Scan] Starting hash scan for device {}", serial);
    
    // Reset cancellation flag so previous cancellations don't block this scan
    crate::scanner::hash_scan::reset_scan_cancelled();
    
    // Emit initial progress event
    let _ = app_handle.emit("android:hash_scan_progress", serde_json::json!({
        "status": "discovering",
        "currentFile": "",
        "filesScanned": 0,
        "totalFiles": 0,
        "matchesFound": 0
    }));
    
    // Discover ALL files for hashing — not just media extensions.
    // CSAM content can have any extension or be renamed.
    let adb_path = get_bundled_adb_path(app_handle);
    let hash_scan_paths = vec![
        "/sdcard/DCIM",
        "/sdcard/Camera",
        "/sdcard/Pictures",
        "/sdcard/Download",
        "/sdcard/Downloads",
        "/sdcard/Movies",
        "/sdcard/Video",
        "/sdcard/WhatsApp/Media/WhatsApp Images",
        "/sdcard/WhatsApp/Media/WhatsApp Video",
        "/sdcard/Telegram",
        "/sdcard/Android/data",
    ];
    
    let mut all_files: Vec<serde_json::Value> = Vec::new();
    
    for base_path in &hash_scan_paths {
        // Check if path exists
        let check_output = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "test", "-d", base_path, "&&", "echo", "exists"])
            .output();
        
        let path_exists = if let Ok(output) = check_output {
            String::from_utf8_lossy(&output.stdout).contains("exists")
        } else {
            false
        };
        
        if !path_exists {
            eprintln!("[Android Hash Scan] Path not found, skipping: {}", base_path);
            continue;
        }
        
        let files_before = all_files.len();
        
        // Find ALL files in a SINGLE adb call — no per-file stat needed for hash scanning
        let find_cmd = format!("find '{}' -type f 2>/dev/null", base_path);
        let find_output = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", &find_cmd])
            .output();
        
        if let Ok(output) = find_output {
            let file_list = String::from_utf8_lossy(&output.stdout).replace('\r', "");
            
            for line in file_list.lines() {
                let file_path = line.trim();
                if file_path.is_empty() {
                    continue;
                }
                
                let filename = file_path.split('/').last().unwrap_or("unknown").to_string();
                
                let mut entry = serde_json::Map::new();
                entry.insert("path".to_string(), serde_json::Value::String(file_path.to_string()));
                entry.insert("filename".to_string(), serde_json::Value::String(filename));
                entry.insert("sizeBytes".to_string(), serde_json::Value::Number(0.into()));
                all_files.push(serde_json::Value::Object(entry));
                
                // Safety cap
                if all_files.len() >= 15000 {
                    eprintln!("[Android Hash Scan] Reached 15,000 file limit, stopping discovery");
                    break;
                }
            }
        }
        
        if all_files.len() >= 15000 {
            break;
        }
        
        eprintln!("[Android Hash Scan] {} => {} files found", base_path, all_files.len() - files_before);
    }
    
    let total_files = all_files.len();
    eprintln!("[Android Hash Scan] Found {} files to hash-check", total_files);
    
    if total_files == 0 {
        return Ok(Vec::new());
    }
    
    // Open hash database
    let hash_db = crate::hash_db::HashDatabase::new()
        .map_err(|e| format!("Failed to open hash database: {}", e))?;
    
    // Check if database has any hashes
    let db_stats = hash_db.get_stats()
        .map_err(|e| format!("Failed to get database statistics: {}", e))?;
    
    if db_stats.total_hashes == 0 {
        return Err("No hash lists loaded. Please import hash lists before scanning.".to_string());
    }
    
    eprintln!("[Android Hash Scan] Database contains {} hashes from {} lists", 
        db_stats.total_hashes, db_stats.total_lists);
    
    // ── Load hashes into memory for O(1) lookups (bloom + HashSet) ──
    // Without this, every check_hash() does a SQLite query — extremely slow.
    eprintln!("[Android Hash Scan] Loading hashes into memory for fast lookups...");
    let loaded = hash_db.load_hashes_into_memory()
        .map_err(|e| format!("Failed to load hashes into memory: {}", e))?;
    eprintln!("[Android Hash Scan] ✓ {} hashes loaded into memory", loaded);
    
    // Determine if we need filtered lookups (only when specific lists are selected AND non-empty)
    let use_filtered = selected_hash_list_ids.as_ref()
        .map(|ids| !ids.is_empty())
        .unwrap_or(false);
    
    if use_filtered {
        eprintln!("[Android Hash Scan] Filtering to {} selected hash list(s)", 
            selected_hash_list_ids.as_ref().unwrap().len());
    } else {
        eprintln!("[Android Hash Scan] Using all available hash lists");
    }
    
    // Check if device has md5sum and sha256sum available
    let has_md5sum = {
        let out = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "which", "md5sum"])
            .output();
        out.map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()).unwrap_or(false)
    };
    let has_sha256sum = {
        let out = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "which", "sha256sum"])
            .output();
        out.map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()).unwrap_or(false)
    };
    
    let on_device_hashing = has_md5sum || has_sha256sum;
    eprintln!("[Android Hash Scan] On-device hashing: md5sum={}, sha256sum={}, using={}", 
        has_md5sum, has_sha256sum, if on_device_hashing { "on-device (fast)" } else { "pull-to-host (slow)" });
    
    // Also check for sha1sum (many CSAM hash lists use SHA-1)
    let has_sha1sum = {
        let out = create_hidden_command(&adb_path)
            .args(&["-s", serial, "shell", "which", "sha1sum"])
            .output();
        out.map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()).unwrap_or(false)
    };
    eprintln!("[Android Hash Scan] sha1sum available: {}", has_sha1sum);
    
    // Only need temp dir if falling back to pull-and-hash
    let temp_dir = if !on_device_hashing {
        let dir = std::env::temp_dir().join(format!("android_hash_scan_{}", serial));
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create temp directory: {}", e))?;
        Some(dir)
    } else {
        None
    };
    
    let mut matches = Vec::new();
    
    // ══════════════════════════════════════════════════════════════════════
    // BATCHED ON-DEVICE HASHING — hash many files per ADB call
    // Instead of 1 ADB call per file (~150ms overhead each = 3+ min for 1300 files),
    // write a shell script to the device that hashes a batch of files in one go.
    // Uses a for-loop on device to avoid ADB arg length limits.
    // 1300 files / 50 per batch = ~26 ADB calls instead of 1300.
    // ══════════════════════════════════════════════════════════════════════
    const BATCH_SIZE: usize = 50;
    
    if on_device_hashing {
        let batches: Vec<&[serde_json::Value]> = all_files.chunks(BATCH_SIZE).collect();
        let num_batches = batches.len();
        eprintln!("[Android Hash Scan] Processing {} files in {} batches of up to {}", 
            total_files, num_batches, BATCH_SIZE);
        
        let mut files_scanned: usize = 0;
        
        for (batch_idx, batch) in batches.iter().enumerate() {
            if crate::scanner::hash_scan::is_scan_cancelled() {
                eprintln!("[Android Hash Scan] ⛔ Scan cancelled at batch {}/{}", batch_idx + 1, num_batches);
                break;
            }
            
            // Collect paths for this batch
            let batch_paths: Vec<&str> = batch.iter()
                .filter_map(|e| e.get("path").and_then(|v| v.as_str()))
                .filter(|p| !p.is_empty())
                .collect();
            
            if batch_paths.is_empty() { 
                files_scanned += batch.len();
                continue; 
            }
            
            // Build a shell script that runs on-device as a for-loop.
            // Output format per file:
            //   ===FILE===<path>
            //   MD5=<hash>
            //   SHA1=<hash>
            //   SHA256=<hash>
            // Using printf for reliability (no echo -n issues).
            let mut file_list_escaped = Vec::new();
            for p in &batch_paths {
                // Double-escape: first escape single quotes for shell, then wrap in quotes
                let escaped = p.replace('\'', "'\\''");
                file_list_escaped.push(format!("'{}'", escaped));
            }
            
            // Build hash commands inside the for loop
            let mut hash_cmds = Vec::new();
            if has_md5sum {
                hash_cmds.push("h=$(md5sum \"$f\" 2>/dev/null | cut -d' ' -f1); printf 'MD5=%s\\n' \"$h\"");
            }
            if has_sha1sum {
                hash_cmds.push("h=$(sha1sum \"$f\" 2>/dev/null | cut -d' ' -f1); printf 'SHA1=%s\\n' \"$h\"");
            }
            if has_sha256sum {
                hash_cmds.push("h=$(sha256sum \"$f\" 2>/dev/null | cut -d' ' -f1); printf 'SHA256=%s\\n' \"$h\"");
            }
            let hash_body = hash_cmds.join("; ");
            
            let script = format!(
                "for f in {}; do printf '===FILE===%s\\n' \"$f\"; {}; done",
                file_list_escaped.join(" "),
                hash_body
            );
            
            // Single ADB call for entire batch
            let output = create_hidden_command(&adb_path)
                .args(&["-s", serial, "shell", &script])
                .output();
            
            let stdout = match output {
                Ok(o) => {
                    let raw = String::from_utf8_lossy(&o.stdout).replace('\r', "");
                    // Log first batch raw output for diagnostics
                    if batch_idx == 0 {
                        let preview: String = raw.chars().take(500).collect();
                        eprintln!("[Android Hash Scan] Batch 1 raw output (first 500 chars):\n{}", preview);
                    }
                    raw
                }
                Err(e) => {
                    eprintln!("[Android Hash Scan] Batch {} ADB error: {}", batch_idx + 1, e);
                    files_scanned += batch.len();
                    continue;
                }
            };
            
            // Parse batched output
            let mut current_path = String::new();
            let mut current_md5 = String::new();
            let mut current_sha1 = String::new();
            let mut current_sha256 = String::new();
            
            for line in stdout.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                
                if let Some(path) = line.strip_prefix("===FILE===") {
                    // Process previous file before moving to next
                    if !current_path.is_empty() {
                        check_android_hash_match(
                            &current_path, &current_md5, &current_sha1, &current_sha256,
                            &hash_db, use_filtered, &selected_hash_list_ids,
                            app_handle, &mut matches,
                        );
                    }
                    current_path = path.to_string();
                    current_md5.clear();
                    current_sha1.clear();
                    current_sha256.clear();
                } else if let Some(hash) = line.strip_prefix("MD5=") {
                    current_md5 = hash.trim().to_lowercase();
                } else if let Some(hash) = line.strip_prefix("SHA1=") {
                    current_sha1 = hash.trim().to_lowercase();
                } else if let Some(hash) = line.strip_prefix("SHA256=") {
                    current_sha256 = hash.trim().to_lowercase();
                }
            }
            // Process last file in batch
            if !current_path.is_empty() {
                check_android_hash_match(
                    &current_path, &current_md5, &current_sha1, &current_sha256,
                    &hash_db, use_filtered, &selected_hash_list_ids,
                    app_handle, &mut matches,
                );
            }
            
            files_scanned += batch.len();
            
            // Emit progress
            if let Some(ref callback) = progress_callback {
                callback(AndroidHashScanProgress {
                    status: "scanning".to_string(),
                    current_file: format!("Batch {}/{}", batch_idx + 1, num_batches),
                    files_scanned,
                    total_files,
                    matches_found: matches.len(),
                });
            }
            let _ = app_handle.emit("android:hash_scan_progress", serde_json::json!({
                "status": "scanning",
                "currentFile": format!("Batch {}/{}", batch_idx + 1, num_batches),
                "filesScanned": files_scanned,
                "totalFiles": total_files,
                "matchesFound": matches.len()
            }));
            
            if batch_idx == 0 {
                eprintln!("[Android Hash Scan] First batch complete: {}/{} files, {} matches", 
                    files_scanned, total_files, matches.len());
            }
        }
    } else {
        // ══════════════════════════════════════════════════════════════════
        // FALLBACK: pull-to-host — no on-device hash tools
        // Still uses in-memory hash lookups (fast), but must pull each file.
        // ══════════════════════════════════════════════════════════════════
        eprintln!("[Android Hash Scan] Using pull-to-host fallback (slower — device lacks hash tools)");
        let td = temp_dir.as_ref().unwrap();
        
        for (index, file_entry) in all_files.iter().enumerate() {
            if crate::scanner::hash_scan::is_scan_cancelled() {
                eprintln!("[Android Hash Scan] ⛔ Scan cancelled at file {}/{}", index + 1, total_files);
                break;
            }
            
            let file_path = file_entry.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let filename = file_entry.get("filename").and_then(|v| v.as_str()).unwrap_or("unknown");
            let file_size = file_entry.get("sizeBytes").and_then(|v| v.as_u64()).unwrap_or(0);
            
            if file_path.is_empty() { continue; }
            
            // Progress — throttled to every 10 files
            if index == 0 || (index + 1) % 10 == 0 || index + 1 == total_files {
                if let Some(ref callback) = progress_callback {
                    callback(AndroidHashScanProgress {
                        status: "scanning".to_string(),
                        current_file: filename.to_string(),
                        files_scanned: index + 1,
                        total_files,
                        matches_found: matches.len(),
                    });
                }
                let _ = app_handle.emit("android:hash_scan_progress", serde_json::json!({
                    "status": "scanning",
                    "currentFile": filename,
                    "filesScanned": index + 1,
                    "totalFiles": total_files,
                    "matchesFound": matches.len()
                }));
            }
            
            let local_file = td.join(format!("{}_{}", index, filename));
            let local_file_str = local_file.to_string_lossy().to_string();
            let pull_result = create_hidden_command(&adb_path)
                .args(&["-s", serial, "pull", file_path, &local_file_str])
                .output();
            
            if let Err(e) = pull_result {
                if (index + 1) % 50 == 0 {
                    eprintln!("  Failed to pull file: {}", e);
                }
                continue;
            }
            let pull_output = pull_result.unwrap();
            if !pull_output.status.success() { 
                let _ = fs::remove_file(&local_file);
                continue; 
            }
            
            let hash_result = compute_file_hashes(&local_file);
            let _ = fs::remove_file(&local_file);
            
            if let Ok((md5, sha256)) = hash_result {
                check_android_hash_match(
                    file_path, &md5, "", &sha256,
                    &hash_db, use_filtered, &selected_hash_list_ids,
                    app_handle, &mut matches,
                );
            }
        }
    }
    
    // Clean up temp directory if used
    if let Some(ref td) = temp_dir {
        let _ = fs::remove_dir_all(td);
    }
    
    eprintln!("[Android Hash Scan] Scan complete. Found {} matches", matches.len());
    
    // Emit completion event
    let _ = app_handle.emit("android:hash_scan_progress", serde_json::json!({
        "status": "complete",
        "currentFile": "",
        "filesScanned": total_files,
        "totalFiles": total_files,
        "matchesFound": matches.len()
    }));
    
    Ok(matches)
}

/// Compute MD5, SHA1, and SHA256 hashes on the Android device itself via adb shell.
/// Returns (md5, sha1, sha256) — any may be empty if that tool isn't available.
/// Uses a SINGLE adb shell call with all hash commands chained via && to minimize
/// USB round-trips (the main bottleneck for Android hash scanning speed).
/// Shared helper: check MD5/SHA1/SHA256 against the hash database and emit match events.
/// Used by both the batched on-device hashing path and the pull-to-host fallback.
fn check_android_hash_match(
    file_path: &str,
    md5: &str,
    sha1: &str,
    sha256: &str,
    hash_db: &crate::hash_db::HashDatabase,
    use_filtered: bool,
    selected_hash_list_ids: &Option<Vec<String>>,
    app_handle: &tauri::AppHandle,
    matches: &mut Vec<AndroidHashMatch>,
) {
    use tauri::Emitter;
    
    let filename = file_path.split('/').last().unwrap_or("unknown");
    let mut found_match = false;
    
    // Check SHA256 first (preferred)
    if !found_match && !sha256.is_empty() {
        let m = if use_filtered {
            hash_db.check_hash_filtered(sha256, "SHA256", selected_hash_list_ids.as_ref().unwrap())
                .ok().flatten()
        } else {
            hash_db.check_hash_fast(sha256, "SHA256")
        };
        if let Some(match_data) = m {
            eprintln!("  ✓ HASH MATCH (SHA256): {}", filename);
            let hm = AndroidHashMatch {
                file_path: file_path.to_string(),
                file_name: filename.to_string(),
                file_size: 0,
                md5_hash: md5.to_string(),
                sha256_hash: sha256.to_string(),
                matched_hash: sha256.to_string(),
                hash_type: "SHA256".to_string(),
                list_name: match_data.source.clone(),
                list_source: match_data.source,
                description: match_data.description,
                severity: "Critical".to_string(),
            };
            let _ = app_handle.emit("android:hash_match", &hm);
            matches.push(hm);
            found_match = true;
        }
    }
    
    // Check SHA1 (many CSAM hash lists use SHA-1)
    if !found_match && !sha1.is_empty() {
        let m = if use_filtered {
            hash_db.check_hash_filtered(sha1, "SHA1", selected_hash_list_ids.as_ref().unwrap())
                .ok().flatten()
        } else {
            hash_db.check_hash_fast(sha1, "SHA1")
        };
        if let Some(match_data) = m {
            eprintln!("  ✓ HASH MATCH (SHA1): {}", filename);
            let hm = AndroidHashMatch {
                file_path: file_path.to_string(),
                file_name: filename.to_string(),
                file_size: 0,
                md5_hash: md5.to_string(),
                sha256_hash: sha256.to_string(),
                matched_hash: sha1.to_string(),
                hash_type: "SHA1".to_string(),
                list_name: match_data.source.clone(),
                list_source: match_data.source,
                description: match_data.description,
                severity: "Critical".to_string(),
            };
            let _ = app_handle.emit("android:hash_match", &hm);
            matches.push(hm);
            found_match = true;
        }
    }
    
    // Check MD5 last
    if !found_match && !md5.is_empty() {
        let m = if use_filtered {
            hash_db.check_hash_filtered(md5, "MD5", selected_hash_list_ids.as_ref().unwrap())
                .ok().flatten()
        } else {
            hash_db.check_hash_fast(md5, "MD5")
        };
        if let Some(match_data) = m {
            eprintln!("  ✓ HASH MATCH (MD5): {}", filename);
            let hm = AndroidHashMatch {
                file_path: file_path.to_string(),
                file_name: filename.to_string(),
                file_size: 0,
                md5_hash: md5.to_string(),
                sha256_hash: sha256.to_string(),
                matched_hash: md5.to_string(),
                hash_type: "MD5".to_string(),
                list_name: match_data.source.clone(),
                list_source: match_data.source,
                description: match_data.description,
                severity: "Critical".to_string(),
            };
            let _ = app_handle.emit("android:hash_match", &hm);
            matches.push(hm);
        }
    }
}

#[allow(dead_code)]
fn compute_hashes_on_device(
    adb_path: &Path,
    serial: &str,
    device_file_path: &str,
    has_md5sum: bool,
    has_sha1sum: bool,
    has_sha256sum: bool,
) -> Result<(String, String, String), String> {
    let escaped_path = device_file_path.replace("'", "'\\''");
    
    // Build a single shell command that outputs all hashes with markers
    // Format: "MD5:<hash>\nSHA1:<hash>\nSHA256:<hash>\n"
    let mut parts = Vec::new();
    if has_md5sum {
        parts.push(format!("echo -n 'MD5:' && md5sum '{}' | cut -d' ' -f1", escaped_path));
    }
    if has_sha1sum {
        parts.push(format!("echo -n 'SHA1:' && sha1sum '{}' | cut -d' ' -f1", escaped_path));
    }
    if has_sha256sum {
        parts.push(format!("echo -n 'SHA256:' && sha256sum '{}' | cut -d' ' -f1", escaped_path));
    }
    
    if parts.is_empty() {
        return Err("No hash tools available on device".to_string());
    }
    
    let combined_cmd = parts.join(" ; ");
    let output = create_hidden_command(adb_path)
        .args(&["-s", serial, "shell", &combined_cmd])
        .output()
        .map_err(|e| format!("Hash command failed: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
    
    let mut md5 = String::new();
    let mut sha1 = String::new();
    let mut sha256 = String::new();
    
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(hash) = line.strip_prefix("MD5:") {
            md5 = hash.trim().to_lowercase();
        } else if let Some(hash) = line.strip_prefix("SHA1:") {
            sha1 = hash.trim().to_lowercase();
        } else if let Some(hash) = line.strip_prefix("SHA256:") {
            sha256 = hash.trim().to_lowercase();
        }
    }
    
    if md5.is_empty() && sha1.is_empty() && sha256.is_empty() {
        return Err("Could not compute any hash on device".to_string());
    }
    
    Ok((md5, sha1, sha256))
}

/// Compute MD5 and SHA256 hashes for a file
fn compute_file_hashes(path: &Path) -> Result<(String, String), String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    let mut md5_hasher = Md5::new();
    let mut sha256_hasher = Sha256::new();
    
    md5_hasher.update(&buffer);
    sha256_hasher.update(&buffer);
    
    let md5_hash = format!("{:x}", md5_hasher.finalize());
    let sha256_hash = format!("{:x}", sha256_hasher.finalize());
    
    Ok((md5_hash, sha256_hash))
}

