use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a Command that runs without showing a window on Windows
fn create_hidden_command(program: &PathBuf) -> Command {
    let mut cmd = Command::new(program);
    
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    cmd
}

/// Get path to libimobiledevice tools
/// Try system PATH first (works better with Apple Mobile Device Service),
/// then fall back to bundled tools
fn get_tool_path(tool_name: &str) -> PathBuf {
    // First, try to find the tool in system PATH by attempting to execute it
    let system_tool = PathBuf::from(tool_name);
    
    // Test if system tool works by checking version or help
    if let Ok(output) = Command::new(&system_tool).arg("--version").output() {
        if output.status.success() {
            eprintln!("[Tool Path] Using system PATH version of {}", tool_name);
            return system_tool;
        }
    }
    
    // Fall back to bundled tools
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    let bundled_path = exe_dir.join("external").join("libimobiledevice").join(tool_name);
    
    if bundled_path.exists() {
        eprintln!("[Tool Path] Using bundled version of {}", tool_name);
        bundled_path
    } else {
        eprintln!("[Tool Path] Neither system nor bundled {} found, using system PATH as fallback", tool_name);
        system_tool
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosInstalledApp {
    pub bundle_id: String,
    pub app_name: String,
    pub version: String,
    pub is_system_app: bool,
    pub install_date: Option<String>,
    pub app_size: Option<u64>,
    pub data_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosDeviceInfo {
    pub udid: String,
    pub device_name: String,
    pub device_model: String,
    pub product_type: String,
    pub ios_version: String,
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
    pub model_number: String,
    pub activation_state: String,
    pub timezone: String,
    pub language: String,
    pub region: String,
}

/// Get comprehensive device information via Apple Mobile Device Service
pub fn get_device_info(udid: &str) -> Result<IosDeviceInfo, String> {
    eprintln!("[iOS Device Info] Retrieving device information for: {}", udid);
    
    let tool_path = get_tool_path("ideviceinfo.exe");
    eprintln!("[iOS Device Info] Using tool: {:?}", tool_path);
    
    let output = create_hidden_command(&tool_path)
        .arg("-u")
        .arg(udid)
        .output()
        .map_err(|e| format!("Failed to execute ideviceinfo: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("[iOS Device Info] Command failed.");
        eprintln!("[iOS Device Info] Stderr: {}", stderr);
        eprintln!("[iOS Device Info] Stdout: {}", stdout);
        
        // Provide helpful error message
        if stderr.is_empty() && stdout.is_empty() {
            return Err("Could not connect to device. Please ensure:\n1. Device is unlocked and trusted\n2. iTunes or Apple Mobile Device Support is installed\n3. Device is not in use by another application\n4. Try reconnecting the device".to_string());
        } else if stderr.contains("lockdownd") || stderr.contains("Could not connect") {
            return Err(format!("Cannot connect to device. Please unlock device and tap 'Trust This Computer'. Error: {}", stderr));
        } else {
            return Err(format!("Failed to get device info: {}", stderr));
        }
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_device_info(udid, &stdout)
}

/// Parse ideviceinfo output into structured device info
fn parse_device_info(udid: &str, info: &str) -> Result<IosDeviceInfo, String> {
    let mut device_name = String::from("Unknown Device");
    let mut device_model = String::from("Unknown");
    let mut product_type = String::from("Unknown");
    let mut ios_version = String::from("Unknown");
    let mut serial_number = String::from("Unknown");
    let mut imei = String::from("Unknown");
    let mut phone_number = String::from("Unknown");
    let mut wifi_address = String::from("Unknown");
    let mut bluetooth_address = String::from("Unknown");
    let mut build_version = String::from("Unknown");
    let mut hardware_model = String::from("Unknown");
    let mut device_color = String::from("Unknown");
    let mut battery_level = String::from("Unknown");
    let mut total_capacity = String::from("Unknown");
    let mut available_capacity = String::from("Unknown");
    let mut model_number = String::from("Unknown");
    let mut activation_state = String::from("Unknown");
    let mut timezone = String::from("Unknown");
    let mut language = String::from("Unknown");
    let mut region = String::from("Unknown");
    
    for line in info.lines() {
        let line = line.trim();
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        
        let key = parts[0].trim();
        let value = parts[1].trim();
        
        match key {
            "DeviceName" => device_name = value.to_string(),
            "ProductType" => product_type = value.to_string(),
            "ProductVersion" => ios_version = value.to_string(),
            "ModelNumber" => model_number = value.to_string(),
            "SerialNumber" => serial_number = value.to_string(),
            "InternationalMobileEquipmentIdentity" | "IMEI" => imei = value.to_string(),
            "PhoneNumber" => phone_number = value.to_string(),
            "WiFiAddress" => wifi_address = value.to_string(),
            "BluetoothAddress" => bluetooth_address = value.to_string(),
            "BuildVersion" => build_version = value.to_string(),
            "HardwareModel" => hardware_model = value.to_string(),
            "DeviceColor" => device_color = value.to_string(),
            "BatteryCurrentCapacity" => battery_level = format!("{}%", value),
            "DiskUsage" => total_capacity = format_capacity(value),
            "AmountDataAvailable" => available_capacity = format_capacity(value),
            "ActivationState" => activation_state = value.to_string(),
            "TimeZone" => timezone = value.to_string(),
            "Language" => language = value.to_string(),
            "Region" => region = value.to_string(),
            _ => {}
        }
    }
    
    // Derive device model from product type if not set
    if device_model == "Unknown" {
        device_model = parse_model_from_product_type(&product_type);
    }
    
    Ok(IosDeviceInfo {
        udid: udid.to_string(),
        device_name,
        device_model,
        product_type,
        ios_version,
        serial_number,
        imei,
        phone_number,
        wifi_address,
        bluetooth_address,
        build_version,
        hardware_model,
        device_color,
        battery_level,
        total_capacity,
        available_capacity,
        model_number,
        activation_state,
        timezone,
        language,
        region,
    })
}

/// Format capacity values to human-readable format
fn format_capacity(value: &str) -> String {
    if let Ok(bytes) = value.parse::<u64>() {
        let gb = bytes as f64 / 1_073_741_824.0; // Convert bytes to GB
        format!("{:.1} GB", gb)
    } else {
        value.to_string()
    }
}

/// Parse user-friendly model name from ProductType
fn parse_model_from_product_type(product_type: &str) -> String {
    match product_type {
        "iPhone14,7" => "iPhone 14".to_string(),
        "iPhone14,8" => "iPhone 14 Plus".to_string(),
        "iPhone15,2" => "iPhone 14 Pro".to_string(),
        "iPhone15,3" => "iPhone 14 Pro Max".to_string(),
        "iPhone15,4" => "iPhone 15".to_string(),
        "iPhone15,5" => "iPhone 15 Plus".to_string(),
        "iPhone16,1" => "iPhone 15 Pro".to_string(),
        "iPhone16,2" => "iPhone 15 Pro Max".to_string(),
        "iPhone13,1" => "iPhone 12 mini".to_string(),
        "iPhone13,2" => "iPhone 12".to_string(),
        "iPhone13,3" => "iPhone 12 Pro".to_string(),
        "iPhone13,4" => "iPhone 12 Pro Max".to_string(),
        "iPhone14,4" => "iPhone 13 mini".to_string(),
        "iPhone14,5" => "iPhone 13".to_string(),
        "iPhone14,2" => "iPhone 13 Pro".to_string(),
        "iPhone14,3" => "iPhone 13 Pro Max".to_string(),
        "iPad13,18" => "iPad Pro 12.9-inch (6th gen)".to_string(),
        "iPad13,19" => "iPad Pro 12.9-inch (6th gen)".to_string(),
        "iPad14,3" => "iPad Pro 11-inch (4th gen)".to_string(),
        "iPad14,4" => "iPad Pro 11-inch (4th gen)".to_string(),
        _ => product_type.to_string(),
    }
}

/// Get list of installed applications via Apple Mobile Device Service
pub fn get_installed_apps(udid: &str) -> Result<Vec<IosInstalledApp>, String> {
    eprintln!("[iOS Apps] Retrieving installed applications for device: {}", udid);
    
    let tool_path = get_tool_path("ideviceinstaller.exe");
    
    // Check if ideviceinstaller exists
    if !tool_path.exists() {
        eprintln!("[iOS Apps] ideviceinstaller not found, trying alternative method");
        return get_apps_via_syslog(udid);
    }
    
    let output = create_hidden_command(&tool_path)
        .arg("-u")
        .arg(udid)
        .arg("-l") // List installed apps
        .output()
        .map_err(|e| format!("Failed to execute ideviceinstaller: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("[iOS Apps] ideviceinstaller failed: {}", stderr);
        return get_apps_via_syslog(udid);
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_installed_apps(&stdout)
}

/// Parse ideviceinstaller output
fn parse_installed_apps(output: &str) -> Result<Vec<IosInstalledApp>, String> {
    let mut apps = Vec::new();
    
    // ideviceinstaller output format:
    // com.example.app - App Name v1.0
    // or XML format with more details
    
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Total:") {
            continue;
        }
        
        // Try to parse: bundle_id - name v version
        if let Some((bundle_id, rest)) = line.split_once(" - ") {
            let bundle_id = bundle_id.trim().to_string();
            
            // Parse name and version
            let (app_name, version) = if let Some(idx) = rest.rfind(" v") {
                let name = rest[..idx].trim().to_string();
                let ver = rest[idx + 2..].trim().to_string();
                (name, ver)
            } else {
                (rest.trim().to_string(), "Unknown".to_string())
            };
            
            // System apps typically have com.apple.* bundle IDs
            let is_system_app = bundle_id.starts_with("com.apple.");
            
            apps.push(IosInstalledApp {
                bundle_id,
                app_name,
                version,
                is_system_app,
                install_date: None,
                app_size: None,
                data_size: None,
            });
        }
    }
    
    if apps.is_empty() {
        return Err("No apps found or unable to parse output".to_string());
    }
    
    eprintln!("[iOS Apps] Found {} installed applications", apps.len());
    Ok(apps)
}

/// Alternative method: Get app info from device syslog (less reliable)
fn get_apps_via_syslog(udid: &str) -> Result<Vec<IosInstalledApp>, String> {
    eprintln!("[iOS Apps] Using fallback method (limited app info)");
    
    // This is a fallback - we can get some app info from device properties
    // but it's limited compared to ideviceinstaller
    
    // For now, return empty with error message
    Err(
        "Unable to retrieve installed apps.\n\
        ideviceinstaller tool not available.\n\
        Apps can be retrieved from iTunes backup instead.".to_string()
    )
}

/// Get installed apps from iTunes backup (most reliable method)
pub fn get_apps_from_backup(backup_path: &std::path::Path) -> Result<Vec<IosInstalledApp>, String> {
    use rusqlite::{Connection, OpenFlags};
    
    eprintln!("[iOS Apps] Extracting app list from iTunes backup");
    
    // Resolve nested UDID directories from pymobiledevice3
    let backup_path = super::ios_backup_parser::resolve_backup_path(backup_path);
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return Err("Invalid backup: Manifest.db not found".to_string());
    }
    
    let conn = Connection::open_with_flags(
        manifest_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open manifest: {}", e))?;
    
    let mut apps = Vec::new();
    
    // Query for app domains in backup
    let mut stmt = conn.prepare(
        "SELECT DISTINCT domain FROM Files \
         WHERE domain LIKE 'AppDomain%' OR domain LIKE 'AppDomainGroup%'"
    ).map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let mut rows = stmt.query([]).map_err(|e| format!("Query failed: {}", e))?;
    
    while let Ok(Some(row)) = rows.next() {
        let domain: String = row.get(0).unwrap_or_default();
        
        // Parse bundle ID from domain (e.g., "AppDomain-com.example.app")
        if let Some(bundle_id) = domain.strip_prefix("AppDomain-") {
            if !bundle_id.starts_with("group.") {
                apps.push(IosInstalledApp {
                    bundle_id: bundle_id.to_string(),
                    app_name: extract_app_name_from_bundle(bundle_id),
                    version: "Unknown".to_string(),
                    is_system_app: bundle_id.starts_with("com.apple."),
                    install_date: None,
                    app_size: None,
                    data_size: None,
                });
            }
        }
    }
    
    eprintln!("[iOS Apps] Found {} apps in backup", apps.len());
    Ok(apps)
}

/// Extract friendly app name from bundle ID
fn extract_app_name_from_bundle(bundle_id: &str) -> String {
    // Try to extract readable name from reverse domain notation
    // e.g., "com.example.MyApp" -> "MyApp"
    bundle_id
        .split('.')
        .last()
        .unwrap_or(bundle_id)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_model() {
        assert_eq!(parse_model_from_product_type("iPhone15,4"), "iPhone 15");
        assert_eq!(parse_model_from_product_type("iPhone14,7"), "iPhone 14");
    }
    
    #[test]
    fn test_format_capacity() {
        assert_eq!(format_capacity("128000000000"), "119.2 GB");
        assert_eq!(format_capacity("invalid"), "invalid");
    }
    
    #[test]
    fn test_extract_app_name() {
        assert_eq!(extract_app_name_from_bundle("com.apple.MobileSafari"), "MobileSafari");
        assert_eq!(extract_app_name_from_bundle("com.example.MyApp"), "MyApp");
    }
}
