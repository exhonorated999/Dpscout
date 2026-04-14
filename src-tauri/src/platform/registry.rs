/// Offline Windows registry parsing for forensic scanning
/// 
/// This module provides functions to parse Windows registry hives
/// without requiring a running Windows OS.

use super::AppInfo;
use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Read};

/// Parse installed applications from SOFTWARE registry hive using nt-hive2
pub fn parse_installed_apps_from_hive(hive_path: &Path) -> Result<Vec<AppInfo>, String> {
    if !hive_path.exists() {
        return Err(format!("Registry hive not found: {:?}", hive_path));
    }
    
    // Try to parse using nt-hive2
    match parse_apps_with_nt_hive2(hive_path) {
        Ok(apps) if !apps.is_empty() => Ok(apps),
        Ok(_) | Err(_) => {
            // Fall back to simpler method or return empty
            // This allows graceful degradation if hive is corrupted
            Ok(Vec::new())
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_apps_with_nt_hive2(hive_path: &Path) -> Result<Vec<AppInfo>, String> {
    use std::io::Seek;
    
    let mut file = File::open(hive_path)
        .map_err(|e| format!("Failed to open hive: {}", e))?;
    
    // Read the entire hive into memory for parsing
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read hive: {}", e))?;
    
    // Parse with nt-hive2
    let hive = nt_hive2::Hive::new(&buffer)
        .map_err(|e| format!("Failed to parse hive: {:?}", e))?;
    
    let mut apps = Vec::new();
    
    // Try both 64-bit and 32-bit uninstall paths
    let uninstall_paths = vec![
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];
    
    for path_str in uninstall_paths {
        if let Some(uninstall_key) = navigate_to_key(&hive, path_str) {
            // Iterate through subkeys (each is an app)
            for subkey_name in get_subkey_names(&hive, &uninstall_key) {
                if let Some(app_key) = navigate_from_key(&hive, &uninstall_key, &subkey_name) {
                    if let Some(app) = parse_app_from_key(&hive, &app_key) {
                        apps.push(app);
                    }
                }
            }
        }
    }
    
    Ok(apps)
}

#[cfg(target_os = "linux")]
fn navigate_to_key(hive: &nt_hive2::Hive, path: &str) -> Option<nt_hive2::KeyNode> {
    let parts: Vec<&str> = path.split('\\').collect();
    let mut current = hive.root_key_node().ok()?;
    
    for part in parts {
        if part.is_empty() {
            continue;
        }
        current = current.subpath(part).ok()?;
    }
    
    Some(current)
}

#[cfg(target_os = "linux")]
fn navigate_from_key(
    hive: &nt_hive2::Hive, 
    parent: &nt_hive2::KeyNode, 
    name: &str
) -> Option<nt_hive2::KeyNode> {
    parent.subpath(name).ok()
}

#[cfg(target_os = "linux")]
fn get_subkey_names(hive: &nt_hive2::Hive, key: &nt_hive2::KeyNode) -> Vec<String> {
    let mut names = Vec::new();
    
    if let Ok(subkeys) = key.subkeys() {
        for subkey in subkeys {
            if let Ok(name) = subkey.name() {
                names.push(name.to_string());
            }
        }
    }
    
    names
}

#[cfg(target_os = "linux")]
fn parse_app_from_key(hive: &nt_hive2::Hive, key: &nt_hive2::KeyNode) -> Option<AppInfo> {
    // Get DisplayName (required)
    let name = get_string_value(key, "DisplayName")?;
    
    // Skip system updates and patches
    if name.contains("Update for") 
        || name.contains("Security Update") 
        || name.contains("Hotfix")
        || name.starts_with("KB") {
        return None;
    }
    
    // Get other values (optional)
    let publisher = get_string_value(key, "Publisher")
        .unwrap_or_else(|| "Unknown".to_string());
    let version = get_string_value(key, "DisplayVersion")
        .unwrap_or_else(|| "Unknown".to_string());
    let install_location = get_string_value(key, "InstallLocation")
        .unwrap_or_else(|| "Unknown".to_string());
    let install_date = get_string_value(key, "InstallDate");
    
    Some(AppInfo {
        name,
        publisher,
        version,
        install_location,
        install_date,
    })
}

#[cfg(target_os = "linux")]
fn get_string_value(key: &nt_hive2::KeyNode, value_name: &str) -> Option<String> {
    let value = key.value(value_name).ok()?;
    let data = value.data().ok()?;
    
    // Try to interpret as UTF-16 string (REG_SZ)
    match data {
        nt_hive2::KeyValueData::String(s) => Some(s.to_string()),
        nt_hive2::KeyValueData::StringList(list) => {
            // Join multiple strings
            Some(list.join("; "))
        }
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
fn parse_apps_with_nt_hive2(_hive_path: &Path) -> Result<Vec<AppInfo>, String> {
    // Not available on non-Linux platforms
    Err("nt-hive2 parsing only available on Linux".to_string())
}

/// Parse Windows version from SOFTWARE hive
pub fn get_windows_version_from_hive(hive_path: &Path) -> Result<String, String> {
    if !hive_path.exists() {
        return Ok("Windows (Unknown Version)".to_string());
    }
    
    #[cfg(target_os = "linux")]
    {
        match parse_windows_version_nt_hive2(hive_path) {
            Ok(version) => Ok(version),
            Err(_) => Ok("Windows".to_string()),
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Ok("Windows".to_string())
    }
}

#[cfg(target_os = "linux")]
fn parse_windows_version_nt_hive2(hive_path: &Path) -> Result<String, String> {
    use std::io::Read;
    
    let mut file = File::open(hive_path)
        .map_err(|e| format!("Failed to open hive: {}", e))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read hive: {}", e))?;
    
    let hive = nt_hive2::Hive::new(&buffer)
        .map_err(|e| format!("Failed to parse hive: {:?}", e))?;
    
    // Navigate to CurrentVersion key
    let cv_path = r"Microsoft\Windows NT\CurrentVersion";
    let cv_key = navigate_to_key(&hive, cv_path)
        .ok_or("CurrentVersion key not found")?;
    
    // Get product name
    let product_name = get_string_value(&cv_key, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    
    // Get build number for more specific version
    let current_build = get_string_value(&cv_key, "CurrentBuild");
    let display_version = get_string_value(&cv_key, "DisplayVersion");
    
    // Construct version string
    let mut version = product_name;
    
    if let Some(dv) = display_version {
        version.push_str(&format!(" {}", dv));
    }
    
    if let Some(build) = current_build {
        version.push_str(&format!(" (Build {})", build));
    }
    
    Ok(version)
}

/// Parse user accounts from SAM hive
pub fn get_user_accounts_from_sam(sam_path: &Path) -> Result<Vec<String>, String> {
    if !sam_path.exists() {
        return Err("SAM hive not found".to_string());
    }
    
    // For MVP, return empty - will use directory listing instead
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_parse_apps_missing_hive() {
        let result = parse_installed_apps_from_hive(&PathBuf::from("/nonexistent/SOFTWARE"));
        assert!(result.is_err());
    }
}
