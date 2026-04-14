/// Android APK parser for Chrome OS forensic scanning
/// 
/// Parses APK files and AndroidManifest.xml to extract app metadata

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidApp {
    pub package_name: String,
    pub app_name: String,
    pub version_name: String,
    pub version_code: String,
    pub permissions: Vec<String>,
    pub install_path: String,
    pub apk_size: u64,
}

/// Parse Android apps from Chrome OS ARC++ directory
pub fn parse_android_apps(android_data_path: &Path) -> Result<Vec<AndroidApp>, String> {
    if !android_data_path.exists() {
        return Err("Android data directory not found".to_string());
    }
    
    let mut apps = Vec::new();
    
    // Iterate through app directories
    for entry in fs::read_dir(android_data_path)
        .map_err(|e| format!("Failed to read Android apps dir: {}", e))? 
    {
        if let Ok(entry) = entry {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            
            // Look for APK files in the app directory
            if let Some(app) = find_and_parse_apk(&path) {
                apps.push(app);
            }
        }
    }
    
    Ok(apps)
}

/// Find APK file in a directory and parse it
fn find_and_parse_apk(app_dir: &Path) -> Option<AndroidApp> {
    // Look for APK files recursively
    if let Ok(entries) = fs::read_dir(app_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.extension().and_then(|e| e.to_str()) == Some("apk") {
                if let Ok(app) = parse_apk_file(&path) {
                    return Some(app);
                }
            }
            
            // Recursively check subdirectories
            if path.is_dir() {
                if let Some(app) = find_and_parse_apk(&path) {
                    return Some(app);
                }
            }
        }
    }
    
    None
}

/// Parse an APK file to extract metadata
fn parse_apk_file(apk_path: &Path) -> Result<AndroidApp, String> {
    // Get APK size
    let apk_size = fs::metadata(apk_path)
        .map(|m| m.len())
        .unwrap_or(0);
    
    // Try using aapt2 if available (best method)
    if let Ok(app) = parse_apk_with_aapt2(apk_path, apk_size) {
        return Ok(app);
    }
    
    // Fallback: Extract package name from path/filename
    let package_name = extract_package_from_path(apk_path);
    
    Ok(AndroidApp {
        package_name: package_name.clone(),
        app_name: package_name,
        version_name: "Unknown".to_string(),
        version_code: "Unknown".to_string(),
        permissions: Vec::new(),
        install_path: apk_path.to_string_lossy().to_string(),
        apk_size,
    })
}

/// Parse APK using aapt2 tool (if available)
fn parse_apk_with_aapt2(apk_path: &Path, apk_size: u64) -> Result<AndroidApp, String> {
    // Check if aapt2 is available
    let aapt_cmd = if let Ok(output) = Command::new("aapt2").arg("version").output() {
        "aapt2"
    } else if let Ok(output) = Command::new("aapt").arg("version").output() {
        "aapt"
    } else {
        return Err("aapt/aapt2 not available".to_string());
    };
    
    // Run aapt dump badging
    let apk_path_str = apk_path.to_str().unwrap();
    let output = Command::new(aapt_cmd)
        .args(&["dump", "badging", apk_path_str])
        .output()
        .map_err(|e| format!("Failed to run aapt: {}", e))?;
    
    if !output.status.success() {
        return Err("aapt command failed".to_string());
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse aapt output
    let mut package_name = String::new();
    let mut app_name = String::new();
    let mut version_name = String::new();
    let mut version_code = String::new();
    let mut permissions = Vec::new();
    
    for line in stdout.lines() {
        if line.starts_with("package:") {
            // Extract: package: name='com.example.app' versionCode='123' versionName='1.0'
            if let Some(name) = extract_quoted_value(line, "name=") {
                package_name = name;
            }
            if let Some(code) = extract_quoted_value(line, "versionCode=") {
                version_code = code;
            }
            if let Some(name) = extract_quoted_value(line, "versionName=") {
                version_name = name;
            }
        } else if line.starts_with("application-label:") {
            app_name = line.trim_start_matches("application-label:")
                .trim()
                .trim_matches('\'')
                .to_string();
        } else if line.starts_with("uses-permission:") {
            if let Some(perm) = extract_quoted_value(line, "name=") {
                permissions.push(perm);
            }
        }
    }
    
    Ok(AndroidApp {
        package_name: package_name.clone(),
        app_name: if app_name.is_empty() { package_name } else { app_name },
        version_name,
        version_code,
        permissions,
        install_path: apk_path.to_string_lossy().to_string(),
        apk_size,
    })
}

/// Extract quoted value from aapt output line
fn extract_quoted_value(line: &str, prefix: &str) -> Option<String> {
    if let Some(start) = line.find(prefix) {
        let after_prefix = &line[start + prefix.len()..];
        if let Some(quote_start) = after_prefix.find('\'') {
            let after_quote = &after_prefix[quote_start + 1..];
            if let Some(quote_end) = after_quote.find('\'') {
                return Some(after_quote[..quote_end].to_string());
            }
        }
    }
    None
}

/// Extract package name from APK path (fallback method)
fn extract_package_from_path(apk_path: &Path) -> String {
    // Try to extract from filename (e.g., "com.example.app-1.apk" or "base.apk")
    if let Some(file_name) = apk_path.file_stem().and_then(|s| s.to_str()) {
        // Remove version suffix if present
        let name = file_name.split('-').next().unwrap_or(file_name);
        
        if name != "base" && name.contains('.') {
            return name.to_string();
        }
    }
    
    // Try to extract from parent directory names
    if let Some(parent) = apk_path.parent() {
        if let Some(dir_name) = parent.file_name().and_then(|s| s.to_str()) {
            if dir_name.contains('.') && dir_name.contains("com") {
                return dir_name.to_string();
            }
        }
    }
    
    "Unknown Package".to_string()
}

/// Categorize Android app risk based on permissions
pub fn categorize_android_app_risk(app: &AndroidApp) -> AndroidAppRiskLevel {
    let dangerous_permissions = vec![
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.CALL_PHONE",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ];
    
    let sensitive_permissions = vec![
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.BLUETOOTH",
    ];
    
    let dangerous_count = app.permissions.iter()
        .filter(|p| dangerous_permissions.iter().any(|dp| p.contains(dp)))
        .count();
    
    let sensitive_count = app.permissions.iter()
        .filter(|p| sensitive_permissions.iter().any(|sp| p.contains(sp)))
        .count();
    
    if dangerous_count >= 3 {
        AndroidAppRiskLevel::High
    } else if dangerous_count >= 1 || sensitive_count >= 4 {
        AndroidAppRiskLevel::Medium
    } else if sensitive_count >= 1 {
        AndroidAppRiskLevel::Low
    } else {
        AndroidAppRiskLevel::Minimal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AndroidAppRiskLevel {
    High,
    Medium,
    Low,
    Minimal,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_package_extraction() {
        let path = Path::new("/data/app/com.example.app-1/base.apk");
        let package = extract_package_from_path(path);
        assert!(package.contains("com.example.app") || package.contains("base"));
    }
    
    #[test]
    fn test_quoted_value_extraction() {
        let line = "package: name='com.example.app' versionCode='123'";
        let name = extract_quoted_value(line, "name=");
        assert_eq!(name, Some("com.example.app".to_string()));
    }
}
