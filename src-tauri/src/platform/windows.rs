/// Windows live scanning implementation using WMI and registry APIs

use super::{AppInfo, PlatformScanner, SystemInfo, BrowserHistoryEntry};
use winreg::RegKey;
use winreg::enums::*;
use std::process::Command;

pub struct WindowsLiveScanner;

impl WindowsLiveScanner {
    pub fn new() -> Result<Self, String> {
        Ok(Self)
    }
}

impl PlatformScanner for WindowsLiveScanner {
    fn get_installed_apps(&self) -> Result<Vec<AppInfo>, String> {
        let mut apps = Vec::new();
        
        // Open registry keys for installed applications
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        let uninstall_paths = vec![
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ];
        
        for path in uninstall_paths {
            if let Ok(uninstall_key) = hklm.open_subkey(path) {
                for subkey_name in uninstall_key.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(app_key) = uninstall_key.open_subkey(&subkey_name) {
                        if let Some(app) = Self::parse_app_from_registry(&app_key) {
                            apps.push(app);
                        }
                    }
                }
            }
        }
        
        Ok(apps)
    }
    
    fn get_system_info(&self) -> Result<SystemInfo, String> {
        let os_name = Self::get_wmi_value("Win32_OperatingSystem", "Caption")?;
        let os_version = Self::get_wmi_value("Win32_OperatingSystem", "Version")?;
        let computer_name = std::env::var("COMPUTERNAME")
            .unwrap_or_else(|_| "Unknown".to_string());
        let username = std::env::var("USERNAME")
            .unwrap_or_else(|_| "Unknown".to_string());
        let install_date = Self::get_wmi_value("Win32_OperatingSystem", "InstallDate").ok();
        
        Ok(SystemInfo {
            os_name,
            os_version,
            computer_name,
            username,
            install_date,
        })
    }
    
    fn get_browser_history(&self) -> Result<Vec<BrowserHistoryEntry>, String> {
        // This would call existing browser history parsing code
        // For now, return empty - this will be integrated with existing scanner
        Ok(Vec::new())
    }
    
    fn get_user_accounts(&self) -> Result<Vec<String>, String> {
        let output = Command::new("wmic")
            .args(&["useraccount", "get", "name"])
            .output()
            .map_err(|e| format!("Failed to execute WMIC: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let accounts: Vec<String> = stdout
            .lines()
            .skip(1) // Skip header
            .filter_map(|line| {
                let name = line.trim();
                if !name.is_empty() && name != "Name" {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect();
        
        Ok(accounts)
    }
}

impl WindowsLiveScanner {
    fn parse_app_from_registry(key: &RegKey) -> Option<AppInfo> {
        let name: String = key.get_value("DisplayName").ok()?;
        
        // Skip system components and updates
        if name.contains("Update for") || name.contains("Security Update") {
            return None;
        }
        
        let publisher: String = key.get_value("Publisher")
            .unwrap_or_else(|_| "Unknown".to_string());
        let version: String = key.get_value("DisplayVersion")
            .unwrap_or_else(|_| "Unknown".to_string());
        let install_location: String = key.get_value("InstallLocation")
            .unwrap_or_else(|_| "Unknown".to_string());
        let install_date: Option<String> = key.get_value("InstallDate").ok();
        
        Some(AppInfo {
            name,
            publisher,
            version,
            install_location,
            install_date,
        })
    }
    
    fn get_wmi_value(class: &str, property: &str) -> Result<String, String> {
        let output = Command::new("wmic")
            .args(&[class, "get", property, "/value"])
            .output()
            .map_err(|e| format!("Failed to execute WMIC: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        let prefix = format!("{}=", property);
        for line in stdout.lines() {
            if line.starts_with(&prefix) {
                return Ok(line.trim_start_matches(&prefix).to_string());
            }
        }
        
        Err(format!("Property {} not found in {}", property, class))
    }
}
