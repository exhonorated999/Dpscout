/// Linux forensic scanner implementation for offline scanning

use super::{AppInfo, PlatformScanner, SystemInfo, BrowserHistoryEntry, TargetSystem};
use std::path::{Path, PathBuf};
use std::fs;

pub struct LinuxForensicScanner {
    target: TargetSystem,
}

impl LinuxForensicScanner {
    pub fn new(target: TargetSystem) -> Result<Self, String> {
        Ok(Self { target })
    }
    
    fn get_mount_point(&self) -> Result<&PathBuf, String> {
        match &self.target {
            TargetSystem::Windows { mount_point, .. } => Ok(mount_point),
            TargetSystem::ChromeOS { mount_point, .. } => Ok(mount_point),
            TargetSystem::Unknown => Err("Unknown target system".to_string()),
        }
    }
}

impl PlatformScanner for LinuxForensicScanner {
    fn get_installed_apps(&self) -> Result<Vec<AppInfo>, String> {
        match &self.target {
            TargetSystem::Windows { .. } => self.get_windows_apps(),
            TargetSystem::ChromeOS { .. } => self.get_chromeos_apps(),
            TargetSystem::Unknown => Err("Unknown target system".to_string()),
        }
    }
    
    fn get_system_info(&self) -> Result<SystemInfo, String> {
        match &self.target {
            TargetSystem::Windows { version, .. } => {
                let mount_point = self.get_mount_point()?;
                self.get_windows_system_info(mount_point, version)
            },
            TargetSystem::ChromeOS { .. } => {
                let mount_point = self.get_mount_point()?;
                self.get_chromeos_system_info(mount_point)
            },
            TargetSystem::Unknown => Err("Unknown target system".to_string()),
        }
    }
    
    fn get_browser_history(&self) -> Result<Vec<BrowserHistoryEntry>, String> {
        match &self.target {
            TargetSystem::Windows { .. } => {
                let mount_point = self.get_mount_point()?;
                self.get_windows_browser_history(mount_point)
            },
            TargetSystem::ChromeOS { .. } => {
                let mount_point = self.get_mount_point()?;
                self.get_chromeos_browser_history(mount_point)
            },
            TargetSystem::Unknown => Err("Unknown target system".to_string()),
        }
    }
    
    fn get_user_accounts(&self) -> Result<Vec<String>, String> {
        let mount_point = self.get_mount_point()?;
        
        match &self.target {
            TargetSystem::Windows { .. } => {
                // List user directories under C:\Users
                let users_dir = mount_point.join("Users");
                if !users_dir.exists() {
                    return Ok(Vec::new());
                }
                
                let mut accounts = Vec::new();
                for entry in fs::read_dir(&users_dir)
                    .map_err(|e| format!("Failed to read Users dir: {}", e))? 
                {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.is_dir() {
                            if let Some(name) = path.file_name() {
                                let name_str = name.to_string_lossy().to_string();
                                // Skip system folders
                                if name_str != "Public" && name_str != "Default" 
                                    && name_str != "All Users" {
                                    accounts.push(name_str);
                                }
                            }
                        }
                    }
                }
                
                Ok(accounts)
            },
            TargetSystem::ChromeOS { .. } => {
                // Chrome OS typically has one user (chronos)
                Ok(vec!["chronos".to_string()])
            },
            TargetSystem::Unknown => Err("Unknown target system".to_string()),
        }
    }
}

// Windows-specific offline scanning methods
impl LinuxForensicScanner {
    fn get_windows_apps(&self) -> Result<Vec<AppInfo>, String> {
        let mount_point = self.get_mount_point()?;
        
        // Try parsing SOFTWARE registry hive first
        let software_hive = mount_point.join("Windows/System32/config/SOFTWARE");
        
        if software_hive.exists() {
            // Try registry parsing
            if let Ok(apps) = super::registry::parse_installed_apps_from_hive(&software_hive) {
                if !apps.is_empty() {
                    return Ok(apps);
                }
            }
        }
        
        // Fallback to simplified app detection from Program Files
        self.get_windows_apps_from_program_files(mount_point)
    }
    
    fn get_windows_apps_from_program_files(&self, mount_point: &Path) -> Result<Vec<AppInfo>, String> {
        let mut apps = Vec::new();
        
        // Get apps from Program Files directories
        let program_files_dirs = vec![
            mount_point.join("Program Files"),
            mount_point.join("Program Files (x86)"),
        ];
        
        for dir in program_files_dirs {
            if !dir.exists() {
                continue;
            }
            
            for entry in fs::read_dir(&dir)
                .map_err(|e| format!("Failed to read Program Files: {}", e))? 
            {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(name) = path.file_name() {
                            apps.push(AppInfo {
                                name: name.to_string_lossy().to_string(),
                                publisher: "Unknown".to_string(),
                                version: "Unknown".to_string(),
                                install_location: path.to_string_lossy().to_string(),
                                install_date: None,
                            });
                        }
                    }
                }
            }
        }
        
        // Also check for Chrome extensions in user profiles
        let users_dir = mount_point.join("Users");
        if users_dir.exists() {
            for user_entry in fs::read_dir(&users_dir).ok().into_iter().flatten() {
                if let Ok(user_entry) = user_entry {
                    let user_path = user_entry.path();
                    let user_name = user_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown");
                    
                    // Skip system folders
                    if user_name == "Public" || user_name == "Default" {
                        continue;
                    }
                    
                    // Check Chrome extensions
                    let chrome_ext = user_path.join("AppData/Local/Google/Chrome/User Data/Default/Extensions");
                    if chrome_ext.exists() {
                        if let Ok(extensions) = super::extension_parser::parse_chrome_extensions(&chrome_ext) {
                            for ext in extensions {
                                let risk = super::extension_parser::categorize_extension_risk(&ext);
                                let risk_str = match risk {
                                    super::extension_parser::ExtensionRiskLevel::High => " [HIGH RISK]",
                                    super::extension_parser::ExtensionRiskLevel::Medium => " [MEDIUM RISK]",
                                    _ => "",
                                };
                                
                                apps.push(AppInfo {
                                    name: format!("Chrome Extension: {}{} ({})", ext.name, risk_str, user_name),
                                    publisher: ext.author.unwrap_or_else(|| "Chrome Web Store".to_string()),
                                    version: ext.version,
                                    install_location: ext.install_path,
                                    install_date: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        
        Ok(apps)
    }
    
    fn get_windows_system_info(&self, mount_point: &Path, version: &str) -> Result<SystemInfo, String> {
        // Read computer name from registry or hostname file
        let system32 = mount_point.join("Windows/System32");
        
        Ok(SystemInfo {
            os_name: format!("Windows (Offline Scan)"),
            os_version: version.to_string(),
            computer_name: "Unknown (Offline)".to_string(),
            username: "Unknown (Offline)".to_string(),
            install_date: None,
        })
    }
    
    fn get_windows_browser_history(&self, mount_point: &Path) -> Result<Vec<BrowserHistoryEntry>, String> {
        let mut history = Vec::new();
        
        // Scan user profiles for browser data
        let users_dir = mount_point.join("Users");
        if !users_dir.exists() {
            return Ok(history);
        }
        
        for user_entry in fs::read_dir(&users_dir)
            .map_err(|e| format!("Failed to read Users dir: {}", e))? 
        {
            if let Ok(user_entry) = user_entry {
                let user_path = user_entry.path();
                let user_name = user_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown");
                
                // Skip system folders
                if user_name == "Public" || user_name == "Default" || user_name == "All Users" {
                    continue;
                }
                
                // Parse Chrome history
                let chrome_history = user_path.join(
                    "AppData/Local/Google/Chrome/User Data/Default/History"
                );
                
                if chrome_history.exists() {
                    match super::browser_parser::parse_chrome_history(&chrome_history) {
                        Ok(mut entries) => {
                            // Add user context to browser type
                            for entry in &mut entries {
                                entry.browser = format!("Chrome ({})", user_name);
                            }
                            history.extend(entries);
                        }
                        Err(e) => {
                            eprintln!("Failed to parse Chrome history for {}: {}", user_name, e);
                            // Add placeholder entry
                            history.push(BrowserHistoryEntry {
                                url: format!("Error parsing Chrome history: {}", e),
                                title: "Chrome History Database".to_string(),
                                visit_count: 0,
                                last_visit_time: "Unknown".to_string(),
                                browser: format!("Chrome ({})", user_name),
                            });
                        }
                    }
                }
                
                // Parse Edge history
                let edge_history = user_path.join(
                    "AppData/Local/Microsoft/Edge/User Data/Default/History"
                );
                
                if edge_history.exists() {
                    match super::browser_parser::parse_chrome_history(&edge_history) {
                        Ok(mut entries) => {
                            for entry in &mut entries {
                                entry.browser = format!("Edge ({})", user_name);
                            }
                            history.extend(entries);
                        }
                        Err(e) => {
                            eprintln!("Failed to parse Edge history for {}: {}", user_name, e);
                            history.push(BrowserHistoryEntry {
                                url: format!("Error parsing Edge history: {}", e),
                                title: "Edge History Database".to_string(),
                                visit_count: 0,
                                last_visit_time: "Unknown".to_string(),
                                browser: format!("Edge ({})", user_name),
                            });
                        }
                    }
                }
                
                // Parse Firefox history
                let firefox_profiles = user_path.join("AppData/Roaming/Mozilla/Firefox/Profiles");
                if firefox_profiles.exists() {
                    if let Ok(profiles) = fs::read_dir(&firefox_profiles) {
                        for profile in profiles.flatten() {
                            let places_db = profile.path().join("places.sqlite");
                            if places_db.exists() {
                                match super::browser_parser::parse_firefox_history(&places_db) {
                                    Ok(mut entries) => {
                                        for entry in &mut entries {
                                            entry.browser = format!("Firefox ({})", user_name);
                                        }
                                        history.extend(entries);
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to parse Firefox history for {}: {}", user_name, e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(history)
    }
}

// Chrome OS-specific scanning methods
impl LinuxForensicScanner {
    // fn get_chromeos_apps(&self) -> Result<Vec<AppInfo>, String> {
        let mount_point = self.get_mount_point()?;
        let mut apps = Vec::new();
        
        // Check for Android apps (if ARC++ is enabled)
        let android_apps_path = mount_point.join(
            "opt/google/containers/android/rootfs/android-data/data/app"
        );
        
        if android_apps_path.exists() {
            match super::apk_parser::parse_android_apps(&android_apps_path) {
                Ok(android_apps) => {
                    for android_app in android_apps {
                        let risk = super::apk_parser::categorize_android_app_risk(&android_app);
                        let risk_str = match risk {
                            super::apk_parser::AndroidAppRiskLevel::High => " [HIGH RISK]",
                            super::apk_parser::AndroidAppRiskLevel::Medium => " [MEDIUM RISK]",
                            _ => "",
                        };
                        
                        let size_mb = android_app.apk_size as f64 / (1024.0 * 1024.0);
                        
                        apps.push(AppInfo {
                            name: format!("Android: {}{}", android_app.app_name, risk_str),
                            publisher: android_app.package_name,
                            version: format!("{} ({})", android_app.version_name, android_app.version_code),
                            install_location: format!("{} ({:.1} MB)", android_app.install_path, size_mb),
                            install_date: None,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse Android apps: {}", e);
                    // Add simple directory listing as fallback
                    for entry in fs::read_dir(&android_apps_path).ok().into_iter().flatten() {
                        if let Ok(entry) = entry {
                            let path = entry.path();
                            if let Some(name) = path.file_name() {
                                apps.push(AppInfo {
                                    name: format!("Android App: {}", name.to_string_lossy()),
                                    publisher: "Google Play".to_string(),
                                    version: "Unknown".to_string(),
                                    install_location: path.to_string_lossy().to_string(),
                                    install_date: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        
        // Parse Chrome extensions properly
        let extensions_dir = mount_point.join("home/chronos/user/Extensions");
        if extensions_dir.exists() {
            match super::extension_parser::parse_chrome_extensions(&extensions_dir) {
                Ok(extensions) => {
                    for ext in extensions {
                        let risk = super::extension_parser::categorize_extension_risk(&ext);
                        let risk_str = match risk {
                            super::extension_parser::ExtensionRiskLevel::High => " [HIGH RISK]",
                            super::extension_parser::ExtensionRiskLevel::Medium => " [MEDIUM RISK]",
                            _ => "",
                        };
                        
                        apps.push(AppInfo {
                            name: format!("{}{}", ext.name, risk_str),
                            publisher: ext.author.unwrap_or_else(|| "Chrome Web Store".to_string()),
                            version: ext.version,
                            install_location: ext.install_path,
                            install_date: None,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse Chrome extensions: {}", e);
                }
            }
        }
        
        Ok(apps)
    }
    
    // fn get_chromeos_system_info(&self, _mount_point: &Path) -> Result<SystemInfo, String> {
        Ok(SystemInfo {
            os_name: "Chrome OS (Offline Scan)".to_string(),
            os_version: "Unknown".to_string(),
            computer_name: "Unknown (Offline)".to_string(),
            username: "chronos".to_string(),
            install_date: None,
        })
    }
    
    // fn get_chromeos_browser_history(&self, mount_point: &Path) -> Result<Vec<BrowserHistoryEntry>, String> {
        let mut history = Vec::new();
        
        // Chrome history on Chrome OS
        let chrome_history = mount_point.join("home/chronos/user/History");
        
        if chrome_history.exists() {
            match super::browser_parser::parse_chrome_history(&chrome_history) {
                Ok(mut entries) => {
                    for entry in &mut entries {
                        entry.browser = "Chrome OS".to_string();
                    }
                    history.extend(entries);
                }
                Err(e) => {
                    eprintln!("Failed to parse Chrome OS history: {}", e);
                    history.push(BrowserHistoryEntry {
                        url: format!("Error parsing Chrome history: {}", e),
                        title: "Chrome History Database".to_string(),
                        visit_count: 0,
                        last_visit_time: "Unknown".to_string(),
                        browser: "Chrome OS".to_string(),
                    });
                }
            }
        }
        
        Ok(history)
    }
}
