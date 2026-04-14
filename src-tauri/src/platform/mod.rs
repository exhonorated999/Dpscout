/// Platform abstraction layer for cross-platform functionality
/// 
/// This module provides a unified interface for platform-specific operations:
/// - Windows: Live scanning using WMI and registry APIs
/// - Linux (bootable): Offline forensic scanning with read-only mounting

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod forensics;

#[cfg(target_os = "linux")]
pub mod registry;

#[cfg(target_os = "linux")]
pub mod browser_parser;

#[cfg(target_os = "linux")]
pub mod extension_parser;

#[cfg(target_os = "linux")]
pub mod apk_parser;

#[cfg(target_os = "linux")]
pub mod forensic_scan;

#[cfg(target_os = "linux")]
pub mod forensic_report;

pub mod paths;

/// Represents a detected app installation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_location: String,
    pub install_date: Option<String>,
}

/// System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub computer_name: String,
    pub username: String,
    pub install_date: Option<String>,
}

/// Browser history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i32,
    pub last_visit_time: String,
    pub browser: String,
}

/// Detected target system for forensic scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetSystem {
    Windows {
        partition: String,
        version: String,
        mount_point: PathBuf,
    },
    Unknown,
}

/// Platform scanner trait - unified interface for all platforms
pub trait PlatformScanner {
    /// Get installed applications
    fn get_installed_apps(&self) -> Result<Vec<AppInfo>, String>;
    
    /// Get system information
    fn get_system_info(&self) -> Result<SystemInfo, String>;
    
    /// Get browser history (all browsers)
    fn get_browser_history(&self) -> Result<Vec<BrowserHistoryEntry>, String>;
    
    /// Get user accounts
    fn get_user_accounts(&self) -> Result<Vec<String>, String>;
}

/// Get the appropriate scanner for the current platform
pub fn get_scanner() -> Result<Box<dyn PlatformScanner>, String> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsLiveScanner::new()?))
    }
    
    #[cfg(target_os = "linux")]
    {
        // On Linux, check if we're in forensic mode or live mode
        // For now, always use forensic scanner
        let targets = forensics::detect_target_systems()?;
        if targets.is_empty() {
            return Err("No target systems detected for forensic scanning".to_string());
        }
        
        // For MVP, use first detected target
        Ok(Box::new(linux::LinuxForensicScanner::new(targets[0].clone())?))
    }
}

/// Platform-specific initialization
pub fn initialize() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        // Ensure we have root privileges for forensic operations
        if unsafe { libc::geteuid() } != 0 {
            return Err("Root privileges required for forensic scanning".to_string());
        }
    }
    
    Ok(())
}
