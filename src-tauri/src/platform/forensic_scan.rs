/// Forensic scan orchestrator for bootable mode
/// 
/// Coordinates all scanning activities on mounted forensic targets

use super::{TargetSystem, AppInfo, SystemInfo, BrowserHistoryEntry};
use crate::scanner::media::{MediaFile, MediaScanOptions};
use crate::scanner::keyword::KeywordMatch;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicScanConfig {
    pub target: TargetSystem,
    pub scan_apps: bool,
    pub scan_browser: bool,
    pub scan_media: bool,
    pub scan_keywords: bool,
    pub check_hashes: bool,
    pub generate_thumbnails: bool,
    pub keyword_lists: Vec<String>, // Paths to keyword list files
    pub use_hash_db: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForensicScanResults {
    pub target_info: TargetSystemInfo,
    pub system_info: SystemInfo,
    pub apps: Vec<AppInfo>,
    pub browser_history: Vec<BrowserHistoryEntry>,
    pub media_files: Vec<MediaFile>,
    pub keyword_matches: Vec<KeywordMatch>,
    pub scan_statistics: ScanStatistics,
    pub scan_start_time: String,
    pub scan_end_time: String,
    pub scan_mode: String, // "Forensic"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSystemInfo {
    pub system_type: String, // "Windows" or "ChromeOS"
    pub partition: String,
    pub mount_point: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatistics {
    pub total_apps: usize,
    pub high_risk_apps: usize,
    pub browser_entries: usize,
    pub media_files_found: usize,
    pub flagged_media: usize,
    pub keyword_matches: usize,
    pub scan_duration_seconds: u64,
    pub directories_scanned: usize,
    pub files_processed: usize,
}

/// Perform a complete forensic scan on a mounted target
pub fn perform_forensic_scan(config: ForensicScanConfig) -> Result<ForensicScanResults, String> {
    let scan_start_time = chrono::Utc::now();
    let scan_start_str = scan_start_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    
    println!("Starting forensic scan...");
    
    // Get target info
    let target_info = extract_target_info(&config.target)?;
    
    // Get mount point for file operations
    let mount_point = get_mount_point(&config.target)?;
    
    // Initialize results
    let mut apps = Vec::new();
    let mut browser_history = Vec::new();
    let mut media_files = Vec::new();
    let mut keyword_matches = Vec::new();
    
    // Get system info (always)
    println!("Gathering system information...");
    let system_info = get_system_info(&config.target)?;
    
    // Scan apps
    if config.scan_apps {
        println!("Scanning applications...");
        apps = get_apps(&config.target)?;
        println!("  Found {} applications", apps.len());
    }
    
    // Scan browser history
    if config.scan_browser {
        println!("Scanning browser history...");
        browser_history = get_browser_history(&config.target)?;
        println!("  Found {} browser entries", browser_history.len());
    }
    
    // Scan media files
    if config.scan_media {
        println!("Scanning media files...");
        media_files = scan_forensic_media(
            &mount_point,
            &config.target,
            config.generate_thumbnails,
            config.check_hashes,
            config.use_hash_db
        )?;
        println!("  Found {} media files", media_files.len());
    }
    
    // Scan keywords
    if config.scan_keywords && !config.keyword_lists.is_empty() {
        println!("Scanning for keywords...");
        keyword_matches = scan_forensic_keywords(
            &mount_point,
            &config.target,
            &config.keyword_lists
        )?;
        println!("  Found {} keyword matches", keyword_matches.len());
    }
    
    // Calculate statistics
    let high_risk_apps = apps.iter()
        .filter(|app| app.name.contains("[HIGH RISK]"))
        .count();
    
    let flagged_media = media_files.iter()
        .filter(|f| !f.flags.is_empty())
        .count();
    
    let scan_end_time = chrono::Utc::now();
    let scan_end_str = scan_end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let scan_duration = (scan_end_time - scan_start_time).num_seconds() as u64;
    
    let statistics = ScanStatistics {
        total_apps: apps.len(),
        high_risk_apps,
        browser_entries: browser_history.len(),
        media_files_found: media_files.len(),
        flagged_media,
        keyword_matches: keyword_matches.len(),
        scan_duration_seconds: scan_duration,
        directories_scanned: 0, // Will be updated by scanners
        files_processed: media_files.len(),
    };
    
    Ok(ForensicScanResults {
        target_info,
        system_info,
        apps,
        browser_history,
        media_files,
        keyword_matches,
        scan_statistics: statistics,
        scan_start_time: scan_start_str,
        scan_end_time: scan_end_str,
        scan_mode: "Forensic".to_string(),
    })
}

/// Get system info using the forensic scanner
fn get_system_info(target: &TargetSystem) -> Result<SystemInfo, String> {
    let scanner = super::linux::LinuxForensicScanner::new(target.clone())?;
    use super::PlatformScanner;
    scanner.get_system_info()
}

/// Get apps using the forensic scanner
fn get_apps(target: &TargetSystem) -> Result<Vec<AppInfo>, String> {
    let scanner = super::linux::LinuxForensicScanner::new(target.clone())?;
    use super::PlatformScanner;
    scanner.get_installed_apps()
}

/// Get browser history using the forensic scanner
fn get_browser_history(target: &TargetSystem) -> Result<Vec<BrowserHistoryEntry>, String> {
    let scanner = super::linux::LinuxForensicScanner::new(target.clone())?;
    use super::PlatformScanner;
    scanner.get_browser_history()
}

/// Scan media files on forensic target
fn scan_forensic_media(
    mount_point: &Path,
    target: &TargetSystem,
    generate_thumbnails: bool,
    compute_hashes: bool,
    use_hash_db: bool,
) -> Result<Vec<MediaFile>, String> {
    // Determine scan paths based on target type
    let scan_paths = get_media_scan_paths(mount_point, target);
    
    // Configure media scanner for forensic mode
    let options = MediaScanOptions {
        scan_paths: scan_paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
        include_images: true,
        include_videos: true,
        generate_thumbnails,
        compute_hashes,
        check_hash_lists: compute_hashes,
        check_keywords: false, // Keywords handled separately
        max_file_size: 500 * 1024 * 1024, // 500 MB
        thumbnail_size: 200,
    };
    
    // Run media scanner
    crate::scanner::media::scan_media_files(
        options,
        Vec::new(), // Keywords handled separately
        use_hash_db
    )
}

/// Scan keywords on forensic target
fn scan_forensic_keywords(
    mount_point: &Path,
    target: &TargetSystem,
    keyword_list_paths: &[String],
) -> Result<Vec<KeywordMatch>, String> {
    use crate::scanner::keyword::{KeywordScanOptions, scan_keywords};
    
    // Load keyword lists
    let mut all_keywords = Vec::new();
    for list_path in keyword_list_paths {
        if let Ok(contents) = std::fs::read_to_string(list_path) {
            let keywords: Vec<String> = contents.lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect();
            all_keywords.push(keywords);
        }
    }
    
    if all_keywords.is_empty() {
        return Ok(Vec::new());
    }
    
    // Determine scan paths
    let scan_paths = get_keyword_scan_paths(mount_point, target);
    
    // Configure keyword scanner for forensic mode
    let options = KeywordScanOptions {
        scan_paths: scan_paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
        case_sensitive: false,
        whole_word_only: false,
        include_hidden: false,
        max_file_size: 100 * 1024 * 1024, // 100 MB
        file_extensions: vec![
            "txt".to_string(),
            "doc".to_string(),
            "docx".to_string(),
            "pdf".to_string(),
            "rtf".to_string(),
            "log".to_string(),
        ],
    };
    
    // Run keyword scanner
    scan_keywords(options, all_keywords)
}

/// Get media scan paths for target system
fn get_media_scan_paths(mount_point: &Path, target: &TargetSystem) -> Vec<PathBuf> {
    match target {
        TargetSystem::Windows { .. } => {
            let users_dir = mount_point.join("Users");
            let mut paths = Vec::new();
            
            if users_dir.exists() {
                // Scan each user's common media folders
                if let Ok(entries) = std::fs::read_dir(&users_dir) {
                    for entry in entries.flatten() {
                        let user_path = entry.path();
                        let user_name = user_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        
                        // Skip system folders
                        if user_name == "Public" || user_name == "Default" || user_name == "All Users" {
                            continue;
                        }
                        
                        // Common Windows media locations
                        paths.push(user_path.join("Pictures"));
                        paths.push(user_path.join("Videos"));
                        paths.push(user_path.join("Downloads"));
                        paths.push(user_path.join("Desktop"));
                        paths.push(user_path.join("Documents"));
                    }
                }
            }
            
            paths
        }
        TargetSystem::ChromeOS { .. } => {
            vec![
                mount_point.join("home/chronos/user/Downloads"),
                mount_point.join("home/chronos/user/MyFiles"),
            ]
        }
        TargetSystem::Unknown => Vec::new(),
    }
}

/// Get keyword scan paths for target system
fn get_keyword_scan_paths(mount_point: &Path, target: &TargetSystem) -> Vec<PathBuf> {
    // Similar to media paths, but focus on document locations
    match target {
        TargetSystem::Windows { .. } => {
            let users_dir = mount_point.join("Users");
            let mut paths = Vec::new();
            
            if users_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&users_dir) {
                    for entry in entries.flatten() {
                        let user_path = entry.path();
                        let user_name = user_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        
                        if user_name == "Public" || user_name == "Default" {
                            continue;
                        }
                        
                        paths.push(user_path.join("Documents"));
                        paths.push(user_path.join("Desktop"));
                        paths.push(user_path.join("Downloads"));
                    }
                }
            }
            
            paths
        }
        TargetSystem::ChromeOS { .. } => {
            vec![
                mount_point.join("home/chronos/user/Downloads"),
                mount_point.join("home/chronos/user/MyFiles"),
            ]
        }
        TargetSystem::Unknown => Vec::new(),
    }
}

/// Extract target system information
fn extract_target_info(target: &TargetSystem) -> Result<TargetSystemInfo, String> {
    match target {
        TargetSystem::Windows { partition, version, mount_point } => {
            Ok(TargetSystemInfo {
                system_type: "Windows".to_string(),
                partition: partition.clone(),
                mount_point: mount_point.to_string_lossy().to_string(),
                version: version.clone(),
            })
        }
        TargetSystem::ChromeOS { partition, mount_point } => {
            Ok(TargetSystemInfo {
                system_type: "ChromeOS".to_string(),
                partition: partition.clone(),
                mount_point: mount_point.to_string_lossy().to_string(),
                version: "Unknown".to_string(),
            })
        }
        TargetSystem::Unknown => {
            Err("Cannot scan unknown target system".to_string())
        }
    }
}

/// Get mount point from target system
fn get_mount_point(target: &TargetSystem) -> Result<PathBuf, String> {
    match target {
        TargetSystem::Windows { mount_point, .. } => Ok(mount_point.clone()),
        TargetSystem::ChromeOS { mount_point, .. } => Ok(mount_point.clone()),
        TargetSystem::Unknown => Err("Unknown target has no mount point".to_string()),
    }
}
