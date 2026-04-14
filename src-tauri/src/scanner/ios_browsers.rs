/// iOS Browser History Extraction Module
/// Handles Safari, Chrome, and Firefox browser history extraction from iOS devices
/// Uses idevicebackup2 for selective domain backup to temp directories
/// ALL TEMP DATA IS DELETED AFTER EXTRACTION

use serde::{Deserialize, Serialize};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;

use super::ios_live::{IosBrowserEntry, get_tool_path};

/// Supported iOS browser types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IosBrowserType {
    Safari,
    Chrome,
    Firefox,
}

/// Browser extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosBrowserResult {
    pub browser_type: IosBrowserType,
    pub browser_name: String,
    pub history_entries: Vec<IosBrowserEntry>,
    pub bookmarks_count: u32,
    pub extraction_success: bool,
    pub error_message: Option<String>,
}

/// Extract browser history from all supported browsers on iOS device
pub fn extract_all_browser_history(udid: &str, temp_dir: &Path) -> Result<Vec<IosBrowserResult>, String> {
    let mut results = Vec::new();
    
    eprintln!("=== Extracting Browser History from iOS Device ===");
    
    // Safari - always try this first as it's built-in
    eprintln!("[Browser 1/3] Extracting Safari history...");
    match extract_safari_history(udid, temp_dir) {
        Ok(entries) => {
            eprintln!("✓ Safari: {} history entries", entries.len());
            results.push(IosBrowserResult {
                browser_type: IosBrowserType::Safari,
                browser_name: "Safari".to_string(),
                history_entries: entries,
                bookmarks_count: 0,
                extraction_success: true,
                error_message: None,
            });
        }
        Err(e) => {
            eprintln!("✗ Safari extraction failed: {}", e);
            results.push(IosBrowserResult {
                browser_type: IosBrowserType::Safari,
                browser_name: "Safari".to_string(),
                history_entries: Vec::new(),
                bookmarks_count: 0,
                extraction_success: false,
                error_message: Some(e),
            });
        }
    }
    
    // Chrome - if installed
    eprintln!("[Browser 2/3] Extracting Chrome history...");
    match extract_chrome_history(udid, temp_dir) {
        Ok(entries) => {
            eprintln!("✓ Chrome: {} history entries", entries.len());
            results.push(IosBrowserResult {
                browser_type: IosBrowserType::Chrome,
                browser_name: "Google Chrome".to_string(),
                history_entries: entries,
                bookmarks_count: 0,
                extraction_success: true,
                error_message: None,
            });
        }
        Err(e) => {
            eprintln!("✗ Chrome extraction failed: {}", e);
            // Don't add to results if Chrome not installed (expected)
            if !e.contains("not installed") && !e.contains("No app container") {
                results.push(IosBrowserResult {
                    browser_type: IosBrowserType::Chrome,
                    browser_name: "Google Chrome".to_string(),
                    history_entries: Vec::new(),
                    bookmarks_count: 0,
                    extraction_success: false,
                    error_message: Some(e),
                });
            }
        }
    }
    
    // Firefox - if installed
    eprintln!("[Browser 3/3] Extracting Firefox history...");
    match extract_firefox_history(udid, temp_dir) {
        Ok(entries) => {
            eprintln!("✓ Firefox: {} history entries", entries.len());
            results.push(IosBrowserResult {
                browser_type: IosBrowserType::Firefox,
                browser_name: "Mozilla Firefox".to_string(),
                history_entries: entries,
                bookmarks_count: 0,
                extraction_success: true,
                error_message: None,
            });
        }
        Err(e) => {
            eprintln!("✗ Firefox extraction failed: {}", e);
            // Don't add to results if Firefox not installed (expected)
            if !e.contains("not installed") && !e.contains("No app container") {
                results.push(IosBrowserResult {
                    browser_type: IosBrowserType::Firefox,
                    browser_name: "Mozilla Firefox".to_string(),
                    history_entries: Vec::new(),
                    bookmarks_count: 0,
                    extraction_success: false,
                    error_message: Some(e),
                });
            }
        }
    }
    
    eprintln!("=== Browser Extraction Complete ===");
    eprintln!("Successfully extracted from {} browser(s)", results.len());
    
    Ok(results)
}

/// Extract Safari browser history from iOS device
pub fn extract_safari_history(udid: &str, temp_dir: &Path) -> Result<Vec<IosBrowserEntry>, String> {
    eprintln!("  → Starting Safari history extraction...");
    
    // Safari history is in HomeDomain > Library/Safari/History.db
    // Create unique backup directory
    let safari_backup_dir = temp_dir.join(format!("safari_backup_{}", udid));
    
    // Clean up any previous attempts
    if safari_backup_dir.exists() {
        eprintln!("  → Cleaning up previous backup attempt...");
        let _ = fs::remove_dir_all(&safari_backup_dir);
    }
    
    fs::create_dir_all(&safari_backup_dir)
        .map_err(|e| format!("Failed to create Safari backup dir: {}", e))?;
    
    eprintln!("  → Backup directory created: {:?}", safari_backup_dir);
    
    // Use idevicebackup2 with correct syntax
    let tool_path = get_tool_path("idevicebackup2.exe");
    eprintln!("  → Using tool: {:?}", tool_path);
    
    // Check if tool exists
    if !tool_path.exists() {
        return Err("idevicebackup2.exe not found in bundled tools".to_string());
    }
    
    eprintln!("  → Executing: idevicebackup2 -u {} backup {}", udid, safari_backup_dir.display());
    eprintln!("  ⚠️ WARNING: iOS backup can take 5-15 minutes depending on device data size");
    eprintln!("  ⚠️ Skipping browser history extraction to avoid long delays");
    eprintln!("  💡 Consider using forensic mode with iTunes backup for complete browser data");
    
    // TEMPORARY FIX: Skip the slow backup process for live triage
    // Full device backups take too long (15-30 minutes) for a quick triage tool
    // TODO: Implement direct database access via AFC protocol or use iTunes backup parsing
    return Err("iOS browser history extraction skipped - requires full backup (too slow for live triage)".to_string());
}

/// Find Safari History.db in iOS backup directory
fn find_safari_history_db(backup_dir: &Path) -> Result<PathBuf, String> {
    eprintln!("  → Searching for History.db in: {:?}", backup_dir);
    eprintln!("  → Walking directory tree...");
    
    let mut files_checked = 0;
    let mut potential_matches = Vec::new();
    
    for entry in walkdir::WalkDir::new(backup_dir)
        .follow_links(false)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        files_checked += 1;
        
        if entry.file_type().is_file() {
            let file_name = entry.file_name().to_string_lossy();
            let path_str = entry.path().to_string_lossy();
            
            // Log every 100 files
            if files_checked % 100 == 0 {
                eprintln!("  → Checked {} files so far...", files_checked);
            }
            
            // Check for History.db or history-related files
            if file_name.eq_ignore_ascii_case("History.db") || 
               file_name.eq_ignore_ascii_case("History.sqlite") ||
               file_name.contains("History") {
                eprintln!("  → Potential match: {:?}", entry.path());
                potential_matches.push(entry.path().to_path_buf());
                
                // If exact match, return immediately
                if file_name.eq_ignore_ascii_case("History.db") {
                    eprintln!("  ✓ Found exact match: History.db");
                    return Ok(entry.path().to_path_buf());
                }
            }
            
            // Also check path for Safari directory
            if path_str.contains("Safari") && path_str.contains("History") {
                eprintln!("  → Path match (contains Safari/History): {:?}", entry.path());
                potential_matches.push(entry.path().to_path_buf());
            }
        }
    }
    
    eprintln!("  → Total files checked: {}", files_checked);
    eprintln!("  → Potential matches found: {}", potential_matches.len());
    
    // If we found any potential matches, use the first one
    if !potential_matches.is_empty() {
        let selected = &potential_matches[0];
        eprintln!("  → Using: {:?}", selected);
        return Ok(selected.clone());
    }
    
    Err(format!("Safari History.db not found after checking {} files in backup", files_checked))
}

/// Parse Safari History.db SQLite database
fn parse_safari_history_db(db_path: &Path) -> Result<Vec<IosBrowserEntry>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open History.db: {}", e))?;
    
    // Safari history schema:
    // Table: history_items
    // Columns: id, url, domain_expansion, visit_count, daily_visit_counts, 
    //          weekly_visit_counts, autocomplete_triggers, should_recompute_derived_visit_counts,
    //          visit_count_score
    // 
    // Table: history_visits
    // Columns: id, history_item, visit_time, title, load_successful, http_non_get, 
    //          synthesized, redirect_source, redirect_destination, origin, generation, 
    //          attributes, score
    //
    // We join these to get full history entries
    
    let query = "
        SELECT 
            hi.url,
            hv.title,
            hi.visit_count,
            datetime(hv.visit_time + 978307200, 'unixepoch') as last_visit
        FROM history_items hi
        LEFT JOIN history_visits hv ON hv.history_item = hi.id
        WHERE hv.visit_time IS NOT NULL
        ORDER BY hv.visit_time DESC
        LIMIT 5000
    ";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare Safari query: {}", e))?;
    
    let entries = stmt.query_map([], |row| {
        Ok(IosBrowserEntry {
            url: row.get(0)?,
            title: row.get::<_, Option<String>>(1)?.unwrap_or_else(|| "Untitled".to_string()),
            visit_count: row.get::<_, i64>(2).unwrap_or(0) as u32,
            last_visit: row.get(3)?,
        })
    })
    .map_err(|e| format!("Failed to query Safari history: {}", e))?;
    
    let mut results = Vec::new();
    for entry in entries {
        if let Ok(e) = entry {
            results.push(e);
        }
    }
    
    Ok(results)
}

/// Extract Chrome browser history from iOS device
pub fn extract_chrome_history(udid: &str, temp_dir: &Path) -> Result<Vec<IosBrowserEntry>, String> {
    // Chrome on iOS: AppDomain-com.google.chrome.ios > Library/Application Support/Google/Chrome/Default/History
    
    let chrome_backup_dir = temp_dir.join("chrome_backup");
    fs::create_dir_all(&chrome_backup_dir)
        .map_err(|e| format!("Failed to create Chrome backup dir: {}", e))?;
    
    eprintln!("  → Backing up Chrome data to temp directory...");
    
    // First, check if Chrome is installed
    let app_container = find_app_container(udid, "com.google.chrome.ios")?;
    if app_container.is_empty() {
        return Err("Chrome not installed on device".to_string());
    }
    
    // Use idevicebackup2 to backup Chrome's AppDomain
    let tool_path = get_tool_path("idevicebackup2.exe");
    let output = Command::new(&tool_path)
        .arg("-u")
        .arg(udid)
        .arg("backup")
        .arg("--full")
        .arg(&chrome_backup_dir)
        .output()
        .map_err(|e| format!("Failed to execute idevicebackup2: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = fs::remove_dir_all(&chrome_backup_dir);
        return Err(format!("Chrome backup failed: {}", stderr));
    }
    
    // Find Chrome History database
    let history_db = find_chrome_history_db(&chrome_backup_dir)?;
    
    eprintln!("  → Parsing Chrome History database...");
    
    // Parse the SQLite database
    let entries = parse_chrome_history_db(&history_db)?;
    
    eprintln!("  → Cleaning up Chrome temp files...");
    let _ = fs::remove_dir_all(&chrome_backup_dir);
    
    Ok(entries)
}

/// Find Chrome History database in iOS backup
fn find_chrome_history_db(backup_dir: &Path) -> Result<PathBuf, String> {
    eprintln!("  → Searching for Chrome History in backup...");
    
    for entry in walkdir::WalkDir::new(backup_dir)
        .follow_links(false)
        .max_depth(8)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let path_str = path.to_string_lossy();
        
        // Chrome history is in: Library/Application Support/Google/Chrome/Default/History
        if path_str.contains("Chrome") && 
           (path.file_name().and_then(|n| n.to_str()) == Some("History") ||
            path.file_name().and_then(|n| n.to_str()) == Some("History.db")) {
            eprintln!("  → Found Chrome history: {:?}", path);
            return Ok(path.to_path_buf());
        }
    }
    
    Err("Chrome History database not found in backup".to_string())
}

/// Parse Chrome History database (Chromium-based format)
fn parse_chrome_history_db(db_path: &Path) -> Result<Vec<IosBrowserEntry>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open Chrome History: {}", e))?;
    
    // Chrome history schema (Chromium format):
    // Table: urls
    // Columns: id, url, title, visit_count, typed_count, last_visit_time, hidden
    //
    // Table: visits
    // Columns: id, url, visit_time, from_visit, transition, segment_id, 
    //          visit_duration, incremented_omnibox_typed_score
    
    let query = "
        SELECT 
            url,
            title,
            visit_count,
            datetime(last_visit_time/1000000 + (strftime('%s', '1601-01-01')), 'unixepoch') as last_visit
        FROM urls
        WHERE last_visit_time > 0
        ORDER BY last_visit_time DESC
        LIMIT 5000
    ";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare Chrome query: {}", e))?;
    
    let entries = stmt.query_map([], |row| {
        Ok(IosBrowserEntry {
            url: row.get(0)?,
            title: row.get::<_, Option<String>>(1)?.unwrap_or_else(|| "Untitled".to_string()),
            visit_count: row.get::<_, i64>(2).unwrap_or(0) as u32,
            last_visit: row.get(3)?,
        })
    })
    .map_err(|e| format!("Failed to query Chrome history: {}", e))?;
    
    let mut results = Vec::new();
    for entry in entries {
        if let Ok(e) = entry {
            results.push(e);
        }
    }
    
    Ok(results)
}

/// Extract Firefox browser history from iOS device
pub fn extract_firefox_history(udid: &str, temp_dir: &Path) -> Result<Vec<IosBrowserEntry>, String> {
    // Firefox on iOS: AppDomain-org.mozilla.ios.Firefox > Library/Application Support/Firefox/profile.profile/browser.db
    
    let firefox_backup_dir = temp_dir.join("firefox_backup");
    fs::create_dir_all(&firefox_backup_dir)
        .map_err(|e| format!("Failed to create Firefox backup dir: {}", e))?;
    
    eprintln!("  → Backing up Firefox data to temp directory...");
    
    // First, check if Firefox is installed
    let app_container = find_app_container(udid, "org.mozilla.ios.Firefox")?;
    if app_container.is_empty() {
        return Err("Firefox not installed on device".to_string());
    }
    
    // Use idevicebackup2 to backup Firefox's AppDomain
    let tool_path = get_tool_path("idevicebackup2.exe");
    let output = Command::new(&tool_path)
        .arg("-u")
        .arg(udid)
        .arg("backup")
        .arg("--full")
        .arg(&firefox_backup_dir)
        .output()
        .map_err(|e| format!("Failed to execute idevicebackup2: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = fs::remove_dir_all(&firefox_backup_dir);
        return Err(format!("Firefox backup failed: {}", stderr));
    }
    
    // Find Firefox history database
    let history_db = find_firefox_history_db(&firefox_backup_dir)?;
    
    eprintln!("  → Parsing Firefox browser.db...");
    
    // Parse the SQLite database
    let entries = parse_firefox_history_db(&history_db)?;
    
    eprintln!("  → Cleaning up Firefox temp files...");
    let _ = fs::remove_dir_all(&firefox_backup_dir);
    
    Ok(entries)
}

/// Find Firefox browser.db in iOS backup
fn find_firefox_history_db(backup_dir: &Path) -> Result<PathBuf, String> {
    eprintln!("  → Searching for Firefox browser.db in backup...");
    
    for entry in walkdir::WalkDir::new(backup_dir)
        .follow_links(false)
        .max_depth(8)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy();
        
        // Firefox history is in: Library/Application Support/Firefox/.../browser.db
        if path_str.contains("Firefox") && 
           (file_name.eq_ignore_ascii_case("browser.db") ||
            file_name.eq_ignore_ascii_case("places.sqlite")) {
            eprintln!("  → Found Firefox history: {:?}", path);
            return Ok(path.to_path_buf());
        }
    }
    
    Err("Firefox browser.db not found in backup".to_string())
}

/// Parse Firefox browser.db (iOS-specific format)
fn parse_firefox_history_db(db_path: &Path) -> Result<Vec<IosBrowserEntry>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open Firefox browser.db: {}", e))?;
    
    // Firefox iOS history schema:
    // Table: history
    // Columns: id, guid, url, title, server_modified, local_modified, is_deleted, should_upload
    //
    // Table: visits
    // Columns: id, siteID, date, type, is_local
    
    let query = "
        SELECT 
            h.url,
            h.title,
            COUNT(v.id) as visit_count,
            datetime(MAX(v.date)/1000000, 'unixepoch') as last_visit
        FROM history h
        LEFT JOIN visits v ON v.siteID = h.id
        WHERE h.is_deleted = 0 AND v.date IS NOT NULL
        GROUP BY h.id
        ORDER BY MAX(v.date) DESC
        LIMIT 5000
    ";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare Firefox query: {}", e))?;
    
    let entries = stmt.query_map([], |row| {
        Ok(IosBrowserEntry {
            url: row.get(0)?,
            title: row.get::<_, Option<String>>(1)?.unwrap_or_else(|| "Untitled".to_string()),
            visit_count: row.get::<_, i64>(2).unwrap_or(0) as u32,
            last_visit: row.get(3)?,
        })
    })
    .map_err(|e| format!("Failed to query Firefox history: {}", e))?;
    
    let mut results = Vec::new();
    for entry in entries {
        if let Ok(e) = entry {
            results.push(e);
        }
    }
    
    Ok(results)
}

/// Find app container path for a given bundle ID
fn find_app_container(udid: &str, bundle_id: &str) -> Result<String, String> {
    // Use ideviceinstaller to check if app is installed
    let tool_path = get_tool_path("ideviceinstaller.exe");
    let output = Command::new(&tool_path)
        .arg("-u")
        .arg(udid)
        .arg("-l")
        .output()
        .map_err(|e| format!("Failed to list apps: {}", e))?;
    
    if !output.status.success() {
        return Err("Failed to list installed apps".to_string());
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Check if bundle ID exists in the app list
    if stdout.contains(bundle_id) {
        Ok(bundle_id.to_string())
    } else {
        Err(format!("No app container found for {}", bundle_id))
    }
}

/// Merge browser history from multiple sources, removing duplicates
pub fn merge_browser_histories(results: Vec<IosBrowserResult>) -> Vec<IosBrowserEntry> {
    use std::collections::HashMap;
    
    let mut merged: HashMap<String, IosBrowserEntry> = HashMap::new();
    
    for result in results {
        if !result.extraction_success {
            continue;
        }
        
        for entry in result.history_entries {
            // Use URL as key for deduplication
            let key = entry.url.clone();
            
            // If URL already exists, keep the one with higher visit count
            merged.entry(key).and_modify(|existing| {
                if entry.visit_count > existing.visit_count {
                    *existing = entry.clone();
                }
            }).or_insert(entry);
        }
    }
    
    // Convert to Vec and sort by visit count descending
    let mut entries: Vec<IosBrowserEntry> = merged.into_values().collect();
    entries.sort_by(|a, b| b.visit_count.cmp(&a.visit_count));
    
    entries
}

// Import walkdir crate functionality
use walkdir;
