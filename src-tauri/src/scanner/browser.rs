use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use rusqlite::{Connection, Result as SqlResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserType {
    Chrome,
    Edge,
    Firefox,
    Brave,
    Opera,
    Vivaldi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserData {
    pub browser_type: BrowserType,
    pub browser_name: String,
    pub profile_name: String,
    pub history: Vec<HistoryEntry>,
    pub bookmarks: Vec<BookmarkEntry>,
    pub credentials: Vec<CredentialEntry>,
    pub downloads: Vec<DownloadEntry>,
    pub install_path: String,
    pub profile_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i32,
    pub last_visit: String,
    pub typed_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkEntry {
    pub url: String,
    pub title: String,
    pub date_added: String,
    pub folder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEntry {
    pub origin_url: String,
    pub username: String,
    pub password_encrypted: bool,
    pub date_created: String,
    pub date_last_used: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadEntry {
    pub target_path: String,
    pub url: String,
    pub start_time: String,
    pub end_time: String,
    pub total_bytes: i64,
    pub danger_type: String,
    pub state: String,
    pub mime_type: String,
    pub referrer_url: String,
}

/// Get browser profile paths for the current system
fn get_browser_paths() -> Vec<(BrowserType, String, PathBuf)> {
    get_browser_paths_for_drives(None)
}

/// Get browser profile paths — either from the host system or from target drives
/// When target_drives is Some, scans `<drive>\Users\*\AppData\...` on each drive
/// When target_drives is None, uses the current system's environment variables
fn get_browser_paths_for_drives(target_drives: Option<&[String]>) -> Vec<(BrowserType, String, PathBuf)> {
    let mut paths = Vec::new();
    
    match target_drives {
        Some(drives) => {
            // Scanning external/attached drives — look for browser data in user profiles on those drives
            for drive in drives {
                let drive_root = if drive.ends_with('\\') || drive.ends_with('/') {
                    drive.clone()
                } else if drive.ends_with(':') {
                    format!("{}\\", drive)
                } else {
                    format!("{}\\", drive)
                };
                
                let users_dir = PathBuf::from(&drive_root).join("Users");
                if !users_dir.exists() {
                    eprintln!("No Users directory on drive {}", drive_root);
                    continue;
                }
                
                // Enumerate all user profiles on this drive
                let user_entries = match std::fs::read_dir(&users_dir) {
                    Ok(entries) => entries,
                    Err(e) => {
                        eprintln!("Failed to read Users directory on {}: {}", drive_root, e);
                        continue;
                    }
                };
                
                for entry in user_entries.flatten() {
                    let user_name = entry.file_name().to_string_lossy().to_string();
                    // Skip system profiles
                    if ["Public", "Default", "Default User", "All Users", "desktop.ini"]
                        .contains(&user_name.as_str()) {
                        continue;
                    }
                    
                    let user_path = entry.path();
                    if !user_path.is_dir() {
                        continue;
                    }
                    
                    let local_appdata = user_path.join("AppData").join("Local");
                    let roaming_appdata = user_path.join("AppData").join("Roaming");
                    
                    // Chromium-based browsers (use Local AppData)
                    if local_appdata.exists() {
                        let chromium_browsers = vec![
                            (BrowserType::Chrome, "Google Chrome", vec!["Google", "Chrome", "User Data"]),
                            (BrowserType::Edge, "Microsoft Edge", vec!["Microsoft", "Edge", "User Data"]),
                            (BrowserType::Brave, "Brave Browser", vec!["BraveSoftware", "Brave-Browser", "User Data"]),
                            (BrowserType::Opera, "Opera", vec!["Opera Software", "Opera Stable"]),
                            (BrowserType::Vivaldi, "Vivaldi", vec!["Vivaldi", "User Data"]),
                        ];
                        
                        for (browser_type, browser_name, subpath) in &chromium_browsers {
                            let mut browser_path = local_appdata.clone();
                            for part in subpath {
                                browser_path = browser_path.join(part);
                            }
                            if browser_path.exists() {
                                let label = format!("{} ({})", browser_name, user_name);
                                paths.push((browser_type.clone(), label, browser_path));
                            }
                        }
                    }
                    
                    // Firefox (uses Roaming AppData)
                    if roaming_appdata.exists() {
                        let firefox_path = roaming_appdata
                            .join("Mozilla")
                            .join("Firefox")
                            .join("Profiles");
                        if firefox_path.exists() {
                            let label = format!("Mozilla Firefox ({})", user_name);
                            paths.push((BrowserType::Firefox, label, firefox_path));
                        }
                    }
                }
            }
        }
        None => {
            // Scanning the host system — use environment variables
            if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
                // Chrome
                let chrome_path = PathBuf::from(&local_appdata)
                    .join("Google")
                    .join("Chrome")
                    .join("User Data");
                if chrome_path.exists() {
                    paths.push((BrowserType::Chrome, "Google Chrome".to_string(), chrome_path));
                }

                // Edge
                let edge_path = PathBuf::from(&local_appdata)
                    .join("Microsoft")
                    .join("Edge")
                    .join("User Data");
                if edge_path.exists() {
                    paths.push((BrowserType::Edge, "Microsoft Edge".to_string(), edge_path));
                }

                // Brave
                let brave_path = PathBuf::from(&local_appdata)
                    .join("BraveSoftware")
                    .join("Brave-Browser")
                    .join("User Data");
                if brave_path.exists() {
                    paths.push((BrowserType::Brave, "Brave Browser".to_string(), brave_path));
                }

                // Opera
                let opera_path = PathBuf::from(&local_appdata)
                    .join("Opera Software")
                    .join("Opera Stable");
                if opera_path.exists() {
                    paths.push((BrowserType::Opera, "Opera".to_string(), opera_path));
                }

                // Vivaldi
                let vivaldi_path = PathBuf::from(&local_appdata)
                    .join("Vivaldi")
                    .join("User Data");
                if vivaldi_path.exists() {
                    paths.push((BrowserType::Vivaldi, "Vivaldi".to_string(), vivaldi_path));
                }
            }

            if let Ok(appdata) = std::env::var("APPDATA") {
                // Firefox
                let firefox_path = PathBuf::from(&appdata)
                    .join("Mozilla")
                    .join("Firefox")
                    .join("Profiles");
                if firefox_path.exists() {
                    paths.push((BrowserType::Firefox, "Mozilla Firefox".to_string(), firefox_path));
                }
            }
        }
    }

    paths
}

/// Scan Chromium-based browser (Chrome, Edge, Brave, etc.)
fn scan_chromium_browser(
    browser_type: BrowserType,
    browser_name: &str,
    base_path: &PathBuf,
) -> Result<Vec<BrowserData>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    // Scan Default profile and numbered profiles
    let profiles = vec!["Default", "Profile 1", "Profile 2", "Profile 3"];

    for profile in profiles {
        let profile_path = base_path.join(profile);
        if !profile_path.exists() {
            continue;
        }

        let history_path = profile_path.join("History");
        let login_data_path = profile_path.join("Login Data");
        let bookmarks_path = profile_path.join("Bookmarks");

        let mut browser_data = BrowserData {
            browser_type: browser_type.clone(),
            browser_name: browser_name.to_string(),
            profile_name: profile.to_string(),
            history: Vec::new(),
            bookmarks: Vec::new(),
            credentials: Vec::new(),
            downloads: Vec::new(),
            install_path: base_path.to_string_lossy().to_string(),
            profile_path: profile_path.to_string_lossy().to_string(),
        };

        // Read history
        if history_path.exists() {
            if let Ok(history) = read_chromium_history(&history_path) {
                browser_data.history = history;
            }
            // Read downloads from the same database
            if let Ok(downloads) = read_chromium_downloads(&history_path) {
                browser_data.downloads = downloads;
            }
        }

        // Read bookmarks
        if bookmarks_path.exists() {
            if let Ok(bookmarks) = read_chromium_bookmarks(&bookmarks_path) {
                browser_data.bookmarks = bookmarks;
            }
        }

        // Read credentials
        if login_data_path.exists() {
            if let Ok(creds) = read_chromium_credentials(&login_data_path) {
                browser_data.credentials = creds;
            }
        }

        // Only add if we found any data
        if !browser_data.history.is_empty() 
            || !browser_data.bookmarks.is_empty() 
            || !browser_data.credentials.is_empty()
            || !browser_data.downloads.is_empty() {
            results.push(browser_data);
        }
    }

    Ok(results)
}

/// Read history from Chromium-based browser
fn read_chromium_history(db_path: &PathBuf) -> SqlResult<Vec<HistoryEntry>> {
    // Create a temporary copy to avoid locking issues
    let temp_path = std::env::temp_dir().join(format!("history_temp_{}.db", std::process::id()));
    let _ = std::fs::copy(db_path, &temp_path);

    let conn = Connection::open(&temp_path)?;
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time, typed_count 
         FROM urls 
         ORDER BY last_visit_time DESC 
         LIMIT 5000"
    )?;

    let entries = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1).unwrap_or_else(|_| String::new());
        let visit_count: i32 = row.get(2)?;
        let last_visit_time: i64 = row.get(3)?;
        let typed_count: i32 = row.get(4)?;

        // Convert Chrome timestamp (microseconds since 1601) to readable format
        let last_visit = chromium_timestamp_to_string(last_visit_time);

        Ok(HistoryEntry {
            url,
            title,
            visit_count,
            last_visit,
            typed_count,
        })
    })?
    .filter_map(|e| e.ok())
    .collect();

    let _ = std::fs::remove_file(temp_path);
    Ok(entries)
}

/// Read download history from Chromium-based browser
fn read_chromium_downloads(db_path: &PathBuf) -> SqlResult<Vec<DownloadEntry>> {
    // Create a temporary copy to avoid locking issues
    let temp_path = std::env::temp_dir().join(format!("downloads_temp_{}.db", std::process::id()));
    let _ = std::fs::copy(db_path, &temp_path);

    let conn = Connection::open(&temp_path)?;
    
    // Check if downloads table exists
    let table_exists: Result<i32, _> = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='downloads'",
        [],
        |row| row.get(0)
    );
    
    if table_exists.unwrap_or(0) == 0 {
        let _ = std::fs::remove_file(temp_path);
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT target_path, tab_url, start_time, end_time, total_bytes, 
                danger_type, state, mime_type, tab_referrer_url
         FROM downloads 
         ORDER BY start_time DESC 
         LIMIT 1000"
    )?;

    let entries = stmt.query_map([], |row| {
        let target_path: String = row.get(0).unwrap_or_else(|_| String::new());
        let url: String = row.get(1).unwrap_or_else(|_| String::new());
        let start_time: i64 = row.get(2).unwrap_or(0);
        let end_time: i64 = row.get(3).unwrap_or(0);
        let total_bytes: i64 = row.get(4).unwrap_or(0);
        let danger_type: i32 = row.get(5).unwrap_or(0);
        let state: i32 = row.get(6).unwrap_or(0);
        let mime_type: String = row.get(7).unwrap_or_else(|_| String::new());
        let referrer_url: String = row.get(8).unwrap_or_else(|_| String::new());

        // Convert Chrome timestamp to readable format
        let start_time_str = chromium_timestamp_to_string(start_time);
        let end_time_str = chromium_timestamp_to_string(end_time);
        
        // Convert danger type enum
        let danger_str = match danger_type {
            0 => "Safe",
            1 => "Dangerous",
            2 => "Dangerous URL",
            3 => "Dangerous Content",
            4 => "Uncommon Content",
            5 => "User Validated",
            6 => "Dangerous Host",
            7 => "Potentially Unwanted",
            _ => "Unknown"
        }.to_string();
        
        // Convert state enum
        let state_str = match state {
            0 => "In Progress",
            1 => "Complete",
            2 => "Cancelled",
            3 => "Interrupted",
            _ => "Unknown"
        }.to_string();

        Ok(DownloadEntry {
            target_path,
            url,
            start_time: start_time_str,
            end_time: end_time_str,
            total_bytes,
            danger_type: danger_str,
            state: state_str,
            mime_type,
            referrer_url,
        })
    })?
    .filter_map(|e| e.ok())
    .collect();

    let _ = std::fs::remove_file(temp_path);
    Ok(entries)
}

/// Read bookmarks from Chromium-based browser
fn read_chromium_bookmarks(bookmarks_path: &PathBuf) -> Result<Vec<BookmarkEntry>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(bookmarks_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let mut bookmarks = Vec::new();

    fn extract_bookmarks(node: &serde_json::Value, folder: &str, bookmarks: &mut Vec<BookmarkEntry>) {
        if let Some(node_type) = node.get("type").and_then(|t| t.as_str()) {
            if node_type == "url" {
                if let (Some(url), Some(name)) = (
                    node.get("url").and_then(|u| u.as_str()),
                    node.get("name").and_then(|n| n.as_str()),
                ) {
                    let date_added = node
                        .get("date_added")
                        .and_then(|d| d.as_str())
                        .unwrap_or("Unknown")
                        .to_string();

                    bookmarks.push(BookmarkEntry {
                        url: url.to_string(),
                        title: name.to_string(),
                        date_added,
                        folder: folder.to_string(),
                    });
                }
            } else if node_type == "folder" {
                if let Some(name) = node.get("name").and_then(|n| n.as_str()) {
                    let new_folder = if folder.is_empty() {
                        name.to_string()
                    } else {
                        format!("{}/{}", folder, name)
                    };

                    if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                        for child in children {
                            extract_bookmarks(child, &new_folder, bookmarks);
                        }
                    }
                }
            }
        }
    }

    if let Some(roots) = json.get("roots") {
        if let Some(roots_obj) = roots.as_object() {
            for (_, root) in roots_obj {
                extract_bookmarks(root, "", &mut bookmarks);
            }
        }
    }

    Ok(bookmarks)
}

/// Read credentials from Chromium-based browser
fn read_chromium_credentials(db_path: &PathBuf) -> SqlResult<Vec<CredentialEntry>> {
    let temp_path = std::env::temp_dir().join(format!("login_data_temp_{}.db", std::process::id()));
    let _ = std::fs::copy(db_path, &temp_path);

    let conn = Connection::open(&temp_path)?;
    let mut stmt = conn.prepare(
        "SELECT origin_url, username_value, date_created, date_last_used 
         FROM logins 
         ORDER BY date_last_used DESC 
         LIMIT 1000"
    )?;

    let entries = stmt.query_map([], |row| {
        let origin_url: String = row.get(0)?;
        let username: String = row.get(1).unwrap_or_else(|_| String::new());
        let date_created: i64 = row.get(2)?;
        let date_last_used: i64 = row.get(3)?;

        Ok(CredentialEntry {
            origin_url,
            username,
            password_encrypted: true, // Always encrypted, won't decrypt
            date_created: chromium_timestamp_to_string(date_created),
            date_last_used: chromium_timestamp_to_string(date_last_used),
        })
    })?
    .filter_map(|e| e.ok())
    .collect();

    let _ = std::fs::remove_file(temp_path);
    Ok(entries)
}

/// Scan Firefox browser
fn scan_firefox_browser(
    base_path: &PathBuf,
) -> Result<Vec<BrowserData>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    // Firefox uses profile folders with random names
    if let Ok(entries) = std::fs::read_dir(base_path) {
        for entry in entries.filter_map(Result::ok) {
            let profile_path = entry.path();
            if !profile_path.is_dir() {
                continue;
            }

            let profile_name = profile_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string();

            let places_db = profile_path.join("places.sqlite");
            let logins_json = profile_path.join("logins.json");

            let mut browser_data = BrowserData {
                browser_type: BrowserType::Firefox,
                browser_name: "Mozilla Firefox".to_string(),
                profile_name,
                history: Vec::new(),
                bookmarks: Vec::new(),
                credentials: Vec::new(),
                downloads: Vec::new(),
                install_path: base_path.to_string_lossy().to_string(),
                profile_path: profile_path.to_string_lossy().to_string(),
            };

            // Read history and bookmarks from places.sqlite
            if places_db.exists() {
                if let Ok(history) = read_firefox_history(&places_db) {
                    browser_data.history = history;
                }
                if let Ok(bookmarks) = read_firefox_bookmarks(&places_db) {
                    browser_data.bookmarks = bookmarks;
                }
                if let Ok(downloads) = read_firefox_downloads(&places_db) {
                    browser_data.downloads = downloads;
                }
            }

            // Read credentials from logins.json
            if logins_json.exists() {
                if let Ok(creds) = read_firefox_credentials(&logins_json) {
                    browser_data.credentials = creds;
                }
            }

            if !browser_data.history.is_empty() 
                || !browser_data.bookmarks.is_empty() 
                || !browser_data.credentials.is_empty()
                || !browser_data.downloads.is_empty() {
                results.push(browser_data);
            }
        }
    }

    Ok(results)
}

/// Read Firefox history
fn read_firefox_history(db_path: &PathBuf) -> SqlResult<Vec<HistoryEntry>> {
    let temp_path = std::env::temp_dir().join(format!("places_temp_{}.db", std::process::id()));
    let _ = std::fs::copy(db_path, &temp_path);

    let conn = Connection::open(&temp_path)?;
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_date, typed 
         FROM moz_places 
         WHERE last_visit_date IS NOT NULL 
         ORDER BY last_visit_date DESC 
         LIMIT 5000"
    )?;

    let entries = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1).unwrap_or_else(|_| String::new());
        let visit_count: i32 = row.get(2)?;
        let last_visit_date: i64 = row.get(3)?;
        let typed: i32 = row.get(4).unwrap_or(0);

        // Firefox timestamp is in microseconds
        let last_visit = firefox_timestamp_to_string(last_visit_date);

        Ok(HistoryEntry {
            url,
            title,
            visit_count,
            last_visit,
            typed_count: typed,
        })
    })?
    .filter_map(|e| e.ok())
    .collect();

    let _ = std::fs::remove_file(temp_path);
    Ok(entries)
}

/// Read Firefox bookmarks
fn read_firefox_bookmarks(db_path: &PathBuf) -> SqlResult<Vec<BookmarkEntry>> {
    let temp_path = std::env::temp_dir().join(format!("places_bookmarks_temp_{}.db", std::process::id()));
    let _ = std::fs::copy(db_path, &temp_path);

    let conn = Connection::open(&temp_path)?;
    let mut stmt = conn.prepare(
        "SELECT p.url, b.title, b.dateAdded, b.parent 
         FROM moz_bookmarks b 
         JOIN moz_places p ON b.fk = p.id 
         WHERE b.type = 1 
         ORDER BY b.dateAdded DESC 
         LIMIT 1000"
    )?;

    let entries = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1).unwrap_or_else(|_| String::new());
        let date_added: i64 = row.get(2)?;

        Ok(BookmarkEntry {
            url,
            title,
            date_added: firefox_timestamp_to_string(date_added),
            folder: "Bookmarks".to_string(),
        })
    })?
    .filter_map(|e| e.ok())
    .collect();

    let _ = std::fs::remove_file(temp_path);
    Ok(entries)
}

/// Read Firefox downloads
fn read_firefox_downloads(db_path: &PathBuf) -> SqlResult<Vec<DownloadEntry>> {
    let temp_path = std::env::temp_dir().join(format!("places_downloads_temp_{}.db", std::process::id()));
    let _ = std::fs::copy(db_path, &temp_path);

    let conn = Connection::open(&temp_path)?;
    
    // Check if downloads table exists (Firefox stores in moz_annos)
    let table_exists: Result<i32, _> = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='moz_annos'",
        [],
        |row| row.get(0)
    );
    
    if table_exists.unwrap_or(0) == 0 {
        let _ = std::fs::remove_file(temp_path);
        return Ok(Vec::new());
    }

    // Firefox stores download info in annotations
    let mut stmt = conn.prepare(
        "SELECT p.url, p.title, p.last_visit_date, a.content
         FROM moz_places p
         JOIN moz_annos a ON p.id = a.place_id
         WHERE a.anno_attribute_id IN (
             SELECT id FROM moz_anno_attributes 
             WHERE name LIKE '%download%'
         )
         ORDER BY p.last_visit_date DESC
         LIMIT 1000"
    )?;

    let entries = stmt.query_map([], |row| {
        let url: String = row.get(0).unwrap_or_else(|_| String::new());
        let title: String = row.get(1).unwrap_or_else(|_| String::new());
        let visit_date: i64 = row.get(2).unwrap_or(0);
        let content: String = row.get(3).unwrap_or_else(|_| String::new());

        let visit_str = firefox_timestamp_to_string(visit_date);

        Ok(DownloadEntry {
            target_path: title.clone(),
            url,
            start_time: visit_str.clone(),
            end_time: visit_str,
            total_bytes: 0,
            danger_type: "Unknown".to_string(),
            state: "Complete".to_string(),
            mime_type: "".to_string(),
            referrer_url: "".to_string(),
        })
    })?
    .filter_map(|e| e.ok())
    .collect();

    let _ = std::fs::remove_file(temp_path);
    Ok(entries)
}

/// Read Firefox credentials
fn read_firefox_credentials(logins_path: &PathBuf) -> Result<Vec<CredentialEntry>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(logins_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let mut credentials = Vec::new();

    if let Some(logins) = json.get("logins").and_then(|l| l.as_array()) {
        for login in logins {
            if let Some(hostname) = login.get("hostname").and_then(|h| h.as_str()) {
                let username = login
                    .get("encryptedUsername")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();

                let time_created = login
                    .get("timeCreated")
                    .and_then(|t| t.as_i64())
                    .unwrap_or(0);

                let time_last_used = login
                    .get("timeLastUsed")
                    .and_then(|t| t.as_i64())
                    .unwrap_or(0);

                credentials.push(CredentialEntry {
                    origin_url: hostname.to_string(),
                    username,
                    password_encrypted: true,
                    date_created: firefox_timestamp_to_string(time_created),
                    date_last_used: firefox_timestamp_to_string(time_last_used),
                });
            }
        }
    }

    Ok(credentials)
}

/// Convert Chromium timestamp (microseconds since Jan 1, 1601) to readable string
fn chromium_timestamp_to_string(timestamp: i64) -> String {
    if timestamp == 0 {
        return "Never".to_string();
    }

    // Convert to Unix timestamp (seconds since Jan 1, 1970)
    let unix_timestamp = (timestamp - 11644473600000000) / 1000000;
    
    if let Some(datetime) = chrono::DateTime::from_timestamp(unix_timestamp, 0) {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "Invalid date".to_string()
    }
}

/// Convert Firefox timestamp (microseconds) to readable string
fn firefox_timestamp_to_string(timestamp: i64) -> String {
    if timestamp == 0 {
        return "Never".to_string();
    }

    let unix_timestamp = timestamp / 1000000;
    
    if let Some(datetime) = chrono::DateTime::from_timestamp(unix_timestamp, 0) {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "Invalid date".to_string()
    }
}

/// Main scan function that scans all browsers
/// Pass target_drives to scan browser data on external/attached drives
/// Pass None to scan the current host system's browsers
pub fn scan_all_browsers() -> Result<Vec<BrowserData>, Box<dyn std::error::Error>> {
    scan_all_browsers_for_drives(None)
}

/// Scan browsers on specific target drives (for external drive forensics)
pub fn scan_all_browsers_for_drives(target_drives: Option<&[String]>) -> Result<Vec<BrowserData>, Box<dyn std::error::Error>> {
    let mut all_browser_data = Vec::new();

    let browser_paths = get_browser_paths_for_drives(target_drives);

    for (browser_type, browser_name, path) in browser_paths {
        // Honor scan cancellation between browsers
        if crate::scanner::hash_scan::is_scan_cancelled() {
            eprintln!("[Browser Scan] ⛔ Cancelled before {}", browser_name);
            return Ok(all_browser_data);
        }

        eprintln!("Scanning {} at {:?}", browser_name, path);
        
        match browser_type {
            BrowserType::Firefox => {
                match scan_firefox_browser(&path) {
                    Ok(mut data) => all_browser_data.append(&mut data),
                    Err(e) => eprintln!("Error scanning Firefox: {}", e),
                }
            }
            _ => {
                // All other browsers are Chromium-based
                match scan_chromium_browser(browser_type, &browser_name, &path) {
                    Ok(mut data) => all_browser_data.append(&mut data),
                    Err(e) => eprintln!("Error scanning {}: {}", browser_name, e),
                }
            }
        }
    }

    Ok(all_browser_data)
}
