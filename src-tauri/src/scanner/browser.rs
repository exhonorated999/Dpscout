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
    /// Chromium-based (The Browser Company), macOS/Windows.
    Arc,
    /// macOS only: `~/Library/Safari` (History.db needs Full Disk Access).
    Safari,
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
                } else if !cfg!(windows) {
                    // e.g. "/Volumes/Target" — no drive-letter suffix
                    format!("{}/", drive)
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

                    // macOS home layout (a Mac volume attached as a target)
                    paths.extend(mac_user_browser_paths(&user_path, &user_name));
                }
            }
        }
        None => {
            // macOS host: every readable home under /Users
            #[cfg(target_os = "macos")]
            paths.extend(mac_host_browser_paths(std::path::Path::new("/Users")));

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

/// Chromium-family browsers under `~/Library/Application Support` on macOS.
/// Each base holds `Default`/`Profile N` like the Windows `User Data` dir.
const MAC_CHROMIUM_BROWSERS: &[(BrowserType, &str, &str)] = &[
    (BrowserType::Chrome, "Google Chrome", "Google/Chrome"),
    (BrowserType::Edge, "Microsoft Edge", "Microsoft Edge"),
    (BrowserType::Brave, "Brave Browser", "BraveSoftware/Brave-Browser"),
    (BrowserType::Opera, "Opera", "com.operasoftware.Opera"),
    (BrowserType::Vivaldi, "Vivaldi", "Vivaldi"),
    (BrowserType::Arc, "Arc", "Arc/User Data"),
];

/// Browser data dirs in one macOS home (`/Users/<name>`).  Returns nothing for
/// a Windows profile (no `Library`), so it is safe to call on any home dir.
fn mac_user_browser_paths(user_path: &std::path::Path, user_name: &str) -> Vec<(BrowserType, String, PathBuf)> {
    let mut paths = Vec::new();
    let library = user_path.join("Library");
    let app_support = library.join("Application Support");

    for (browser_type, browser_name, rel) in MAC_CHROMIUM_BROWSERS {
        let base = app_support.join(rel);
        if base.is_dir() {
            paths.push((browser_type.clone(), format!("{} ({})", browser_name, user_name), base));
        }
    }

    let firefox = app_support.join("Firefox").join("Profiles");
    if firefox.is_dir() {
        paths.push((BrowserType::Firefox, format!("Mozilla Firefox ({})", user_name), firefox));
    }

    // Stat on the TCC-protected dir itself works without Full Disk Access;
    // reading inside it is what fails (handled in scan_safari_browser).
    let safari = library.join("Safari");
    if safari.is_dir() {
        paths.push((BrowserType::Safari, format!("Safari ({})", user_name), safari));
    }

    paths
}

/// All homes under `users_root` (normally `/Users`).  Other users' homes are
/// usually unreadable without root; those simply yield nothing.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mac_host_browser_paths(users_root: &std::path::Path) -> Vec<(BrowserType, String, PathBuf)> {
    crate::scanner::walker::mac_home_dirs(users_root)
        .iter()
        .flat_map(|(name, path)| mac_user_browser_paths(path, name))
        .collect()
}

/// Copy a SQLite DB plus its `-wal`/`-shm` side files into the scratch dir so
/// recent (un-checkpointed) rows are visible and the live DB is never locked.
fn copy_sqlite_to_scratch(src: &std::path::Path, stem: &str) -> std::io::Result<PathBuf> {
    let dst = crate::app_paths::scratch_dir().join(format!("{}_{}.db", stem, std::process::id()));
    std::fs::copy(src, &dst)?;
    for sfx in ["-wal", "-shm"] {
        let side = |p: &std::path::Path| {
            let mut o = p.as_os_str().to_owned();
            o.push(sfx);
            PathBuf::from(o)
        };
        let (s, d) = (side(src), side(&dst));
        if s.is_file() {
            let _ = std::fs::copy(&s, &d);
        } else {
            let _ = std::fs::remove_file(&d);
        }
    }
    Ok(dst)
}

fn remove_sqlite_copy(dst: &std::path::Path) {
    let _ = std::fs::remove_file(dst);
    for sfx in ["-wal", "-shm"] {
        let mut o = dst.as_os_str().to_owned();
        o.push(sfx);
        let _ = std::fs::remove_file(PathBuf::from(o));
    }
}

/// Seconds between 1970-01-01 and 2001-01-01 (Apple "Mac absolute time").
const MAC_EPOCH_OFFSET: f64 = 978_307_200.0;

/// Mac absolute time (seconds since 2001-01-01 UTC) → `YYYY-MM-DD HH:MM:SS`.
fn mac_absolute_to_string(secs: f64) -> String {
    if secs == 0.0 || !secs.is_finite() {
        return "Never".to_string();
    }
    match chrono::DateTime::from_timestamp((secs + MAC_EPOCH_OFFSET).floor() as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "Invalid date".to_string(),
    }
}

fn plist_date_to_string(v: Option<&plist::Value>) -> String {
    match v.and_then(|v| v.as_date()) {
        Some(d) => {
            let st: std::time::SystemTime = d.into();
            chrono::DateTime::<chrono::Utc>::from(st).format("%Y-%m-%d %H:%M:%S").to_string()
        }
        None => String::new(),
    }
}

/// Safari: `History.db` (history_items + history_visits), `Bookmarks.plist`,
/// `Downloads.plist`.  Without Full Disk Access the directory can't be listed;
/// that is recorded with the walk policy so the UI can say what was skipped.
fn scan_safari_browser(browser_name: &str, base: &std::path::Path) -> Result<Vec<BrowserData>, Box<dyn std::error::Error>> {
    if let Err(e) = std::fs::read_dir(base) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            crate::scanner::walker::host_policy().record_protected(base);
            return Ok(Vec::new());
        }
        return Err(e.into());
    }

    let mut data = BrowserData {
        browser_type: BrowserType::Safari,
        browser_name: browser_name.to_string(),
        profile_name: "Default".to_string(),
        history: Vec::new(),
        bookmarks: Vec::new(),
        credentials: Vec::new(),
        downloads: Vec::new(),
        install_path: "/Applications/Safari.app".to_string(),
        profile_path: base.to_string_lossy().to_string(),
    };

    let history = base.join("History.db");
    if history.is_file() {
        match read_safari_history(&history) {
            Ok(h) => data.history = h,
            Err(e) => eprintln!("[Browser Scan] Safari history unreadable: {}", e),
        }
    }
    let bookmarks = base.join("Bookmarks.plist");
    if bookmarks.is_file() {
        match plist::Value::from_file(&bookmarks) {
            Ok(root) => walk_safari_bookmarks(&root, "", &mut data.bookmarks),
            Err(e) => eprintln!("[Browser Scan] Safari bookmarks unreadable: {}", e),
        }
    }
    let downloads = base.join("Downloads.plist");
    if downloads.is_file() {
        match plist::Value::from_file(&downloads) {
            Ok(root) => data.downloads = read_safari_downloads(&root),
            Err(e) => eprintln!("[Browser Scan] Safari downloads unreadable: {}", e),
        }
    }

    if data.history.is_empty() && data.bookmarks.is_empty() && data.downloads.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![data])
}

fn read_safari_history(db_path: &std::path::Path) -> Result<Vec<HistoryEntry>, Box<dyn std::error::Error>> {
    let copy = copy_sqlite_to_scratch(db_path, "safari_history")?;
    let result = (|| -> SqlResult<Vec<HistoryEntry>> {
        let conn = Connection::open(&copy)?;
        // SQLite returns the bare `title` from the row that supplied MAX().
        let mut stmt = conn.prepare(
            "SELECT hi.url, hv.title, hi.visit_count, MAX(hv.visit_time)
             FROM history_items hi
             JOIN history_visits hv ON hv.history_item = hi.id
             GROUP BY hi.id
             ORDER BY MAX(hv.visit_time) DESC
             LIMIT 5000",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let title: Option<String> = row.get(1).unwrap_or(None);
                let visit_count: i64 = row.get(2).unwrap_or(0);
                let visit_time: f64 = row.get(3).unwrap_or(0.0);
                Ok(HistoryEntry {
                    url,
                    title: title.unwrap_or_default(),
                    visit_count: visit_count.clamp(0, i32::MAX as i64) as i32,
                    last_visit: mac_absolute_to_string(visit_time),
                    typed_count: 0,
                })
            })?
            .filter_map(|e| e.ok())
            .collect();
        Ok(rows)
    })();
    remove_sqlite_copy(&copy);
    Ok(result?)
}

/// Safari bookmark tree: `WebBookmarkTypeList` (folder, `Children`) and
/// `WebBookmarkTypeLeaf` (`URLString`, `URIDictionary.title`).  Proxies (the
/// History pseudo-folder) are skipped.
fn walk_safari_bookmarks(node: &plist::Value, folder: &str, out: &mut Vec<BookmarkEntry>) {
    let Some(d) = node.as_dictionary() else { return };
    let kind = d.get("WebBookmarkType").and_then(|v| v.as_string());
    match kind {
        Some("WebBookmarkTypeLeaf") => {
            let url = d.get("URLString").and_then(|v| v.as_string()).unwrap_or("");
            if url.is_empty() {
                return;
            }
            let title = d
                .get("URIDictionary")
                .and_then(|v| v.as_dictionary())
                .and_then(|u| u.get("title"))
                .and_then(|v| v.as_string())
                .unwrap_or("");
            let date_added = plist_date_to_string(
                d.get("ReadingList")
                    .and_then(|v| v.as_dictionary())
                    .and_then(|r| r.get("DateAdded")),
            );
            out.push(BookmarkEntry {
                url: url.to_string(),
                title: title.to_string(),
                date_added,
                folder: folder.to_string(),
            });
        }
        Some("WebBookmarkTypeList") | None => {
            let title = d.get("Title").and_then(|v| v.as_string()).unwrap_or("");
            let shown = match title {
                "BookmarksBar" => "Favorites",
                "BookmarksMenu" => "Bookmarks Menu",
                "com.apple.ReadingList" => "Reading List",
                t => t,
            };
            let sub = match (folder.is_empty(), shown.is_empty()) {
                (_, true) => folder.to_string(),
                (true, false) => shown.to_string(),
                (false, false) => format!("{}/{}", folder, shown),
            };
            if let Some(children) = d.get("Children").and_then(|v| v.as_array()) {
                for c in children {
                    walk_safari_bookmarks(c, &sub, out);
                }
            }
        }
        _ => {}
    }
}

fn read_safari_downloads(root: &plist::Value) -> Vec<DownloadEntry> {
    let Some(list) = root
        .as_dictionary()
        .and_then(|d| d.get("DownloadHistory"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    let num = |d: &plist::Dictionary, k: &str| -> i64 {
        match d.get(k) {
            Some(plist::Value::Integer(i)) => i.as_signed().unwrap_or(0),
            Some(plist::Value::Real(r)) => *r as i64,
            _ => 0,
        }
    };
    list.iter()
        .filter_map(|v| v.as_dictionary())
        .map(|d| {
            let s = |k: &str| d.get(k).and_then(|v| v.as_string()).unwrap_or("").to_string();
            let total = num(d, "DownloadEntryProgressTotalToLoad");
            let so_far = num(d, "DownloadEntryProgressBytesSoFar");
            let finished = d.get("DownloadEntryDateFinishedKey").is_some();
            let state = if finished && (total == 0 || so_far >= total) {
                "Complete"
            } else {
                "Incomplete"
            };
            DownloadEntry {
                target_path: s("DownloadEntryPath"),
                url: s("DownloadEntryURL"),
                start_time: plist_date_to_string(d.get("DownloadEntryDateAddedKey")),
                end_time: plist_date_to_string(d.get("DownloadEntryDateFinishedKey")),
                total_bytes: total,
                danger_type: "Unknown".to_string(),
                state: state.to_string(),
                mime_type: String::new(),
                referrer_url: String::new(),
            }
        })
        .collect()
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
    let temp_path = crate::app_paths::scratch_dir().join(format!("history_temp_{}.db", std::process::id()));
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
    let temp_path = crate::app_paths::scratch_dir().join(format!("downloads_temp_{}.db", std::process::id()));
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
    let temp_path = crate::app_paths::scratch_dir().join(format!("login_data_temp_{}.db", std::process::id()));
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
    let temp_path = crate::app_paths::scratch_dir().join(format!("places_temp_{}.db", std::process::id()));
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
    let temp_path = crate::app_paths::scratch_dir().join(format!("places_bookmarks_temp_{}.db", std::process::id()));
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
    let temp_path = crate::app_paths::scratch_dir().join(format!("places_downloads_temp_{}.db", std::process::id()));
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
            BrowserType::Safari => {
                match scan_safari_browser(&browser_name, &path) {
                    Ok(mut data) => all_browser_data.append(&mut data),
                    Err(e) => eprintln!("Error scanning Safari: {}", e),
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fresh_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scout_browser_{}_{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mkdirs(root: &Path, rel: &str) -> PathBuf {
        let p = root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn kinds(v: &[(BrowserType, String, PathBuf)]) -> Vec<String> {
        v.iter().map(|(_, label, _)| label.clone()).collect()
    }

    #[test]
    fn mac_home_layout_is_detected() {
        let home = fresh_dir("home");
        mkdirs(&home, "Library/Application Support/Google/Chrome/Default");
        mkdirs(&home, "Library/Application Support/Arc/User Data/Default");
        mkdirs(&home, "Library/Application Support/Firefox/Profiles/abc.default");
        mkdirs(&home, "Library/Safari");
        let got = kinds(&mac_user_browser_paths(&home, "alice"));
        assert_eq!(
            got,
            vec!["Google Chrome (alice)", "Arc (alice)", "Mozilla Firefox (alice)", "Safari (alice)"]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn windows_profile_yields_no_mac_paths() {
        let home = fresh_dir("winprof");
        mkdirs(&home, "AppData/Local/Google/Chrome/User Data/Default");
        assert!(mac_user_browser_paths(&home, "bob").is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn mac_host_scan_skips_shared_guest_and_hidden() {
        let users = fresh_dir("users");
        for u in ["zed", "alice", "Shared", "Guest", ".localized"] {
            mkdirs(&users, &format!("{}/Library/Safari", u));
        }
        let got = kinds(&mac_host_browser_paths(&users));
        assert_eq!(got, vec!["Safari (alice)", "Safari (zed)"]);
        let _ = std::fs::remove_dir_all(&users);
    }

    #[test]
    fn mac_absolute_time_converts_from_2001_epoch() {
        assert_eq!(mac_absolute_to_string(0.0), "Never");
        assert_eq!(mac_absolute_to_string(700_000_000.0), "2023-03-08 20:26:40");
        assert_eq!(mac_absolute_to_string(750_000_000.75), "2024-10-07 13:20:00");
    }

    fn write_safari_history(dir: &Path) {
        let conn = Connection::open(dir.join("History.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
             INSERT INTO history_items VALUES (1, 'https://old.example/', 1);
             INSERT INTO history_items VALUES (2, 'https://news.example/', 3);
             INSERT INTO history_visits VALUES (10, 1, 700000000.0, 'Old');
             INSERT INTO history_visits VALUES (20, 2, 700000100.0, 'News v1');
             INSERT INTO history_visits VALUES (21, 2, 750000000.75, 'News latest');
             INSERT INTO history_visits VALUES (22, 2, 710000000.0, NULL);",
        )
        .unwrap();
    }

    fn date(unix: u64) -> plist::Value {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix);
        plist::Value::Date(plist::Date::from(t))
    }

    fn dict(pairs: Vec<(&str, plist::Value)>) -> plist::Value {
        let mut d = plist::Dictionary::new();
        for (k, v) in pairs {
            d.insert(k.to_string(), v);
        }
        plist::Value::Dictionary(d)
    }

    fn s(v: &str) -> plist::Value {
        plist::Value::String(v.to_string())
    }

    fn leaf(url: &str, title: &str) -> plist::Value {
        dict(vec![
            ("WebBookmarkType", s("WebBookmarkTypeLeaf")),
            ("URLString", s(url)),
            ("URIDictionary", dict(vec![("title", s(title))])),
        ])
    }

    fn list(title: &str, children: Vec<plist::Value>) -> plist::Value {
        dict(vec![
            ("WebBookmarkType", s("WebBookmarkTypeList")),
            ("Title", s(title)),
            ("Children", plist::Value::Array(children)),
        ])
    }

    #[test]
    fn safari_history_bookmarks_and_downloads() {
        let dir = fresh_dir("safari");
        write_safari_history(&dir);

        let mut reading = leaf("https://later.example/", "Later");
        if let plist::Value::Dictionary(d) = &mut reading {
            d.insert("ReadingList".into(), dict(vec![("DateAdded", date(1_700_000_000))]));
        }
        let bookmarks = dict(vec![
            ("WebBookmarkType", s("WebBookmarkTypeList")),
            ("Title", s("")),
            (
                "Children",
                plist::Value::Array(vec![
                    dict(vec![("WebBookmarkType", s("WebBookmarkTypeProxy")), ("Title", s("History"))]),
                    list("BookmarksBar", vec![leaf("https://bar.example/", "Bar"), list("Work", vec![leaf("https://w.example/", "W")])]),
                    list("com.apple.ReadingList", vec![reading]),
                ]),
            ),
        ]);
        bookmarks.to_file_xml(dir.join("Bookmarks.plist")).unwrap();

        let downloads = dict(vec![(
            "DownloadHistory",
            plist::Value::Array(vec![
                dict(vec![
                    ("DownloadEntryURL", s("https://dl.example/a.zip")),
                    ("DownloadEntryPath", s("/Users/alice/Downloads/a.zip")),
                    ("DownloadEntryProgressTotalToLoad", plist::Value::Integer(100i64.into())),
                    ("DownloadEntryProgressBytesSoFar", plist::Value::Integer(100i64.into())),
                    ("DownloadEntryDateAddedKey", date(1_700_000_000)),
                    ("DownloadEntryDateFinishedKey", date(1_700_000_060)),
                ]),
                dict(vec![
                    ("DownloadEntryURL", s("https://dl.example/b.iso")),
                    ("DownloadEntryProgressTotalToLoad", plist::Value::Integer(500i64.into())),
                    ("DownloadEntryProgressBytesSoFar", plist::Value::Integer(20i64.into())),
                ]),
            ]),
        )]);
        downloads.to_file_binary(dir.join("Downloads.plist")).unwrap();

        let out = scan_safari_browser("Safari (alice)", &dir).unwrap();
        assert_eq!(out.len(), 1);
        let b = &out[0];
        assert!(matches!(b.browser_type, BrowserType::Safari));

        let h: Vec<(&str, &str, i32, &str)> = b
            .history
            .iter()
            .map(|e| (e.url.as_str(), e.title.as_str(), e.visit_count, e.last_visit.as_str()))
            .collect();
        assert_eq!(
            h,
            vec![
                ("https://news.example/", "News latest", 3, "2024-10-07 13:20:00"),
                ("https://old.example/", "Old", 1, "2023-03-08 20:26:40"),
            ]
        );

        let bm: Vec<(&str, &str, &str, &str)> = b
            .bookmarks
            .iter()
            .map(|e| (e.url.as_str(), e.title.as_str(), e.folder.as_str(), e.date_added.as_str()))
            .collect();
        assert_eq!(
            bm,
            vec![
                ("https://bar.example/", "Bar", "Favorites", ""),
                ("https://w.example/", "W", "Favorites/Work", ""),
                ("https://later.example/", "Later", "Reading List", "2023-11-14 22:13:20"),
            ]
        );

        let dl: Vec<(&str, &str, i64, &str)> = b
            .downloads
            .iter()
            .map(|e| (e.url.as_str(), e.state.as_str(), e.total_bytes, e.end_time.as_str()))
            .collect();
        assert_eq!(
            dl,
            vec![
                ("https://dl.example/a.zip", "Complete", 100, "2023-11-14 22:14:20"),
                ("https://dl.example/b.iso", "Incomplete", 500, ""),
            ]
        );

        // Scratch copies are cleaned up; the source DB is untouched.
        assert!(dir.join("History.db").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safari_empty_dir_yields_nothing() {
        let dir = fresh_dir("safari_empty");
        assert!(scan_safari_browser("Safari (x)", &dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
