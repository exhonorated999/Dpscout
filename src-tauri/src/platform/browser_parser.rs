/// Offline browser history parsing for forensic scanning
/// 
/// Parses Chrome, Edge, and Firefox SQLite databases without requiring
/// a running browser or OS.

use super::BrowserHistoryEntry;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Parse Chrome/Chromium-based browser history
pub fn parse_chrome_history(db_path: &Path) -> Result<Vec<BrowserHistoryEntry>, String> {
    if !db_path.exists() {
        return Err(format!("History database not found: {:?}", db_path));
    }
    
    // Open database in read-only mode
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open database: {}", e))?;
    
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time 
         FROM urls 
         ORDER BY last_visit_time DESC 
         LIMIT 1000"
    ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
    
    let mut history = Vec::new();
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i32>(2)?,
            row.get::<_, i64>(3)?,
        ))
    }).map_err(|e| format!("Failed to query: {}", e))?;
    
    for row in rows {
        if let Ok((url, title, visit_count, last_visit_time)) = row {
            history.push(BrowserHistoryEntry {
                url,
                title,
                visit_count,
                last_visit_time: convert_chrome_timestamp(last_visit_time),
                browser: "Chrome".to_string(),
            });
        }
    }
    
    Ok(history)
}

/// Parse Firefox history
pub fn parse_firefox_history(db_path: &Path) -> Result<Vec<BrowserHistoryEntry>, String> {
    if !db_path.exists() {
        return Err(format!("History database not found: {:?}", db_path));
    }
    
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open database: {}", e))?;
    
    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_date 
         FROM moz_places 
         ORDER BY last_visit_date DESC 
         LIMIT 1000"
    ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
    
    let mut history = Vec::new();
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, i32>(2)?,
            row.get::<_, Option<i64>>(3)?,
        ))
    }).map_err(|e| format!("Failed to query: {}", e))?;
    
    for row in rows {
        if let Ok((url, title, visit_count, last_visit_date)) = row {
            history.push(BrowserHistoryEntry {
                url,
                title: title.unwrap_or_else(|| "Untitled".to_string()),
                visit_count,
                last_visit_time: convert_firefox_timestamp(last_visit_date),
                browser: "Firefox".to_string(),
            });
        }
    }
    
    Ok(history)
}

/// Parse Chrome downloads
pub fn parse_chrome_downloads(db_path: &Path) -> Result<Vec<ChromeDownload>, String> {
    if !db_path.exists() {
        return Err(format!("History database not found: {:?}", db_path));
    }
    
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open database: {}", e))?;
    
    let mut stmt = conn.prepare(
        "SELECT target_path, tab_url, start_time, received_bytes, total_bytes, state, danger_type 
         FROM downloads 
         ORDER BY start_time DESC 
         LIMIT 500"
    ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
    
    let mut downloads = Vec::new();
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i32>(5)?,
            row.get::<_, i32>(6)?,
        ))
    }).map_err(|e| format!("Failed to query: {}", e))?;
    
    for row in rows {
        if let Ok((target_path, tab_url, start_time, received_bytes, total_bytes, state, danger_type)) = row {
            downloads.push(ChromeDownload {
                target_path,
                source_url: tab_url,
                start_time: convert_chrome_timestamp(start_time),
                received_bytes: received_bytes as u64,
                total_bytes: total_bytes as u64,
                state,
                danger_type,
            });
        }
    }
    
    Ok(downloads)
}

/// Parse Chrome cookies
pub fn parse_chrome_cookies(db_path: &Path) -> Result<Vec<ChromeCookie>, String> {
    if !db_path.exists() {
        return Err(format!("Cookie database not found: {:?}", db_path));
    }
    
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open database: {}", e))?;
    
    let mut stmt = conn.prepare(
        "SELECT host_key, name, value, creation_utc, expires_utc, is_secure, is_httponly 
         FROM cookies 
         ORDER BY creation_utc DESC 
         LIMIT 1000"
    ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
    
    let mut cookies = Vec::new();
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i32>(5)?,
            row.get::<_, i32>(6)?,
        ))
    }).map_err(|e| format!("Failed to query: {}", e))?;
    
    for row in rows {
        if let Ok((host_key, name, value, creation_utc, expires_utc, is_secure, is_httponly)) = row {
            // Note: Cookies may be encrypted, value might not be readable
            let value_str = String::from_utf8(value.clone())
                .unwrap_or_else(|_| format!("[Encrypted {} bytes]", value.len()));
            
            cookies.push(ChromeCookie {
                host_key,
                name,
                value: value_str,
                creation_time: convert_chrome_timestamp(creation_utc),
                expiration_time: convert_chrome_timestamp(expires_utc),
                is_secure: is_secure != 0,
                is_httponly: is_httponly != 0,
            });
        }
    }
    
    Ok(cookies)
}

/// Convert Chrome timestamp (microseconds since 1601-01-01) to readable string
fn convert_chrome_timestamp(timestamp: i64) -> String {
    // Chrome uses Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    // We convert to Unix timestamp (seconds since 1970-01-01)
    
    const EPOCH_DIFF: i64 = 11644473600; // Seconds between 1601 and 1970
    
    if timestamp == 0 {
        return "Never".to_string();
    }
    
    let unix_seconds = (timestamp / 1_000_000) - EPOCH_DIFF;
    
    if let Some(datetime) = chrono::DateTime::from_timestamp(unix_seconds, 0) {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        format!("Invalid timestamp: {}", timestamp)
    }
}

/// Convert Firefox timestamp (microseconds since 1970-01-01) to readable string
fn convert_firefox_timestamp(timestamp: Option<i64>) -> String {
    match timestamp {
        Some(ts) if ts > 0 => {
            let unix_seconds = ts / 1_000_000;
            if let Some(datetime) = chrono::DateTime::from_timestamp(unix_seconds, 0) {
                datetime.format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                format!("Invalid timestamp: {}", ts)
            }
        }
        _ => "Never".to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct ChromeDownload {
    pub target_path: String,
    pub source_url: String,
    pub start_time: String,
    pub received_bytes: u64,
    pub total_bytes: u64,
    pub state: i32, // 0=in progress, 1=complete, 2=cancelled, etc.
    pub danger_type: i32, // 0=safe, 1=dangerous, etc.
}

#[derive(Debug, Clone)]
pub struct ChromeCookie {
    pub host_key: String,
    pub name: String,
    pub value: String, // May be encrypted
    pub creation_time: String,
    pub expiration_time: String,
    pub is_secure: bool,
    pub is_httponly: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chrome_timestamp_conversion() {
        // Test known timestamp
        let chrome_time = 13318932000000000i64; // 2022-11-01 00:00:00
        let result = convert_chrome_timestamp(chrome_time);
        assert!(result.contains("2022"));
    }
    
    #[test]
    fn test_zero_timestamp() {
        let result = convert_chrome_timestamp(0);
        assert_eq!(result, "Never");
    }
}
