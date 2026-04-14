use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use rusqlite::{Connection, Result as SqliteResult};
use chrono::{DateTime, Utc};

/// iOS Device information from iTunes backup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosDevice {
    pub udid: String,
    pub device_name: String,
    pub device_model: String,
    pub product_type: String,
    pub ios_version: String,
    pub serial_number: String,
    pub phone_number: Option<String>,
    pub imei: Option<String>,
    pub last_backup_date: String,
    pub backup_path: String,
}

/// iOS Application information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosApp {
    pub bundle_id: String,
    pub app_name: String,
    pub version: String,
    pub bundle_version: String,
    pub is_system_app: bool,
}

/// SMS/iMessage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosMessage {
    pub message_id: i64,
    pub chat_id: i64,
    pub sender: String,
    pub message_text: String,
    pub date: String,
    pub is_from_me: bool,
    pub service: String, // "SMS" or "iMessage"
}

/// Contact entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosContact {
    pub record_id: i32,
    pub first_name: String,
    pub last_name: String,
    pub phone_numbers: Vec<String>,
    pub emails: Vec<String>,
}

/// Call log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosCall {
    pub call_id: i64,
    pub phone_number: String,
    pub date: String,
    pub duration: i32,
    pub call_type: String, // "Incoming", "Outgoing", "Missed"
}

/// Safari history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosBrowserHistory {
    pub url: String,
    pub title: String,
    pub visit_count: i32,
    pub last_visit: String,
}

/// Photo/Video metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosMedia {
    pub filename: String,
    pub file_path: String,
    pub creation_date: String,
    pub modification_date: String,
    pub file_size: u64,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// WhatsApp message (from backup)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosWhatsAppMessage {
    pub message_id: i64,
    pub chat_id: String,
    pub sender: String,
    pub message_text: String,
    pub timestamp: String,
    pub is_from_me: bool,
}

/// Complete iOS backup data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosBackupData {
    pub device: IosDevice,
    pub apps: Vec<IosApp>,
    pub messages: Vec<IosMessage>,
    pub contacts: Vec<IosContact>,
    pub calls: Vec<IosCall>,
    pub browser_history: Vec<IosBrowserHistory>,
    pub media_files: Vec<IosMedia>,
}

/// Check if iTunes/Apple Devices is installed
pub fn check_itunes_available() -> Result<bool, String> {
    // Check for Apple Mobile Device Support (installed with iTunes)
    let program_files = std::env::var("ProgramFiles").unwrap_or_default();
    let itunes_path = Path::new(&program_files).join("Common Files\\Apple\\Mobile Device Support");
    
    if itunes_path.exists() {
        return Ok(true);
    }
    
    // Also check Program Files (x86)
    let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
    let itunes_path_x86 = Path::new(&program_files_x86).join("Common Files\\Apple\\Mobile Device Support");
    
    Ok(itunes_path_x86.exists())
}

/// Get default iTunes backup directory
pub fn get_backup_directory() -> PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    Path::new(&appdata).join("Apple Computer\\MobileSync\\Backup")
}

/// List all available iOS backups
pub fn list_ios_backups() -> Result<Vec<IosDevice>, String> {
    let backup_dir = get_backup_directory();
    
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }
    
    let mut devices = Vec::new();
    
    // Iterate through backup directories
    let entries = fs::read_dir(&backup_dir)
        .map_err(|e| format!("Failed to read backup directory: {}", e))?;
    
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            if let Some(device) = parse_backup_info(&path) {
                devices.push(device);
            }
        }
    }
    
    Ok(devices)
}

/// Parse Info.plist from backup to get device information
fn parse_backup_info(backup_path: &Path) -> Option<IosDevice> {
    let info_plist = backup_path.join("Info.plist");
    
    if !info_plist.exists() {
        return None;
    }
    
    // Read the plist file
    let content = fs::read(&info_plist).ok()?;
    
    // Parse plist (simplified - in production use plist crate)
    let info = parse_plist_simple(&content)?;
    
    let udid = backup_path.file_name()?.to_string_lossy().to_string();
    
    Some(IosDevice {
        udid: udid.clone(),
        device_name: info.get("Device Name").cloned().unwrap_or_else(|| "Unknown".to_string()),
        device_model: info.get("Product Name").cloned().unwrap_or_else(|| "iPhone".to_string()),
        product_type: info.get("Product Type").cloned().unwrap_or_else(|| "Unknown".to_string()),
        ios_version: info.get("Product Version").cloned().unwrap_or_else(|| "Unknown".to_string()),
        serial_number: info.get("Serial Number").cloned().unwrap_or_else(|| "Unknown".to_string()),
        phone_number: info.get("Phone Number").cloned(),
        imei: info.get("IMEI").cloned(),
        last_backup_date: info.get("Last Backup Date").cloned().unwrap_or_else(|| "Unknown".to_string()),
        backup_path: backup_path.to_string_lossy().to_string(),
    })
}

/// Simple plist parser (for demonstration - should use plist crate in production)
fn parse_plist_simple(content: &[u8]) -> Option<HashMap<String, String>> {
    let text = String::from_utf8_lossy(content);
    let mut map = HashMap::new();
    
    // Very basic XML parsing - extract key-value pairs
    let keys_to_extract = vec![
        "Device Name",
        "Product Name",
        "Product Type",
        "Product Version",
        "Serial Number",
        "Phone Number",
        "IMEI",
        "Last Backup Date",
    ];
    
    for key in keys_to_extract {
        if let Some(value) = extract_plist_value(&text, key) {
            map.insert(key.to_string(), value);
        }
    }
    
    Some(map)
}

/// Extract a value from plist XML
fn extract_plist_value(text: &str, key: &str) -> Option<String> {
    let key_tag = format!("<key>{}</key>", key);
    if let Some(pos) = text.find(&key_tag) {
        let after_key = &text[pos + key_tag.len()..];
        
        // Look for <string>, <integer>, or <date> tag
        if let Some(string_start) = after_key.find("<string>") {
            let value_start = string_start + 8;
            if let Some(string_end) = after_key[value_start..].find("</string>") {
                return Some(after_key[value_start..value_start + string_end].to_string());
            }
        }
        
        if let Some(integer_start) = after_key.find("<integer>") {
            let value_start = integer_start + 9;
            if let Some(integer_end) = after_key[value_start..].find("</integer>") {
                return Some(after_key[value_start..value_start + integer_end].to_string());
            }
        }
        
        if let Some(date_start) = after_key.find("<date>") {
            let value_start = date_start + 6;
            if let Some(date_end) = after_key[value_start..].find("</date>") {
                return Some(after_key[value_start..value_start + date_end].to_string());
            }
        }
    }
    None
}

/// Get installed apps from backup
pub fn get_installed_apps(backup_path: &str) -> Result<Vec<IosApp>, String> {
    let manifest_db = find_file_in_backup(backup_path, "Manifest.db")?;
    
    if !manifest_db.exists() {
        return Err("Manifest.db not found in backup".to_string());
    }
    
    let conn = Connection::open(&manifest_db)
        .map_err(|e| format!("Failed to open Manifest database: {}", e))?;
    
    // Query for app directories which typically contain the bundle identifier
    let mut stmt = conn.prepare("
        SELECT DISTINCT 
            domain,
            relativePath
        FROM Files
        WHERE domain LIKE 'AppDomain%' OR domain LIKE 'AppDomainGroup%'
        GROUP BY domain
        LIMIT 200
    ").map_err(|e| format!("Failed to prepare apps query: {}", e))?;
    
    let app_iter = stmt.query_map([], |row| {
        let domain: String = row.get(0)?;
        
        // Extract bundle ID from domain (e.g., "AppDomain-com.facebook.Facebook")
        let bundle_id = if let Some(pos) = domain.find('-') {
            domain[pos+1..].to_string()
        } else {
            domain.clone()
        };
        
        // Extract app name from bundle ID (last component)
        let bundle_id_ref = bundle_id.as_str();
        let app_name = bundle_id
            .split('.')
            .last()
            .unwrap_or(&bundle_id_ref)
            .to_string();
        
        Ok(IosApp {
            bundle_id: bundle_id.clone(),
            app_name,
            version: "Unknown".to_string(),
            bundle_version: "Unknown".to_string(),
            is_system_app: domain.starts_with("SysSharedContainer") || domain.starts_with("SystemPreferences"),
        })
    }).map_err(|e| format!("Failed to execute apps query: {}", e))?;
    
    let mut apps = Vec::new();
    for app in app_iter {
        if let Ok(a) = app {
            apps.push(a);
        }
    }
    
    // Remove duplicates by bundle_id
    apps.sort_by(|a, b| a.bundle_id.cmp(&b.bundle_id));
    apps.dedup_by(|a, b| a.bundle_id == b.bundle_id);
    
    eprintln!("Found {} apps in backup", apps.len());
    Ok(apps)
}

/// Extract SMS/iMessage database
pub fn get_messages(backup_path: &str) -> Result<Vec<IosMessage>, String> {
    // The SMS database is at a specific hash in the backup
    // Hash for HomeDomain/Library/SMS/sms.db: 3d0d7e5fb2ce288813306e4d4636395e047a3d28
    let sms_db = find_file_by_hash(backup_path, "3d0d7e5fb2ce288813306e4d4636395e047a3d28")?;
    
    if !sms_db.exists() {
        return Err("SMS database not found in backup".to_string());
    }
    
    // Parse SQLite database
    parse_sms_database(&sms_db)
}

/// Extract contacts from backup
pub fn get_contacts(backup_path: &str) -> Result<Vec<IosContact>, String> {
    // AddressBook.sqlitedb hash: 31bb7ba8914766d4ba40d6dfb6113c8b614be442
    let contacts_db = find_file_by_hash(backup_path, "31bb7ba8914766d4ba40d6dfb6113c8b614be442")?;
    
    if !contacts_db.exists() {
        return Err("Contacts database not found in backup".to_string());
    }
    
    parse_contacts_database(&contacts_db)
}

/// Extract call history
pub fn get_call_history(backup_path: &str) -> Result<Vec<IosCall>, String> {
    // CallHistory.storedata hash: 2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca
    let calls_db = find_file_by_hash(backup_path, "2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca")?;
    
    if !calls_db.exists() {
        return Err("Call history database not found in backup".to_string());
    }
    
    parse_call_history_database(&calls_db)
}

/// Extract Safari browser history
pub fn get_browser_history(backup_path: &str) -> Result<Vec<IosBrowserHistory>, String> {
    // History.db hash: 5e0da3ef69e20fd3d22c2cd37a7d73e38d78a3c1
    let history_db = find_file_by_hash(backup_path, "5e0da3ef69e20fd3d22c2cd37a7d73e38d78a3c1")?;
    
    if !history_db.exists() {
        return Err("Safari history database not found in backup".to_string());
    }
    
    parse_safari_history(&history_db)
}

/// Extract photos and videos metadata
pub fn get_media_files(backup_path: &str) -> Result<Vec<IosMedia>, String> {
    let manifest_db = find_file_in_backup(backup_path, "Manifest.db")?;
    
    // Parse Manifest.db to find media files
    parse_media_from_manifest(&manifest_db)
}

/// Find a file in backup by hash (iOS backup structure)
fn find_file_by_hash(backup_path: &str, hash: &str) -> Result<PathBuf, String> {
    let backup_dir = Path::new(backup_path);
    
    // iOS backups store files by hash in subdirectories
    // Format: backupdir/ab/abcdef1234567890...
    let subdir = &hash[0..2];
    let file_path = backup_dir.join(subdir).join(hash);
    
    Ok(file_path)
}

/// Find a file in backup by name
fn find_file_in_backup(backup_path: &str, filename: &str) -> Result<PathBuf, String> {
    let backup_dir = Path::new(backup_path);
    let file = backup_dir.join(filename);
    
    Ok(file)
}

/// Parse SMS database (sms.db)
fn parse_sms_database(db_path: &Path) -> Result<Vec<IosMessage>, String> {
    if !db_path.exists() {
        return Err(format!("SMS database not found at: {}", db_path.display()));
    }

    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open SMS database: {}", e))?;
    
    // Query to get messages with sender information
    let mut stmt = conn.prepare("
        SELECT 
            message.ROWID,
            COALESCE(chat.ROWID, 0) as chat_id,
            COALESCE(handle.id, 'Unknown') as sender,
            COALESCE(message.text, '') as text,
            message.date,
            message.is_from_me,
            COALESCE(message.service, 'Unknown') as service
        FROM message
        LEFT JOIN handle ON message.handle_id = handle.ROWID
        LEFT JOIN chat_message_join ON message.ROWID = chat_message_join.message_id
        LEFT JOIN chat ON chat_message_join.chat_id = chat.ROWID
        ORDER BY message.date DESC
        LIMIT 5000
    ").map_err(|e| format!("Failed to prepare SMS query: {}", e))?;
    
    let message_iter = stmt.query_map([], |row| {
        let date_raw: f64 = row.get(4)?;
        Ok(IosMessage {
            message_id: row.get(0)?,
            chat_id: row.get(1)?,
            sender: row.get(2)?,
            message_text: row.get(3)?,
            date: convert_apple_timestamp(date_raw),
            is_from_me: row.get::<_, i32>(5)? == 1,
            service: row.get(6)?,
        })
    }).map_err(|e| format!("Failed to execute SMS query: {}", e))?;
    
    let mut messages = Vec::new();
    for message in message_iter {
        if let Ok(msg) = message {
            messages.push(msg);
        }
    }
    
    eprintln!("Extracted {} SMS/iMessage entries", messages.len());
    Ok(messages)
}

/// Convert Apple Core Data timestamp to readable date string
/// Apple timestamps are seconds since 2001-01-01 00:00:00 UTC
fn convert_apple_timestamp(timestamp: f64) -> String {
    // Add Apple epoch offset (978307200 = seconds from Unix epoch to 2001-01-01)
    let unix_timestamp = timestamp + 978307200.0;
    
    match DateTime::from_timestamp(unix_timestamp as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("Invalid timestamp: {}", timestamp),
    }
}

/// Parse contacts database
fn parse_contacts_database(db_path: &Path) -> Result<Vec<IosContact>, String> {
    if !db_path.exists() {
        return Err(format!("Contacts database not found at: {}", db_path.display()));
    }

    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open contacts database: {}", e))?;
    
    // First, get all persons
    let mut stmt = conn.prepare("
        SELECT 
            ROWID,
            COALESCE(First, '') as first_name,
            COALESCE(Last, '') as last_name
        FROM ABPerson
        ORDER BY Last, First
    ").map_err(|e| format!("Failed to prepare contacts query: {}", e))?;
    
    let person_iter = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    }).map_err(|e| format!("Failed to execute contacts query: {}", e))?;
    
    let mut contacts = Vec::new();
    
    for person in person_iter {
        if let Ok((record_id, first_name, last_name)) = person {
            // Get phone numbers for this person
            let mut phone_stmt = conn.prepare("
                SELECT value 
                FROM ABMultiValue 
                WHERE record_id = ?1 AND property = 3
            ").map_err(|e| format!("Failed to prepare phone query: {}", e))?;
            
            let phone_iter = phone_stmt.query_map([record_id], |row| {
                row.get::<_, String>(0)
            }).map_err(|e| format!("Failed to execute phone query: {}", e))?;
            
            let mut phone_numbers = Vec::new();
            for phone in phone_iter {
                if let Ok(p) = phone {
                    phone_numbers.push(p);
                }
            }
            
            // Get emails for this person
            let mut email_stmt = conn.prepare("
                SELECT value 
                FROM ABMultiValue 
                WHERE record_id = ?1 AND property = 4
            ").map_err(|e| format!("Failed to prepare email query: {}", e))?;
            
            let email_iter = email_stmt.query_map([record_id], |row| {
                row.get::<_, String>(0)
            }).map_err(|e| format!("Failed to execute email query: {}", e))?;
            
            let mut emails = Vec::new();
            for email in email_iter {
                if let Ok(e) = email {
                    emails.push(e);
                }
            }
            
            contacts.push(IosContact {
                record_id,
                first_name,
                last_name,
                phone_numbers,
                emails,
            });
        }
    }
    
    eprintln!("Extracted {} contacts", contacts.len());
    Ok(contacts)
}

/// Parse call history database
fn parse_call_history_database(db_path: &Path) -> Result<Vec<IosCall>, String> {
    if !db_path.exists() {
        return Err(format!("Call history database not found at: {}", db_path.display()));
    }

    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open call history database: {}", e))?;
    
    // Query call records (table structure varies by iOS version)
    let mut stmt = conn.prepare("
        SELECT 
            Z_PK,
            COALESCE(ZADDRESS, '') as phone_number,
            COALESCE(ZDATE, 0) as date,
            COALESCE(ZDURATION, 0) as duration,
            COALESCE(ZCALLTYPE, 0) as call_type
        FROM ZCALLRECORD
        ORDER BY ZDATE DESC
        LIMIT 1000
    ").map_err(|e| format!("Failed to prepare call history query: {}", e))?;
    
    let call_iter = stmt.query_map([], |row| {
        let call_type_int: i32 = row.get(4)?;
        let call_type = match call_type_int {
            1 => "Incoming",
            2 => "Outgoing",
            3 => "Missed",
            _ => "Unknown",
        };
        
        let date_raw: f64 = row.get(2)?;
        
        Ok(IosCall {
            call_id: row.get(0)?,
            phone_number: row.get(1)?,
            date: convert_apple_timestamp(date_raw),
            duration: row.get(3)?,
            call_type: call_type.to_string(),
        })
    }).map_err(|e| format!("Failed to execute call history query: {}", e))?;
    
    let mut calls = Vec::new();
    for call in call_iter {
        if let Ok(c) = call {
            calls.push(c);
        }
    }
    
    eprintln!("Extracted {} call history entries", calls.len());
    Ok(calls)
}

/// Parse Safari history
fn parse_safari_history(db_path: &Path) -> Result<Vec<IosBrowserHistory>, String> {
    if !db_path.exists() {
        return Err(format!("Safari history database not found at: {}", db_path.display()));
    }

    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open Safari history database: {}", e))?;
    
    // Query history items with visit information
    let mut stmt = conn.prepare("
        SELECT 
            hi.id,
            COALESCE(hi.url, '') as url,
            COALESCE(hv.title, hi.url) as title,
            COALESCE(hi.visit_count, 0) as visit_count,
            MAX(COALESCE(hv.visit_time, 0)) as last_visit
        FROM history_items hi
        LEFT JOIN history_visits hv ON hi.id = hv.history_item
        GROUP BY hi.id
        ORDER BY last_visit DESC
        LIMIT 1000
    ").map_err(|e| format!("Failed to prepare Safari history query: {}", e))?;
    
    let history_iter = stmt.query_map([], |row| {
        let visit_time: f64 = row.get(4)?;
        
        Ok(IosBrowserHistory {
            url: row.get(1)?,
            title: row.get(2)?,
            visit_count: row.get(3)?,
            last_visit: convert_apple_timestamp(visit_time),
        })
    }).map_err(|e| format!("Failed to execute Safari history query: {}", e))?;
    
    let mut history = Vec::new();
    for entry in history_iter {
        if let Ok(h) = entry {
            // Filter out empty URLs
            if !h.url.is_empty() {
                history.push(h);
            }
        }
    }
    
    eprintln!("Extracted {} Safari history entries", history.len());
    Ok(history)
}

/// Parse media files from manifest
fn parse_media_from_manifest(manifest_path: &Path) -> Result<Vec<IosMedia>, String> {
    if !manifest_path.exists() {
        return Err(format!("Manifest database not found at: {}", manifest_path.display()));
    }

    let conn = Connection::open(manifest_path)
        .map_err(|e| format!("Failed to open Manifest database: {}", e))?;
    
    // Query for media files (photos and videos)
    let mut stmt = conn.prepare("
        SELECT 
            fileID,
            domain,
            relativePath,
            file
        FROM Files
        WHERE (
            relativePath LIKE '%.jpg' OR 
            relativePath LIKE '%.jpeg' OR 
            relativePath LIKE '%.png' OR 
            relativePath LIKE '%.heic' OR 
            relativePath LIKE '%.mp4' OR 
            relativePath LIKE '%.mov' OR
            relativePath LIKE '%.m4v'
        )
        AND domain LIKE '%Camera%'
        LIMIT 500
    ").map_err(|e| format!("Failed to prepare media query: {}", e))?;
    
    let media_iter = stmt.query_map([], |row| {
        let file_id: String = row.get(0)?;
        let relative_path: String = row.get(2)?;
        
        // Extract filename from path
        let relative_path_ref = relative_path.as_str();
        let filename = Path::new(&relative_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&relative_path_ref)
            .to_string();
        
        Ok(IosMedia {
            filename,
            file_path: relative_path,
            creation_date: "Unknown".to_string(),
            modification_date: "Unknown".to_string(),
            file_size: 0,
            latitude: None,
            longitude: None,
        })
    }).map_err(|e| format!("Failed to execute media query: {}", e))?;
    
    let mut media_files = Vec::new();
    for media in media_iter {
        if let Ok(m) = media {
            media_files.push(m);
        }
    }
    
    eprintln!("Found {} media files in manifest", media_files.len());
    Ok(media_files)
}

/// Extract WhatsApp messages if available
pub fn get_whatsapp_messages(backup_path: &str) -> Result<Vec<IosWhatsAppMessage>, String> {
    // WhatsApp ChatStorage.sqlite location in backup
    // Hash: 7c7fba66680ef796b916b067077cc246adacf01d
    let whatsapp_db = find_file_by_hash(backup_path, "7c7fba66680ef796b916b067077cc246adacf01d")?;
    
    if !whatsapp_db.exists() {
        return Err("WhatsApp database not found in backup".to_string());
    }
    
    parse_whatsapp_database(&whatsapp_db)
}

/// Parse WhatsApp ChatStorage.sqlite
fn parse_whatsapp_database(db_path: &Path) -> Result<Vec<IosWhatsAppMessage>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open WhatsApp database: {}", e))?;
    
    // Query WhatsApp messages (table structure may vary by version)
    let mut stmt = conn.prepare("
        SELECT 
            Z_PK,
            COALESCE(ZCHATSESSION, '') as chat_id,
            COALESCE(ZFROMJID, '') as sender,
            COALESCE(ZTEXT, '') as text,
            COALESCE(ZMESSAGEDATE, 0) as date,
            COALESCE(ZISFROMME, 0) as is_from_me
        FROM ZWAMESSAGE
        ORDER BY ZMESSAGEDATE DESC
        LIMIT 1000
    ").map_err(|e| format!("Failed to prepare WhatsApp query: {}", e))?;
    
    let message_iter = stmt.query_map([], |row| {
        let date_raw: f64 = row.get(4)?;
        
        Ok(IosWhatsAppMessage {
            message_id: row.get(0)?,
            chat_id: row.get(1)?,
            sender: row.get(2)?,
            message_text: row.get(3)?,
            timestamp: convert_apple_timestamp(date_raw),
            is_from_me: row.get::<_, i32>(5)? == 1,
        })
    }).map_err(|e| format!("Failed to execute WhatsApp query: {}", e))?;
    
    let mut messages = Vec::new();
    for message in message_iter {
        if let Ok(msg) = message {
            messages.push(msg);
        }
    }
    
    eprintln!("Extracted {} WhatsApp messages", messages.len());
    Ok(messages)
}

/// Get all data from a backup (comprehensive extraction)
pub fn extract_all_data(backup_path: &str) -> Result<IosBackupData, String> {
    let devices = list_ios_backups()?;
    let device = devices.iter()
        .find(|d| d.backup_path == backup_path)
        .ok_or("Device not found")?
        .clone();
    
    let apps = get_installed_apps(backup_path).unwrap_or_default();
    let messages = get_messages(backup_path).unwrap_or_default();
    let contacts = get_contacts(backup_path).unwrap_or_default();
    let calls = get_call_history(backup_path).unwrap_or_default();
    let browser_history = get_browser_history(backup_path).unwrap_or_default();
    let media_files = get_media_files(backup_path).unwrap_or_default();
    
    Ok(IosBackupData {
        device,
        apps,
        messages,
        contacts,
        calls,
        browser_history,
        media_files,
    })
}

/// List critical iOS artifact file hashes for forensic investigation
pub fn get_critical_artifact_hashes() -> HashMap<&'static str, &'static str> {
    let mut hashes = HashMap::new();
    
    // SMS/iMessage
    hashes.insert("SMS Database", "3d0d7e5fb2ce288813306e4d4636395e047a3d28");
    
    // Contacts
    hashes.insert("AddressBook", "31bb7ba8914766d4ba40d6dfb6113c8b614be442");
    
    // Call History
    hashes.insert("Call History", "2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca");
    
    // Safari History
    hashes.insert("Safari History", "5e0da3ef69e20fd3d22c2cd37a7d73e38d78a3c1");
    
    // Safari Bookmarks
    hashes.insert("Safari Bookmarks", "0dfe50a0a1a8e5e5ba2e1b5e8b8f6e7b8e5e5ba2");
    
    // Calendar
    hashes.insert("Calendar", "2041457d5fe04d39d0ab481178355df6781e6858");
    
    // Notes
    hashes.insert("Notes", "ca3bc056d4da0bbf88b5fb3be254f3b7147e639c");
    
    // Photos Library
    hashes.insert("Photos Database", "12b144c0bd44f2b3dffd9186d3f9c05b917cee25");
    
    // WhatsApp
    hashes.insert("WhatsApp Messages", "7c7fba66680ef796b916b067077cc246adacf01d");
    
    // Telegram
    hashes.insert("Telegram Cache", "2dfc1b53b655d67c33e1b33d9c36f8ad99dc1c0c");
    
    hashes
}
