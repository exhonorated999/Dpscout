use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use rusqlite::{Connection, OpenFlags};
use chrono::{DateTime, Utc, TimeZone};

/// iTunes backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItunesBackup {
    pub udid: String,
    pub device_name: String,
    pub backup_path: String,
    pub last_backup_date: String,
    pub ios_version: String,
    pub device_model: String,
    pub backup_size_mb: f64,
}

/// SMS/iMessage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosMessage {
    pub id: i64,
    pub address: String,
    pub text: String,
    pub date: String,
    pub is_from_me: bool,
    pub is_delivered: bool,
    pub is_read: bool,
    pub message_type: String, // "SMS" or "iMessage"
}

/// Find iTunes backup directory
pub fn get_itunes_backup_directory() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA")
            .map_err(|_| "APPDATA environment variable not found".to_string())?;
        
        let backup_dir = PathBuf::from(appdata)
            .join("Apple Computer")
            .join("MobileSync")
            .join("Backup");
        
        if backup_dir.exists() {
            Ok(backup_dir)
        } else {
            Err("iTunes backup directory not found. Make sure iTunes is installed and at least one backup has been created.".to_string())
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME")
            .map_err(|_| "HOME environment variable not found".to_string())?;
        
        let backup_dir = PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("MobileSync")
            .join("Backup");
        
        if backup_dir.exists() {
            Ok(backup_dir)
        } else {
            Err("iTunes backup directory not found".to_string())
        }
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Err("iTunes backups not supported on this platform".to_string())
    }
}

/// List all iTunes backups
pub fn list_itunes_backups() -> Result<Vec<ItunesBackup>, String> {
    let backup_dir = get_itunes_backup_directory()?;
    let mut backups = Vec::new();
    
    eprintln!("[iTunes Backup] Scanning directory: {:?}", backup_dir);
    
    let entries = fs::read_dir(&backup_dir)
        .map_err(|e| format!("Failed to read backup directory: {}", e))?;
    
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        
        // Each backup is in a folder named with the UDID
        let udid = match path.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => continue,
        };
        
        eprintln!("[iTunes Backup] Found backup: {}", udid);
        
        // Try to read Info.plist for metadata
        let info_plist = path.join("Info.plist");
        if !info_plist.exists() {
            eprintln!("[iTunes Backup] No Info.plist for {}", udid);
            continue;
        }
        
        // Parse Info.plist (simplified - just check it exists)
        let backup_size = calculate_backup_size(&path);
        
        backups.push(ItunesBackup {
            udid: udid.clone(),
            device_name: format!("iOS Device ({})", &udid[..8]),
            backup_path: path.to_string_lossy().to_string(),
            last_backup_date: get_backup_date(&path),
            ios_version: "Unknown".to_string(),
            device_model: "Unknown".to_string(),
            backup_size_mb: backup_size,
        });
    }
    
    eprintln!("[iTunes Backup] Found {} backups", backups.len());
    Ok(backups)
}

/// Calculate backup size in MB
fn calculate_backup_size(path: &Path) -> f64 {
    let mut total_size: u64 = 0;
    
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total_size += metadata.len();
                }
            }
        }
    }
    
    total_size as f64 / (1024.0 * 1024.0)
}

/// Get backup date
fn get_backup_date(path: &Path) -> String {
    let status_plist = path.join("Status.plist");
    if let Ok(metadata) = fs::metadata(&status_plist) {
        if let Ok(modified) = metadata.modified() {
            let datetime: DateTime<Utc> = modified.into();
            return datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        }
    }
    "Unknown".to_string()
}

/// Get backup information from Info.plist
pub fn get_backup_info(backup_path: &Path) -> Result<ItunesBackup, String> {
    // Resolve nested UDID directories from pymobiledevice3
    let backup_path = super::ios_backup_parser::resolve_backup_path(backup_path);
    let backup_path = backup_path.as_path();
    
    let info_plist = backup_path.join("Info.plist");
    
    if !info_plist.exists() {
        return Err(format!("Info.plist not found in backup: {:?}", backup_path));
    }
    
    // Extract UDID from path
    let udid = backup_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "Could not extract UDID from backup path".to_string())?
        .to_string();
    
    eprintln!("[iTunes Backup] Reading backup info for: {}", udid);
    
    // Calculate backup size
    let backup_size = calculate_backup_size(backup_path);
    let last_backup_date = get_backup_date(backup_path);
    
    // Try to parse Info.plist using plist crate if available
    // For now, just return basic info
    Ok(ItunesBackup {
        udid: udid.clone(),
        device_name: format!("Manually Selected Device"),
        backup_path: backup_path.to_string_lossy().to_string(),
        last_backup_date,
        ios_version: "Unknown".to_string(),
        device_model: "Unknown".to_string(),
        backup_size_mb: backup_size,
    })
}

/// Parse SMS/iMessages from iTunes backup
pub fn parse_sms_from_backup(backup_path: &Path) -> Result<Vec<IosMessage>, String> {
    let backup_path = super::ios_backup_parser::resolve_backup_path(backup_path);
    let backup_path = backup_path.as_path();
    eprintln!("[iTunes Backup] Parsing SMS from: {:?}", backup_path);
    
    // In iTunes backups, sms.db is hashed as: 3d0d7e5fb2ce288813306e4d4636395e047a3d28
    // This is the hash of: HomeDomain-Library/SMS/sms.db
    let sms_db_hash = "3d0d7e5fb2ce288813306e4d4636395e047a3d28";
    
    // SMS database is in a subfolder: 3d/0d7e5fb2ce288813306e4d4636395e047a3d28
    let sms_db_folder = &sms_db_hash[..2];
    let sms_db_path = backup_path
        .join(sms_db_folder)
        .join(sms_db_hash);
    
    if !sms_db_path.exists() {
        eprintln!("[iTunes Backup] SMS database not found at: {:?}", sms_db_path);
        return Ok(Vec::new()); // No SMS data in this backup
    }
    
    eprintln!("[iTunes Backup] Found SMS database: {:?}", sms_db_path);
    
    // Open SMS database
    let conn = Connection::open_with_flags(
        &sms_db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    ).map_err(|e| format!("Failed to open SMS database: {}", e))?;
    
    let mut messages = Vec::new();
    
    // Query messages
    let query = "
        SELECT 
            message.ROWID,
            COALESCE(handle.id, message.destination_caller_id) as address,
            COALESCE(message.text, message.subject, '') as text,
            message.date,
            message.is_from_me,
            message.is_delivered,
            message.is_read,
            message.service as message_type
        FROM message
        LEFT JOIN handle ON message.handle_id = handle.ROWID
        WHERE message.text IS NOT NULL OR message.subject IS NOT NULL
        ORDER BY message.date DESC
        LIMIT 5000
    ";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare SMS query: {}", e))?;
    
    let rows = stmt.query_map([], |row| {
        let id: i64 = row.get(0)?;
        let address: String = row.get(1)?;
        let text: String = row.get(2)?;
        let date: i64 = row.get(3)?;
        let is_from_me: i32 = row.get(4)?;
        let is_delivered: i32 = row.get(5)?;
        let is_read: i32 = row.get(6)?;
        let message_type: Option<String> = row.get(7)?;
        
        // Convert Apple's Core Data timestamp (seconds since 2001-01-01) to UTC
        let apple_epoch = Utc.with_ymd_and_hms(2001, 1, 1, 0, 0, 0).unwrap().timestamp();
        let timestamp = apple_epoch + date;
        let datetime = Utc.timestamp_opt(timestamp, 0).unwrap();
        let date_str = datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        
        Ok(IosMessage {
            id,
            address,
            text,
            date: date_str,
            is_from_me: is_from_me != 0,
            is_delivered: is_delivered != 0,
            is_read: is_read != 0,
            message_type: message_type.unwrap_or_else(|| "SMS".to_string()),
        })
    }).map_err(|e| format!("Failed to execute SMS query: {}", e))?;
    
    for row in rows {
        if let Ok(message) = row {
            messages.push(message);
        }
    }
    
    eprintln!("[iTunes Backup] Found {} messages", messages.len());
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_backup_directory() {
        // Should not panic
        let _result = get_itunes_backup_directory();
    }
}
