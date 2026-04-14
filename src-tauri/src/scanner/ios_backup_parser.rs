use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;
use rusqlite::{Connection, Result as SqliteResult};
use chrono::DateTime;

/// iOS backup file entry from Manifest.db
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupFileEntry {
    pub file_id: String,      // SHA1 hash used as filename
    pub domain: String,        // e.g., "HomeDomain", "CameraRollDomain"
    pub relative_path: String, // Path within domain
    pub flags: i32,
    pub file_size: Option<i64>,
}

/// Safari history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafariHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i32,
    pub last_visit_time: String,
}

/// Chrome history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChromeHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_count: i32,
    pub last_visit_time: String,
}

/// Media file from iOS backup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupMediaFile {
    pub filename: String,
    pub file_path: String,  // Original path on device
    pub backup_file_id: String,  // Hash in backup
    pub file_size: i64,
    pub domain: String,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
}

/// Open Manifest.db and list all files in backup
pub fn list_backup_files(backup_path: &Path) -> Result<Vec<BackupFileEntry>, String> {
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return Err(format!("Manifest.db not found in backup: {:?}", backup_path));
    }
    
    eprintln!("[iOS Backup Parser] Opening Manifest.db: {:?}", manifest_db);
    
    let conn = Connection::open(&manifest_db)
        .map_err(|e| format!("Failed to open Manifest.db: {}", e))?;
    
    // Query all files
    let mut stmt = conn.prepare("
        SELECT 
            fileID,
            domain,
            relativePath,
            flags,
            file
        FROM Files
        ORDER BY domain, relativePath
    ").map_err(|e| format!("Failed to prepare file list query: {}", e))?;
    
    let file_iter = stmt.query_map([], |row| {
        let file_id_blob: Vec<u8> = row.get(0)?;
        let file_id = hex::encode(file_id_blob);
        
        // Try to get file blob (contains metadata)
        let file_size = row.get::<_, Option<Vec<u8>>>(4).ok()
            .and_then(|blob| {
                // File blob is a plist, would need proper parsing
                // For now, just return None
                None
            });
        
        Ok(BackupFileEntry {
            file_id,
            domain: row.get(1)?,
            relative_path: row.get(2)?,
            flags: row.get(3)?,
            file_size,
        })
    }).map_err(|e| format!("Failed to query files: {}", e))?;
    
    let mut files = Vec::new();
    for file in file_iter {
        if let Ok(f) = file {
            files.push(f);
        }
    }
    
    eprintln!("[iOS Backup Parser] Found {} files in backup", files.len());
    Ok(files)
}

/// Extract a specific file from backup by its hash
pub fn extract_file_from_backup(
    backup_path: &Path,
    file_id: &str,
    output_path: &Path
) -> Result<(), String> {
    // Try standard iTunes backup layout: <first2chars>/<file_id>
    let subdir = &file_id[0..2];
    let source_file = backup_path.join(subdir).join(file_id);
    
    if source_file.exists() {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create output directory: {}", e))?;
        }
        fs::copy(&source_file, output_path)
            .map_err(|e| format!("Failed to extract file: {}", e))?;
        return Ok(());
    }
    
    Err(format!("Backup file not found: {}", file_id))
}

/// Extract a file from a decrypted backup using domain and relative path.
/// Decrypted backups store files at: <backup_path>/files/<domain>/<relativePath>
pub fn extract_file_from_decrypted_backup(
    backup_path: &Path,
    domain: &str,
    relative_path: &str,
    output_path: &Path,
) -> Result<(), String> {
    let files_dir = backup_path.join("files");
    let source_file = files_dir.join(domain).join(relative_path);
    
    if source_file.exists() {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create output directory: {}", e))?;
        }
        fs::copy(&source_file, output_path)
            .map_err(|e| format!("Failed to extract file: {}", e))?;
        return Ok(());
    }
    
    Err(format!("Decrypted file not found: {}/{}", domain, relative_path))
}

/// Resolve the actual backup path by checking for a valid (non-empty) Manifest.db.
/// pymobiledevice3 creates a UDID subfolder inside the backup_directory, so the path
/// may be one level too shallow. This function checks the given path first, then
/// tries immediate subdirectories.
pub fn resolve_backup_path(backup_path: &Path) -> PathBuf {
    let manifest = backup_path.join("Manifest.db");
    if manifest.exists() {
        if let Ok(meta) = fs::metadata(&manifest) {
            if meta.len() > 0 {
                return backup_path.to_path_buf();
            }
        }
    }

    // Check one-level-deep subdirectories (common: UDID nested inside UDID)
    if let Ok(entries) = fs::read_dir(backup_path) {
        for entry in entries.filter_map(Result::ok) {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let sub = entry.path();
                let sub_manifest = sub.join("Manifest.db");
                if sub_manifest.exists() {
                    if let Ok(meta) = fs::metadata(&sub_manifest) {
                        if meta.len() > 0 {
                            eprintln!("[iOS Backup Parser] Resolved nested backup path: {:?}", sub);
                            return sub;
                        }
                    }
                }
            }
        }
    }

    // Fallback: return as-is
    backup_path.to_path_buf()
}

/// Find file ID for a specific path in backup
pub fn find_file_by_path(
    backup_path: &Path,
    domain: &str,
    relative_path: &str
) -> Result<Option<String>, String> {
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return Err(format!("Manifest.db not found"));
    }
    
    let conn = Connection::open(&manifest_db)
        .map_err(|e| format!("Failed to open Manifest.db: {}", e))?;
    
    let mut stmt = conn.prepare("
        SELECT fileID
        FROM Files
        WHERE domain = ?1 AND relativePath = ?2
        LIMIT 1
    ").map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let file_id = stmt.query_row([domain, relative_path], |row| {
        let file_id_blob: Vec<u8> = row.get(0)?;
        Ok(hex::encode(file_id_blob))
    }).ok();
    
    Ok(file_id)
}

/// Extract Safari history from backup
pub fn extract_safari_history(backup_path: &Path) -> Result<Vec<SafariHistoryEntry>, String> {
    eprintln!("[iOS Backup Parser] Extracting Safari history...");
    
    let domain = "HomeDomain";
    let relative_path = "Library/Safari/History.db";
    let temp_dir = std::env::temp_dir();
    let temp_db = temp_dir.join("safari_history_extract.db");
    
    // Try decrypted backup layout first (files/<domain>/<path>)
    if extract_file_from_decrypted_backup(backup_path, domain, relative_path, &temp_db).is_ok() {
        eprintln!("[iOS Backup Parser] Found Safari History.db in decrypted backup");
        let history = parse_safari_history_db(&temp_db)?;
        let _ = fs::remove_file(&temp_db);
        eprintln!("[iOS Backup Parser] Found {} Safari history entries", history.len());
        return Ok(history);
    }
    
    // Fall back to standard encrypted backup layout (hash-based)
    let history_file_id = find_file_by_path(backup_path, domain, relative_path)?;
    
    let file_id = match history_file_id {
        Some(id) => id,
        None => {
            eprintln!("[iOS Backup Parser] Safari History.db not found in backup");
            return Ok(Vec::new());
        }
    };
    
    let temp_db = temp_dir.join(format!("safari_history_{}.db", file_id));
    extract_file_from_backup(backup_path, &file_id, &temp_db)?;
    let history = parse_safari_history_db(&temp_db)?;
    let _ = fs::remove_file(temp_db);
    
    eprintln!("[iOS Backup Parser] Found {} Safari history entries", history.len());
    Ok(history)
}

/// Parse Safari History.db
fn parse_safari_history_db(db_path: &Path) -> Result<Vec<SafariHistoryEntry>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open Safari history database: {}", e))?;
    
    // Safari history table structure
    let mut stmt = conn.prepare("
        SELECT 
            url,
            COALESCE(title, '') as title,
            visit_count,
            visit_time
        FROM history_items
        ORDER BY visit_time DESC
        LIMIT 1000
    ").map_err(|e| format!("Failed to prepare Safari history query: {}", e))?;
    
    let history_iter = stmt.query_map([], |row| {
        let visit_time: f64 = row.get(3).unwrap_or(0.0);
        
        Ok(SafariHistoryEntry {
            url: row.get(0)?,
            title: row.get(1)?,
            visit_count: row.get(2)?,
            last_visit_time: convert_cocoa_timestamp(visit_time),
        })
    }).map_err(|e| format!("Failed to query Safari history: {}", e))?;
    
    let mut history = Vec::new();
    for entry in history_iter {
        if let Ok(h) = entry {
            history.push(h);
        }
    }
    
    Ok(history)
}

/// Extract Chrome history from backup
pub fn extract_chrome_history(backup_path: &Path) -> Result<Vec<ChromeHistoryEntry>, String> {
    eprintln!("[iOS Backup Parser] Extracting Chrome history...");
    
    let manifest_db = backup_path.join("Manifest.db");
    let conn = Connection::open(&manifest_db)
        .map_err(|e| format!("Failed to open Manifest.db: {}", e))?;
    
    // Find Chrome history file
    let mut stmt = conn.prepare("
        SELECT fileID, domain, relativePath
        FROM Files
        WHERE domain LIKE '%com.google.chrome%' 
        AND relativePath LIKE '%History'
        LIMIT 10
    ").map_err(|e| format!("Failed to prepare Chrome query: {}", e))?;
    
    let file_iter = stmt.query_map([], |row| {
        let file_id_blob: Vec<u8> = row.get(0)?;
        let file_id = hex::encode(file_id_blob);
        let domain: String = row.get(1)?;
        let relative_path: String = row.get(2)?;
        Ok((file_id, domain, relative_path))
    }).ok();
    
    let mut all_history = Vec::new();
    
    if let Some(iter) = file_iter {
        for result in iter {
            if let Ok((file_id, domain, path)) = result {
                eprintln!("[iOS Backup Parser] Found Chrome history: {}", path);
                
                let temp_dir = std::env::temp_dir();
                let temp_db = temp_dir.join(format!("chrome_history_{}.db", &file_id[0..8]));
                
                // Try decrypted layout first, then hash-based layout
                let extracted = extract_file_from_decrypted_backup(backup_path, &domain, &path, &temp_db)
                    .or_else(|_| extract_file_from_backup(backup_path, &file_id, &temp_db));
                
                if extracted.is_ok() {
                    if let Ok(mut history) = parse_chrome_history_db(&temp_db) {
                        all_history.append(&mut history);
                    }
                    let _ = fs::remove_file(temp_db);
                }
            }
        }
    }
    
    eprintln!("[iOS Backup Parser] Found {} Chrome history entries", all_history.len());
    Ok(all_history)
}

/// Parse Chrome History database
fn parse_chrome_history_db(db_path: &Path) -> Result<Vec<ChromeHistoryEntry>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open Chrome history database: {}", e))?;
    
    // Chrome uses same schema as desktop
    let mut stmt = conn.prepare("
        SELECT 
            url,
            COALESCE(title, '') as title,
            visit_count,
            last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT 1000
    ").map_err(|e| format!("Failed to prepare Chrome history query: {}", e))?;
    
    let history_iter = stmt.query_map([], |row| {
        let last_visit: i64 = row.get(3).unwrap_or(0);
        
        Ok(ChromeHistoryEntry {
            url: row.get(0)?,
            title: row.get(1)?,
            visit_count: row.get(2)?,
            last_visit_time: convert_chrome_timestamp(last_visit),
        })
    }).map_err(|e| format!("Failed to query Chrome history: {}", e))?;
    
    let mut history = Vec::new();
    for entry in history_iter {
        if let Ok(h) = entry {
            history.push(h);
        }
    }
    
    Ok(history)
}

/// Extract media files from backup
pub fn extract_media_files(backup_path: &Path) -> Result<Vec<BackupMediaFile>, String> {
    eprintln!("[iOS Backup Parser] Extracting media files...");
    
    let manifest_db = backup_path.join("Manifest.db");
    let conn = Connection::open(&manifest_db)
        .map_err(|e| format!("Failed to open Manifest.db: {}", e))?;
    
    // Find media files (photos, videos)
    let mut stmt = conn.prepare("
        SELECT 
            fileID,
            domain,
            relativePath,
            file
        FROM Files
        WHERE (
            domain = 'CameraRollDomain' OR
            domain = 'MediaDomain' OR
            relativePath LIKE '%.jpg' OR
            relativePath LIKE '%.jpeg' OR
            relativePath LIKE '%.png' OR
            relativePath LIKE '%.heic' OR
            relativePath LIKE '%.mp4' OR
            relativePath LIKE '%.mov' OR
            relativePath LIKE '%.MOV'
        )
        AND flags != 2  -- Exclude directories
        LIMIT 5000
    ").map_err(|e| format!("Failed to prepare media query: {}", e))?;
    
    let media_iter = stmt.query_map([], |row| {
        let file_id_blob: Vec<u8> = row.get(0)?;
        let file_id = hex::encode(file_id_blob);
        let domain: String = row.get(1)?;
        let relative_path: String = row.get(2)?;
        
        // Extract filename from path
        let filename = relative_path
            .split('/')
            .last()
            .unwrap_or(&relative_path)
            .to_string();
        
        // Get file size from blob if available
        let file_size = row.get::<_, Option<Vec<u8>>>(3).ok()
            .and_then(|_blob| {
                // Would need to parse plist blob for size
                None
            })
            .unwrap_or(0);
        
        Ok(BackupMediaFile {
            filename,
            file_path: relative_path,
            backup_file_id: file_id,
            file_size,
            domain,
            creation_date: None,
            modification_date: None,
        })
    }).map_err(|e| format!("Failed to query media files: {}", e))?;
    
    let mut media_files = Vec::new();
    for media in media_iter {
        if let Ok(m) = media {
            media_files.push(m);
        }
    }
    
    eprintln!("[iOS Backup Parser] Found {} media files in backup", media_files.len());
    Ok(media_files)
}

/// Convert Cocoa/WebKit timestamp (seconds since 2001-01-01) to readable date
fn convert_cocoa_timestamp(timestamp: f64) -> String {
    // Add Cocoa epoch offset (978307200 = seconds from Unix epoch to 2001-01-01)
    let unix_timestamp = timestamp + 978307200.0;
    
    match DateTime::from_timestamp(unix_timestamp as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Unknown".to_string(),
    }
}

/// Convert Chrome timestamp (microseconds since 1601-01-01) to readable date
fn convert_chrome_timestamp(timestamp: i64) -> String {
    const EPOCH_DIFF: i64 = 11644473600; // Seconds between 1601 and 1970
    let unix_seconds = (timestamp / 1_000_000) - EPOCH_DIFF;
    
    match DateTime::from_timestamp(unix_seconds, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Unknown".to_string(),
    }
}

/// Extract media file from backup and compute hash
pub fn extract_and_hash_media(
    backup_path: &Path,
    file_id: &str,
    output_dir: &Path
) -> Result<(PathBuf, String, String), String> {
    // Extract file to output directory
    let output_file = output_dir.join(file_id);
    extract_file_from_backup(backup_path, file_id, &output_file)?;
    
    // Compute hashes
    let mut file = fs::File::open(&output_file)
        .map_err(|e| format!("Failed to open extracted file: {}", e))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    // Compute MD5
    use md5::{Md5, Digest as Md5Digest};
    let mut md5_hasher = Md5::new();
    md5_hasher.update(&buffer);
    let md5_hash = format!("{:x}", md5_hasher.finalize());
    
    // Compute SHA256
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let sha256_hash = format!("{:x}", hasher.finalize());
    
    Ok((output_file, md5_hash, sha256_hash))
}

/// Complete backup analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupAnalysisResults {
    pub safari_history: Vec<SafariHistoryEntry>,
    pub chrome_history: Vec<ChromeHistoryEntry>,
    pub media_files: Vec<BackupMediaFile>,
    pub total_files: usize,
    pub backup_size_mb: f64,
}

/// Perform complete analysis of iOS backup
pub fn analyze_backup(backup_path: &Path) -> Result<BackupAnalysisResults, String> {
    eprintln!("[iOS Backup Analysis] Starting comprehensive backup analysis...");
    eprintln!("[iOS Backup Analysis] Backup path: {:?}", backup_path);
    
    // Resolve the actual backup path (handles nested UDID directories)
    let backup_path = &resolve_backup_path(backup_path);
    eprintln!("[iOS Backup Analysis] Resolved path: {:?}", backup_path);
    
    // Extract all data types
    let safari_history = extract_safari_history(backup_path)
        .unwrap_or_else(|e| {
            eprintln!("[iOS Backup Analysis] Safari history extraction failed: {}", e);
            Vec::new()
        });
    
    let chrome_history = extract_chrome_history(backup_path)
        .unwrap_or_else(|e| {
            eprintln!("[iOS Backup Analysis] Chrome history extraction failed: {}", e);
            Vec::new()
        });
    
    let media_files = extract_media_files(backup_path)
        .unwrap_or_else(|e| {
            eprintln!("[iOS Backup Analysis] Media extraction failed: {}", e);
            Vec::new()
        });
    
    let all_files = list_backup_files(backup_path)
        .unwrap_or_else(|_| Vec::new());
    
    // Calculate backup size
    let backup_size = calculate_backup_size(backup_path);
    
    eprintln!("[iOS Backup Analysis] Analysis complete:");
    eprintln!("  - Safari history: {} entries", safari_history.len());
    eprintln!("  - Chrome history: {} entries", chrome_history.len());
    eprintln!("  - Media files: {} files", media_files.len());
    eprintln!("  - Total files: {}", all_files.len());
    eprintln!("  - Backup size: {:.1} MB", backup_size);
    
    Ok(BackupAnalysisResults {
        safari_history,
        chrome_history,
        media_files,
        total_files: all_files.len(),
        backup_size_mb: backup_size,
    })
}

/// Calculate total backup size in MB
fn calculate_backup_size(backup_path: &Path) -> f64 {
    let mut total_size: u64 = 0;
    
    if let Ok(entries) = fs::read_dir(backup_path) {
        for entry in entries.filter_map(Result::ok) {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total_size += metadata.len();
                } else if metadata.is_dir() {
                    // Recursively calculate directory size
                    total_size += calculate_dir_size(&entry.path());
                }
            }
        }
    }
    
    total_size as f64 / (1024.0 * 1024.0)
}

/// Calculate directory size recursively
fn calculate_dir_size(path: &Path) -> u64 {
    let mut size: u64 = 0;
    
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.filter_map(Result::ok) {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    size += metadata.len();
                } else if metadata.is_dir() {
                    size += calculate_dir_size(&entry.path());
                }
            }
        }
    }
    
    size
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cocoa_timestamp_conversion() {
        // Test known timestamp
        let timestamp = 689000000.0; // ~2022-11-02
        let result = convert_cocoa_timestamp(timestamp);
        assert!(result.contains("2022"));
    }
    
    #[test]
    fn test_chrome_timestamp_conversion() {
        let timestamp = 13318932000000000i64; // 2022-10-01
        let result = convert_chrome_timestamp(timestamp);
        assert!(result.contains("2022"));
    }
}
