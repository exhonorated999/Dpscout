use serde::{Deserialize, Serialize};
use std::path::Path;
use rusqlite::{Connection, OpenFlags};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosNote {
    pub title: String,
    pub content: String,
    pub created_date: String,
    pub modified_date: String,
    pub folder: String,
    pub note_id: String,
}

/// Extract Notes from iTunes backup
pub fn get_notes_from_backup(backup_path: &Path) -> Result<Vec<IosNote>, String> {
    eprintln!("[iOS Notes] Extracting notes from iTunes backup");
    
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return Err("Invalid backup: Manifest.db not found".to_string());
    }
    
    // Find the Notes database file in the backup
    let notes_db_path = find_notes_database(backup_path)?;
    
    if !notes_db_path.exists() {
        return Err("Notes database not found in backup".to_string());
    }
    
    parse_notes_database(&notes_db_path)
}

/// Find Notes database in iTunes backup
fn find_notes_database(backup_path: &Path) -> Result<std::path::PathBuf, String> {
    use std::fs;
    
    let manifest_db = backup_path.join("Manifest.db");
    
    let conn = Connection::open_with_flags(
        manifest_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open manifest: {}", e))?;
    
    // Notes are stored in the NoteStore.sqlite database
    // Domain: AppDomainGroup-group.com.apple.notes or HomeDomain
    let mut stmt = conn.prepare(
        "SELECT fileID, relativePath FROM Files \
         WHERE (domain LIKE '%notes%' OR relativePath LIKE '%NoteStore.sqlite%') \
         AND relativePath NOT LIKE '%.wal' \
         AND relativePath NOT LIKE '%.shm'"
    ).map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let mut rows = stmt.query([]).map_err(|e| format!("Query failed: {}", e))?;
    
    while let Ok(Some(row)) = rows.next() {
        let file_id: String = row.get(0).unwrap_or_default();
        let relative_path: String = row.get(1).unwrap_or_default();
        
        eprintln!("[iOS Notes] Found potential notes DB: {} -> {}", file_id, relative_path);
        
        // Backup files are stored as fileID (first 2 chars as directory)
        let backup_file_path = if file_id.len() >= 2 {
            backup_path.join(&file_id[0..2]).join(&file_id)
        } else {
            backup_path.join(&file_id)
        };
        
        if backup_file_path.exists() && relative_path.contains("NoteStore.sqlite") {
            eprintln!("[iOS Notes] Located notes database at: {:?}", backup_file_path);
            return Ok(backup_file_path);
        }
    }
    
    Err("Notes database not found in backup manifest".to_string())
}

/// Parse Notes from NoteStore.sqlite database
fn parse_notes_database(db_path: &Path) -> Result<Vec<IosNote>, String> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open notes database: {}", e))?;
    
    let mut notes = Vec::new();
    
    // iOS Notes database schema varies by iOS version
    // Modern iOS (13+): ZICCLOUDSYNCINGOBJECT table with ZDATA (compressed)
    // Older iOS: ZNOTE table with ZCONTENT
    
    // Try modern format first
    match parse_modern_notes(&conn) {
        Ok(modern_notes) if !modern_notes.is_empty() => {
            notes = modern_notes;
        }
        _ => {
            // Fall back to legacy format
            match parse_legacy_notes(&conn) {
                Ok(legacy_notes) => notes = legacy_notes,
                Err(e) => eprintln!("[iOS Notes] Legacy parsing failed: {}", e),
            }
        }
    }
    
    if notes.is_empty() {
        eprintln!("[iOS Notes] No notes found or unsupported database format");
        return Err("No notes found in database".to_string());
    }
    
    eprintln!("[iOS Notes] Successfully extracted {} notes", notes.len());
    Ok(notes)
}

/// Parse modern iOS Notes format (iOS 13+)
fn parse_modern_notes(conn: &Connection) -> Result<Vec<IosNote>, String> {
    let mut notes = Vec::new();
    
    // Check if modern tables exist
    let table_check: Result<i64, _> = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ZICCLOUDSYNCINGOBJECT'",
        [],
        |row| row.get(0)
    );
    
    if table_check.unwrap_or(0) == 0 {
        return Err("Modern notes table not found".to_string());
    }
    
    let query = "
        SELECT 
            ZTITLE1 as title,
            ZSNIPPET as snippet,
            datetime(ZCREATIONDATE + 978307200, 'unixepoch') as created,
            datetime(ZMODIFICATIONDATE1 + 978307200, 'unixepoch') as modified,
            ZFOLDER as folder_id
        FROM ZICCLOUDSYNCINGOBJECT
        WHERE ZTITLE1 IS NOT NULL
        ORDER BY ZMODIFICATIONDATE1 DESC
    ";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare modern notes query: {}", e))?;
    
    let mut rows = stmt.query([])
        .map_err(|e| format!("Modern notes query failed: {}", e))?;
    
    let mut note_id = 1;
    while let Ok(Some(row)) = rows.next() {
        let title: String = row.get(0).unwrap_or_else(|_| "Untitled".to_string());
        let content: String = row.get(1).unwrap_or_else(|_| "".to_string());
        let created: String = row.get(2).unwrap_or_else(|_| "Unknown".to_string());
        let modified: String = row.get(3).unwrap_or_else(|_| "Unknown".to_string());
        
        notes.push(IosNote {
            title: title.clone(),
            content: sanitize_note_content(&content),
            created_date: created,
            modified_date: modified,
            folder: "Notes".to_string(),
            note_id: format!("note_{}", note_id),
        });
        
        note_id += 1;
    }
    
    Ok(notes)
}

/// Parse legacy iOS Notes format (iOS 12 and earlier)
fn parse_legacy_notes(conn: &Connection) -> Result<Vec<IosNote>, String> {
    let mut notes = Vec::new();
    
    // Check if legacy tables exist
    let table_check: Result<i64, _> = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ZNOTE'",
        [],
        |row| row.get(0)
    );
    
    if table_check.unwrap_or(0) == 0 {
        return Err("Legacy notes table not found".to_string());
    }
    
    let query = "
        SELECT 
            ZTITLE as title,
            ZCONTENT as content,
            datetime(ZCREATIONDATE + 978307200, 'unixepoch') as created,
            datetime(ZMODIFICATIONDATE + 978307200, 'unixepoch') as modified
        FROM ZNOTE
        WHERE ZTITLE IS NOT NULL OR ZCONTENT IS NOT NULL
        ORDER BY ZMODIFICATIONDATE DESC
    ";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare legacy notes query: {}", e))?;
    
    let mut rows = stmt.query([])
        .map_err(|e| format!("Legacy notes query failed: {}", e))?;
    
    let mut note_id = 1;
    while let Ok(Some(row)) = rows.next() {
        let title: String = row.get(0).unwrap_or_else(|_| "Untitled".to_string());
        let content: String = row.get(1).unwrap_or_else(|_| "".to_string());
        let created: String = row.get(2).unwrap_or_else(|_| "Unknown".to_string());
        let modified: String = row.get(3).unwrap_or_else(|_| "Unknown".to_string());
        
        // Use title or first line of content as title if empty
        let final_title = if title.is_empty() {
            content.lines().next().unwrap_or("Untitled").to_string()
        } else {
            title
        };
        
        notes.push(IosNote {
            title: final_title,
            content: sanitize_note_content(&content),
            created_date: created,
            modified_date: modified,
            folder: "Notes".to_string(),
            note_id: format!("note_{}", note_id),
        });
        
        note_id += 1;
    }
    
    Ok(notes)
}

/// Sanitize note content for display
fn sanitize_note_content(content: &str) -> String {
    // Remove any binary data, control characters, etc.
    content
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Get notes from live device (requires backup extraction)
pub fn get_notes_from_live_device(udid: &str) -> Result<Vec<IosNote>, String> {
    // Notes cannot be directly accessed from live device without backup
    // This requires creating a temporary backup or using AFC + database extraction
    
    eprintln!("[iOS Notes] Notes extraction from live device requires iTunes backup");
    
    Err(
        "Notes extraction requires iTunes backup.\n\
        Please create a backup first:\n\
        1. Open iTunes/Finder\n\
        2. Select your device\n\
        3. Click 'Back Up Now'\n\
        4. Then use 'Scan iOS Backup' option".to_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sanitize_content() {
        let input = "Hello\x00World\n\nTest\r\n";
        let output = sanitize_note_content(input);
        assert_eq!(output, "HelloWorld\n\nTest");
    }
}
