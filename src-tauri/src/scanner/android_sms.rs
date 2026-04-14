// Android SMS/MMS message extraction and parsing
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use rusqlite::{Connection, Result as SqliteResult};
use chrono::{DateTime, Utc, TimeZone};
use super::android::{get_bundled_adb_path, create_hidden_command};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmsMessage {
    pub id: i64,
    pub thread_id: i64,
    pub address: String,      // Phone number or contact
    pub person: Option<String>, // Contact name if available
    pub date: i64,            // Unix timestamp (milliseconds)
    pub date_sent: i64,
    pub date_formatted: String,
    pub message_type: MessageType,
    pub body: String,
    pub read: bool,
    pub status: i32,
    pub service_center: Option<String>,
    pub subject: Option<String>, // For MMS
    pub has_attachments: bool,
    pub attachment_count: i32,
    pub attachments: Vec<MmsAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MmsAttachment {
    pub id: i64,
    pub msg_id: i64,
    pub content_type: String,
    pub file_name: Option<String>,
    pub file_path: String,        // Extracted file path
    pub file_size: i64,
    pub thumbnail_path: Option<String>, // For images/videos
    pub width: Option<i32>,
    pub height: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Inbox,      // Received (type 1)
    Sent,       // Sent (type 2)
    Draft,      // Draft (type 3)
    Outbox,     // Outbox (type 4)
    Failed,     // Failed (type 5)
    Queued,     // Queued (type 6)
    Unknown,
}

impl MessageType {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => MessageType::Inbox,
            2 => MessageType::Sent,
            3 => MessageType::Draft,
            4 => MessageType::Outbox,
            5 => MessageType::Failed,
            6 => MessageType::Queued,
            _ => MessageType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmsThread {
    pub thread_id: i64,
    pub contact_name: Option<String>,
    pub contact_number: String,
    pub message_count: i32,
    pub snippet: String,
    pub last_message_date: i64,
    pub last_message_date_formatted: String,
    pub unread_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmsExtractionResult {
    pub total_messages: usize,
    pub threads: Vec<SmsThread>,
    pub messages: Vec<SmsMessage>,
    pub date_range: Option<(String, String)>,
    pub extraction_method: String,
}

/// Check if device has root access
fn check_root_access(app_handle: &tauri::AppHandle, device_id: Option<&str>) -> bool {
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    let output = cmd
        .arg("shell")
        .arg("su -c 'id'")
        .output();
    
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.contains("uid=0(root)")
        }
        Err(_) => false,
    }
}

/// Extract SMS database using ADB with root access
fn extract_sms_db_root(app_handle: &tauri::AppHandle, device_id: Option<&str>, output_path: &Path) -> Result<PathBuf, String> {
    eprintln!("[SMS] Using root method to extract SMS database");
    
    let adb_path = get_bundled_adb_path(app_handle);
    let db_path = "/data/data/com.android.providers.telephony/databases/mmssms.db";
    let temp_path = "/sdcard/Download/mmssms_temp.db";
    
    // Copy to accessible location with root
    let mut cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    let copy_result = cmd
        .arg("shell")
        .arg(format!("su -c 'cp {} {}'", db_path, temp_path))
        .output()
        .map_err(|e| format!("Failed to copy database: {}", e))?;
    
    if !copy_result.status.success() {
        return Err(format!("Failed to copy SMS database: {}", 
            String::from_utf8_lossy(&copy_result.stderr)));
    }
    
    // Make it readable
    let mut chmod_cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        chmod_cmd.arg("-s").arg(device);
    }
    
    chmod_cmd
        .arg("shell")
        .arg(format!("chmod 644 {}", temp_path))
        .output()
        .map_err(|e| format!("Failed to set permissions: {}", e))?;
    
    // Pull the database
    let output_file = output_path.join("mmssms.db");
    let mut pull_cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        pull_cmd.arg("-s").arg(device);
    }
    
    let pull_result = pull_cmd
        .arg("pull")
        .arg(temp_path)
        .arg(&output_file)
        .output()
        .map_err(|e| format!("Failed to pull database: {}", e))?;
    
    if !pull_result.status.success() {
        return Err(format!("Failed to pull SMS database: {}", 
            String::from_utf8_lossy(&pull_result.stderr)));
    }
    
    // Clean up temp file
    let mut cleanup_cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        cleanup_cmd.arg("-s").arg(device);
    }
    cleanup_cmd
        .arg("shell")
        .arg(format!("rm {}", temp_path))
        .output()
        .ok();
    
    eprintln!("[SMS] Database extracted successfully: {:?}", output_file);
    Ok(output_file)
}

/// Extract SMS database using ADB backup (non-root method)
fn extract_sms_db_backup(app_handle: &tauri::AppHandle, device_id: Option<&str>, output_path: &Path) -> Result<PathBuf, String> {
    eprintln!("[SMS] Using backup method to extract SMS database (non-root)");
    eprintln!("[SMS] ⚠️  IMPORTANT: You will need to approve the backup on your device!");
    eprintln!("[SMS] ⚠️  The backup dialog should appear shortly. Tap 'BACK UP MY DATA' to continue.");
    
    let adb_path = get_bundled_adb_path(app_handle);
    let backup_file = output_path.join("sms_backup.ab");
    
    // Remove old backup file if it exists
    if backup_file.exists() {
        std::fs::remove_file(&backup_file).ok();
    }
    
    // Create ADB backup (this spawns async and returns immediately)
    let mut cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    eprintln!("[SMS] Initiating backup request...");
    let _child = cmd
        .arg("backup")
        .arg("-f")
        .arg(&backup_file)
        .arg("-noapk")
        .arg("com.android.providers.telephony")
        .spawn()
        .map_err(|e| format!("Failed to start backup: {}", e))?;
    
    // Wait for user to approve and backup to complete (with timeout)
    eprintln!("[SMS] Waiting for user to approve backup on device...");
    let max_wait_seconds = 120; // 2 minutes
    let check_interval_ms = 500; // Check every 500ms
    let max_checks = (max_wait_seconds * 1000) / check_interval_ms;
    
    for i in 0..max_checks {
        std::thread::sleep(std::time::Duration::from_millis(check_interval_ms));
        
        if backup_file.exists() {
            let metadata = std::fs::metadata(&backup_file)
                .map_err(|e| format!("Failed to check backup file: {}", e))?;
            let size = metadata.len();
            
            // Wait for file to stop growing (backup complete)
            if size > 0 {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let new_metadata = std::fs::metadata(&backup_file)
                    .map_err(|e| format!("Failed to check backup file: {}", e))?;
                let new_size = new_metadata.len();
                
                if new_size == size && size > 100 {
                    eprintln!("[SMS] ✓ Backup complete! File size: {} bytes", size);
                    break;
                }
            }
        }
        
        // Show progress every 10 seconds
        if i > 0 && i % 20 == 0 {
            let elapsed = (i * check_interval_ms) / 1000;
            eprintln!("[SMS] Still waiting... ({} seconds elapsed)", elapsed);
        }
    }
    
    if !backup_file.exists() {
        return Err("Backup timed out. Please ensure you approved the backup on your device and try again.".to_string());
    }
    
    let file_size = std::fs::metadata(&backup_file)
        .map(|m| m.len())
        .unwrap_or(0);
    
    if file_size < 100 {
        return Err("Backup file is too small or empty. User may have cancelled on device.".to_string());
    }
    
    eprintln!("[SMS] Parsing backup file...");
    // Parse backup file to extract database
    let db_file = parse_android_backup(&backup_file, output_path)?;
    
    eprintln!("[SMS] Database extracted from backup: {:?}", db_file);
    Ok(db_file)
}

/// Decrypt Android backup using password "1"
fn decrypt_backup<R: std::io::Read>(_reader: &mut R, encryption: &str) -> Result<Vec<u8>, String> {
    // TODO: Encryption support temporarily disabled due to compilation issues
    return Err(format!("Encrypted backups not yet supported (encryption: {}). Please retry backup without password.", encryption));
    
    /*
    use std::io::Read;
    use sha1::{Sha1, Digest};
    use aes::Aes256;
    use aes::cipher::{BlockDecrypt, KeyInit};
    
    // Password for backup decryption (configurable)
    const BACKUP_PASSWORD: &str = "1";
    
    eprintln!("[SMS Backup] Using password: '{}'", BACKUP_PASSWORD);
    
    if encryption != "AES-256" && encryption != "none" {
        return Err(format!("Unsupported encryption: {}", encryption));
    }
    
    // Read encryption parameters (user salt, checksum salt, rounds, IV, master key blob)
    let mut line = String::new();
    use std::io::BufRead;
    let mut buf_reader = std::io::BufReader::new(reader);
    
    // Line 5: User password salt (hex)
    line.clear();
    buf_reader.read_line(&mut line)
        .map_err(|e| format!("Failed to read user salt: {}", e))?;
    let user_salt_hex = line.trim();
    let user_salt = hex::decode(user_salt_hex)
        .map_err(|e| format!("Invalid user salt hex: {}", e))?;
    
    // Line 6: Checksum salt (hex)
    line.clear();
    buf_reader.read_line(&mut line)
        .map_err(|e| format!("Failed to read checksum salt: {}", e))?;
    let checksum_salt_hex = line.trim();
    let checksum_salt = hex::decode(checksum_salt_hex)
        .map_err(|e| format!("Invalid checksum salt hex: {}", e))?;
    
    // Line 7: PBKDF2 rounds
    line.clear();
    buf_reader.read_line(&mut line)
        .map_err(|e| format!("Failed to read rounds: {}", e))?;
    let rounds = line.trim().parse::<u32>()
        .map_err(|e| format!("Invalid rounds: {}", e))?;
    
    // Line 8: IV (hex)
    line.clear();
    buf_reader.read_line(&mut line)
        .map_err(|e| format!("Failed to read IV: {}", e))?;
    let iv_hex = line.trim();
    let iv = hex::decode(iv_hex)
        .map_err(|e| format!("Invalid IV hex: {}", e))?;
    
    // Line 9: Master key blob (hex) - encrypted master key
    line.clear();
    buf_reader.read_line(&mut line)
        .map_err(|e| format!("Failed to read master key blob: {}", e))?;
    let master_key_blob_hex = line.trim();
    let master_key_blob = hex::decode(master_key_blob_hex)
        .map_err(|e| format!("Invalid master key blob hex: {}", e))?;
    
    eprintln!("[SMS Backup] Deriving keys with {} PBKDF2 rounds...", rounds);
    
    // Derive user key from password using PBKDF2
    use pbkdf2::pbkdf2_hmac;
    let mut user_key = [0u8; 32]; // 256 bits
    pbkdf2_hmac::<Sha1>(BACKUP_PASSWORD.as_bytes(), &user_salt, rounds, &mut user_key);
    
    // Derive checksum key
    let mut checksum_key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(BACKUP_PASSWORD.as_bytes(), &checksum_salt, rounds, &mut checksum_key);
    
    // Decrypt master key blob using user key
    // The blob contains: IV (16 bytes) + encrypted master key + checksum
    if master_key_blob.len() < 16 + 32 + 32 {
        return Err("Master key blob too short".to_string());
    }
    
    let blob_iv = &master_key_blob[0..16];
    let encrypted_master_key = &master_key_blob[16..48];
    let blob_checksum = &master_key_blob[48..80];
    
    // Verify checksum
    let mut hasher = Sha1::new();
    hasher.update(&master_key_blob[0..48]);
    let computed_checksum = hasher.finalize();
    
    if &computed_checksum[0..32] != blob_checksum {
        return Err("Master key blob checksum mismatch - wrong password?".to_string());
    }
    
    // Decrypt master key using AES-256-CBC
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    
    let cipher = Aes256CbcDec::new(&user_key.into(), blob_iv.into());
    let mut master_key_buffer = encrypted_master_key.to_vec();
    cipher.decrypt_padded_mut::<NoPadding>(&mut master_key_buffer)
        .map_err(|e| format!("Failed to decrypt master key: {:?}", e))?;
    let master_key = &master_key_buffer[0..32];
    
    eprintln!("[SMS Backup] Master key decrypted successfully");
    
    // Read encrypted backup data
    let mut encrypted_data = Vec::new();
    buf_reader.read_to_end(&mut encrypted_data)
        .map_err(|e| format!("Failed to read encrypted data: {}", e))?;
    
    // Decrypt backup data using master key
    let cipher = Aes256CbcDec::new(master_key.into(), iv.as_slice().into());
    let mut decrypted_data = encrypted_data.clone();
    
    // Remove padding after decryption
    cipher.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut decrypted_data)
        .map_err(|e| format!("Failed to decrypt backup data: {:?}", e))?;
    
    eprintln!("[SMS Backup] Backup decrypted successfully ({} bytes)", decrypted_data.len());
    
    Ok(decrypted_data)
    */
}

/// Parse Android backup file to extract SMS database
fn parse_android_backup(backup_file: &Path, output_dir: &Path) -> Result<PathBuf, String> {
    // Android backup format:
    // Header (24+ bytes) + optional encryption header + zlib compressed tar
    
    use std::io::{Read, Write, BufReader};
    use std::fs::File;
    
    let file = File::open(backup_file)
        .map_err(|e| format!("Failed to open backup file: {}", e))?;
    let mut reader = BufReader::new(file);
    
    // Read and parse header line by line
    let mut header_line = String::new();
    use std::io::BufRead;
    
    // Line 1: "ANDROID BACKUP"
    reader.read_line(&mut header_line)
        .map_err(|e| format!("Failed to read backup header: {}", e))?;
    if !header_line.starts_with("ANDROID BACKUP") {
        return Err("Invalid backup file format".to_string());
    }
    
    // Line 2: Version number
    header_line.clear();
    reader.read_line(&mut header_line)
        .map_err(|e| format!("Failed to read version: {}", e))?;
    let version = header_line.trim().parse::<i32>().unwrap_or(1);
    
    // Line 3: Compression (1 = compressed, 0 = uncompressed)
    header_line.clear();
    reader.read_line(&mut header_line)
        .map_err(|e| format!("Failed to read compression flag: {}", e))?;
    let is_compressed = header_line.trim() == "1";
    
    // Line 4: Encryption (AES-256 or none)
    header_line.clear();
    reader.read_line(&mut header_line)
        .map_err(|e| format!("Failed to read encryption: {}", e))?;
    let encryption = header_line.trim().to_string();
    let is_encrypted = encryption != "none";
    
    eprintln!("[SMS Backup] Version: {}, Compressed: {}, Encrypted: {}", version, is_compressed, is_encrypted);
    
    let mut data = Vec::new();
    
    if is_encrypted {
        eprintln!("[SMS Backup] Backup is encrypted, attempting decryption with password '1'");
        data = decrypt_backup(&mut reader, &encryption)?;
    } else {
        // Read remaining data
        reader.read_to_end(&mut data)
            .map_err(|e| format!("Failed to read backup data: {}", e))?;
    }
    
    // Decompress if needed
    let decompressed = if is_compressed {
        use flate2::read::ZlibDecoder;
        let mut decoder = ZlibDecoder::new(&data[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| format!("Failed to decompress backup: {}", e))?;
        decompressed
    } else {
        data
    };
    
    // Write tar to temp file
    let tar_file = output_dir.join("sms_backup.tar");
    let mut tar_out = File::create(&tar_file)
        .map_err(|e| format!("Failed to create tar file: {}", e))?;
    tar_out.write_all(&decompressed)
        .map_err(|e| format!("Failed to write tar: {}", e))?;
    
    // Extract tar using tar-rs
    use tar::Archive;
    let tar_reader = File::open(&tar_file)
        .map_err(|e| format!("Failed to open tar: {}", e))?;
    let mut archive = Archive::new(tar_reader);
    
    // List all entries for debugging
    eprintln!("[SMS Backup] Listing backup contents:");
    let tar_reader2 = File::open(&tar_file)
        .map_err(|e| format!("Failed to open tar: {}", e))?;
    let mut archive2 = Archive::new(tar_reader2);
    for (idx, entry) in archive2.entries().map_err(|e| format!("Failed to read tar entries: {}", e))?.enumerate() {
        if let Ok(entry) = entry {
            if let Ok(path) = entry.path() {
                eprintln!("[SMS Backup]   {}: {}", idx, path.display());
            }
        }
    }
    
    // Find and extract mmssms.db (look for various paths)
    let db_patterns = vec!["mmssms.db", "telephony", "databases"];
    
    for entry in archive.entries().map_err(|e| format!("Failed to read tar entries: {}", e))? {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path().map_err(|e| format!("Failed to get path: {}", e))?;
        let path_str = path.to_string_lossy().to_lowercase();
        
        // Check if this looks like the SMS database
        if path_str.contains("mmssms.db") || 
           (path_str.contains("telephony") && path_str.contains("databases") && path_str.ends_with(".db")) {
            
            eprintln!("[SMS Backup] Found potential SMS database: {}", path.display());
            
            let db_file = output_dir.join("mmssms.db");
            let mut db_out = File::create(&db_file)
                .map_err(|e| format!("Failed to create db file: {}", e))?;
            std::io::copy(&mut entry, &mut db_out)
                .map_err(|e| format!("Failed to extract database: {}", e))?;
            
            let db_size = std::fs::metadata(&db_file)
                .map(|m| m.len())
                .unwrap_or(0);
            
            eprintln!("[SMS Backup] ✓ Extracted database ({} bytes)", db_size);
            
            // Clean up tar file
            std::fs::remove_file(&tar_file).ok();
            
            return Ok(db_file);
        }
    }
    
    // Clean up tar file even if not found
    std::fs::remove_file(&tar_file).ok();
    
    Err("SMS database not found in backup. The backup may not include SMS data, or the device may be encrypted.".to_string())
}

/// Extract MMS attachments from device
fn extract_mms_attachments(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    output_dir: &Path,
) -> Result<(), String> {
    eprintln!("[SMS] Extracting MMS attachments...");
    
    let adb_path = get_bundled_adb_path(app_handle);
    
    // Create attachments directory
    let attachments_dir = output_dir.join("mms_attachments");
    std::fs::create_dir_all(&attachments_dir)
        .map_err(|e| format!("Failed to create attachments directory: {}", e))?;
    
    // Check if device has root
    let has_root = check_root_access(app_handle, device_id);
    
    if has_root {
        // Pull entire parts directory with root
        let parts_path = "/data/data/com.android.providers.telephony/app_parts";
        let temp_path = "/sdcard/Download/mms_parts_temp";
        
        let mut cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            cmd.arg("-s").arg(device);
        }
        
        // Copy to accessible location
        cmd.arg("shell")
           .arg(format!("su -c 'cp -r {} {}'", parts_path, temp_path))
           .output()
           .ok();
        
        // Make readable
        let mut chmod_cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            chmod_cmd.arg("-s").arg(device);
        }
        chmod_cmd.arg("shell")
                 .arg(format!("chmod -R 644 {}", temp_path))
                 .output()
                 .ok();
        
        // Pull the parts
        let mut pull_cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            pull_cmd.arg("-s").arg(device);
        }
        pull_cmd.arg("pull")
                .arg(temp_path)
                .arg(&attachments_dir)
                .output()
                .ok();
        
        // Clean up
        let mut cleanup_cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            cleanup_cmd.arg("-s").arg(device);
        }
        cleanup_cmd.arg("shell")
                   .arg(format!("rm -rf {}", temp_path))
                   .output()
                   .ok();
        
        eprintln!("[SMS] MMS attachments extracted via root");
    } else {
        eprintln!("[SMS] Non-root device - MMS attachments may be limited");
    }
    
    Ok(())
}

/// Parse MMS parts from database and link to extracted files
fn get_mms_attachments(
    conn: &Connection,
    msg_id: i64,
    attachments_dir: &Path,
) -> Vec<MmsAttachment> {
    let query = "SELECT _id, mid, ct, cl, _data, text 
                 FROM part 
                 WHERE mid = ?";
    
    let mut stmt = match conn.prepare(query) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    
    let attachments: Vec<MmsAttachment> = match stmt.query_map([msg_id], |row| {
        let part_id: i64 = row.get(0)?;
        let content_type: String = row.get(2)?;
        let content_location: Option<String> = row.get(3)?;
        let data_path: Option<String> = row.get(4)?;
        
        // Try to find the actual file
        let file_name = content_location.clone()
            .or_else(|| data_path.clone())
            .or_else(|| Some(format!("part_{}.dat", part_id)));
        
        // Look for file in extracted attachments
        let file_path = if let Some(name) = &file_name {
            let potential_path = attachments_dir.join(name);
            if potential_path.exists() {
                potential_path.to_string_lossy().to_string()
            } else {
                // Try with part ID
                let id_path = attachments_dir.join(format!("{}", part_id));
                if id_path.exists() {
                    id_path.to_string_lossy().to_string()
                } else {
                    format!("part_{}.dat", part_id)
                }
            }
        } else {
            format!("part_{}.dat", part_id)
        };
        
        let file_size = if let Ok(metadata) = std::fs::metadata(&file_path) {
            metadata.len() as i64
        } else {
            0
        };
        
        // Generate thumbnail for images
        let thumbnail_path = if content_type.starts_with("image/") && std::path::Path::new(&file_path).exists() {
            match crate::thumbnail_generator::get_or_generate_thumbnail(
                std::path::Path::new(&file_path),
                "image"
            ) {
                Ok(thumb) => Some(thumb),
                Err(_) => None,
            }
        } else {
            None
        };
        
        Ok(MmsAttachment {
            id: part_id,
            msg_id,
            content_type,
            file_name,
            file_path,
            file_size,
            thumbnail_path,
            width: None,
            height: None,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    };
    
    attachments
}

/// Parse SMS database and extract messages
fn parse_sms_database(db_path: &Path, limit: Option<usize>) -> Result<SmsExtractionResult, String> {
    eprintln!("[SMS] Parsing database: {:?}", db_path);
    
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;
    
    let attachments_dir = db_path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("mms_attachments");
    
    // Query SMS messages
    let query = if let Some(lim) = limit {
        format!(
            "SELECT _id, thread_id, address, person, date, date_sent, type, body, read, status, service_center, subject 
             FROM sms 
             ORDER BY date DESC 
             LIMIT {}",
            lim
        )
    } else {
        "SELECT _id, thread_id, address, person, date, date_sent, type, body, read, status, service_center, subject 
         FROM sms 
         ORDER BY date DESC".to_string()
    };
    
    let mut stmt = conn.prepare(&query)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let mut messages: Vec<SmsMessage> = stmt
        .query_map(rusqlite::params![], |row| {
            let date: i64 = row.get(4)?;
            let date_sent: i64 = row.get(5)?;
            let msg_type: i32 = row.get(6)?;
            let body: String = row.get(7)?;
            
            // Format date
            let dt = Utc.timestamp_millis_opt(date).single()
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            Ok(SmsMessage {
                id: row.get(0)?,
                thread_id: row.get(1)?,
                address: row.get(2)?,
                person: row.get(3)?,
                date,
                date_sent,
                date_formatted,
                message_type: MessageType::from_i32(msg_type),
                body,
                read: row.get::<_, i32>(8)? != 0,
                status: row.get(9)?,
                service_center: row.get(10)?,
                subject: row.get(11)?,
                has_attachments: false,
                attachment_count: 0,
                attachments: Vec::new(),
            })
        })
        .map_err(|e| format!("Failed to query messages: {}", e))?
        .filter_map(|r| r.ok())
        .collect();
    
    // Query MMS messages and merge with SMS
    let mms_query = if let Some(lim) = limit {
        format!(
            "SELECT _id, thread_id, date, date_sent, msg_box, read, sub, _id as m_id
             FROM pdu 
             ORDER BY date DESC 
             LIMIT {}",
            lim
        )
    } else {
        "SELECT _id, thread_id, date, date_sent, msg_box, read, sub, _id as m_id
         FROM pdu 
         ORDER BY date DESC".to_string()
    };
    
    if let Ok(mut mms_stmt) = conn.prepare(&mms_query) {
        let mms_messages: Vec<SmsMessage> = match mms_stmt.query_map(rusqlite::params![], |row| {
            let msg_id: i64 = row.get(0)?;
            let date: i64 = row.get(2)?;
            let date_sent: i64 = row.get(3)?;
            let msg_box: i32 = row.get(4)?;
            
            let dt = Utc.timestamp_millis_opt(date * 1000).single() // MMS uses seconds
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            // Get address from addr table
            let address = get_mms_address(&conn, msg_id).unwrap_or_else(|| "Unknown".to_string());
            
            // Get MMS body text
            let body = get_mms_body(&conn, msg_id).unwrap_or_else(|| String::new());
            
            // Get MMS attachments
            let attachments = get_mms_attachments(&conn, msg_id, &attachments_dir);
            let attachment_count = attachments.len() as i32;
            let has_attachments = !attachments.is_empty();
            
            Ok(SmsMessage {
                id: msg_id,
                thread_id: row.get(1)?,
                address,
                person: None,
                date: date * 1000, // Convert to milliseconds
                date_sent: date_sent * 1000,
                date_formatted,
                message_type: MessageType::from_i32(msg_box),
                body,
                read: row.get::<_, i32>(5)? != 0,
                status: 0,
                service_center: None,
                subject: row.get(6)?,
                has_attachments,
                attachment_count,
                attachments,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        
        // Merge MMS into messages
        messages.extend(mms_messages);
    }
    
    // Sort all messages by date
    messages.sort_by(|a, b| b.date.cmp(&a.date));
    
    eprintln!("[SMS] Found {} messages", messages.len());
    
    // Build threads
    let threads = build_message_threads(&conn, &messages)
        .map_err(|e| format!("Failed to build message threads: {}", e))?;
    
    // Get date range
    let date_range = if !messages.is_empty() {
        let newest = &messages[0];
        let oldest = &messages[messages.len() - 1];
        Some((oldest.date_formatted.clone(), newest.date_formatted.clone()))
    } else {
        None
    };
    
    let extraction_method = if db_path.to_string_lossy().contains("backup") {
        "ADB Backup (Non-Root)".to_string()
    } else {
        "ADB Root".to_string()
    };
    
    Ok(SmsExtractionResult {
        total_messages: messages.len(),
        threads,
        messages,
        date_range,
        extraction_method,
    })
}

/// Build threaded conversation view
fn build_message_threads(conn: &Connection, messages: &[SmsMessage]) -> SqliteResult<Vec<SmsThread>> {
    // Query threads table for metadata
    let query = "SELECT _id, recipient_ids, message_count, snippet, date 
                 FROM threads 
                 ORDER BY date DESC";
    
    let mut stmt = conn.prepare(query)?;
    
    let threads: Vec<SmsThread> = stmt
        .query_map(rusqlite::params![], |row| {
            let thread_id: i64 = row.get(0)?;
            let date: i64 = row.get(4)?;
            
            let dt = Utc.timestamp_millis_opt(date).single()
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            // Find messages for this thread
            let thread_messages: Vec<&SmsMessage> = messages.iter()
                .filter(|m| m.thread_id == thread_id)
                .collect();
            
            let contact_number = thread_messages.first()
                .map(|m| m.address.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            
            let unread_count = thread_messages.iter()
                .filter(|m| !m.read)
                .count() as i32;
            
            Ok(SmsThread {
                thread_id,
                contact_name: None, // TODO: Lookup from contacts
                contact_number,
                message_count: row.get(2)?,
                snippet: row.get(3)?,
                last_message_date: date,
                last_message_date_formatted: date_formatted,
                unread_count,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    
    Ok(threads)
}

/// Get MMS address from addr table
fn get_mms_address(conn: &Connection, msg_id: i64) -> Option<String> {
    let query = "SELECT address FROM addr WHERE msg_id = ? AND type = 137 LIMIT 1"; // 137 = FROM
    
    conn.query_row(query, [msg_id], |row| row.get::<_, String>(0))
        .ok()
}

/// Get MMS body text from part table
fn get_mms_body(conn: &Connection, msg_id: i64) -> Option<String> {
    let query = "SELECT text FROM part WHERE mid = ? AND ct = 'text/plain' LIMIT 1";
    
    conn.query_row(query, [msg_id], |row| row.get::<_, String>(0))
        .ok()
}

/// Tauri command to extract and parse SMS messages
#[tauri::command]
pub async fn extract_android_sms(
    app_handle: tauri::AppHandle,
    device_id: Option<String>,
    limit: Option<usize>,
) -> Result<SmsExtractionResult, String> {
    eprintln!("[SMS] Starting SMS extraction...");
    
    let device = device_id.as_deref();
    
    // Create temp directory for extraction
    let temp_dir = std::env::temp_dir().join("datapilot_sms_extraction");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;
    
    // Check if device has root
    let has_root = check_root_access(&app_handle, device);
    eprintln!("[SMS] Device root access: {}", has_root);
    
    // ── Strategy: Multi-silo first (merges all message sources) ──
    // This scans: standard telephony, Google Messages (RCS/bugle_db),
    //             Samsung Messages, Samsung Recycle Bin, Knox Secure Folder
    eprintln!("[SMS] Method 1: Multi-silo message discovery");
    match super::android_messages_multisilo::extract_messages_multisilo(&app_handle, device) {
        Ok(multisilo_result) if multisilo_result.unique_messages > 0 => {
            eprintln!("[SMS] ✓ Multi-silo succeeded: {} unique messages from {} silos",
                multisilo_result.unique_messages, multisilo_result.silos_scanned.len());
            
            let mut messages = multisilo_result.messages;
            
            // Apply limit if specified
            if let Some(lim) = limit {
                if messages.len() > lim {
                    messages.sort_by(|a, b| b.date.cmp(&a.date));
                    messages.truncate(lim);
                }
            }
            
            let result = build_extraction_result(messages, "Multi-Silo Discovery");
            eprintln!("[SMS] ✓ Extraction complete: {} messages, {} threads",
                result.total_messages, result.threads.len());
            return Ok(result);
        }
        Ok(_) => {
            eprintln!("[SMS] Multi-silo returned 0 messages, falling back...");
        }
        Err(e) => {
            eprintln!("[SMS] Multi-silo failed: {}, falling back...", e);
        }
    }
    
    // ── Fallback: direct extraction methods ──
    let result = if has_root {
        eprintln!("[SMS] Method 2: Root access (mmssms.db)");
        match extract_sms_db_root(&app_handle, device, &temp_dir) {
            Ok(db_path) => {
                extract_mms_attachments(&app_handle, device, &temp_dir).ok();
                parse_sms_database(&db_path, limit)
            }
            Err(e) => {
                eprintln!("[SMS] Root method failed: {}", e);
                Err(e)
            }
        }
    } else {
        // Content provider: SMS + MMS
        eprintln!("[SMS] Method 2: Content provider query (SMS + MMS)");
        match extract_sms_via_content_provider(&app_handle, device, limit) {
            Ok(result) => {
                eprintln!("[SMS] ✓ Content provider succeeded");
                Ok(result)
            }
            Err(e) => {
                eprintln!("[SMS] Content provider failed: {}", e);
                eprintln!("[SMS] Method 3: ADB backup (requires user approval)");
                
                match extract_sms_db_backup(&app_handle, device, &temp_dir) {
                    Ok(db_path) => {
                        extract_mms_attachments(&app_handle, device, &temp_dir).ok();
                        parse_sms_database(&db_path, limit)
                    }
                    Err(backup_error) => {
                        Err(format!("All methods failed. Content provider: {}. Backup: {}", e, backup_error))
                    }
                }
            }
        }
    };
    
    match result {
        Ok(res) => {
            eprintln!("[SMS] ✓ Extraction complete: {} messages, {} threads", 
                res.total_messages, res.threads.len());
            Ok(res)
        }
        Err(e) => Err(e)
    }
}

/// Build a unified SmsExtractionResult from a flat list of messages
fn build_extraction_result(messages: Vec<SmsMessage>, method: &str) -> SmsExtractionResult {
    // Build threads by grouping on thread_id (fallback to address if thread_id is 0)
    let mut thread_map: std::collections::HashMap<i64, Vec<&SmsMessage>> = std::collections::HashMap::new();
    let mut next_synthetic_id = -1i64; // negative IDs for address-based grouping
    let mut address_thread_map: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    
    for msg in &messages {
        let tid = if msg.thread_id > 0 {
            msg.thread_id
        } else {
            // Group by address when no thread_id
            *address_thread_map.entry(msg.address.clone()).or_insert_with(|| {
                let id = next_synthetic_id;
                next_synthetic_id -= 1;
                id
            })
        };
        thread_map.entry(tid).or_insert_with(Vec::new).push(msg);
    }
    
    let mut threads = Vec::new();
    for (thread_id, thread_msgs) in &thread_map {
        if let Some(first_msg) = thread_msgs.first() {
            let last_msg = thread_msgs.iter().max_by_key(|m| m.date).unwrap();
            let unread_count = thread_msgs.iter().filter(|m| !m.read).count() as i32;
            
            threads.push(SmsThread {
                thread_id: *thread_id,
                contact_number: first_msg.address.clone(),
                contact_name: first_msg.person.clone(),
                message_count: thread_msgs.len() as i32,
                snippet: last_msg.body.chars().take(100).collect(),
                last_message_date: last_msg.date,
                last_message_date_formatted: last_msg.date_formatted.clone(),
                unread_count,
            });
        }
    }
    
    threads.sort_by(|a, b| b.last_message_date.cmp(&a.last_message_date));
    
    let date_range = if !messages.is_empty() {
        let oldest = messages.iter().min_by_key(|m| m.date).unwrap();
        let newest = messages.iter().max_by_key(|m| m.date).unwrap();
        Some((oldest.date_formatted.clone(), newest.date_formatted.clone()))
    } else {
        None
    };
    
    SmsExtractionResult {
        total_messages: messages.len(),
        threads,
        messages,
        date_range,
        extraction_method: method.to_string(),
    }
}

/// Extract SMS via content provider (works without root or backup)
fn extract_sms_via_content_provider(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    limit: Option<usize>,
) -> Result<SmsExtractionResult, String> {
    eprintln!("[SMS] Using content provider method (no root/backup needed)");
    
    let adb_path = get_bundled_adb_path(app_handle);
    let max_messages = limit.unwrap_or(5000);
    
    let mut messages = Vec::new();
    
    // ── Query 1: SMS messages via content://sms ──
    {
        let mut cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            cmd.arg("-s").arg(device);
        }
        let query = "content query --uri content://sms --projection _id:thread_id:address:person:date:date_sent:type:body:read:status --sort 'date DESC'";
        eprintln!("[SMS] Querying content://sms ...");
        
        if let Ok(output) = cmd.arg("shell").arg(query).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let sms_msgs = parse_content_provider_rows(&stdout, false);
                eprintln!("[SMS] content://sms returned {} messages", sms_msgs.len());
                messages.extend(sms_msgs);
            } else {
                eprintln!("[SMS] content://sms query failed");
            }
        }
    }
    
    // ── Query 2: MMS messages via content://mms ──
    {
        let mut cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            cmd.arg("-s").arg(device);
        }
        // MMS uses different columns: _id, thread_id, date (seconds not ms), msg_box (like type), sub (subject), read
        let query = "content query --uri content://mms --projection _id:thread_id:date:msg_box:sub:read --sort 'date DESC'";
        eprintln!("[SMS] Querying content://mms ...");
        
        if let Ok(output) = cmd.arg("shell").arg(query).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut mms_msgs = parse_mms_content_rows(&stdout);
                eprintln!("[SMS] content://mms returned {} messages", mms_msgs.len());
                
                // For each MMS, try to get the text body from content://mms/{id}/part
                for msg in &mut mms_msgs {
                    if msg.body.is_empty() {
                        if let Some(body) = get_mms_text_part_via_adb(app_handle, device_id, msg.id) {
                            msg.body = body;
                        }
                    }
                    // Try to get the sender/recipient address
                    if msg.address.is_empty() || msg.address == "Unknown" {
                        if let Some(addr) = get_mms_address_via_adb(app_handle, device_id, msg.id) {
                            msg.address = addr;
                        }
                    }
                }
                
                // Filter out MMS with no text body (pure image MMS etc.)
                let mms_with_text: Vec<SmsMessage> = mms_msgs.into_iter()
                    .filter(|m| !m.body.is_empty())
                    .collect();
                eprintln!("[SMS] MMS with text content: {}", mms_with_text.len());
                messages.extend(mms_with_text);
            } else {
                eprintln!("[SMS] content://mms query failed (might not be supported)");
            }
        }
    }
    
    // Sort all messages by date descending
    messages.sort_by(|a, b| b.date.cmp(&a.date));
    
    // Apply limit
    if messages.len() > max_messages {
        eprintln!("[SMS] Limiting results from {} to {} messages", messages.len(), max_messages);
        messages.truncate(max_messages);
    }
    
    if messages.is_empty() {
        eprintln!("[SMS] ❌ No SMS or MMS messages found via content providers");
        
        // Diagnostic query
        let mut test_cmd = create_hidden_command(&adb_path);
        if let Some(device) = device_id {
            test_cmd.arg("-s").arg(device);
        }
        if let Ok(test_out) = test_cmd.arg("shell").arg("content query --uri content://sms --projection _id").output() {
            let test_stdout = String::from_utf8_lossy(&test_out.stdout);
            eprintln!("[SMS] Diagnostic query: {}", test_stdout.chars().take(200).collect::<String>());
        }
        
        return Err("No SMS/MMS messages found via content providers.".to_string());
    }
    
    eprintln!("[SMS] Found {} total messages (SMS + MMS) via content providers", messages.len());
    
    Ok(build_extraction_result(messages, "Content Provider (SMS + MMS)"))
}

/// Parse SMS rows from content://sms output
fn parse_content_provider_rows(output: &str, _is_mms: bool) -> Vec<SmsMessage> {
    let mut messages = Vec::new();
    
    for line in output.lines() {
        if !line.starts_with("Row:") {
            continue;
        }
        
        let parts: Vec<&str> = line.split(", ").collect();
        let mut msg_data: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        
        for part in parts {
            if let Some(eq_pos) = part.find('=') {
                let key_part = part[..eq_pos].trim();
                let key = if let Some(space_pos) = key_part.rfind(' ') {
                    key_part[space_pos + 1..].to_string()
                } else {
                    key_part.to_string()
                };
                let value = part[eq_pos + 1..].trim().to_string();
                if value != "NULL" && !value.is_empty() {
                    msg_data.insert(key, value);
                }
            }
        }
        
        if let (Some(id), Some(thread_id), Some(address), Some(date), Some(msg_type), Some(body)) = (
            msg_data.get("_id").and_then(|s| s.parse::<i64>().ok()),
            msg_data.get("thread_id").and_then(|s| s.parse::<i64>().ok()),
            msg_data.get("address"),
            msg_data.get("date").and_then(|s| s.parse::<i64>().ok()),
            msg_data.get("type").and_then(|s| s.parse::<i32>().ok()),
            msg_data.get("body"),
        ) {
            let date_sent = msg_data.get("date_sent")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(date);
            
            let dt = Utc.timestamp_millis_opt(date).single()
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            let person = msg_data.get("person")
                .filter(|p| *p != "NULL" && !p.is_empty())
                .cloned();
            
            messages.push(SmsMessage {
                id,
                thread_id,
                address: address.clone(),
                person,
                date,
                date_sent,
                date_formatted,
                message_type: MessageType::from_i32(msg_type),
                body: body.clone(),
                read: msg_data.get("read").and_then(|s| s.parse::<i32>().ok()).unwrap_or(0) == 1,
                status: msg_data.get("status").and_then(|s| s.parse::<i32>().ok()).unwrap_or(0),
                service_center: None,
                subject: None,
                has_attachments: false,
                attachment_count: 0,
                attachments: Vec::new(),
            });
        }
    }
    
    messages
}

/// Parse MMS rows from content://mms output
fn parse_mms_content_rows(output: &str) -> Vec<SmsMessage> {
    let mut messages = Vec::new();
    
    for line in output.lines() {
        if !line.starts_with("Row:") {
            continue;
        }
        
        let parts: Vec<&str> = line.split(", ").collect();
        let mut msg_data: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        
        for part in parts {
            if let Some(eq_pos) = part.find('=') {
                let key_part = part[..eq_pos].trim();
                let key = if let Some(space_pos) = key_part.rfind(' ') {
                    key_part[space_pos + 1..].to_string()
                } else {
                    key_part.to_string()
                };
                let value = part[eq_pos + 1..].trim().to_string();
                if value != "NULL" && !value.is_empty() {
                    msg_data.insert(key, value);
                }
            }
        }
        
        if let (Some(id), Some(date_secs)) = (
            msg_data.get("_id").and_then(|s| s.parse::<i64>().ok()),
            msg_data.get("date").and_then(|s| s.parse::<i64>().ok()),
        ) {
            // MMS date is in SECONDS, convert to milliseconds
            let date_ms = date_secs * 1000;
            let thread_id = msg_data.get("thread_id").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            let msg_box = msg_data.get("msg_box").and_then(|s| s.parse::<i32>().ok()).unwrap_or(1);
            let subject = msg_data.get("sub").cloned();
            let read = msg_data.get("read").and_then(|s| s.parse::<i32>().ok()).unwrap_or(0) == 1;
            
            let dt = Utc.timestamp_millis_opt(date_ms).single()
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            // msg_box: 1=received, 2=sent, 3=draft, 4=outbox
            let message_type = MessageType::from_i32(msg_box);
            
            messages.push(SmsMessage {
                id,
                thread_id,
                address: "Unknown".to_string(), // Will be resolved via content://mms/{id}/addr
                person: None,
                date: date_ms,
                date_sent: date_ms,
                date_formatted,
                message_type,
                body: String::new(), // Will be resolved via content://mms/{id}/part
                read,
                status: 0,
                service_center: None,
                subject,
                has_attachments: true, // MMS always has parts
                attachment_count: 0,
                attachments: Vec::new(),
            });
        }
    }
    
    messages
}

/// Get the text body of an MMS from content://mms/{id}/part via ADB content query
fn get_mms_text_part_via_adb(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    mms_id: i64,
) -> Option<String> {
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    let query = format!(
        "content query --uri content://mms/{}/part --projection _id:ct:text --where \"ct='text/plain'\"",
        mms_id
    );
    
    if let Ok(output) = cmd.arg("shell").arg(&query).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Row:") {
                    // Look for text= field
                    for part in line.split(", ") {
                        if let Some(eq_pos) = part.find('=') {
                            let key = part[..eq_pos].trim();
                            let key = if let Some(sp) = key.rfind(' ') { &key[sp+1..] } else { key };
                            if key == "text" {
                                let value = part[eq_pos + 1..].trim();
                                if value != "NULL" && !value.is_empty() {
                                    return Some(value.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Get the address (sender/recipient) of an MMS from content://mms/{id}/addr via ADB content query
fn get_mms_address_via_adb(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    mms_id: i64,
) -> Option<String> {
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    let query = format!(
        "content query --uri content://mms/{}/addr --projection address:type",
        mms_id
    );
    
    if let Ok(output) = cmd.arg("shell").arg(&query).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Row:") {
                    let mut addr = String::new();
                    let mut addr_type = 0i32;
                    for part in line.split(", ") {
                        if let Some(eq_pos) = part.find('=') {
                            let key = part[..eq_pos].trim();
                            let key = if let Some(sp) = key.rfind(' ') { &key[sp+1..] } else { key };
                            let value = part[eq_pos + 1..].trim();
                            match key {
                                "address" => addr = value.to_string(),
                                "type" => addr_type = value.parse().unwrap_or(0),
                                _ => {}
                            }
                        }
                    }
                    // type 137 = FROM, type 151 = TO — prefer FROM for received
                    if !addr.is_empty() && addr != "insert-address-token" {
                        return Some(addr);
                    }
                }
            }
        }
    }
    None
}

/// Tauri command to get messages for a specific thread
#[tauri::command]
pub async fn get_sms_thread_messages(
    thread_id: i64,
) -> Result<Vec<SmsMessage>, String> {
    let temp_dir = std::env::temp_dir().join("datapilot_sms_extraction");
    let db_path = temp_dir.join("mmssms.db");
    let attachments_dir = temp_dir.join("mms_attachments");
    
    if !db_path.exists() {
        return Err("SMS database not extracted yet. Run extract_android_sms first.".to_string());
    }
    
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;
    
    // Get SMS messages
    let query = "SELECT _id, thread_id, address, person, date, date_sent, type, body, read, status, service_center, subject 
                 FROM sms 
                 WHERE thread_id = ?
                 ORDER BY date ASC";
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let mut messages: Vec<SmsMessage> = stmt
        .query_map([thread_id], |row| {
            let date: i64 = row.get(4)?;
            let date_sent: i64 = row.get(5)?;
            let msg_type: i32 = row.get(6)?;
            let body: String = row.get(7)?;
            
            let dt = Utc.timestamp_millis_opt(date).single()
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            Ok(SmsMessage {
                id: row.get(0)?,
                thread_id: row.get(1)?,
                address: row.get(2)?,
                person: row.get(3)?,
                date,
                date_sent,
                date_formatted,
                message_type: MessageType::from_i32(msg_type),
                body,
                read: row.get::<_, i32>(8)? != 0,
                status: row.get(9)?,
                service_center: row.get(10)?,
                subject: row.get(11)?,
                has_attachments: false,
                attachment_count: 0,
                attachments: Vec::new(),
            })
        })
        .map_err(|e| format!("Failed to query messages: {}", e))?
        .filter_map(|r| r.ok())
        .collect();
    
    // Get MMS messages for this thread
    let mms_query = "SELECT _id, thread_id, date, date_sent, msg_box, read, sub
                     FROM pdu 
                     WHERE thread_id = ?
                     ORDER BY date ASC";
    
    if let Ok(mut mms_stmt) = conn.prepare(mms_query) {
        let mms_messages: Vec<SmsMessage> = match mms_stmt.query_map([thread_id], |row| {
            let msg_id: i64 = row.get(0)?;
            let date: i64 = row.get(2)?;
            let date_sent: i64 = row.get(3)?;
            let msg_box: i32 = row.get(4)?;
            
            let dt = Utc.timestamp_millis_opt(date * 1000).single()
                .unwrap_or_else(|| Utc::now());
            let date_formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
            
            let address = get_mms_address(&conn, msg_id).unwrap_or_else(|| "Unknown".to_string());
            let body = get_mms_body(&conn, msg_id).unwrap_or_else(|| String::new());
            let attachments = get_mms_attachments(&conn, msg_id, &attachments_dir);
            let attachment_count = attachments.len() as i32;
            let has_attachments = !attachments.is_empty();
            
            Ok(SmsMessage {
                id: msg_id,
                thread_id: row.get(1)?,
                address,
                person: None,
                date: date * 1000,
                date_sent: date_sent * 1000,
                date_formatted,
                message_type: MessageType::from_i32(msg_box),
                body,
                read: row.get::<_, i32>(5)? != 0,
                status: 0,
                service_center: None,
                subject: row.get(6)?,
                has_attachments,
                attachment_count,
                attachments,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        
        messages.extend(mms_messages);
    }
    
    // Sort by date
    messages.sort_by(|a, b| a.date.cmp(&b.date));
    
    Ok(messages)
}
