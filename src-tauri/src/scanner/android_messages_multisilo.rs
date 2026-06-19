// Multi-Silo Android Message Discovery Engine
// Scans multiple messaging app databases and deduplicates results

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use rusqlite::Connection;
use chrono::{Utc, TimeZone};
use md5::{Md5, Digest};
use super::android::{get_bundled_adb_path, create_hidden_command};
use super::android_sms::{SmsMessage, MessageType};
use crate::dlog;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSilo {
    pub silo_name: String,
    pub app_package: String,
    pub database_path: String,
    pub is_accessible: bool,
    pub message_count: usize,
    pub requires_root: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiSiloResult {
    pub total_messages: usize,
    pub unique_messages: usize,
    pub duplicates_removed: usize,
    pub silos_scanned: Vec<MessageSilo>,
    pub messages: Vec<SmsMessage>,
    pub extraction_summary: String,
}

/// Message fingerprint for deduplication
#[derive(Hash, Eq, PartialEq, Debug)]
struct MessageFingerprint {
    timestamp: i64,
    body_hash: String,
    address: String,
}

impl MessageFingerprint {
    fn from_message(msg: &SmsMessage) -> Self {
        // Use a 10-second window for timestamp matching (accounts for clock drift)
        let normalized_timestamp = (msg.date / 10000) * 10000;
        
        // Normalize body: lowercase, remove whitespace
        let normalized_body = msg.body
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        
        // Simple hash of body
        let mut hasher = Md5::new();
        hasher.update(&normalized_body);
        let body_hash = format!("{:x}", hasher.finalize());
        
        MessageFingerprint {
            timestamp: normalized_timestamp,
            body_hash,
            address: msg.address.clone(),
        }
    }
}

/// Check if running inside Samsung Knox container
fn is_knox_container(app_handle: &tauri::AppHandle, device_id: Option<&str>) -> Result<bool, String> {
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    cmd.args(&["shell", "getprop", "ro.samsung.knox.container"]);
    
    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.trim() == "1" || stdout.contains("true"))
        }
        Err(_) => Ok(false)
    }
}

/// Get Knox telephony provider URI if in Knox container
fn get_knox_sms_uri(app_handle: &tauri::AppHandle, device_id: Option<&str>) -> Result<String, String> {
    if is_knox_container(app_handle, device_id)? {
        // Knox uses isolated content provider
        Ok("content://com.samsung.knox.securefolder.sms/".to_string())
    } else {
        Ok("content://sms/".to_string())
    }
}

/// Scan Google RCS/Messages (Bugle DB)
fn scan_google_messages(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    has_root: bool
) -> Result<Vec<SmsMessage>, String> {
    eprintln!("[Multi-Silo] Scanning Google Messages (Bugle DB)...");
    
    let db_path = "/data/data/com.google.android.apps.messaging/databases/bugle_db";
    let temp_dir = std::env::temp_dir().join("hindsight_android_messages");
    std::fs::create_dir_all(&temp_dir).ok();
    
    let local_db = temp_dir.join("bugle_db");
    
    // Pull database
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    if has_root {
        cmd.args(&["shell", "su", "-c", &format!("cat {}", db_path)]);
    } else {
        // Try run-as method
        cmd.args(&["shell", "run-as", "com.google.android.apps.messaging", "cat", "databases/bugle_db"]);
    }
    
    let output = cmd.output().map_err(|e| format!("Failed to pull Google Messages DB: {}", e))?;
    
    if !output.status.success() {
        return Err("Cannot access Google Messages database. App not installed or no permission.".to_string());
    }
    
    std::fs::write(&local_db, &output.stdout).map_err(|e| format!("Failed to write DB: {}", e))?;
    
    // Parse bugle_db
    parse_bugle_db(&local_db)
}

/// Parse Google Messages bugle_db
fn parse_bugle_db(db_path: &Path) -> Result<Vec<SmsMessage>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open bugle_db: {}", e))?;
    
    let mut messages = Vec::new();
    
    // Query bugle_db structure
    // Main tables: messages, parts, conversations, participants
    let query = r#"
        SELECT 
            m._id as msg_id,
            m.conversation_id,
            m.sender_participant_id,
            m.received_timestamp,
            m.sent_timestamp,
            m.message_status,
            m.read,
            p.text as body,
            p.content_type,
            conv.name as thread_name,
            part.normalized_destination as address
        FROM messages m
        LEFT JOIN parts p ON m._id = p.message_id
        LEFT JOIN conversations conv ON m.conversation_id = conv._id
        LEFT JOIN participants part ON m.sender_participant_id = part._id
        WHERE p.text IS NOT NULL
        ORDER BY m.received_timestamp DESC
        LIMIT 5000
    "#;
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let rows = stmt.query_map([], |row| {
        Ok(SmsMessage {
            id: row.get::<_, i64>(0)?,
            thread_id: row.get::<_, i64>(1).unwrap_or(0),
            address: row.get::<_, Option<String>>(10)?.unwrap_or_else(|| "Unknown".to_string()),
            person: None,
            date: row.get::<_, i64>(3)?,
            date_sent: row.get::<_, i64>(4)?,
            date_formatted: format_timestamp(row.get::<_, i64>(3)?),
            message_type: MessageType::Inbox, // Determine from status
            body: row.get::<_, Option<String>>(7)?.unwrap_or_else(|| String::new()),
            read: row.get::<_, i64>(6)? == 1,
            status: row.get::<_, i32>(5).unwrap_or(0),
            service_center: None,
            subject: None,
            has_attachments: false,
            attachment_count: 0,
            attachments: Vec::new(),
        })
    }).map_err(|e| format!("Query failed: {}", e))?;
    
    for row in rows {
        if let Ok(msg) = row {
            messages.push(msg);
        }
    }
    
    eprintln!("[Multi-Silo] Google Messages: Found {} messages", messages.len());
    Ok(messages)
}

/// Scan Samsung OEM messaging app
fn scan_samsung_messages(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    has_root: bool
) -> Result<Vec<SmsMessage>, String> {
    eprintln!("[Multi-Silo] Scanning Samsung Messages...");
    
    let db_path = "/data/data/com.samsung.android.messaging/databases/message.db";
    let temp_dir = std::env::temp_dir().join("hindsight_android_messages");
    std::fs::create_dir_all(&temp_dir).ok();
    
    let local_db = temp_dir.join("samsung_message.db");
    
    // Pull database
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    if has_root {
        cmd.args(&["shell", "su", "-c", &format!("cat {}", db_path)]);
    } else {
        return Err("Samsung Messages database requires root access".to_string());
    }
    
    let output = cmd.output().map_err(|e| format!("Failed to pull Samsung Messages DB: {}", e))?;
    
    if !output.status.success() {
        return Err("Cannot access Samsung Messages database".to_string());
    }
    
    std::fs::write(&local_db, &output.stdout).map_err(|e| format!("Failed to write DB: {}", e))?;
    
    // Parse Samsung message.db (similar structure to standard SMS)
    parse_samsung_db(&local_db)
}

/// Parse Samsung message.db
fn parse_samsung_db(db_path: &Path) -> Result<Vec<SmsMessage>, String> {
    let conn = Connection::open(db_path)
        .map_err(|e| format!("Failed to open Samsung message.db: {}", e))?;
    
    let mut messages = Vec::new();
    
    // Samsung uses similar schema to AOSP telephony provider
    let query = r#"
        SELECT 
            _id, thread_id, address, person, date, date_sent, type, body, read, status,
            service_center, subject
        FROM sms
        WHERE body IS NOT NULL AND body != ''
        ORDER BY date DESC
        LIMIT 5000
    "#;
    
    let mut stmt = conn.prepare(query)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let rows = stmt.query_map([], |row| {
        Ok(SmsMessage {
            id: row.get(0)?,
            thread_id: row.get(1)?,
            address: row.get::<_, Option<String>>(2)?.unwrap_or_else(|| "Unknown".to_string()),
            person: row.get(3)?,
            date: row.get(4)?,
            date_sent: row.get(5)?,
            date_formatted: format_timestamp(row.get::<_, i64>(4)?),
            message_type: MessageType::from_i32(row.get(6)?),
            body: row.get::<_, Option<String>>(7)?.unwrap_or_else(|| String::new()),
            read: row.get::<_, i32>(8)? == 1,
            status: row.get(9)?,
            service_center: row.get(10)?,
            subject: row.get(11)?,
            has_attachments: false,
            attachment_count: 0,
            attachments: Vec::new(),
        })
    }).map_err(|e| format!("Query failed: {}", e))?;
    
    for row in rows {
        if let Ok(msg) = row {
            messages.push(msg);
        }
    }
    
    eprintln!("[Multi-Silo] Samsung Messages: Found {} messages", messages.len());
    Ok(messages)
}

/// Scan Samsung Recycle Bin for deleted messages
fn scan_samsung_recycle_bin(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>,
    has_root: bool
) -> Result<Vec<SmsMessage>, String> {
    eprintln!("[Multi-Silo] Scanning Samsung Recycle Bin...");
    
    if !has_root {
        return Err("Samsung Recycle Bin requires root access".to_string());
    }
    
    // Samsung may store deleted messages with a flag or in a separate table
    // Check for 'deleted' column or 'recycle' table
    let db_path = "/data/data/com.samsung.android.messaging/databases/message.db";
    let temp_dir = std::env::temp_dir().join("hindsight_android_messages");
    let local_db = temp_dir.join("samsung_message.db");
    
    // Database should already be pulled by scan_samsung_messages
    if !local_db.exists() {
        return Err("Samsung database not available".to_string());
    }
    
    let conn = Connection::open(&local_db)
        .map_err(|e| format!("Failed to open Samsung DB: {}", e))?;
    
    // Check if deleted column exists
    let has_deleted_column: bool = conn.query_row(
        "PRAGMA table_info(sms)",
        [],
        |row| {
            let col_name: String = row.get(1)?;
            Ok(col_name == "deleted" || col_name == "is_deleted")
        }
    ).unwrap_or(false);
    
    let mut messages = Vec::new();
    
    if has_deleted_column {
        let query = r#"
            SELECT 
                _id, thread_id, address, person, date, date_sent, type, body, read, status,
                service_center, subject
            FROM sms
            WHERE (deleted = 1 OR is_deleted = 1) AND body IS NOT NULL
            ORDER BY date DESC
            LIMIT 1000
        "#;
        
        let mut stmt = conn.prepare(query)
            .map_err(|e| format!("Failed to prepare query: {}", e))?;
        
        let rows = stmt.query_map([], |row| {
            Ok(SmsMessage {
                id: row.get(0)?,
                thread_id: row.get(1)?,
                address: row.get::<_, Option<String>>(2)?.unwrap_or_else(|| "Unknown".to_string()),
                person: row.get(3)?,
                date: row.get(4)?,
                date_sent: row.get(5)?,
                date_formatted: format_timestamp(row.get::<_, i64>(4)?),
                message_type: MessageType::from_i32(row.get(6)?),
                body: format!("[DELETED] {}", row.get::<_, Option<String>>(7)?.unwrap_or_else(|| String::new())),
                read: row.get::<_, i32>(8)? == 1,
                status: row.get(9)?,
                service_center: row.get(10)?,
                subject: row.get(11)?,
                has_attachments: false,
                attachment_count: 0,
                attachments: Vec::new(),
            })
        }).map_err(|e| format!("Query failed: {}", e))?;
        
        for row in rows {
            if let Ok(msg) = row {
                messages.push(msg);
            }
        }
    }
    
    eprintln!("[Multi-Silo] Samsung Recycle Bin: Found {} deleted messages", messages.len());
    Ok(messages)
}

/// Deduplicate messages using fingerprinting
fn deduplicate_messages(messages: Vec<SmsMessage>) -> (Vec<SmsMessage>, usize) {
    let mut seen = HashSet::new();
    let mut unique_messages = Vec::new();
    let mut duplicates = 0;
    
    for msg in messages {
        let fingerprint = MessageFingerprint::from_message(&msg);
        
        if seen.insert(fingerprint) {
            unique_messages.push(msg);
        } else {
            duplicates += 1;
        }
    }
    
    eprintln!("[Multi-Silo] Deduplication: {} unique messages, {} duplicates removed", 
              unique_messages.len(), duplicates);
    
    (unique_messages, duplicates)
}

/// Main multi-silo message extraction
pub fn extract_messages_multisilo(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>
) -> Result<MultiSiloResult, String> {
    eprintln!("[Multi-Silo] Starting multi-silo message discovery...");
    dlog!("[MULTISILO] Starting multi-silo discovery");
    
    let mut all_messages = Vec::new();
    let mut silos_scanned = Vec::new();
    
    // Check root access
    let has_root = check_root_access(app_handle, device_id);
    eprintln!("[Multi-Silo] Root access: {}", has_root);
    dlog!("[MULTISILO] Root access: {}", has_root);
    
    // Silo 1: Standard Android Telephony Provider
    eprintln!("[Multi-Silo] Silo 1: Standard Telephony Provider");
    dlog!("[MULTISILO] Silo 1 START: Standard Telephony (content://sms --limit 5000)");
    let t1 = std::time::Instant::now();
    match extract_standard_telephony(app_handle, device_id) {
        Ok(messages) => {
            let count = messages.len();
            dlog!("[MULTISILO] Silo 1 OK in {}ms — {} messages", t1.elapsed().as_millis(), count);
            silos_scanned.push(MessageSilo {
                silo_name: "Standard Telephony".to_string(),
                app_package: "com.android.providers.telephony".to_string(),
                database_path: "content://sms/".to_string(),
                is_accessible: true,
                message_count: count,
                requires_root: false,
            });
            all_messages.extend(messages);
            eprintln!("[Multi-Silo] ✓ Standard Telephony: {} messages", count);
        }
        Err(e) => {
            dlog!("[MULTISILO] Silo 1 FAILED in {}ms — {}", t1.elapsed().as_millis(), e);
            eprintln!("[Multi-Silo] ✗ Standard Telephony failed: {}", e);
        }
    }
    
    // Silo 2: Google RCS/Messages (Bugle DB)
    eprintln!("[Multi-Silo] Silo 2: Google Messages (RCS)");
    dlog!("[MULTISILO] Silo 2 START: Google Messages bugle_db (run-as or root)");
    let t2 = std::time::Instant::now();
    match scan_google_messages(app_handle, device_id, has_root) {
        Ok(messages) => {
            let count = messages.len();
            dlog!("[MULTISILO] Silo 2 OK in {}ms — {} messages", t2.elapsed().as_millis(), count);
            silos_scanned.push(MessageSilo {
                silo_name: "Google Messages (RCS)".to_string(),
                app_package: "com.google.android.apps.messaging".to_string(),
                database_path: "/data/data/com.google.android.apps.messaging/databases/bugle_db".to_string(),
                is_accessible: true,
                message_count: count,
                requires_root: !has_root,
            });
            all_messages.extend(messages);
            eprintln!("[Multi-Silo] ✓ Google Messages: {} messages", count);
        }
        Err(e) => {
            dlog!("[MULTISILO] Silo 2 FAILED in {}ms — {}", t2.elapsed().as_millis(), e);
            eprintln!("[Multi-Silo] ✗ Google Messages failed: {}", e);
            silos_scanned.push(MessageSilo {
                silo_name: "Google Messages (RCS)".to_string(),
                app_package: "com.google.android.apps.messaging".to_string(),
                database_path: "/data/data/com.google.android.apps.messaging/databases/bugle_db".to_string(),
                is_accessible: false,
                message_count: 0,
                requires_root: true,
            });
        }
    }
    
    // Silo 3: Samsung OEM Messages
    eprintln!("[Multi-Silo] Silo 3: Samsung Messages");
    dlog!("[MULTISILO] Silo 3 START: Samsung Messages message.db (root only)");
    let t3 = std::time::Instant::now();
    match scan_samsung_messages(app_handle, device_id, has_root) {
        Ok(messages) => {
            let count = messages.len();
            dlog!("[MULTISILO] Silo 3 OK in {}ms — {} messages", t3.elapsed().as_millis(), count);
            silos_scanned.push(MessageSilo {
                silo_name: "Samsung Messages".to_string(),
                app_package: "com.samsung.android.messaging".to_string(),
                database_path: "/data/data/com.samsung.android.messaging/databases/message.db".to_string(),
                is_accessible: true,
                message_count: count,
                requires_root: true,
            });
            all_messages.extend(messages);
            eprintln!("[Multi-Silo] ✓ Samsung Messages: {} messages", count);
        }
        Err(e) => {
            dlog!("[MULTISILO] Silo 3 FAILED in {}ms — {}", t3.elapsed().as_millis(), e);
            eprintln!("[Multi-Silo] ✗ Samsung Messages failed: {}", e);
        }
    }
    
    // Silo 4: Samsung Recycle Bin
    eprintln!("[Multi-Silo] Silo 4: Samsung Recycle Bin (Deleted Messages)");
    dlog!("[MULTISILO] Silo 4 START: Samsung Recycle Bin (root only)");
    let t4 = std::time::Instant::now();
    match scan_samsung_recycle_bin(app_handle, device_id, has_root) {
        Ok(messages) => {
            let count = messages.len();
            dlog!("[MULTISILO] Silo 4 OK in {}ms — {} messages", t4.elapsed().as_millis(), count);
            silos_scanned.push(MessageSilo {
                silo_name: "Samsung Recycle Bin".to_string(),
                app_package: "com.samsung.android.messaging".to_string(),
                database_path: "/data/data/com.samsung.android.messaging/databases/message.db (deleted)".to_string(),
                is_accessible: true,
                message_count: count,
                requires_root: true,
            });
            all_messages.extend(messages);
            eprintln!("[Multi-Silo] ✓ Samsung Recycle Bin: {} messages", count);
        }
        Err(e) => {
            dlog!("[MULTISILO] Silo 4 FAILED in {}ms — {}", t4.elapsed().as_millis(), e);
            eprintln!("[Multi-Silo] ✗ Samsung Recycle Bin failed: {}", e);
        }
    }
    
    // Silo 5: Knox/Secure Folder (if applicable)
    if is_knox_container(app_handle, device_id).unwrap_or(false) {
        eprintln!("[Multi-Silo] Silo 5: Samsung Knox Secure Folder");
        match extract_knox_messages(app_handle, device_id) {
            Ok(messages) => {
                let count = messages.len();
                silos_scanned.push(MessageSilo {
                    silo_name: "Knox Secure Folder".to_string(),
                    app_package: "com.samsung.knox.securefolder".to_string(),
                    database_path: "content://com.samsung.knox.securefolder.sms/".to_string(),
                    is_accessible: true,
                    message_count: count,
                    requires_root: false,
                });
                all_messages.extend(messages);
                eprintln!("[Multi-Silo] ✓ Knox Messages: {} messages", count);
            }
            Err(e) => {
                eprintln!("[Multi-Silo] ✗ Knox Messages failed: {}", e);
            }
        }
    }
    
    let total_before_dedup = all_messages.len();
    
    // Deduplicate
    let (unique_messages, duplicates) = deduplicate_messages(all_messages);
    
    let summary = format!(
        "Scanned {} message silos. Found {} total messages, {} unique after deduplication ({} duplicates removed).",
        silos_scanned.len(),
        total_before_dedup,
        unique_messages.len(),
        duplicates
    );
    
    eprintln!("[Multi-Silo] {}", summary);
    
    Ok(MultiSiloResult {
        total_messages: total_before_dedup,
        unique_messages: unique_messages.len(),
        duplicates_removed: duplicates,
        silos_scanned,
        messages: unique_messages,
        extraction_summary: summary,
    })
}

/// Extract messages from standard Android telephony provider
fn extract_standard_telephony(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>
) -> Result<Vec<SmsMessage>, String> {
    // Use Knox URI if in Knox container
    let sms_uri = get_knox_sms_uri(app_handle, device_id)?;
    
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    cmd.args(&[
        "shell",
        &format!("content query --uri {} --projection _id:thread_id:address:person:date:date_sent:type:body:read:status --sort 'date DESC' --limit 5000", sms_uri)
    ]);
    
    let output = cmd.output().map_err(|e| format!("Failed to query telephony: {}", e))?;
    
    if !output.status.success() {
        return Err("Failed to access standard telephony provider".to_string());
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_content_provider_output(&stdout)
}

/// Extract messages from Knox secure folder
fn extract_knox_messages(
    app_handle: &tauri::AppHandle,
    device_id: Option<&str>
) -> Result<Vec<SmsMessage>, String> {
    extract_standard_telephony(app_handle, device_id) // Will use Knox URI automatically
}

/// Parse content provider output
fn parse_content_provider_output(output: &str) -> Result<Vec<SmsMessage>, String> {
    let mut messages = Vec::new();
    
    for line in output.lines() {
        if line.starts_with("Row:") {
            // Parse content provider row format
            // Example: Row: 0 _id=123, thread_id=45, address=+1234567890, ...
            let mut id = 0i64;
            let mut thread_id = 0i64;
            let mut address = String::new();
            let mut person = None;
            let mut date = 0i64;
            let mut date_sent = 0i64;
            let mut msg_type = 1i32;
            let mut body = String::new();
            let mut read = false;
            let mut status = 0i32;
            
            for part in line.split(',') {
                let part = part.trim();
                if let Some(eq_pos) = part.find('=') {
                    let key = part[..eq_pos].trim();
                    let value = part[eq_pos + 1..].trim();
                    
                    match key {
                        "_id" => id = value.parse().unwrap_or(0),
                        "thread_id" => thread_id = value.parse().unwrap_or(0),
                        "address" => address = value.to_string(),
                        "person" => person = Some(value.to_string()),
                        "date" => date = value.parse().unwrap_or(0),
                        "date_sent" => date_sent = value.parse().unwrap_or(0),
                        "type" => msg_type = value.parse().unwrap_or(1),
                        "body" => body = value.to_string(),
                        "read" => read = value == "1",
                        "status" => status = value.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            
            if !body.is_empty() {
                messages.push(SmsMessage {
                    id,
                    thread_id,
                    address,
                    person,
                    date,
                    date_sent,
                    date_formatted: format_timestamp(date),
                    message_type: MessageType::from_i32(msg_type),
                    body,
                    read,
                    status,
                    service_center: None,
                    subject: None,
                    has_attachments: false,
                    attachment_count: 0,
                    attachments: Vec::new(),
                });
            }
        }
    }
    
    Ok(messages)
}

/// Check if device has root access
fn check_root_access(app_handle: &tauri::AppHandle, device_id: Option<&str>) -> bool {
    let adb_path = get_bundled_adb_path(app_handle);
    let mut cmd = create_hidden_command(&adb_path);
    
    if let Some(device) = device_id {
        cmd.arg("-s").arg(device);
    }
    
    cmd.args(&["shell", "su", "-c", "id"]);
    
    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("uid=0")
        }
        Err(_) => false
    }
}

/// Format Unix timestamp to readable string
fn format_timestamp(timestamp: i64) -> String {
    if timestamp == 0 {
        return "Unknown".to_string();
    }
    
    let datetime = Utc.timestamp_millis_opt(timestamp).single();
    match datetime {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Invalid Date".to_string()
    }
}
