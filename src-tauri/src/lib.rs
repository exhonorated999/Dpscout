mod scanner;
mod settings;
mod system_info;
mod events;
mod reporter;
mod hash_db;
mod security;
mod platform;
mod media_server;
mod thumbnail_generator;
mod licensing;

use scanner::QuestionableApp;
use scanner::questionable_apps;
use scanner::media::{self, MediaFile, MediaScanOptions};
use scanner::browser::{self, BrowserData};
use scanner::keyword::{self, KeywordMatch, KeywordScanOptions, load_keyword_lists_from_dir, get_default_scan_paths, get_scan_paths_for_drives};
use scanner::intrusion::{self, IntrusionScanResults, IntrusionScanOptions};
use scanner::android::{self, AndroidDevice, AndroidApp, AndroidBrowserData, AndroidHashMatch};
use scanner::ios::{self, IosDevice, IosApp, IosBackupData, IosMessage, IosContact, IosCall, IosBrowserHistory};
use scanner::ios_live::{self, LiveIosDevice, IosLiveTriageResults};
use settings::{AppSettings, load_settings, save_settings, import_project_vic, initialize_directories};
use system_info::{SystemInfo, collect_system_info};
use platform::TargetSystem;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use tauri::Manager;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn get_trial_status() -> Result<security::TrialStatus, String> {
    security::get_trial_status()
}

// ---------------------------------------------------------------------------
// Licensing commands (server-backed)
// ---------------------------------------------------------------------------

#[tauri::command]
fn register_agency(data: licensing::RegistrationData) -> Result<licensing::RegisterResponse, String> {
    licensing::register_agency(data)
}

#[tauri::command]
fn get_license_status() -> Result<licensing::LicenseInfo, String> {
    licensing::get_license_status()
}

#[tauri::command]
fn activate_license_key(license_key: String) -> Result<licensing::ActivateResponse, String> {
    licensing::activate_license_key(license_key)
}

#[tauri::command]
fn check_for_updates() -> Result<licensing::UpdateInfo, String> {
    licensing::check_for_updates()
}

#[tauri::command]
fn submit_bug_report(data: licensing::BugReportData) -> Result<licensing::BugReportResponse, String> {
    licensing::submit_bug_report(data)
}

#[tauri::command]
fn is_agency_registered() -> Result<bool, String> {
    Ok(licensing::is_registration_saved())
}

#[tauri::command]
fn scan_questionable_applications() -> Result<Vec<QuestionableApp>, String> {
    eprintln!("=== SCANNING APPLICATIONS ===");
    let result = questionable_apps::scan_questionable_apps()
        .map_err(|e| format!("Failed to scan applications: {}", e))?;
    eprintln!("Total apps found: {}", result.len());
    if result.len() > 0 {
        eprintln!("First 5 apps:");
        for (i, app) in result.iter().take(5).enumerate() {
            eprintln!("  {}: {} -> {:?}", i+1, app.name, app.category);
        }
    }
    eprintln!("=== SCAN COMPLETE ===");
    Ok(result)
}

#[tauri::command]
fn get_settings() -> Result<AppSettings, String> {
    load_settings()
}

#[tauri::command]
fn get_category_mappings() -> Result<scanner::simple_categorizer::CategoryMappings, String> {
    scanner::simple_categorizer::CategoryMappings::load()
        .map_err(|e| format!("Failed to load category mappings: {}", e))
}

#[tauri::command]
fn save_category_mappings(mappings: scanner::simple_categorizer::CategoryMappings) -> Result<(), String> {
    mappings.save()
        .map_err(|e| format!("Failed to save category mappings: {}", e))
}

#[tauri::command]
fn add_category_mapping(keyword: String, category: String) -> Result<(), String> {
    let mut mappings = scanner::simple_categorizer::CategoryMappings::load()
        .map_err(|e| format!("Failed to load mappings: {}", e))?;
    
    mappings.mappings.insert(keyword.to_lowercase(), category);
    
    mappings.save()
        .map_err(|e| format!("Failed to save mappings: {}", e))
}

#[tauri::command]
fn remove_category_mapping(keyword: String) -> Result<(), String> {
    let mut mappings = scanner::simple_categorizer::CategoryMappings::load()
        .map_err(|e| format!("Failed to load mappings: {}", e))?;
    
    mappings.mappings.remove(&keyword.to_lowercase());
    
    mappings.save()
        .map_err(|e| format!("Failed to save mappings: {}", e))
}

#[tauri::command]
async fn get_system_info() -> Result<SystemInfo, String> {
    tauri::async_runtime::spawn_blocking(|| {
        collect_system_info()
    }).await.map_err(|e| format!("System info thread panicked: {}", e))?
}

// #[tauri::command]
// fn start_progressive_scan(
//     app: tauri::AppHandle,
//     scan_apps: bool,
//     scan_browser: bool,
// ) -> Result<(), String> {
//     // Temporarily disabled for debugging
//     Ok(())
// }

#[tauri::command]
fn save_app_settings(settings: AppSettings) -> Result<(), String> {
    save_settings(&settings)
}

#[tauri::command]
fn initialize_app() -> Result<(), String> {
    initialize_directories()
}

#[tauri::command]
async fn import_vic_hash_list(json_path: String) -> Result<settings::HashList, String> {
    tauri::async_runtime::spawn_blocking(move || {
        import_project_vic(json_path)
    }).await.map_err(|e| format!("VIC import thread panicked: {}", e))?
}

#[derive(Clone, Serialize)]
struct HashImportProgress {
    stage: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<usize>,
}

#[tauri::command]
async fn import_txt_hash_list(
    app: tauri::AppHandle,
    txt_path: String,
    list_name: String,
    hash_type: String, // "MD5", "SHA1", or "SHA256"
) -> Result<settings::HashList, String> {
    use tauri::Emitter;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    
    eprintln!("[Hash Import] Importing text file: {}", txt_path);
    eprintln!("[Hash Import] List name: {}", list_name);
    eprintln!("[Hash Import] Hash type: {}", hash_type);
    
    let expected_len = match hash_type.as_str() {
        "MD5" => 32,
        "SHA1" => 40,
        "SHA256" => 64,
        _ => return Err(format!("Invalid hash type: {}", hash_type)),
    };
    
    let file = File::open(&txt_path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    
    let _ = app.emit("hash-import-progress", HashImportProgress {
        stage: "importing".to_string(),
        message: format!("Streaming import of {:.1} MB file...", file_size as f64 / 1_048_576.0),
        total: None,
        progress: None,
    });
    
    let hash_db = hash_db::HashDatabase::new()?;
    let list_id = hash_db.import_hash_list(
        &list_name,
        &format!("Text file: {}", std::path::Path::new(&txt_path).file_name().unwrap_or_default().to_string_lossy()),
        &hash_type,
    )?;
    
    // Stream: read lines, accumulate 50K batch, flush, repeat — peak RAM ~5MB
    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut batch: Vec<(String, String, Option<String>, Option<String>)> = Vec::with_capacity(50_000);
    let mut imported_count = 0u64;
    let mut skipped = 0u64;
    let batch_flush_size = 50_000;
    
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim();
        
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        
        let hash = line.split_whitespace().next().unwrap_or(line).to_lowercase();
        
        if hash.len() == expected_len && hash.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
            batch.push((hash, hash_type.clone(), None, None));
        } else {
            skipped += 1;
            if skipped <= 3 {
                eprintln!("[Hash Import] Skipping invalid hash: {}", &line[..line.len().min(80)]);
            }
            continue;
        }
        
        if batch.len() >= batch_flush_size {
            hash_db.add_hashes_batch(list_id, &batch).ok();
            imported_count += batch.len() as u64;
            batch.clear();
            
            let _ = app.emit("hash-import-progress", HashImportProgress {
                stage: "importing".to_string(),
                message: format!("Imported {} hashes...", imported_count),
                total: None,
                progress: Some(imported_count as usize),
            });
            eprintln!("[Hash Import] {} hashes imported...", imported_count);
        }
    }
    
    // Flush remaining
    if !batch.is_empty() {
        hash_db.add_hashes_batch(list_id, &batch).ok();
        imported_count += batch.len() as u64;
        batch.clear();
    }
    
    if imported_count == 0 {
        return Err("No valid hashes found in file".to_string());
    }
    
    // Update hash count on the list record
    hash_db.update_list_hash_count(list_id, imported_count).ok();
    
    if skipped > 0 {
        eprintln!("[Hash Import] Skipped {} invalid lines", skipped);
    }
    eprintln!("✓ Text hash list imported: {} hashes", imported_count);
    
    // Reload memory cache
    let _ = app.emit("hash-import-progress", HashImportProgress {
        stage: "loading".to_string(),
        message: format!("Loading {} hashes into memory...", imported_count),
        total: Some(imported_count as usize),
        progress: Some(imported_count as usize),
    });
    let _ = hash_db.load_hashes_into_memory();
    
    let _ = app.emit("hash-import-progress", HashImportProgress {
        stage: "complete".to_string(),
        message: format!("Imported {} hashes!", imported_count),
        total: Some(imported_count as usize),
        progress: Some(imported_count as usize),
    });
    
    // Return lightweight HashList (no individual hashes — would be 19M entries)
    let now = chrono::Utc::now().to_rfc3339();
    let hash_list = settings::HashList {
        id: uuid::Uuid::new_v4().to_string(),
        name: list_name.clone(),
        description: format!("Imported from text file: {} hashes", imported_count),
        source: format!("Text file: {}", std::path::Path::new(&txt_path).file_name().unwrap_or_default().to_string_lossy()),
        hash_type: match hash_type.as_str() {
            "MD5" => settings::HashType::MD5,
            "SHA1" => settings::HashType::SHA1,
            "SHA256" => settings::HashType::SHA256,
            _ => settings::HashType::SHA256,
        },
        hashes: Vec::new(), // Don't return 19M entries — DB is source of truth
        hash_count: imported_count as usize,
        enabled: true,
        created_at: now.clone(),
        modified_at: now,
    };
    
    eprintln!("✓ Text hash list imported successfully: {} hashes", imported_count);
    Ok(hash_list)
}

#[tauri::command]
async fn import_and_load_hash_list(
    app: tauri::AppHandle,
    json_path: String
) -> Result<settings::HashList, String> {
    use tauri::Emitter;
    
    let _ = app.emit("hash-import-progress", HashImportProgress {
        stage: "parsing".to_string(),
        message: "Analyzing file...".to_string(),
        total: None,
        progress: None,
    });
    
    // Check file size — large files use streaming import (no full-memory load)
    let file_size = std::fs::metadata(&json_path)
        .map(|m| m.len())
        .unwrap_or(0);
    
    let is_large = file_size > 10_000_000; // >10 MB → streaming path
    eprintln!("[Hash Import] File: {} ({:.1} MB) — using {} path", 
        json_path, file_size as f64 / 1_048_576.0, if is_large { "streaming" } else { "standard" });
    
    if is_large {
        // ── STREAMING PATH: mmap + brace-counting, ~50MB peak RAM ──
        let _ = app.emit("hash-import-progress", HashImportProgress {
            stage: "importing".to_string(),
            message: format!("Streaming import of {:.0} MB file...", file_size as f64 / 1_048_576.0),
            total: None,
            progress: None,
        });
        
        let file_name = std::path::Path::new(&json_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Project VIC Import")
            .to_string();
        
        let hash_db = hash_db::HashDatabase::new()?;
        let app_clone = app.clone();
        let imported_count = hash_db.import_vic_json(&json_path, &file_name, move |imported, scanned| {
            let _ = app_clone.emit("hash-import-progress", HashImportProgress {
                stage: "importing".to_string(),
                message: format!("Streaming import... {} hashes from {} objects", imported, scanned),
                total: None,
                progress: Some(imported as usize),
            });
        })?;
        
        // Reload in-memory cache with new hashes
        let _ = app.emit("hash-import-progress", HashImportProgress {
            stage: "loading".to_string(),
            message: format!("Loading {} hashes into memory for fast scanning...", imported_count),
            total: Some(imported_count as usize),
            progress: Some(imported_count as usize),
        });
        let _ = hash_db.load_hashes_into_memory();
        
        let _ = app.emit("hash-import-progress", HashImportProgress {
            stage: "complete".to_string(),
            message: format!("Imported {} hashes!", imported_count),
            total: Some(imported_count as usize),
            progress: Some(imported_count as usize),
        });
        
        // Return metadata-only HashList (hashes: [] — they live in SQLite only)
        let now = chrono::Utc::now().to_rfc3339();
        let hash_list = settings::HashList {
            id: chrono::Utc::now().timestamp().to_string(),
            name: file_name,
            description: format!("Project VIC — {} hashes from {}", imported_count, 
                std::path::Path::new(&json_path).file_name().unwrap_or_default().to_string_lossy()),
            hash_type: settings::HashType::MD5, // VIC primarily uses MD5
            hashes: vec![], // DB-only — no inline hashes
            hash_count: imported_count as usize,
            enabled: true,
            source: "Project VIC".to_string(),
            created_at: now.clone(),
            modified_at: now,
        };
        
        eprintln!("✓ Streaming import complete: {} hashes (metadata-only HashList)", imported_count);
        Ok(hash_list)
    } else {
        // ── STANDARD PATH: small files, load into memory ──
        let _ = app.emit("hash-import-progress", HashImportProgress {
            stage: "parsing".to_string(),
            message: "Reading JSON file...".to_string(),
            total: None,
            progress: None,
        });
        
        let hash_list = import_project_vic(json_path)?;
        let total_hashes = hash_list.hashes.len();
        
        let _ = app.emit("hash-import-progress", HashImportProgress {
            stage: "importing".to_string(),
            message: format!("Importing {} hashes...", total_hashes),
            total: Some(total_hashes),
            progress: Some(0),
        });
        
        let hash_db = hash_db::HashDatabase::new()?;
        
        let default_hash_type = match hash_list.hash_type {
            settings::HashType::MD5 => "MD5",
            settings::HashType::SHA1 => "SHA1",
            settings::HashType::SHA256 => "SHA256",
        };
        
        let list_id = hash_db.import_hash_list(
            &hash_list.name,
            &hash_list.source,
            default_hash_type,
        )?;
        
        let batch_size = 5000;
        for (batch_idx, chunk) in hash_list.hashes.chunks(batch_size).enumerate() {
            let batch_data: Vec<(String, String, Option<String>, Option<String>)> = chunk.iter().map(|entry| {
                let hash_type_str = match entry.hash.len() {
                    32 => "MD5".to_string(),
                    40 => "SHA1".to_string(),
                    64 => "SHA256".to_string(),
                    _ => default_hash_type.to_string(),
                };
                (entry.hash.clone(), hash_type_str, entry.category.clone(), entry.description.clone())
            }).collect();
            
            hash_db.add_hashes_batch(list_id, &batch_data).ok();
            
            let processed = ((batch_idx + 1) * batch_size).min(hash_list.hashes.len());
            let _ = app.emit("hash-import-progress", HashImportProgress {
                stage: "importing".to_string(),
                message: format!("Imported {} of {} hashes...", processed, total_hashes),
                total: Some(total_hashes),
                progress: Some(processed),
            });
        }
        
        // Reload in-memory cache
        let _ = hash_db.load_hashes_into_memory();
        
        let _ = app.emit("hash-import-progress", HashImportProgress {
            stage: "complete".to_string(),
            message: "Import complete!".to_string(),
            total: Some(total_hashes),
            progress: Some(total_hashes),
        });
        
        eprintln!("✓ Hash list imported successfully");
        Ok(hash_list)
    }
}

#[tauri::command]
fn load_hash_list_into_db(hash_list: settings::HashList) -> Result<(), String> {
    let hash_db = hash_db::HashDatabase::new()?;
    
    eprintln!("Importing hash list: {} with {} hashes", hash_list.name, hash_list.hashes.len());
    
    // Default hash type from the list
    let default_hash_type = match hash_list.hash_type {
        settings::HashType::MD5 => "MD5",
        settings::HashType::SHA1 => "SHA1",
        settings::HashType::SHA256 => "SHA256",
    };
    
    // Import the hash list
    let list_id = hash_db.import_hash_list(
        &hash_list.name,
        &hash_list.source,
        default_hash_type,
    )?;
    
    // Import all hashes in batches, auto-detecting hash type for each hash
    let batch_size = 5000;
    for chunk in hash_list.hashes.chunks(batch_size) {
        let batch_data: Vec<(String, String, Option<String>, Option<String>)> = chunk.iter().map(|entry| {
            let hash_type_str = match entry.hash.len() {
                32 => "MD5".to_string(),
                40 => "SHA1".to_string(),
                64 => "SHA256".to_string(),
                _ => default_hash_type.to_string(),
            };
            (entry.hash.clone(), hash_type_str, entry.category.clone(), entry.description.clone())
        }).collect();
        
        hash_db.add_hashes_batch(list_id, &batch_data).ok();
    }
    
    eprintln!("✓ Hash list imported successfully");
    Ok(())
}

#[tauri::command]
fn get_hash_database_stats() -> Result<hash_db::DatabaseStats, String> {
    let hash_db = hash_db::HashDatabase::new()?;
    hash_db.get_stats()
}

#[tauri::command]
fn get_db_hash_lists() -> Result<Vec<hash_db::DbHashListInfo>, String> {
    let hash_db = hash_db::HashDatabase::new()?;
    hash_db.get_lists()
}

#[tauri::command]
fn clear_hash_database() -> Result<(), String> {
    use std::fs;
    
    // The hash database lives at %APPDATA%\Hindsight\hash_database.db
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "Could not find APPDATA directory".to_string())?;
    let db_path = std::path::PathBuf::from(&app_data)
        .join("Hindsight")
        .join("hash_database.db");
    
    eprintln!("Clearing hash database by removing file: {:?}", db_path);
    
    // Drop any existing connections first
    if let Ok(db) = hash_db::HashDatabase::new() {
        drop(db);
    }
    
    // Delete the database file if it exists
    if db_path.exists() {
        fs::remove_file(&db_path)
            .map_err(|e| format!("Failed to delete database file: {}", e))?;
        eprintln!("✓ Hash database file deleted successfully");
    } else {
        eprintln!("⚠ Database file not found at {:?} (already cleared?)", db_path);
    }
    
    // Also delete WAL and SHM journal files if present
    let wal_path = db_path.with_extension("db-wal");
    let shm_path = db_path.with_extension("db-shm");
    if wal_path.exists() { let _ = fs::remove_file(&wal_path); }
    if shm_path.exists() { let _ = fs::remove_file(&shm_path); }
    
    // Create a fresh empty database
    let _hash_db = hash_db::HashDatabase::new()?;
    eprintln!("✓ Fresh hash database created");
    
    Ok(())
}

#[tauri::command]
async fn delete_hash_list(app: tauri::AppHandle, list_name: String) -> Result<(), String> {
    eprintln!("Deleting hash list from database: {}", list_name);
    
    let name = list_name.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        use tauri::Emitter;
        let hash_db = hash_db::HashDatabase::new()?;
        
        // Phase 1: Delete the hashes
        app.emit("hash_db:delete_phase", "Deleting hashes...").ok();
        hash_db.delete_list_by_name(&name)?;
        
        // Phase 2: VACUUM to reclaim disk space
        app.emit("hash_db:delete_phase", "Compacting database...").ok();
        hash_db.vacuum()?;
        
        // Phase 3: Reload memory cache
        app.emit("hash_db:delete_phase", "Reloading hash cache...").ok();
        match hash_db.load_hashes_into_memory() {
            Ok(count) => eprintln!("✓ Reloaded {} hashes into memory after deletion", count),
            Err(e) => eprintln!("Warning: Failed to reload cache after deletion: {}", e),
        }
        
        app.emit("hash_db:delete_phase", "Done").ok();
        eprintln!("✓ Hash list '{}' deleted from database", name);
        Ok(())
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

// ── Hash Exclusion Commands ──

#[tauri::command]
fn exclude_hash(hash: String, hash_type: String, file_name: Option<String>, reason: Option<String>) -> Result<(), String> {
    let hash_db = hash_db::HashDatabase::new()?;
    hash_db.exclude_hash(&hash, &hash_type, file_name.as_deref(), reason.as_deref())
}

#[tauri::command]
fn remove_hash_exclusion(id: i64) -> Result<(), String> {
    let hash_db = hash_db::HashDatabase::new()?;
    hash_db.remove_exclusion(id)
}

#[tauri::command]
fn get_hash_exclusions() -> Result<Vec<hash_db::ExcludedHash>, String> {
    let hash_db = hash_db::HashDatabase::new()?;
    hash_db.get_exclusions()
}

#[tauri::command]
fn clear_hash_exclusions() -> Result<(), String> {
    let hash_db = hash_db::HashDatabase::new()?;
    hash_db.clear_exclusions()
}

#[tauri::command]
fn remove_hashes_from_file(file_path: String, hashes_to_remove: Vec<String>) -> Result<u64, String> {
    use std::io::{BufRead, BufWriter, Write};
    use std::collections::HashSet;

    let remove_set: HashSet<String> = hashes_to_remove
        .iter()
        .map(|h| h.to_lowercase().trim().to_string())
        .collect();

    let input = std::fs::File::open(&file_path)
        .map_err(|e| format!("Failed to open {}: {}", file_path, e))?;
    let reader = std::io::BufReader::new(input);

    // Write to temp file, then rename
    let tmp_path = format!("{}.tmp", file_path);
    let tmp_file = std::fs::File::create(&tmp_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    let mut writer = BufWriter::new(tmp_file);

    let mut removed_count: u64 = 0;
    let mut kept_count: u64 = 0;

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Read error: {}", e))?;
        let trimmed = line.trim();
        // Keep comment lines and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            writeln!(writer, "{}", line).map_err(|e| format!("Write error: {}", e))?;
            continue;
        }
        // Check if this hash should be removed
        if remove_set.contains(&trimmed.to_lowercase()) {
            removed_count += 1;
        } else {
            writeln!(writer, "{}", line).map_err(|e| format!("Write error: {}", e))?;
            kept_count += 1;
        }
    }

    writer.flush().map_err(|e| format!("Flush error: {}", e))?;
    drop(writer);

    // Backup original, rename temp to original
    let backup_path = format!("{}.bak", file_path);
    if std::path::Path::new(&backup_path).exists() {
        std::fs::remove_file(&backup_path).ok();
    }
    std::fs::rename(&file_path, &backup_path)
        .map_err(|e| format!("Failed to backup original: {}", e))?;
    std::fs::rename(&tmp_path, &file_path)
        .map_err(|e| format!("Failed to rename temp file: {}", e))?;

    eprintln!("✓ Removed {} false positive hashes from {} ({} kept)", removed_count, file_path, kept_count);

    // Also reload the hash database memory after modifying the source file
    let hash_db = hash_db::HashDatabase::new().ok();
    if let Some(db) = hash_db {
        db.load_hashes_into_memory().ok();
    }

    Ok(removed_count)
}

#[tauri::command]
fn scan_media(options: MediaScanOptions) -> Result<Vec<MediaFile>, String> {
    // Load settings to get keyword lists
    let settings = load_settings().unwrap_or_default();
    
    // Extract enabled keyword lists
    let keyword_lists: Vec<Vec<String>> = settings
        .keyword_lists
        .iter()
        .filter(|list| list.enabled)
        .map(|list| list.keywords.clone())
        .collect();
    
    // Use basic scanning without hash database for now
    media::scan_media_files(options, keyword_lists, false)
}

#[tauri::command]
fn scan_intrusion_artifacts(options: IntrusionScanOptions) -> Result<IntrusionScanResults, String> {
    intrusion::scan_intrusion_artifacts(options)
        .map_err(|e| format!("Failed to scan intrusion artifacts: {}", e))
}

#[tauri::command]
async fn scan_intrusion_progressive(
    app: tauri::AppHandle,
    options: IntrusionScanOptions,
) -> Result<IntrusionScanResults, String> {
    use crate::events::{ScanEventEmitter, ModuleName};
    
    let emitter = ScanEventEmitter::new(app);
    
    eprintln!("Received intrusion scan options: {:?}", options);
    
    // Emit module started
    emitter.emit_module_started(ModuleName::Keywords); // Reusing Keywords for now
    
    eprintln!("Starting intrusion artifact scan...");
    
    // Scan for intrusion artifacts
    let result = intrusion::scan_intrusion_artifacts(options);
    
    match result {
        Ok(results) => {
            let total_findings = results.event_log_anomalies.len() + 
                                results.persistence_items.len() + 
                                results.command_history.len();
            
            emitter.emit_module_complete(ModuleName::Keywords, total_findings);
            Ok(results)
        }
        Err(e) => {
            emitter.emit_module_error(ModuleName::Keywords, e.to_string());
            Err(format!("Failed to scan intrusion artifacts: {}", e))
        }
    }
}

#[tauri::command]
async fn scan_media_progressive(
    app: tauri::AppHandle,
    options: MediaScanOptions,
) -> Result<Vec<MediaFile>, String> {
    use crate::events::{ScanEventEmitter, ModuleName};
    
    // Load settings to get keyword lists
    let settings = load_settings().unwrap_or_default();
    
    // Extract enabled keyword lists
    let keyword_lists: Vec<Vec<String>> = settings
        .keyword_lists
        .iter()
        .filter(|list| list.enabled)
        .map(|list| list.keywords.clone())
        .collect();
    
    let emitter = ScanEventEmitter::new(app);
    
    // Emit module started
    emitter.emit_module_started(ModuleName::Media);
    
    // Use Arc for thread-safe access to emitter
    let emitter_for_callback = std::sync::Arc::new(emitter);
    let emitter_clone = emitter_for_callback.clone();
    let emitter_for_files = emitter_for_callback.clone();
    
    // Run on blocking thread so UI stays responsive
    let result = tauri::async_runtime::spawn_blocking(move || {
        media::scan_media_files_with_progress(
            options, 
            keyword_lists, 
            false, 
            move |processed, total, current_file| {
                let progress = if total > 0 {
                    ((processed as f32 / total as f32) * 100.0) as u8
                } else {
                    0
                };
                
                emitter_clone.emit_module_progress(
                    ModuleName::Media,
                    progress,
                    Some(current_file),
                    Some(processed),
                    Some(total),
                );
            },
            Some(move |file: &media::MediaFile| {
                // Emit each file immediately for live preview
                emitter_for_files.emit_media_found(file);
            })
        )
    }).await.map_err(|e| format!("Media scan thread panicked: {}", e))?;
    
    match result {
        Ok(files) => {
            emitter_for_callback.emit_module_complete(ModuleName::Media, files.len());
            Ok(files)
        }
        Err(e) => {
            emitter_for_callback.emit_module_error(ModuleName::Media, e.to_string());
            Err(format!("Failed to scan media: {}", e))
        }
    }
}

#[tauri::command]
fn clear_thumbnails() -> Result<(), String> {
    media::clear_thumbnail_cache()
}

#[tauri::command]
fn cancel_scan() {
    scanner::hash_scan::cancel_scan();
}

#[tauri::command]
async fn scan_for_hash_matches(
    options: scanner::hash_scan::HashScanOptions,
    app: tauri::AppHandle,
) -> Result<Vec<scanner::hash_scan::HashMatch>, String> {
    use crate::events::{ScanEventEmitter, ModuleName};
    
    eprintln!("[Hash Scan Command] Starting dedicated hash scan");
    
    let emitter = ScanEventEmitter::new(app);
    let emitter_clone = std::sync::Arc::new(emitter);
    let emitter_for_progress = emitter_clone.clone();
    let emitter_for_matches = emitter_clone.clone();
    
    // Run on a blocking thread so the UI stays responsive
    let result = tauri::async_runtime::spawn_blocking(move || {
        scanner::hash_scan::scan_files_for_hash_matches_with_progress(
            options,
            move |processed, total, current_file| {
                let progress = if total > 0 {
                    ((processed as f32 / total as f32) * 100.0) as u8
                } else {
                    0
                };
                
                emitter_for_progress.emit_module_progress(
                    ModuleName::HashMatching,
                    progress,
                    Some(current_file),
                    Some(processed),
                    Some(total),
                );
            },
            Some(move |hash_match: &scanner::hash_scan::HashMatch| {
                eprintln!("[Hash Scan Command] Emitting live match: {}", hash_match.file_name);
                emitter_for_matches.emit_hash_match(hash_match);
            }),
        )
    }).await.map_err(|e| format!("Hash scan thread panicked: {}", e))?;
    
    match result {
        Ok(matches) => {
            emitter_clone.emit_module_complete(ModuleName::HashMatching, matches.len());
            
            if matches.len() > 0 {
                eprintln!("[Hash Scan Command] ⚠️  CRITICAL: Found {} hash matches", matches.len());
            } else {
                eprintln!("[Hash Scan Command] ✓ No hash matches found");
            }
            
            Ok(matches)
        }
        Err(e) => {
            emitter_clone.emit_module_error(ModuleName::HashMatching, e.to_string());
            Err(format!("Hash scan failed: {}", e))
        }
    }
}

#[tauri::command]
async fn scan_browser_history(target_drives: Option<Vec<String>>) -> Result<Vec<BrowserData>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        match &target_drives {
            Some(drives) if !drives.is_empty() => {
                eprintln!("[Browser Scan] Scanning target drives: {:?}", drives);
                browser::scan_all_browsers_for_drives(Some(drives))
                    .map_err(|e| format!("Failed to scan browser history: {}", e))
            }
            _ => {
                eprintln!("[Browser Scan] Scanning host system browsers");
                browser::scan_all_browsers()
                    .map_err(|e| format!("Failed to scan browser history: {}", e))
            }
        }
    }).await.map_err(|e| format!("Browser scan thread panicked: {}", e))?
}

/// Get the keyword_lists directory path
/// Stored in %APPDATA%\Hindsight\keyword_lists\ so it survives installer updates
fn get_keyword_lists_dir() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "Could not find APPDATA directory".to_string())?;
    let keyword_dir = std::path::PathBuf::from(&app_data)
        .join("Hindsight")
        .join("keyword_lists");

    // Create directory if it doesn't exist
    if !keyword_dir.exists() {
        std::fs::create_dir_all(&keyword_dir)
            .map_err(|e| format!("Failed to create keyword_lists directory: {}", e))?;
        eprintln!("✓ Created keyword_lists directory: {:?}", keyword_dir);
    }

    // Migrate from old location (next to exe) if any .txt files exist there
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let old_dir = exe_dir.join("keyword_lists");
            if old_dir.exists() && old_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&old_dir) {
                    let mut migrated = 0;
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("txt") {
                            let dest = keyword_dir.join(entry.file_name());
                            if !dest.exists() {
                                if std::fs::copy(&path, &dest).is_ok() {
                                    let _ = std::fs::remove_file(&path);
                                    migrated += 1;
                                }
                            }
                        }
                    }
                    if migrated > 0 {
                        eprintln!("[Keywords] ✓ Migrated {} keyword lists to {:?}", migrated, keyword_dir);
                        // Remove old dir if now empty
                        let _ = std::fs::remove_dir(&old_dir);
                    }
                }
            }
        }
    }

    // Also check dev mode project root as fallback for loading
    if std::fs::read_dir(&keyword_dir).map(|mut d| d.next().is_none()).unwrap_or(true) {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                if let Some(project_root) = exe_dir.ancestors().nth(2) {
                    let dev_keyword_dir = project_root.join("keyword_lists");
                    if dev_keyword_dir.exists() {
                        return Ok(dev_keyword_dir);
                    }
                }
            }
        }
    }

    Ok(keyword_dir)
}

#[tauri::command]
fn load_keyword_lists() -> Result<Vec<keyword::KeywordList>, String> {
    let keyword_dir = get_keyword_lists_dir()?;
    eprintln!("✓ Loading keyword lists from: {:?}", keyword_dir);
    load_keyword_lists_from_dir(&keyword_dir)
        .map_err(|e| format!("Failed to load keyword lists: {}", e))
}

#[tauri::command]
fn import_keyword_list(file_path: String, file_name: String) -> Result<String, String> {
    let keyword_dir = get_keyword_lists_dir()?;
    let source_path = PathBuf::from(&file_path);
    
    // Validate file extension
    if source_path.extension().and_then(|s| s.to_str()) != Some("txt") {
        return Err("Only .txt files are supported".to_string());
    }
    
    // Read and validate content
    let content = std::fs::read_to_string(&source_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    let keywords: Vec<&str> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    
    if keywords.is_empty() {
        return Err("No valid keywords found in file. File must contain at least one keyword.".to_string());
    }
    
    // Determine destination filename (avoid overwriting)
    let mut dest_name = file_name.clone();
    let mut dest_path = keyword_dir.join(&dest_name);
    let mut counter = 1;
    
    while dest_path.exists() {
        let path_buf = PathBuf::from(&file_name);
        let stem = path_buf
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("keyword_list");
        dest_name = format!("{}_{}.txt", stem, counter);
        dest_path = keyword_dir.join(&dest_name);
        counter += 1;
    }
    
    // Copy file to keyword_lists directory
    std::fs::copy(&source_path, &dest_path)
        .map_err(|e| format!("Failed to copy file: {}", e))?;
    
    eprintln!("✓ Imported keyword list: {} ({} keywords)", dest_name, keywords.len());
    Ok(format!("Successfully imported {} with {} keywords", dest_name, keywords.len()))
}

#[tauri::command]
fn delete_keyword_list(list_name: String) -> Result<String, String> {
    let keyword_dir = get_keyword_lists_dir()?;
    let file_path = keyword_dir.join(format!("{}.txt", list_name));
    
    if !file_path.exists() {
        return Err(format!("Keyword list '{}' not found", list_name));
    }
    
    std::fs::remove_file(&file_path)
        .map_err(|e| format!("Failed to delete keyword list: {}", e))?;
    
    eprintln!("✓ Deleted keyword list: {}", list_name);
    Ok(format!("Successfully deleted keyword list '{}'", list_name))
}

#[tauri::command]
fn get_keyword_scan_paths() -> Result<Vec<String>, String> {
    Ok(get_default_scan_paths())
}

#[tauri::command]
fn get_scan_paths_for_selected_drives(drives: Vec<String>) -> Result<Vec<String>, String> {
    Ok(get_scan_paths_for_drives(drives))
}

// Android scanning commands
#[tauri::command]
fn check_adb_available(app_handle: tauri::AppHandle) -> Result<bool, String> {
    android::check_adb_available(&app_handle)
}

#[tauri::command]
fn get_android_devices(app_handle: tauri::AppHandle) -> Result<Vec<AndroidDevice>, String> {
    android::get_connected_devices(&app_handle)
}

#[tauri::command]
fn get_android_apps(app_handle: tauri::AppHandle, serial: String) -> Result<Vec<AndroidApp>, String> {
    android::get_installed_apps(&app_handle, &serial)
}

#[tauri::command]
fn get_android_chrome_history(app_handle: tauri::AppHandle, serial: String) -> Result<AndroidBrowserData, String> {
    android::get_chrome_history(&app_handle, &serial)
}

#[tauri::command]
fn scan_android_browsers(app_handle: tauri::AppHandle, serial: String) -> Result<Vec<serde_json::Value>, String> {
    android::scan_android_browsers(&app_handle, &serial)
}

#[tauri::command]
fn pull_android_files(app_handle: tauri::AppHandle, serial: String, paths: Vec<String>) -> Result<String, String> {
    android::pull_files_for_scanning(&app_handle, &serial, paths)
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn pull_android_file(app_handle: tauri::AppHandle, serial: String, android_path: String) -> Result<String, String> {
    android::pull_single_file(&app_handle, &serial, &android_path)
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
async fn pull_android_media_for_viewing(
    app_handle: tauri::AppHandle,
    serial: String,
    android_path: String,
    media_type: String, // "image" or "video"
) -> Result<serde_json::Value, String> {
    eprintln!("[Android Media] Pulling file for viewing: {}", android_path);
    
    // Pull the file from Android device
    let local_path = android::pull_single_file(&app_handle, &serial, &android_path)?;
    eprintln!("[Android Media] File pulled to: {:?}", local_path);
    
    // Generate thumbnail
    let thumbnail_path = if media_type == "image" || media_type == "video" {
        match thumbnail_generator::get_or_generate_thumbnail(&local_path, &media_type) {
            Ok(path) => {
                eprintln!("[Android Media] Thumbnail generated: {}", path);
                Some(path)
            }
            Err(e) => {
                eprintln!("[Android Media] Warning: Failed to generate thumbnail: {}", e);
                None
            }
        }
    } else {
        None
    };
    
    // Return both the local file path and thumbnail path
    let mut result = serde_json::Map::new();
    result.insert("localPath".to_string(), serde_json::Value::String(local_path.to_string_lossy().to_string()));
    if let Some(thumb) = thumbnail_path {
        result.insert("thumbnailPath".to_string(), serde_json::Value::String(thumb));
    }
    
    Ok(serde_json::Value::Object(result))
}

#[tauri::command]
fn check_android_root_status(app_handle: tauri::AppHandle, serial: String) -> Result<bool, String> {
    android::check_root_status(&app_handle, &serial)
}

#[tauri::command]
fn check_android_device_ready(app_handle: tauri::AppHandle, serial: String) -> Result<bool, String> {
    android::check_device_ready(&app_handle, &serial)
}

#[tauri::command]
fn get_android_device_info(app_handle: tauri::AppHandle, serial: String) -> Result<serde_json::Value, String> {
    android::get_android_device_info(&app_handle, &serial)
}

#[tauri::command]
async fn scan_android_media(app_handle: tauri::AppHandle, serial: String) -> Result<Vec<serde_json::Value>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        android::scan_android_media(&app_handle, &serial)
    })
    .await
    .map_err(|e| format!("Media scan task failed: {}", e))?
}

#[tauri::command]
async fn scan_android_media_hashes(
    app_handle: tauri::AppHandle, 
    serial: String,
    selected_hash_list_ids: Option<Vec<String>>
) -> Result<Vec<android::AndroidHashMatch>, String> {
    // Run on a dedicated blocking thread so the main thread stays free for UI
    tauri::async_runtime::spawn_blocking(move || {
        android::scan_android_media_hashes(&app_handle, &serial, None, selected_hash_list_ids)
    })
    .await
    .map_err(|e| format!("Hash scan task failed: {}", e))?
}

#[tauri::command]
fn install_android_usb_drivers(app_handle: tauri::AppHandle) -> Result<(), String> {
    let driver_path = app_handle.path()
        .resource_dir()
        .expect("Failed to get resource directory")
        .join("_up_/external/usb-drivers/install_driver.bat");
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let driver_path_str = driver_path.to_str().unwrap();
        Command::new("cmd")
            .args(&["/C", "start", "", driver_path_str])
            .spawn()
            .map_err(|e| format!("Failed to launch driver installer: {}", e))?;
    }
    
    Ok(())
}

// Multi-silo is now integrated directly into extract_android_sms
// No separate command needed — it runs as the first extraction method

// iOS scanning commands (backup-based)
#[tauri::command]
fn check_itunes_available() -> Result<bool, String> {
    ios::check_itunes_available()
}

#[tauri::command]
fn get_ios_backups() -> Result<Vec<IosDevice>, String> {
    ios::list_ios_backups()
}

// iOS Python-based commands (new backup workflow)
#[tauri::command]
fn check_ios_python_available() -> Result<bool, String> {
    scanner::ios_python::check_ios_python_available()
}

#[tauri::command]
fn detect_ios_devices_python() -> Result<Vec<scanner::ios_python::PythonIosDevice>, String> {
    scanner::ios_python::detect_ios_devices_python()
}

#[tauri::command]
fn get_ios_device_info_python(udid: String) -> Result<scanner::ios_python::PythonIosDevice, String> {
    scanner::ios_python::get_ios_device_info_python(&udid)
}

#[tauri::command]
fn list_itunes_backups() -> Result<Vec<scanner::ios_backup_scanner::ItunesBackup>, String> {
    scanner::ios_backup_scanner::list_itunes_backups()
}

#[tauri::command]
fn scan_itunes_backup_sms(backup_path: String) -> Result<Vec<scanner::ios_backup_scanner::IosMessage>, String> {
    use std::path::Path;
    let path = Path::new(&backup_path);
    scanner::ios_backup_scanner::parse_sms_from_backup(path)
}

#[tauri::command]
fn get_ios_backup_info(backup_path: String) -> Result<scanner::ios_backup_scanner::ItunesBackup, String> {
    use std::path::Path;
    let path = Path::new(&backup_path);
    scanner::ios_backup_scanner::get_backup_info(path)
}

#[tauri::command]
async fn start_ios_backup_python(
    app: tauri::AppHandle,
    udid: String,
    output_dir: Option<String>,
    password: Option<String>
) -> Result<scanner::ios_python::BackupProgress, String> {
    let pwd = password.unwrap_or_else(|| "scout1234".to_string());
    let output_dir_ref = output_dir.as_deref();
    
    // Emit progress events to the frontend
    let progress_callback = {
        let app = app.clone();
        Box::new(move |progress: scanner::ios_python::BackupProgress| {
            use tauri::Emitter;
            let _ = app.emit("ios:backup_progress", &progress);
        }) as Box<dyn Fn(scanner::ios_python::BackupProgress) + Send>
    };
    
    scanner::ios_python::start_ios_backup_python(
        &udid,
        output_dir_ref,
        &pwd,
        Some(progress_callback)
    )
}

#[tauri::command]
async fn decrypt_ios_backup(
    backup_path: String,
    password: Option<String>,
) -> Result<scanner::ios_python::BackupProgress, String> {
    let pwd = password.unwrap_or_else(|| "scout1234".to_string());
    scanner::ios_python::decrypt_ios_backup(&backup_path, &pwd, None)
}

// iOS Live Device Commands
#[tauri::command]
fn check_libimobiledevice_available() -> Result<bool, String> {
    ios_live::check_libimobiledevice_available()
}

#[tauri::command]
fn scan_ios_device_media(udid: String) -> Result<Vec<serde_json::Value>, String> {
    scanner::ios_media::scan_ios_media(&udid, None)
}

#[tauri::command]
fn scan_ios_backup_media(backup_path: String) -> Result<Vec<serde_json::Value>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_media::scan_ios_backup_media(&path)
}

#[tauri::command]
fn get_ios_device_info(udid: String) -> Result<scanner::ios_apps::IosDeviceInfo, String> {
    scanner::ios_apps::get_device_info(&udid)
}

#[tauri::command]
fn get_ios_installed_apps(udid: String) -> Result<Vec<scanner::ios_apps::IosInstalledApp>, String> {
    scanner::ios_apps::get_installed_apps(&udid)
}

#[tauri::command]
fn get_ios_apps_from_backup(backup_path: String) -> Result<Vec<scanner::ios_apps::IosInstalledApp>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_apps::get_apps_from_backup(&path)
}

#[tauri::command]
fn get_ios_notes_from_backup(backup_path: String) -> Result<Vec<scanner::ios_notes::IosNote>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_notes::get_notes_from_backup(&path)
}

#[tauri::command]
fn detect_live_ios_devices() -> Result<Vec<LiveIosDevice>, String> {
    ios_live::detect_live_ios_devices()
}

// Detect iPhone via Windows MTP (shows in File Explorer)
#[tauri::command]
fn detect_ios_mtp_devices() -> Result<Vec<serde_json::Value>, String> {
    use scanner::ios_mtp;
    match ios_mtp::detect_mtp_ios_devices() {
        Ok(devices) => {
            let json_devices: Vec<serde_json::Value> = devices
                .into_iter()
                .map(|d| serde_json::json!({
                    "devicePath": d.device_path,
                    "deviceName": d.device_name,
                    "isAccessible": d.is_accessible,
                    "instructions": d.instructions,
                }))
                .collect();
            Ok(json_devices)
        }
        Err(e) => Err(e),
    }
}

#[tauri::command]
fn request_ios_device_trust(udid: String) -> Result<bool, String> {
    ios_live::request_device_trust(&udid)
}

#[tauri::command]
fn list_ios_device_apps(udid: String) -> Result<Vec<String>, String> {
    ios_live::list_installed_apps(&udid)
}

#[tauri::command]
fn perform_ios_live_triage(
    udid: String,
    keyword_lists: Vec<String>,
    hash_lists: Vec<String>
) -> Result<IosLiveTriageResults, String> {
    ios_live::perform_live_triage(&udid, keyword_lists, hash_lists)
}

#[tauri::command]
fn get_ios_apps(backup_path: String) -> Result<Vec<IosApp>, String> {
    ios::get_installed_apps(&backup_path)
}

#[tauri::command]
fn get_ios_messages(backup_path: String) -> Result<Vec<IosMessage>, String> {
    ios::get_messages(&backup_path)
}

#[tauri::command]
fn get_ios_contacts(backup_path: String) -> Result<Vec<IosContact>, String> {
    ios::get_contacts(&backup_path)
}

#[tauri::command]
fn get_ios_calls(backup_path: String) -> Result<Vec<IosCall>, String> {
    ios::get_call_history(&backup_path)
}

#[tauri::command]
fn get_ios_browser_history(backup_path: String) -> Result<Vec<IosBrowserHistory>, String> {
    ios::get_browser_history(&backup_path)
}

// New enhanced iOS backup parsing commands
#[tauri::command]
fn parse_ios_backup_safari_history(backup_path: String) -> Result<Vec<scanner::ios_backup_parser::SafariHistoryEntry>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_backup_parser::extract_safari_history(&path)
}

#[tauri::command]
fn parse_ios_backup_chrome_history(backup_path: String) -> Result<Vec<scanner::ios_backup_parser::ChromeHistoryEntry>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_backup_parser::extract_chrome_history(&path)
}

#[tauri::command]
fn parse_ios_backup_media(backup_path: String) -> Result<Vec<scanner::ios_backup_parser::BackupMediaFile>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_backup_parser::extract_media_files(&path)
}

#[tauri::command]
fn list_ios_backup_files(backup_path: String) -> Result<Vec<scanner::ios_backup_parser::BackupFileEntry>, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_backup_parser::list_backup_files(&path)
}

#[tauri::command]
fn analyze_ios_backup(backup_path: String) -> Result<scanner::ios_backup_parser::BackupAnalysisResults, String> {
    use std::path::PathBuf;
    let path = PathBuf::from(backup_path);
    scanner::ios_backup_parser::analyze_backup(&path)
}

#[tauri::command]
fn extract_all_ios_data(backup_path: String) -> Result<IosBackupData, String> {
    ios::extract_all_data(&backup_path)
}

#[tauri::command]
fn get_available_drives() -> Result<Vec<DriveInfo>, String> {
    get_system_drives()
}

#[tauri::command]
fn get_usb_device_info(drive_letter: String) -> Result<scanner::usb_device::UsbDeviceInfo, String> {
    scanner::usb_device::get_usb_device_info(&drive_letter)
}

#[tauri::command]
fn scan_ios_mtp_media() -> Result<scanner::ios_mtp::MtpScanResult, String> {
    scanner::ios_mtp::scan_iphone_media_mtp_full("iPhone")
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveInfo {
    letter: String,
    label: String,
    drive_type: String,
    total_space: u64,
    free_space: u64,
}

#[cfg(windows)]
fn get_system_drives() -> Result<Vec<DriveInfo>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    
    let mut drives = Vec::new();
    
    // Get drive letters A-Z
    for letter in b'A'..=b'Z' {
        let drive_letter = format!("{}:", letter as char);
        let drive_path = format!("{}\\", drive_letter);
        
        // Check if drive exists
        if PathBuf::from(&drive_path).exists() {
            // Get drive type and info
            let drive_type = get_drive_type(&drive_path);
            let (total, free) = get_drive_space(&drive_path);
            let label = get_drive_label(&drive_path);
            
            drives.push(DriveInfo {
                letter: drive_letter,
                label,
                drive_type,
                total_space: total,
                free_space: free,
            });
        }
    }
    
    Ok(drives)
}

#[cfg(not(windows))]
fn get_system_drives() -> Result<Vec<DriveInfo>, String> {
    // For non-Windows systems, return root and common mount points
    Ok(vec![
        DriveInfo {
            letter: "/".to_string(),
            label: "Root".to_string(),
            drive_type: "Fixed".to_string(),
            total_space: 0,
            free_space: 0,
        }
    ])
}

#[cfg(windows)]
fn get_drive_type(path: &str) -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetDriveTypeW;
    
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    
    unsafe {
        let drive_type = GetDriveTypeW(wide.as_ptr());
        match drive_type {
            2 => "Removable".to_string(),
            3 => "Fixed".to_string(),
            4 => "Network".to_string(),
            5 => "CD-ROM".to_string(),
            6 => "RAM Disk".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

#[cfg(windows)]
fn get_drive_space(path: &str) -> (u64, u64) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetDiskFreeSpaceExW;
    use winapi::shared::minwindef::FALSE;
    
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    
    let mut free_bytes: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut _total_free_bytes: u64 = 0;
    
    unsafe {
        let result = GetDiskFreeSpaceExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            &mut total_bytes as *mut u64 as *mut _,
            &mut free_bytes as *mut u64 as *mut _,
        );
        
        if result == FALSE {
            return (0, 0);
        }
    }
    
    (total_bytes, free_bytes)
}

#[cfg(windows)]
fn get_drive_label(path: &str) -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetVolumeInformationW;
    use winapi::shared::minwindef::FALSE;
    
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    
    let mut volume_name: Vec<u16> = vec![0; 256];
    
    unsafe {
        let success = GetVolumeInformationW(
            wide.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
        
        if success != FALSE {
            let len = volume_name.iter().position(|&c| c == 0).unwrap_or(volume_name.len());
            String::from_utf16_lossy(&volume_name[..len])
        } else {
            String::new()
        }
    }
}

#[tauri::command]
fn scan_keywords(options: KeywordScanOptions) -> Result<Vec<KeywordMatch>, String> {
    keyword::scan_keywords(options)
        .map_err(|e| format!("Failed to scan keywords: {}", e))
}

#[tauri::command]
async fn scan_keywords_progressive(
    app: tauri::AppHandle,
    options: KeywordScanOptions,
) -> Result<Vec<KeywordMatch>, String> {
    use crate::events::{ScanEventEmitter, ModuleName};
    
    let emitter = ScanEventEmitter::new(app);
    
    // Emit module started
    emitter.emit_module_started(ModuleName::Keywords);
    
    let emitter_arc = std::sync::Arc::new(emitter);
    let emitter_for_progress = emitter_arc.clone();
    
    // Run on blocking thread so UI stays responsive
    let result = tauri::async_runtime::spawn_blocking(move || {
        keyword::scan_keywords_with_progress(options, move |processed, total, current_file| {
            let progress = if total > 0 {
                ((processed as f32 / total as f32) * 100.0) as u8
            } else {
                0
            };
            
            emitter_for_progress.emit_module_progress(
                ModuleName::Keywords,
                progress,
                Some(current_file),
                Some(processed),
                Some(total),
            );
        }).map_err(|e| e.to_string())
    }).await.map_err(|e| format!("Keyword scan thread panicked: {}", e))?;
    
    match result {
        Ok(matches) => {
            emitter_arc.emit_module_complete(ModuleName::Keywords, matches.len());
            Ok(matches)
        }
        Err(e) => {
            emitter_arc.emit_module_error(ModuleName::Keywords, e.to_string());
            Err(format!("Failed to scan keywords: {}", e))
        }
    }
}

#[tauri::command]
fn open_in_explorer(path: String) -> Result<(), String> {
    use std::process::Command;
    
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .args(&["/select,", &path])
            .spawn()
            .map_err(|e| format!("Failed to open Explorer: {}", e))?;
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("This feature is only available on Windows".to_string())
    }
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    created: String,
    modified: String,
    accessed: String,
    size: u64,
    readonly: bool,
    hidden: bool,
}

#[tauri::command]
fn get_file_metadata(path: String) -> Result<FileMetadata, String> {
    use std::fs;
    use std::time::SystemTime;
    
    let metadata = fs::metadata(&path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    
    let created = metadata.created()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| {
            let datetime = chrono::DateTime::<chrono::Local>::from(
                SystemTime::UNIX_EPOCH + d
            );
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|| "Unknown".to_string());
    
    let modified = metadata.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| {
            let datetime = chrono::DateTime::<chrono::Local>::from(
                SystemTime::UNIX_EPOCH + d
            );
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|| "Unknown".to_string());
    
    let accessed = metadata.accessed()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| {
            let datetime = chrono::DateTime::<chrono::Local>::from(
                SystemTime::UNIX_EPOCH + d
            );
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|| "Unknown".to_string());
    
    #[cfg(target_os = "windows")]
    let (readonly, hidden) = {
        use std::os::windows::fs::MetadataExt;
        let attrs = metadata.file_attributes();
        let readonly = (attrs & 0x1) != 0;
        let hidden = (attrs & 0x2) != 0;
        (readonly, hidden)
    };
    
    #[cfg(not(target_os = "windows"))]
    let (readonly, hidden) = {
        let readonly = metadata.permissions().readonly();
        (readonly, false)
    };
    
    Ok(FileMetadata {
        created,
        modified,
        accessed,
        size: metadata.len(),
        readonly,
        hidden,
    })
}

#[derive(Serialize, Deserialize)]
struct FileAccessEvent {
    timestamp: String,
    event_id: u32,
    event_type: String,
    process_name: String,
    user_name: String,
    description: String,
}

#[tauri::command]
fn get_file_access_events(path: String) -> Result<Vec<FileAccessEvent>, String> {
    // This function attempts to retrieve file access events from Windows Event Logs
    // Note: This requires file auditing to be enabled in Windows
    
    #[cfg(target_os = "windows")]
    {
        use std::path::Path;
        
        let file_path = Path::new(&path);
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        // For now, return a message about enabling auditing
        // A full implementation would use the Windows API to query Security event logs
        // Event IDs 4663 (file access), 4656 (handle request), 4658 (handle close)
        
        eprintln!("Searching for file access events for: {}", file_name);
        eprintln!("Note: File auditing must be enabled in Windows Group Policy");
        eprintln!("Advanced Audit Policy Configuration -> Object Access -> Audit File System");
        
        // TODO: Implement actual Windows Event Log querying
        // This would require:
        // 1. Windows API calls to EvtQuery
        // 2. Filtering by Event IDs 4663, 4656, 4658
        // 3. XML parsing of event data
        // 4. Matching file path in event details
        
        // Return empty for now - indicates no events found or auditing not enabled
        Ok(Vec::new())
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("File access event logging is only available on Windows".to_string())
    }
}

#[tauri::command]
fn generate_report(payload: reporter::ReportPayload, password: String) -> Result<reporter::ReportGenerationResult, String> {
    // Generate PDF as raw bytes
    let pdf_data = reporter::generate_report_bytes(payload.clone())
        .map_err(|e| format!("Failed to generate report: {}", e))?;
    
    // Generate Datapilot hash file if requested (runs before encryption step)
    if payload.metadata.generate_datapilot_file.unwrap_or(false) {
        let reports_dir = reporter::get_reports_dir()
            .map_err(|e| format!("Failed to get reports dir: {}", e))?;
        match reporter::generate_datapilot_hashlist_public(&payload, &reports_dir) {
            Ok(path) => eprintln!("✓ Generated Datapilot hash file: {}", path.display()),
            Err(e) => eprintln!("⚠ Failed to generate Datapilot hash file: {}", e),
        }
    }
    
    // Generate report name from metadata
    let report_name = format!(
        "Hindsight_Report_{}_{}",
        payload.metadata.case_number.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_"),
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    );
    
    // Encrypt and save to database
    let report_id = security::save_encrypted_report(report_name.clone(), pdf_data, password)
        .map_err(|e| format!("Failed to encrypt and save report: {}", e))?;
    
    eprintln!("✓ Report generated and encrypted: {} (ID: {})", report_name, report_id);
    
    Ok(reporter::ReportGenerationResult {
        success: true,
        pdf_path: Some(format!("encrypted::{}", report_id)), // Return encrypted ID instead of path
        error: None,
    })
}

/// Pull a file from a connected Android device via ADB and open it locally
#[tauri::command]
fn pull_and_open_android_file(app_handle: tauri::AppHandle, device_path: String) -> Result<String, String> {
    use crate::scanner::android::{get_bundled_adb_path, create_hidden_command};
    
    eprintln!("Pulling Android file: {}", device_path);
    
    let adb_path = get_bundled_adb_path(&app_handle);
    
    // Get filename from device path
    let filename = device_path.split('/').last().unwrap_or("file");
    
    // Create temp directory for pulled files
    let temp_dir = std::env::temp_dir().join("scout_android_preview");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;
    
    let local_path = temp_dir.join(filename);
    let local_path_str = local_path.to_string_lossy().to_string();
    
    // Pull file from device (use first connected device)
    let output = create_hidden_command(&adb_path)
        .args(&["pull", &device_path, &local_path_str])
        .output()
        .map_err(|e| format!("Failed to run adb pull: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ADB pull failed: {}", stderr));
    }
    
    eprintln!("File pulled to: {}", local_path_str);
    
    // Open the file with the default application
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        // Use explorer /select to open the folder and highlight the file
        std::process::Command::new("explorer")
            .args(["/select,", &local_path_str])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Failed to open file: {}", e))?;
    }
    
    Ok(local_path_str)
}

#[tauri::command]
fn open_file_location(path: String) -> Result<(), String> {
    eprintln!("Opening file location: {}", path);
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        
        // Use explorer with /select to open folder and highlight file
        std::process::Command::new("explorer")
            .args(["/select,", &path])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Failed to open file location: {}", e))?;
    }
    
    #[cfg(target_os = "macos")]
    {
        // On macOS, use "open" with -R to reveal in Finder
        std::process::Command::new("open")
            .args(["-R", &path])
            .spawn()
            .map_err(|e| format!("Failed to open file location: {}", e))?;
    }
    
    #[cfg(target_os = "linux")]
    {
        // On Linux, try to open the parent directory
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::process::Command::new("xdg-open")
                .arg(parent)
                .spawn()
                .map_err(|e| format!("Failed to open file location: {}", e))?;
        } else {
            return Err("Cannot determine parent directory".to_string());
        }
    }
    
    Ok(())
}

#[tauri::command]
fn open_pdf_file(file_path: String) -> Result<(), String> {
    eprintln!("Opening PDF file: {}", file_path);
    
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &file_path])
            .spawn()
            .map_err(|e| format!("Failed to open PDF: {}", e))?;
    }
    
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&file_path)
            .spawn()
            .map_err(|e| format!("Failed to open PDF: {}", e))?;
    }
    
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&file_path)
            .spawn()
            .map_err(|e| format!("Failed to open PDF: {}", e))?;
    }
    
    Ok(())
}

// ===== REPORT MANAGEMENT COMMANDS =====

#[tauri::command]
fn list_reports() -> Result<Vec<reporter::ReportListItem>, String> {
    reporter::list_reports()
        .map_err(|e| format!("Failed to list reports: {}", e))
}

#[tauri::command]
fn open_report(file_path: String) -> Result<(), String> {
    reporter::open_report(&file_path)
        .map_err(|e| format!("Failed to open report: {}", e))
}

#[tauri::command]
fn delete_report(file_path: String) -> Result<(), String> {
    reporter::delete_report(&file_path)
        .map_err(|e| format!("Failed to delete report: {}", e))
}

#[tauri::command]
fn export_report(file_path: String, destination: String) -> Result<(), String> {
    reporter::export_report(&file_path, &destination)
        .map_err(|e| format!("Failed to export report: {}", e))
}

#[tauri::command]
fn list_datapilot_files() -> Result<Vec<reporter::ReportListItem>, String> {
    reporter::list_datapilot_files()
        .map_err(|e| format!("Failed to list Datapilot files: {}", e))
}

#[tauri::command]
fn get_reports_directory() -> Result<String, String> {
    reporter::get_reports_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to get reports directory: {}", e))
}

// ===== SECURITY COMMANDS =====

#[tauri::command]
fn check_is_registered() -> Result<bool, String> {
    security::is_registered()
}

#[tauri::command]
fn register_new_user(username: String, password: String) -> Result<(), String> {
    security::register_user(username, password)
}

#[tauri::command]
fn login_user(username: String, password: String) -> Result<security::User, String> {
    security::login(username, password)
}

// Password reset functionality removed - use master password for recovery
// USB fingerprinting removed - simplified security model
// #[tauri::command]
// fn get_usb_info() -> Result<security::UsbFingerprint, String> {
//     security::get_usb_fingerprint()
// }

#[tauri::command]
fn save_encrypted_pdf_report(
    report_name: String,
    pdf_data: Vec<u8>,
    password: String,
) -> Result<i64, String> {
    security::save_encrypted_report(report_name, pdf_data, password)
}

#[tauri::command]
fn list_saved_reports() -> Result<Vec<security::EncryptedReport>, String> {
    security::list_encrypted_reports()
}

#[tauri::command]
fn load_encrypted_pdf_report(report_id: i64, password: String) -> Result<Vec<u8>, String> {
    security::load_encrypted_report(report_id, password)
}

#[tauri::command]
fn export_encrypted_report_to_file(report_id: i64, password: String, destination: String) -> Result<(), String> {
    let pdf_data = security::load_encrypted_report(report_id, password)?;
    std::fs::write(&destination, pdf_data)
        .map_err(|e| format!("Failed to write report to {}: {}", destination, e))?;
    eprintln!("Report exported to: {}", destination);
    Ok(())
}

#[tauri::command]
fn delete_saved_report(report_id: i64) -> Result<(), String> {
    security::delete_encrypted_report(report_id)
}

#[tauri::command]
fn open_encrypted_report(report_id: i64, password: String) -> Result<(), String> {
    // Load and decrypt the PDF
    let pdf_data = security::load_encrypted_report(report_id, password)?;
    
    // Save to temp file
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("hindsight_report_{}.pdf", report_id));
    
    std::fs::write(&temp_path, pdf_data)
        .map_err(|e| format!("Failed to save temp PDF: {}", e))?;
    
    // Open the PDF with default viewer
    #[cfg(target_os = "windows")]
    {
        let temp_path_str = temp_path.to_str().unwrap();
        std::process::Command::new("cmd")
            .args(&["/C", "start", "", temp_path_str])
            .spawn()
            .map_err(|e| format!("Failed to open PDF: {}", e))?;
    }
    
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&temp_path)
            .spawn()
            .map_err(|e| format!("Failed to open PDF: {}", e))?;
    }
    
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&temp_path)
            .spawn()
            .map_err(|e| format!("Failed to open PDF: {}", e))?;
    }
    
    Ok(())
}

// ========== Forensic Mode Commands (Linux Bootable) ==========

/// Detect target systems for forensic scanning (Windows, Chrome OS)
#[cfg(target_os = "linux")]
#[tauri::command]
fn detect_forensic_targets() -> Result<Vec<TargetSystem>, String> {
    platform::forensics::detect_target_systems()
}

/// Get information about a forensic target
#[cfg(target_os = "linux")]
#[tauri::command]
fn get_forensic_system_info(target: TargetSystem) -> Result<platform::SystemInfo, String> {
    let scanner = platform::linux::LinuxForensicScanner::new(target)?;
    scanner.get_system_info()
}

/// Get apps from a forensic target
#[cfg(target_os = "linux")]
#[tauri::command]
fn get_forensic_apps(target: TargetSystem) -> Result<Vec<platform::AppInfo>, String> {
    let scanner = platform::linux::LinuxForensicScanner::new(target)?;
    scanner.get_installed_apps()
}

/// Get browser history from a forensic target
#[cfg(target_os = "linux")]
#[tauri::command]
fn get_forensic_browser_history(target: TargetSystem) -> Result<Vec<platform::BrowserHistoryEntry>, String> {
    let scanner = platform::linux::LinuxForensicScanner::new(target)?;
    scanner.get_browser_history()
}

/// Unmount a forensic target safely
#[cfg(target_os = "linux")]
#[tauri::command]
fn unmount_forensic_target(target: TargetSystem) -> Result<(), String> {
    platform::forensics::unmount_target(&target)
}

/// Check if running in forensic mode (Linux bootable)
#[tauri::command]
fn is_forensic_mode() -> bool {
    cfg!(target_os = "linux")
}

/// Get unified data partition paths
#[tauri::command]
fn get_data_paths() -> Result<platform::paths::DataPaths, String> {
    platform::paths::DataPaths::new()
}

/// Verify data partition is accessible
#[tauri::command]
fn verify_data_partition() -> Result<bool, String> {
    platform::paths::verify_data_partition()
}

/// Initialize data partition directories
#[tauri::command]
fn initialize_data_partition() -> Result<(), String> {
    platform::paths::initialize_data_partition()
}

/// Perform complete forensic scan (Linux only, but stub needs to exist for compilation)
#[cfg(target_os = "linux")]
#[tauri::command]
fn perform_forensic_scan(
    target: TargetSystem,
    scan_apps: bool,
    scan_browser: bool,
    scan_media: bool,
    scan_keywords: bool,
    check_hashes: bool,
    generate_thumbnails: bool,
    keyword_lists: Vec<String>,
    use_hash_db: bool,
) -> Result<String, String> {
    let config = platform::forensic_scan::ForensicScanConfig {
        target,
        scan_apps,
        scan_browser,
        scan_media,
        scan_keywords,
        check_hashes,
        generate_thumbnails,
        keyword_lists,
        use_hash_db,
    };
    
    let results = platform::forensic_scan::perform_forensic_scan(config)?;
    
    // Serialize results to JSON string
    serde_json::to_string(&results)
        .map_err(|e| format!("Failed to serialize results: {}", e))
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn perform_forensic_scan(
    _target: TargetSystem,
    _scan_apps: bool,
    _scan_browser: bool,
    _scan_media: bool,
    _scan_keywords: bool,
    _check_hashes: bool,
    _generate_thumbnails: bool,
    _keyword_lists: Vec<String>,
    _use_hash_db: bool,
) -> Result<String, String> {
    Err("Forensic scanning only available in bootable Linux mode".to_string())
}

/// Generate forensic report from scan results
#[cfg(target_os = "linux")]
#[tauri::command]
fn generate_forensic_report(
    results_json: String,
    case_number: String,
    detective: String,
    officer: Option<String>,
    agency: Option<String>,
) -> Result<String, String> {
    use crate::reporter::generate_reports;
    
    // Parse scan results
    let results: platform::forensic_scan::ForensicScanResults = 
        serde_json::from_str(&results_json)
            .map_err(|e| format!("Failed to parse results: {}", e))?;
    
    // Create report payload
    let payload = platform::forensic_report::create_forensic_report_payload(
        results,
        case_number,
        detective,
        officer,
        agency,
    );
    
    // Generate report
    let result = generate_reports(payload)
        .map_err(|e| format!("Failed to generate report: {}", e))?;
    
    if result.success {
        Ok(result.pdf_path.unwrap_or_else(|| "Report generated".to_string()))
    } else {
        Err(result.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn generate_forensic_report(
    _results_json: String,
    _case_number: String,
    _detective: String,
    _officer: Option<String>,
    _agency: Option<String>,
) -> Result<String, String> {
    Err("Forensic reports only available in bootable Linux mode".to_string())
}

// Stub implementations for Windows (these commands only work on Linux)
#[cfg(target_os = "windows")]
#[tauri::command]
fn detect_forensic_targets() -> Result<Vec<TargetSystem>, String> {
    Err("Forensic mode only available in bootable Linux environment".to_string())
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn get_forensic_system_info(_target: TargetSystem) -> Result<platform::SystemInfo, String> {
    Err("Forensic mode only available in bootable Linux environment".to_string())
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn get_forensic_apps(_target: TargetSystem) -> Result<Vec<platform::AppInfo>, String> {
    Err("Forensic mode only available in bootable Linux environment".to_string())
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn get_forensic_browser_history(_target: TargetSystem) -> Result<Vec<platform::BrowserHistoryEntry>, String> {
    Err("Forensic mode only available in bootable Linux environment".to_string())
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn unmount_forensic_target(_target: TargetSystem) -> Result<(), String> {
    Err("Forensic mode only available in bootable Linux environment".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .register_asynchronous_uri_scheme_protocol("media", move |_app, request, responder| {
            eprintln!("[Media Protocol] Request received: {:?}", request.uri());
            
            // Parse the URI to get the file path
            let uri = request.uri();
            let path_str = uri.path();
            
            // Decode URL-encoded path
            let decoded_path = urlencoding::decode(path_str)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(path_str));
            
            eprintln!("[Media Protocol] Decoded path: {}", decoded_path);
            
            // Remove leading slash if present on Windows
            #[cfg(target_os = "windows")]
            let file_path = if decoded_path.starts_with('/') && decoded_path.len() > 2 && decoded_path.chars().nth(2) == Some(':') {
                &decoded_path[1..]
            } else {
                decoded_path.as_ref()
            };
            
            #[cfg(not(target_os = "windows"))]
            let file_path = decoded_path.as_ref();
            
            eprintln!("[Media Protocol] Final path: {}", file_path);
            
            // Handle the request
            let path = std::path::Path::new(file_path);
            match media_server::handle_media_request(&request, path) {
                Ok(response) => responder.respond(response),
                Err(e) => {
                    eprintln!("[Media Protocol] Error: {}", e);
                    let error_response = tauri::http::Response::builder()
                        .status(500)
                        .body(format!("Error: {}", e).into_bytes())
                        .unwrap();
                    responder.respond(error_response);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            get_trial_status,
            register_agency,
            get_license_status,
            activate_license_key,
            check_for_updates,
            submit_bug_report,
            is_agency_registered,
            scan_questionable_applications,
            get_settings,
            save_app_settings,
            initialize_app,
            get_category_mappings,
            save_category_mappings,
            add_category_mapping,
            remove_category_mapping,
            get_system_info,
            // start_progressive_scan,  // Temporarily disabled
            import_vic_hash_list,
            import_and_load_hash_list,
            import_txt_hash_list,
            scan_media,
            scan_media_progressive,
            clear_thumbnails,
            scan_for_hash_matches,
            cancel_scan,
            scan_browser_history,
            load_keyword_lists,
            import_keyword_list,
            delete_keyword_list,
            get_keyword_scan_paths,
            scan_keywords,
            scan_keywords_progressive,
            scan_intrusion_artifacts,
            scan_intrusion_progressive,
            get_available_drives,
            get_usb_device_info,
            get_scan_paths_for_selected_drives,
            check_adb_available,
            get_android_devices,
            get_android_apps,
            get_android_chrome_history,
            scan_android_browsers,
            pull_android_files,
            pull_android_file,
            pull_android_media_for_viewing,
            check_android_root_status,
            check_android_device_ready,
            get_android_device_info,
            scan_android_media,
            scan_android_media_hashes,
            // Multi-silo integrated into extract_android_sms
            install_android_usb_drivers,
            check_itunes_available,
            get_ios_backups,
            check_ios_python_available,
            detect_ios_devices_python,
            get_ios_device_info_python,
            start_ios_backup_python,
            decrypt_ios_backup,
            list_itunes_backups,
            get_ios_backup_info,
            scan_itunes_backup_sms,
            scan_ios_device_media,
            scan_ios_backup_media,
            get_ios_device_info,
            get_ios_installed_apps,
            get_ios_apps_from_backup,
            get_ios_notes_from_backup,
            get_ios_apps,
            get_ios_messages,
            get_ios_contacts,
            get_ios_calls,
            get_ios_browser_history,
            extract_all_ios_data,
            parse_ios_backup_safari_history,
            parse_ios_backup_chrome_history,
            parse_ios_backup_media,
            list_ios_backup_files,
            analyze_ios_backup,
            check_libimobiledevice_available,
            detect_live_ios_devices,
            detect_ios_mtp_devices,
            scan_ios_mtp_media,
            request_ios_device_trust,
            list_ios_device_apps,
            perform_ios_live_triage,
            open_in_explorer,
            get_file_metadata,
            get_file_access_events,
            generate_report,
            open_pdf_file,
            open_file_location,
            pull_and_open_android_file,
            list_reports,
            open_report,
            delete_report,
            export_report,
            list_datapilot_files,
            get_reports_directory,
            load_hash_list_into_db,
            get_hash_database_stats,
            get_db_hash_lists,
            clear_hash_database,
            delete_hash_list,
            exclude_hash,
            remove_hash_exclusion,
            get_hash_exclusions,
            clear_hash_exclusions,
            remove_hashes_from_file,
            check_is_registered,
            register_new_user,
            login_user,
            // reset_user_registration, // Removed - use master password for recovery
            // get_usb_info, // Removed - USB fingerprinting disabled
            save_encrypted_pdf_report,
            list_saved_reports,
            load_encrypted_pdf_report,
            export_encrypted_report_to_file,
            delete_saved_report,
            open_encrypted_report,
            // Forensic mode commands
            is_forensic_mode,
            detect_forensic_targets,
            get_forensic_system_info,
            get_forensic_apps,
            get_forensic_browser_history,
            unmount_forensic_target,
            // Unified data partition access
            get_data_paths,
            verify_data_partition,
            initialize_data_partition,
            // Forensic scan orchestrator
            perform_forensic_scan,
            generate_forensic_report,
            // Media server commands
            media_server::get_file_as_base64,
            media_server::get_media_file_info,
            // Thumbnail generator commands
            thumbnail_generator::generate_thumbnail,
            thumbnail_generator::batch_generate_thumbnails_command,
            thumbnail_generator::clear_thumbnail_cache_command,
            thumbnail_generator::get_thumbnail_cache_stats,
            // Android SMS commands
            scanner::android_sms::extract_android_sms,
            scanner::android_sms::get_sms_thread_messages
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
