use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use md5::Md5;
use std::io::Read;
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

// ── Global scan cancellation flag ──
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

/// Request cancellation of the current scan
pub fn cancel_scan() {
    eprintln!("[Hash Scan] ⛔ CANCELLATION REQUESTED");
    SCAN_CANCELLED.store(true, Ordering::SeqCst);
}

/// Check if scan was cancelled
#[inline]
fn is_cancelled() -> bool {
    SCAN_CANCELLED.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMatch {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub extension: String,
    pub md5_hash: String,
    pub sha256_hash: String,
    pub matched_hash: String,
    pub hash_type: String, // "MD5" or "SHA256"
    pub list_name: String,
    pub list_source: String,
    pub description: Option<String>,
    pub severity: String, // Always "Critical"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashScanOptions {
    #[serde(rename = "scanPaths")]
    pub scan_paths: Vec<String>,
    #[serde(rename = "maxFileSize")]
    pub max_file_size: u64, // in bytes, 0 = no limit (500MB default for safety)
}

// ── Media extension filter (CSAM is overwhelmingly images/videos) ──
const IMAGE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif",
    "webp", "heic", "heif", "raw", "cr2", "nef", "arw",
];
const VIDEO_EXTENSIONS: &[&str] = &[
    "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm",
    "m4v", "mpg", "mpeg", "3gp", "ogv",
];

// File size limits for triage
const MIN_FILE_SIZE: u64 = 40_960;         // 40KB min (skip icons/thumbs)
const MAX_FILE_SIZE: u64 = 100_000_000;    // 100MB max (CSAM rarely exceeds)

// I/O buffer for streaming fallback — 128KB
const HASH_BUFFER_SIZE: usize = 131_072;

/// Directories to skip during triage — these never contain user media
const SKIP_DIRS: &[&str] = &[
    // Windows system
    "Windows", "WinSxS", "System32", "SysWOW64", "assembly",
    "Microsoft.NET", "servicing", "Installer", "SoftwareDistribution",
    "WER", "Logs", "Panther",
    // Program dirs (installers, DLLs — not user media)
    "Program Files", "Program Files (x86)", "ProgramData",
    // Package managers / dev caches
    "node_modules", ".git", ".svn", ".hg", "__pycache__", ".venv",
    "target", ".cargo", ".rustup", ".npm", ".nuget",
    // Browser caches (not actual saved media)
    "Cache", "Code Cache", "GPUCache", "ShaderCache", "Service Worker",
    "CacheStorage", "ScriptCache",
    // App data caches
    "Temp", "tmp",
    // System restore / volume shadow
    "System Volume Information", "$WinREAgent", "Recovery",
    "Config.Msi", "MSOCache", "PerfLogs",
    // Boot
    "Boot", "EFI",
];

#[inline]
fn is_media_extension(ext: &str) -> bool {
    IMAGE_EXTENSIONS.contains(&ext) || VIDEO_EXTENSIONS.contains(&ext)
}

#[inline]
fn should_skip_dir(name: &str) -> bool {
    // Skip hidden/system dirs starting with $ (except Recycle Bin)
    if name.starts_with('$') && name != "$Recycle.Bin" && name != "$RECYCLE.BIN" {
        return true;
    }
    let lower = name.to_lowercase();
    SKIP_DIRS.iter().any(|s| s.to_lowercase() == lower)
}

/// Scan directories for files and check their hashes against the database
pub fn scan_files_for_hash_matches(
    options: HashScanOptions,
) -> Result<Vec<HashMatch>, String> {
    scan_files_for_hash_matches_with_progress(
        options,
        |_, _, _| {},
        None::<fn(&HashMatch)>,
    )
}

/// Scan with progress callback and optional match callback for live triage
///
/// Optimizations:
/// - jwalk: parallel directory walking
/// - memmap2: zero-copy memory-mapped file hashing
/// - Hash-type awareness: only computes MD5/SHA256 if those types exist in DB
/// - File size pre-filter: skips files whose size doesn't match any known hash
/// - Media extension filter: only hashes images/videos
/// - Directory skip list: avoids Windows/system/cache directories
pub fn scan_files_for_hash_matches_with_progress<F, G>(
    options: HashScanOptions,
    progress_callback: F,
    match_callback: Option<G>,
) -> Result<Vec<HashMatch>, String>
where
    F: Fn(usize, usize, String) + Send + Sync,
    G: Fn(&HashMatch) + Send + Sync,
{
    eprintln!("[Hash Scan] ========== STARTING HASH SCAN ==========");
    eprintln!("[Hash Scan] Scan paths: {:?}", options.scan_paths);
    
    // Reset cancellation flag
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
    
    let start_time = std::time::Instant::now();
    
    // Open hash database and verify it has hashes
    let hash_db = crate::hash_db::HashDatabase::new()
        .map_err(|e| format!("Failed to open hash database: {}", e))?;
    
    let stats = hash_db.get_stats()
        .map_err(|e| format!("Failed to get database stats: {}", e))?;
    
    eprintln!("[Hash Scan] Database: {} hashes from {} lists", stats.total_hashes, stats.total_lists);
    
    if stats.total_hashes == 0 {
        return Err("Hash database is empty! Please import hash lists first.".to_string());
    }
    
    // ── Optimization: only compute hash types present in DB ──
    let db_hash_types = hash_db.get_hash_types();
    let need_md5 = db_hash_types.contains("MD5");
    let need_sha256 = db_hash_types.contains("SHA256") || db_hash_types.is_empty();
    eprintln!("[Hash Scan] Hash types: MD5={}, SHA256={}", need_md5, need_sha256);
    
    // ── Optimization: file size pre-filter ──
    let known_sizes = hash_db.get_known_sizes();
    if let Some(ref sizes) = known_sizes {
        eprintln!("[Hash Scan] Size pre-filter active: {} known sizes", sizes.len());
    }
    
    // ── Phase 1: Parallel directory discovery (jwalk) ──
    let discover_start = std::time::Instant::now();
    let mut candidate_files: Vec<(PathBuf, u64)> = Vec::new();
    let mut skipped_non_media = 0u64;
    let mut skipped_size = 0u64;
    let mut skipped_by_known_size = 0u64;
    
    for scan_path in &options.scan_paths {
        if !Path::new(scan_path).exists() {
            eprintln!("[Hash Scan] Path does not exist, skipping: {}", scan_path);
            continue;
        }

        eprintln!("[Hash Scan] Walking: {}", scan_path);
        
        // jwalk: parallel directory walking (multi-threaded enumeration)
        // max_depth(20) prevents hanging on deeply nested/circular structures
        for entry in jwalk::WalkDir::new(scan_path)
            .skip_hidden(false)
            .follow_links(false)
            .max_depth(20)
            .process_read_dir(|_depth, _path, _state, children| {
                // Prune skip-listed directories during traversal
                children.retain(|child_result| {
                    if let Ok(child) = child_result {
                        if child.file_type().is_dir() {
                            if let Some(name) = child.file_name.to_str() {
                                return !should_skip_dir(name);
                            }
                        }
                    }
                    true
                });
            })
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_dir() {
                continue;
            }
            
            let path = entry.path();

            // Extension filter (cheapest check first)
            let ext_lower = match path.extension().and_then(|e| e.to_str()) {
                Some(ext) => ext.to_lowercase(),
                None => { skipped_non_media += 1; continue; }
            };
            
            if !is_media_extension(&ext_lower) {
                skipped_non_media += 1;
                continue;
            }

            // Size filter
            if let Ok(metadata) = fs::metadata(&path) {
                let file_size = metadata.len();
                if file_size < MIN_FILE_SIZE || file_size > MAX_FILE_SIZE {
                    skipped_size += 1;
                    continue;
                }
                
                // Size pre-filter: skip if size doesn't match any known hash
                if let Some(ref sizes) = known_sizes {
                    if !sizes.contains(&file_size) {
                        skipped_by_known_size += 1;
                        continue;
                    }
                }
                
                candidate_files.push((path, file_size));
            }
        }
    }
    
    let discover_elapsed = discover_start.elapsed();
    eprintln!("[Hash Scan] Discovery: {:.2}s (parallel jwalk)", discover_elapsed.as_secs_f64());
    eprintln!("[Hash Scan]   Media files to hash: {}", candidate_files.len());
    eprintln!("[Hash Scan]   Skipped non-media: {}", skipped_non_media);
    eprintln!("[Hash Scan]   Skipped by size range: {}", skipped_size);
    if skipped_by_known_size > 0 {
        eprintln!("[Hash Scan]   Skipped by size pre-filter: {}", skipped_by_known_size);
    }
    
    let total_files = candidate_files.len();
    if total_files == 0 {
        return Ok(Vec::new());
    }
    
    // ── Phase 2: Parallel hashing with mmap + type-aware ──
    eprintln!("[Hash Scan] Hashing {} files (parallel mmap)...", total_files);
    let hash_start = std::time::Instant::now();
    
    let processed_count = std::sync::atomic::AtomicUsize::new(0);
    let progress_cb = &progress_callback;
    let match_cb = &match_callback;
    let counter = &processed_count;
    
    let matches: Vec<HashMatch> = candidate_files
        .par_iter()
        .filter_map(|(path, file_size)| {
            // Check cancellation before hashing each file
            if is_cancelled() {
                return None;
            }
            
            let result = check_file_hash(path, *file_size, &hash_db, need_md5, need_sha256);
            
            let prev = counter.fetch_add(1, Ordering::Relaxed);
            let done = prev + 1;
            
            if done % 25 == 0 || done == total_files {
                progress_cb(done, total_files, path.to_string_lossy().to_string());
            }
            
            if let Some(ref hash_match) = result {
                eprintln!("[Hash Scan] ✓ MATCH: {}", path.display());
                if let Some(ref cb) = match_cb {
                    cb(hash_match);
                }
            }
            
            result
        })
        .collect();
    
    let was_cancelled = is_cancelled();
    let hash_elapsed = hash_start.elapsed();
    let total_elapsed = start_time.elapsed();
    let files_processed = counter.load(Ordering::Relaxed);
    
    if was_cancelled {
        eprintln!("[Hash Scan] ========== SCAN STOPPED BY USER ==========");
        eprintln!("[Hash Scan] Files hashed before stop: {}/{}", files_processed, total_files);
    } else {
        eprintln!("[Hash Scan] ========== SCAN COMPLETE ==========");
        eprintln!("[Hash Scan] Files hashed: {} in {:.2}s ({:.0} files/sec)",
            total_files, hash_elapsed.as_secs_f64(),
            total_files as f64 / hash_elapsed.as_secs_f64().max(0.001));
    }
    eprintln!("[Hash Scan] Matches found: {}", matches.len());
    eprintln!("[Hash Scan] Total time: {:.2}s", total_elapsed.as_secs_f64());
    
    if !matches.is_empty() {
        eprintln!("[Hash Scan] ⚠️  CRITICAL: {} HASH MATCHES FOUND", matches.len());
    }
    
    // Return matches found so far (even if cancelled)
    Ok(matches)
}

/// Check a single file's hash against the database.
/// Only computes the hash types present in the DB.
fn check_file_hash(
    path: &Path,
    file_size: u64,
    hash_db: &crate::hash_db::HashDatabase,
    need_md5: bool,
    need_sha256: bool,
) -> Option<HashMatch> {
    let (md5, sha256) = match compute_file_hashes_mmap(path, need_md5, need_sha256) {
        Ok(hashes) => hashes,
        Err(_) => return None,
    };
    
    let file_name = || path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let extension = || path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();
    
    // Check SHA256 first (more unique, preferred)
    if let Some(ref h) = sha256 {
        if let Some(match_data) = hash_db.check_hash_fast(h, "SHA256") {
            return Some(HashMatch {
                file_path: path.to_string_lossy().to_string(),
                file_name: file_name(),
                file_size,
                extension: extension(),
                md5_hash: md5.clone().unwrap_or_default(),
                sha256_hash: h.clone(),
                matched_hash: h.clone(),
                hash_type: "SHA256".to_string(),
                list_name: match_data.source.clone(),
                list_source: match_data.source.clone(),
                description: match_data.description.clone(),
                severity: "Critical".to_string(),
            });
        }
    }
    
    // Check MD5 as fallback
    if let Some(ref h) = md5 {
        if let Some(match_data) = hash_db.check_hash_fast(h, "MD5") {
            return Some(HashMatch {
                file_path: path.to_string_lossy().to_string(),
                file_name: file_name(),
                file_size,
                extension: extension(),
                md5_hash: h.clone(),
                sha256_hash: sha256.unwrap_or_default(),
                matched_hash: h.clone(),
                hash_type: "MD5".to_string(),
                list_name: match_data.source.clone(),
                list_source: match_data.source.clone(),
                description: match_data.description.clone(),
                severity: "Critical".to_string(),
            });
        }
    }
    
    None
}

/// Compute file hashes using memory-mapped I/O (zero-copy, OS read-ahead).
/// Only computes hash types that exist in the DB.
/// Falls back to streaming for files > 512MB.
fn compute_file_hashes_mmap(
    path: &Path,
    need_md5: bool,
    need_sha256: bool,
) -> Result<(Option<String>, Option<String>), String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("Failed to open: {}", e))?;
    
    let file_len = file.metadata()
        .map_err(|e| format!("Metadata error: {}", e))?
        .len();
    
    if file_len == 0 {
        let md5 = if need_md5 { Some("d41d8cd98f00b204e9800998ecf8427e".to_string()) } else { None };
        let sha256 = if need_sha256 { Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()) } else { None };
        return Ok((md5, sha256));
    }
    
    // Memory-mapped I/O for files <= 512MB (vast majority of media)
    if file_len <= 512 * 1024 * 1024 {
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .map_err(|e| format!("mmap failed: {}", e))?;
        
        let md5_hash = if need_md5 {
            let mut h = Md5::new();
            h.update(&mmap[..]);
            Some(format!("{:x}", h.finalize()))
        } else {
            None
        };
        
        let sha256_hash = if need_sha256 {
            let mut h = Sha256::new();
            h.update(&mmap[..]);
            Some(format!("{:x}", h.finalize()))
        } else {
            None
        };
        
        return Ok((md5_hash, sha256_hash));
    }
    
    // Streaming fallback for very large files
    let mut file = file;
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];
    let mut md5_hasher = if need_md5 { Some(Md5::new()) } else { None };
    let mut sha256_hasher = if need_sha256 { Some(Sha256::new()) } else { None };
    
    loop {
        let n = file.read(&mut buffer)
            .map_err(|e| format!("Read error: {}", e))?;
        if n == 0 { break; }
        if let Some(ref mut h) = md5_hasher { h.update(&buffer[..n]); }
        if let Some(ref mut h) = sha256_hasher { h.update(&buffer[..n]); }
    }
    
    Ok((
        md5_hasher.map(|h| format!("{:x}", h.finalize())),
        sha256_hasher.map(|h| format!("{:x}", h.finalize())),
    ))
}
