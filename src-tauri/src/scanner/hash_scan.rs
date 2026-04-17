use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use md5::Md5;
use std::io::Read;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use crossbeam_channel::{bounded, Sender};

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

// Triage size limits — small files are hashed first and fastest
const MIN_FILE_SIZE: u64 = 1_024;           // 1KB min (skip truly empty)
const MAX_FILE_SIZE: u64 = 500_000_000;     // 500MB max

// I/O buffer for streaming fallback — 128KB
const HASH_BUFFER_SIZE: usize = 131_072;

/// Directories to skip during triage — never contain user media
const SKIP_DIRS: &[&str] = &[
    // Windows system
    "Windows", "WinSxS", "System32", "SysWOW64", "assembly",
    "Microsoft.NET", "servicing", "Installer", "SoftwareDistribution",
    "WER", "Logs", "Panther",
    // Program dirs
    "Program Files", "Program Files (x86)", "ProgramData",
    // Package managers / dev caches
    "node_modules", ".git", ".svn", ".hg", "__pycache__", ".venv",
    "target", ".cargo", ".rustup", ".npm", ".nuget",
    // Browser caches (not saved media)
    "Cache", "Code Cache", "GPUCache", "ShaderCache", "Service Worker",
    "CacheStorage", "ScriptCache",
    // Temp/system
    "Temp", "tmp",
    "System Volume Information", "$WinREAgent", "Recovery",
    "Config.Msi", "MSOCache", "PerfLogs",
    "Boot", "EFI",
];

/// Priority tiers — directories scanned in order of likelihood
/// Tier 1: Where contraband is almost always found
const TIER1_DIRS: &[&str] = &[
    "Downloads", "Desktop", "Documents", "Pictures", "Videos",
    "Music", "Saved Pictures", "Camera Roll",
];

/// Tier 1 also includes app cache directories (messaging apps)
const TIER1_APPDATA_DIRS: &[&str] = &[
    // Messaging apps
    "Telegram Desktop",
    "Discord",
    "WhatsApp",
    "Signal",
    "Kik",
    // Browsers (saved files, not cache)
    "Google\\Chrome\\User Data",
    "Microsoft\\Edge\\User Data",
    "Mozilla\\Firefox\\Profiles",
    // Torrent clients
    "qBittorrent",
    "uTorrent",
    "BitTorrent",
    "Vuze",
];

/// File candidate with metadata for priority sorting
#[derive(Debug)]
struct FileCandidate {
    path: PathBuf,
    size: u64,
    tier: u8,
}

#[inline]
fn is_media_extension(ext: &str) -> bool {
    IMAGE_EXTENSIONS.contains(&ext) || VIDEO_EXTENSIONS.contains(&ext)
}

#[inline]
fn should_skip_dir(name: &str) -> bool {
    if name.starts_with('$') && name != "$Recycle.Bin" && name != "$RECYCLE.BIN" {
        return true;
    }
    let lower = name.to_lowercase();
    SKIP_DIRS.iter().any(|s| s.to_lowercase() == lower)
}

// ════════════════════════════════════════════════════════════════════════
// Public API — backward compatible
// ════════════════════════════════════════════════════════════════════════

/// Simple scan (no progress/match callbacks)
pub fn scan_files_for_hash_matches(
    options: HashScanOptions,
) -> Result<Vec<HashMatch>, String> {
    scan_files_for_hash_matches_with_progress(
        options,
        |_, _, _| {},
        None::<fn(&HashMatch)>,
    )
}

/// Streaming triage scanner with priority queue
///
/// Architecture:
///   Producer thread: walks directories in tier order, sends candidates
///   Worker pool: N threads pull candidates, hash, check DB
///   Pivot logic: hit in dir X → inject all files from X at high priority
///
/// Optimizations:
///   - Tier 1/2/3 priority ordering (highest-probability dirs first)
///   - Small-first sorting within each tier batch
///   - File size pre-filter (stat() only, no reads)
///   - Media extension filter
///   - In-memory hash DB for O(1) lookups
///   - memmap2 zero-copy hashing
///   - Pivot-on-hit: deep-scan directories with confirmed matches
pub fn scan_files_for_hash_matches_with_progress<F, G>(
    options: HashScanOptions,
    progress_callback: F,
    match_callback: Option<G>,
) -> Result<Vec<HashMatch>, String>
where
    F: Fn(usize, usize, String) + Send + Sync,
    G: Fn(&HashMatch) + Send + Sync,
{
    eprintln!("[Hash Scan] ════════ STREAMING TRIAGE SCAN ════════");
    eprintln!("[Hash Scan] Scan paths: {:?}", options.scan_paths);
    
    // Reset cancellation flag
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
    
    let start_time = std::time::Instant::now();
    
    // Open hash database and verify it has hashes
    let hash_db = Arc::new(
        crate::hash_db::HashDatabase::new()
            .map_err(|e| format!("Failed to open hash database: {}", e))?
    );
    
    let stats = hash_db.get_stats()
        .map_err(|e| format!("Failed to get database stats: {}", e))?;
    
    eprintln!("[Hash Scan] Database: {} hashes from {} lists", stats.total_hashes, stats.total_lists);
    
    if stats.total_hashes == 0 {
        return Err("Hash database is empty! Please import hash lists first.".to_string());
    }
    
    // Which hash types to compute
    let db_hash_types = hash_db.get_hash_types();
    let need_md5 = db_hash_types.contains("MD5");
    let need_sha256 = db_hash_types.contains("SHA256") || db_hash_types.is_empty();
    eprintln!("[Hash Scan] Hash types: MD5={}, SHA256={}", need_md5, need_sha256);
    
    // File size pre-filter from DB
    let known_sizes = hash_db.get_known_sizes();
    if let Some(ref sizes) = known_sizes {
        eprintln!("[Hash Scan] Size pre-filter active: {} known sizes", sizes.len());
    }
    
    // ── Streaming architecture ──
    // Bounded channel: producer sends candidates, workers consume
    // Backpressure: if workers are slow, producer blocks (no memory blowup)
    let (tx, rx) = bounded::<FileCandidate>(256);
    
    // Pivot channel: workers signal back when they find a hit
    let (pivot_tx, pivot_rx) = bounded::<PathBuf>(64);
    
    // Shared counters
    let files_hashed = Arc::new(AtomicUsize::new(0));
    let files_discovered = Arc::new(AtomicUsize::new(0));
    let match_count = Arc::new(AtomicUsize::new(0));
    
    // Collect matches from workers
    let (match_tx, match_rx) = bounded::<HashMatch>(256);
    
    // ── Spawn worker pool ──
    let num_workers = num_cpus().max(2).min(8);
    eprintln!("[Hash Scan] Spawning {} hash workers", num_workers);
    
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let rx = rx.clone();
        let hash_db = Arc::clone(&hash_db);
        let known_sizes = known_sizes.clone();
        let match_tx = match_tx.clone();
        let pivot_tx = pivot_tx.clone();
        let files_hashed = Arc::clone(&files_hashed);
        let match_count_w = Arc::clone(&match_count);
        
        let handle = std::thread::spawn(move || {
            let mut local_matches = 0u64;
            
            while let Ok(candidate) = rx.recv() {
                if is_cancelled() { break; }
                
                // Size pre-filter: skip if DB has sizes and this file's size isn't in it
                if let Some(ref sizes) = known_sizes {
                    if !sizes.is_empty() && !sizes.contains(&candidate.size) {
                        files_hashed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                
                // Hash the file and check
                if let Some(hash_match) = check_file_hash(
                    &candidate.path,
                    candidate.size,
                    &hash_db,
                    need_md5,
                    need_sha256,
                ) {
                    eprintln!("[Worker {}] ✓ HIT: {} (tier {})", 
                        worker_id, candidate.path.display(), candidate.tier);
                    
                    local_matches += 1;
                    match_count_w.fetch_add(1, Ordering::Relaxed);
                    
                    // Signal pivot: deep-scan this file's parent directory
                    if let Some(parent) = candidate.path.parent() {
                        let _ = pivot_tx.try_send(parent.to_path_buf());
                    }
                    
                    let _ = match_tx.send(hash_match);
                }
                
                files_hashed.fetch_add(1, Ordering::Relaxed);
            }
            
            local_matches
        });
        
        worker_handles.push(handle);
    }
    
    // Drop our copies so channels close when producer/workers finish
    drop(match_tx);
    drop(pivot_tx);
    
    // ── Spawn producer thread ──
    let scan_paths = options.scan_paths.clone();
    let files_discovered_p = Arc::clone(&files_discovered);
    
    let producer_handle = std::thread::spawn(move || {
        let mut pivoted_dirs: HashSet<PathBuf> = HashSet::new();
        
        // ── Phase 1: Tier 1 — High priority directories ──
        eprintln!("[Producer] Phase 1: Tier 1 (high-priority user dirs)");
        for scan_root in &scan_paths {
            if is_cancelled() { break; }
            discover_tier1_files(scan_root, &tx, &files_discovered_p, &known_sizes);
            
            // Check for pivot requests between tiers
            drain_pivot_requests(&pivot_rx, &tx, &files_discovered_p, &known_sizes, &mut pivoted_dirs);
        }
        
        // ── Phase 2: Tier 2 — User-created root folders ──
        eprintln!("[Producer] Phase 2: Tier 2 (user-created folders)");
        for scan_root in &scan_paths {
            if is_cancelled() { break; }
            discover_tier2_files(scan_root, &tx, &files_discovered_p, &known_sizes);
            
            drain_pivot_requests(&pivot_rx, &tx, &files_discovered_p, &known_sizes, &mut pivoted_dirs);
        }
        
        // ── Phase 3: Tier 3 — Remaining files on drive ──
        eprintln!("[Producer] Phase 3: Tier 3 (full drive sweep)");
        for scan_root in &scan_paths {
            if is_cancelled() { break; }
            discover_tier3_files(scan_root, &tx, &files_discovered_p, &known_sizes);
            
            drain_pivot_requests(&pivot_rx, &tx, &files_discovered_p, &known_sizes, &mut pivoted_dirs);
        }
        
        // Final pivot drain
        drain_pivot_requests(&pivot_rx, &tx, &files_discovered_p, &known_sizes, &mut pivoted_dirs);
        
        eprintln!("[Producer] Discovery complete. {} files sent to workers.", 
            files_discovered_p.load(Ordering::Relaxed));
        
        drop(tx); // Signal workers: no more files coming
    });
    
    // ── Collect results from workers, emit progress ──
    let mut all_matches: Vec<HashMatch> = Vec::new();
    let progress_cb = &progress_callback;
    let match_cb = &match_callback;
    
    let mut last_progress_report = std::time::Instant::now();
    
    for hash_match in match_rx.iter() {
        if let Some(ref cb) = match_cb {
            cb(&hash_match);
        }
        
        all_matches.push(hash_match);
        
        // Emit progress periodically
        if last_progress_report.elapsed().as_millis() > 250 {
            let hashed = files_hashed.load(Ordering::Relaxed);
            let discovered = files_discovered.load(Ordering::Relaxed).max(hashed);
            progress_cb(hashed, discovered, format!("{} matches found", all_matches.len()));
            last_progress_report = std::time::Instant::now();
        }
    }
    
    // Wait for producer and workers to finish
    let _ = producer_handle.join();
    for handle in worker_handles {
        let _ = handle.join();
    }
    
    // Final progress
    let hashed = files_hashed.load(Ordering::Relaxed);
    let discovered = files_discovered.load(Ordering::Relaxed);
    progress_cb(hashed, discovered.max(hashed), "Scan complete".to_string());
    
    let was_cancelled = is_cancelled();
    let total_elapsed = start_time.elapsed();
    
    if was_cancelled {
        eprintln!("[Hash Scan] ════════ SCAN STOPPED BY USER ════════");
    } else {
        eprintln!("[Hash Scan] ════════ SCAN COMPLETE ════════");
    }
    eprintln!("[Hash Scan] Files discovered: {}", discovered);
    eprintln!("[Hash Scan] Files hashed: {}", hashed);
    eprintln!("[Hash Scan] Matches: {}", all_matches.len());
    eprintln!("[Hash Scan] Total time: {:.2}s", total_elapsed.as_secs_f64());
    if hashed > 0 {
        eprintln!("[Hash Scan] Throughput: {:.0} files/sec", 
            hashed as f64 / total_elapsed.as_secs_f64().max(0.001));
    }
    
    if !all_matches.is_empty() {
        eprintln!("[Hash Scan] ⚠️  CRITICAL: {} HASH MATCHES FOUND", all_matches.len());
    }
    
    Ok(all_matches)
}

// ════════════════════════════════════════════════════════════════════════
// Producer: Tiered directory discovery
// ════════════════════════════════════════════════════════════════════════

/// Tier 1: Scan high-priority user directories (Downloads, Desktop, app caches)
/// Files are sorted small-first within each directory batch
fn discover_tier1_files(
    scan_root: &str,
    tx: &Sender<FileCandidate>,
    counter: &Arc<AtomicUsize>,
    _known_sizes: &Option<HashSet<u64>>,
) {
    let root = PathBuf::from(scan_root);
    
    // For system drive, enumerate user profiles
    let users_dir = root.join("Users");
    if users_dir.exists() {
        if let Ok(entries) = fs::read_dir(&users_dir) {
            for entry in entries.flatten() {
                if is_cancelled() { return; }
                let user_path = entry.path();
                if !user_path.is_dir() { continue; }
                let uname = entry.file_name().to_string_lossy().to_string();
                if ["Public", "Default", "Default User", "All Users"].contains(&uname.as_str()) {
                    continue;
                }
                
                // Tier 1 user directories
                for dir_name in TIER1_DIRS {
                    let dir_path = user_path.join(dir_name);
                    if dir_path.exists() {
                        send_directory_files(&dir_path, 1, 15, tx, counter);
                    }
                }
                
                // Tier 1 AppData directories (messaging apps, browser data)
                let local_appdata = user_path.join("AppData").join("Local");
                let roaming_appdata = user_path.join("AppData").join("Roaming");
                
                for appdata_dir in TIER1_APPDATA_DIRS {
                    for base in [&local_appdata, &roaming_appdata] {
                        let app_path = base.join(appdata_dir);
                        if app_path.exists() {
                            send_directory_files(&app_path, 1, 10, tx, counter);
                        }
                    }
                }
                
                // Recycle bin for this drive
                let recycle_bin = root.join("$Recycle.Bin");
                if recycle_bin.exists() {
                    send_directory_files(&recycle_bin, 1, 10, tx, counter);
                }
            }
        }
    } else {
        // Non-system drive or external: scan root-level user-like dirs
        for dir_name in TIER1_DIRS {
            let dir_path = root.join(dir_name);
            if dir_path.exists() {
                send_directory_files(&dir_path, 1, 15, tx, counter);
            }
        }
        
        // Also check Recycle Bin
        let recycle_bin = root.join("$Recycle.Bin");
        if recycle_bin.exists() {
            send_directory_files(&recycle_bin, 1, 10, tx, counter);
        }
    }
}

/// Tier 2: User-created root folders (not system directories)
fn discover_tier2_files(
    scan_root: &str,
    tx: &Sender<FileCandidate>,
    counter: &Arc<AtomicUsize>,
    _known_sizes: &Option<HashSet<u64>>,
) {
    let root = PathBuf::from(scan_root);
    
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            if is_cancelled() { return; }
            let path = entry.path();
            if !path.is_dir() { continue; }
            
            let name = entry.file_name().to_string_lossy().to_string();
            
            // Skip system dirs, Users (already scanned in T1), and hidden dirs
            if should_skip_dir(&name) { continue; }
            if name == "Users" || name == "users" { continue; }
            if name.starts_with('.') { continue; }
            
            // This catches user-created folders like "Photos", "Work", "Backup", etc.
            send_directory_files(&path, 2, 15, tx, counter);
        }
    }
}

/// Tier 3: Full drive sweep — catch anything missed by T1/T2
/// Uses jwalk for parallel directory enumeration
fn discover_tier3_files(
    scan_root: &str,
    tx: &Sender<FileCandidate>,
    counter: &Arc<AtomicUsize>,
    _known_sizes: &Option<HashSet<u64>>,
) {
    if !Path::new(scan_root).exists() { return; }
    
    // Walk the entire drive with max depth, but skip dirs we already covered
    for entry in jwalk::WalkDir::new(scan_root)
        .skip_hidden(false)
        .follow_links(false)
        .max_depth(20)
        .process_read_dir(|_depth, _path, _state, children| {
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
        if is_cancelled() { return; }
        
        if entry.file_type().is_dir() { continue; }
        
        let path = entry.path();
        
        let ext_lower = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_lowercase(),
            None => continue,
        };
        
        if !is_media_extension(&ext_lower) { continue; }
        
        if let Ok(metadata) = fs::metadata(&path) {
            let file_size = metadata.len();
            if file_size < MIN_FILE_SIZE || file_size > MAX_FILE_SIZE { continue; }
            
            counter.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(FileCandidate {
                path,
                size: file_size,
                tier: 3,
            });
        }
    }
}

/// Pivot scan: when a hit is found, deep-scan that directory
/// Sends ALL files (not just media) since files may be renamed/extensionless
fn discover_pivot_files(
    dir: &Path,
    tx: &Sender<FileCandidate>,
    counter: &Arc<AtomicUsize>,
) {
    eprintln!("[Pivot] Deep-scanning hit directory: {}", dir.display());
    
    for entry in jwalk::WalkDir::new(dir)
        .skip_hidden(false)
        .follow_links(false)
        .max_depth(5) // Don't go too deep from the hit directory
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if is_cancelled() { return; }
        if entry.file_type().is_dir() { continue; }
        
        let path = entry.path();
        
        if let Ok(metadata) = fs::metadata(&path) {
            let file_size = metadata.len();
            if file_size < MIN_FILE_SIZE || file_size > MAX_FILE_SIZE { continue; }
            
            // In pivot mode, hash ALL file types (not just media)
            // because CSAM is often renamed with wrong extensions
            counter.fetch_add(1, Ordering::Relaxed);
            let _ = tx.try_send(FileCandidate {
                path,
                size: file_size,
                tier: 0, // Highest priority
            });
        }
    }
}

/// Send all media files from a directory, sorted small-first
fn send_directory_files(
    dir: &Path,
    tier: u8,
    max_depth: usize,
    tx: &Sender<FileCandidate>,
    counter: &Arc<AtomicUsize>,
) {
    // Collect files from this directory
    let mut candidates: Vec<(PathBuf, u64)> = Vec::new();
    
    for entry in jwalk::WalkDir::new(dir)
        .skip_hidden(false)
        .follow_links(false)
        .max_depth(max_depth)
        .process_read_dir(|_depth, _path, _state, children| {
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
        if is_cancelled() { return; }
        if entry.file_type().is_dir() { continue; }
        
        let path = entry.path();
        
        let ext_lower = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_lowercase(),
            None => continue,
        };
        
        if !is_media_extension(&ext_lower) { continue; }
        
        if let Ok(metadata) = fs::metadata(&path) {
            let file_size = metadata.len();
            if file_size < MIN_FILE_SIZE || file_size > MAX_FILE_SIZE { continue; }
            candidates.push((path, file_size));
        }
    }
    
    // Sort small-first: hash small files before large ones
    // Small images are processed in milliseconds, maximizing time-to-first-hit
    candidates.sort_by_key(|(_, size)| *size);
    
    // Send to workers
    for (path, size) in candidates {
        if is_cancelled() { return; }
        counter.fetch_add(1, Ordering::Relaxed);
        let _ = tx.send(FileCandidate { path, size, tier });
    }
}

/// Drain any pending pivot requests and deep-scan those directories
fn drain_pivot_requests(
    pivot_rx: &crossbeam_channel::Receiver<PathBuf>,
    tx: &Sender<FileCandidate>,
    counter: &Arc<AtomicUsize>,
    _known_sizes: &Option<HashSet<u64>>,
    pivoted_dirs: &mut HashSet<PathBuf>,
) {
    while let Ok(dir) = pivot_rx.try_recv() {
        if is_cancelled() { return; }
        // Don't pivot the same directory twice
        if pivoted_dirs.insert(dir.clone()) {
            discover_pivot_files(&dir, tx, counter);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Hashing engine
// ════════════════════════════════════════════════════════════════════════

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
    
    // Memory-mapped I/O for files <= 512MB
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

/// Get number of CPU cores
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
