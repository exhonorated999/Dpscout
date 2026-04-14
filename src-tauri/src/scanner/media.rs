use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use md5::Md5;
use std::io::Read;
use rayon::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaFile {
    pub id: String,
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub extension: String,
    pub media_type: MediaType,
    pub thumbnail_path: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub date_created: Option<String>,
    pub date_modified: Option<String>,
    pub date_accessed: Option<String>,
    pub md5_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub flags: Vec<MediaFlag>,
    pub metadata: Option<MediaMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaType {
    Image,
    Video,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaFlag {
    pub flag_type: FlagType,
    pub severity: Severity,
    pub reason: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlagType {
    HashMatch,
    KeywordMatch,
    SuspiciousFilename,
    MetadataFlag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaMetadata {
    pub camera: Option<String>,
    pub date_taken: Option<String>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude: Option<f64>,
    pub orientation: Option<u32>,
    pub software: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaScanOptions {
    #[serde(rename = "scanPaths")]
    pub scan_paths: Vec<String>,
    #[serde(rename = "includeImages")]
    pub include_images: bool,
    #[serde(rename = "includeVideos")]
    pub include_videos: bool,
    #[serde(rename = "generateThumbnails")]
    pub generate_thumbnails: bool,
    #[serde(rename = "computeHashes")]
    pub compute_hashes: bool,
    #[serde(rename = "checkHashLists")]
    pub check_hash_lists: bool,
    #[serde(rename = "checkKeywords")]
    pub check_keywords: bool,
    #[serde(rename = "maxFileSize")]
    pub max_file_size: u64, // in bytes
    #[serde(rename = "thumbnailSize")]
    pub thumbnail_size: u32,
}

/// Supported image extensions
const IMAGE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", 
    "webp", "heic", "heif", "ico", "raw", "cr2", "nef", "arw"
];

/// Supported video extensions
const VIDEO_EXTENSIONS: &[&str] = &[
    "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm", 
    "m4v", "mpg", "mpeg", "3gp", "ogv"
];

/// Common suspicious filename patterns
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "child", "kid", "young", "teen", "pedo", "loli", "lolita",
    "preteen", "underage", "minor", "jailbait", "cp", "csam",
    "pthc", "r@ygold", "hussyfan", "babyj", "kidzilla"
];

/// Scan directories for media files (optimized with parallel processing)
pub fn scan_media_files(
    options: MediaScanOptions,
    keyword_lists: Vec<Vec<String>>,
    use_hash_db: bool,
) -> Result<Vec<MediaFile>, String> {
    println!("Starting optimized media scan...");
    let start_time = std::time::Instant::now();
    
    let temp_dir = get_temp_thumbnail_dir()?;
    
    // Phase 1: Fast file discovery (single-threaded walk, but efficient)
    let mut candidate_files = Vec::new();
    
    for scan_path in &options.scan_paths {
        if !Path::new(scan_path).exists() {
            continue;
        }

        println!("Scanning directory: {}", scan_path);
        
        for entry in WalkDir::new(scan_path)
            .follow_links(false)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            
            if !path.is_file() {
                continue;
            }

            // Quick extension check
            if let Some(ext) = path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                
                let media_type = if IMAGE_EXTENSIONS.contains(&ext_lower.as_str()) && options.include_images {
                    MediaType::Image
                } else if VIDEO_EXTENSIONS.contains(&ext_lower.as_str()) && options.include_videos {
                    MediaType::Video
                } else {
                    continue;
                };

                // Check file size limit
                if let Ok(metadata) = fs::metadata(path) {
                    let file_size = metadata.len();
                    if options.max_file_size > 0 && file_size > options.max_file_size {
                        continue;
                    }
                    
                    // Skip small files (icons, thumbnails, etc.) - focus on contraband
                    // 10KB minimum = 10,240 bytes
                    if file_size < 10_240 {
                        continue;
                    }

                    candidate_files.push((path.to_path_buf(), media_type, file_size));
                }
            }
        }
    }
    
    println!("Found {} candidate media files", candidate_files.len());
    
    // Phase 2: Parallel processing of candidates
    let keyword_lists = Arc::new(keyword_lists);
    let temp_dir = Arc::new(temp_dir);
    let options_arc = Arc::new(options);
    
    // Hash database disabled for now
    let _use_hash_db = use_hash_db; // Keep parameter for future use
    
    let media_files: Vec<MediaFile> = candidate_files
        .par_iter()
        .filter_map(|(path, media_type, file_size)| {
            process_media_file(
                path,
                media_type,
                *file_size,
                &keyword_lists,
                &temp_dir,
                &options_arc,
            ).ok()
        })
        .collect();
    
    let elapsed = start_time.elapsed();
    println!("Scan complete: {} files processed in {:.2}s", media_files.len(), elapsed.as_secs_f64());
    
    Ok(media_files)
}

pub fn scan_media_files_with_progress<F, G>(
    options: MediaScanOptions,
    keyword_lists: Vec<Vec<String>>,
    use_hash_db: bool,
    progress_callback: F,
    file_found_callback: Option<G>,
) -> Result<Vec<MediaFile>, String>
where
    F: Fn(usize, usize, String) + Send + Sync,
    G: Fn(&MediaFile) + Send + Sync,
{
    println!("Starting optimized media scan with progress...");
    let start_time = std::time::Instant::now();
    
    let temp_dir = get_temp_thumbnail_dir()?;
    
    // Phase 1: Fast file discovery (single-threaded walk, but efficient)
    let mut candidate_files = Vec::new();
    
    for scan_path in &options.scan_paths {
        if !Path::new(scan_path).exists() {
            continue;
        }

        println!("Scanning directory: {}", scan_path);
        
        for entry in WalkDir::new(scan_path)
            .follow_links(false)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            
            if !path.is_file() {
                continue;
            }

            // Quick extension check
            if let Some(ext) = path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                
                let media_type = if IMAGE_EXTENSIONS.contains(&ext_lower.as_str()) && options.include_images {
                    MediaType::Image
                } else if VIDEO_EXTENSIONS.contains(&ext_lower.as_str()) && options.include_videos {
                    MediaType::Video
                } else {
                    continue;
                };

                // Check file size limit
                if let Ok(metadata) = fs::metadata(path) {
                    let file_size = metadata.len();
                    if options.max_file_size > 0 && file_size > options.max_file_size {
                        continue;
                    }
                    
                    // Skip small files (icons, thumbnails, etc.) - focus on contraband
                    // 10KB minimum = 10,240 bytes
                    if file_size < 10_240 {
                        continue;
                    }

                    candidate_files.push((path.to_path_buf(), media_type, file_size));
                }
            }
        }
    }
    
    let total_files = candidate_files.len();
    println!("Found {} candidate media files", total_files);
    eprintln!("[Media Scan] Phase 1 complete: Found {} candidate media files", total_files);
    eprintln!("[Media Scan] Hash checking enabled: {}", options.check_hash_lists);
    eprintln!("[Media Scan] Hash computing enabled: {}", options.compute_hashes);
    
    // Phase 2: Sequential processing with progress updates
    let keyword_lists = Arc::new(keyword_lists);
    let temp_dir = Arc::new(temp_dir);
    let options_arc = Arc::new(options);
    
    let _use_hash_db = use_hash_db;
    
    let mut media_files = Vec::new();
    
    eprintln!("[Media Scan] Starting Phase 2: Processing {} files", total_files);
    
    for (idx, (path, media_type, file_size)) in candidate_files.iter().enumerate() {
        if let Ok(media_file) = process_media_file(
            path,
            media_type,
            *file_size,
            &keyword_lists,
            &temp_dir,
            &options_arc,
        ) {
            // Emit file immediately for live preview
            if let Some(ref callback) = file_found_callback {
                callback(&media_file);
            }
            
            media_files.push(media_file);
        }
        
        let processed = idx + 1;
        
        // Report progress every 10 files or at the end
        if processed % 10 == 0 || processed == total_files {
            let current_file = path.to_string_lossy().to_string();
            progress_callback(processed, total_files, current_file);
        }
    }
    
    let elapsed = start_time.elapsed();
    println!("Scan complete: {} files processed in {:.2}s", media_files.len(), elapsed.as_secs_f64());
    eprintln!("[Media Scan] ========== SCAN COMPLETE ==========");
    eprintln!("[Media Scan] Total candidates found: {}", total_files);
    eprintln!("[Media Scan] Successfully processed: {}", media_files.len());
    eprintln!("[Media Scan] Time elapsed: {:.2}s", elapsed.as_secs_f64());
    eprintln!("[Media Scan] Files with hash matches: {}", media_files.iter().filter(|f| f.flags.iter().any(|flag| matches!(flag.flag_type, FlagType::HashMatch))).count());
    
    Ok(media_files)
}

/// Process a single media file (called in parallel)
fn process_media_file(
    path: &Path,
    media_type: &MediaType,
    file_size: u64,
    keyword_lists: &Arc<Vec<Vec<String>>>,
    temp_dir: &Arc<PathBuf>,
    options: &Arc<MediaScanOptions>,
) -> Result<MediaFile, String> {
    // Create media file entry
    let mut media_file = create_media_file_entry(path, media_type, file_size)?;

    // Check for suspicious filename patterns
    check_suspicious_filename(&mut media_file);

    // Check keywords in filename
    if options.check_keywords {
        check_filename_keywords(&mut media_file, keyword_lists);
    }

    // Compute hashes if enabled (for display purposes, NOT for hash matching)
    // Hash matching is now done separately via scan_for_hash_matches command
    if options.compute_hashes {
        if let Ok((md5, sha256)) = compute_file_hashes(path) {
            media_file.md5_hash = Some(md5.clone());
            media_file.sha256_hash = Some(sha256.clone());
        } else {
            eprintln!("Failed to compute hashes for: {}", path.display());
        }
    }

    // Generate thumbnail using optimized cached generator
    if options.generate_thumbnails {
        let media_type_str = match media_type {
            MediaType::Image => "image",
            MediaType::Video => "video",
            _ => return Ok(media_file),
        };
        
        match crate::thumbnail_generator::get_or_generate_thumbnail(path, media_type_str) {
            Ok(thumb_path) => {
                eprintln!("✓ Thumbnail ready: {} -> {}", path.display(), thumb_path);
                media_file.thumbnail_path = thumb_path;
            }
            Err(e) => {
                eprintln!("✗ Thumbnail generation failed for {}: {}", path.display(), e);
            }
        }
    }

    Ok(media_file)
}

/// Create a media file entry from path
fn create_media_file_entry(
    path: &Path,
    media_type: &MediaType,
    file_size: u64,
) -> Result<MediaFile, String> {
    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let extension = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    let metadata = fs::metadata(path).ok();
    
    let date_modified = metadata.as_ref()
        .and_then(|m| m.modified().ok())
        .and_then(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339().into());

    let date_created = metadata.as_ref()
        .and_then(|m| m.created().ok())
        .and_then(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339().into());

    let date_accessed = metadata.as_ref()
        .and_then(|m| m.accessed().ok())
        .and_then(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339().into());

    Ok(MediaFile {
        id: uuid::Uuid::new_v4().to_string(),
        file_path: path.to_string_lossy().to_string(),
        file_name,
        file_size,
        extension,
        media_type: media_type.clone(),
        thumbnail_path: String::new(),
        width: None,
        height: None,
        date_created,
        date_modified,
        date_accessed,
        md5_hash: None,
        sha256_hash: None,
        flags: Vec::new(),
        metadata: None,
    })
}

/// Check filename for suspicious patterns
fn check_suspicious_filename(media_file: &mut MediaFile) {
    let filename_lower = media_file.file_name.to_lowercase();
    
    for pattern in SUSPICIOUS_PATTERNS {
        if filename_lower.contains(pattern) {
            media_file.flags.push(MediaFlag {
                flag_type: FlagType::SuspiciousFilename,
                severity: Severity::Critical,
                reason: format!("Suspicious pattern detected in filename: '{}'", pattern),
                source: "Built-in Pattern Detection".to_string(),
            });
        }
    }
}

/// Check filename against keyword lists
fn check_filename_keywords(media_file: &mut MediaFile, keyword_lists: &[Vec<String>]) {
    let filename_lower = media_file.file_name.to_lowercase();
    
    for keyword_list in keyword_lists {
        for keyword in keyword_list {
            let keyword_lower = keyword.to_lowercase();
            if filename_lower.contains(&keyword_lower) {
                media_file.flags.push(MediaFlag {
                    flag_type: FlagType::KeywordMatch,
                    severity: Severity::High,
                    reason: format!("Keyword match: '{}'", keyword),
                    source: "Custom Keyword List".to_string(),
                });
            }
        }
    }
}

/// Compute MD5 and SHA256 hashes for a file
fn compute_file_hashes(path: &Path) -> Result<(String, String), String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Failed to open file for hashing: {}", e))?;
    
    let mut md5_hasher = Md5::new();
    let mut sha256_hasher = Sha256::new();
    let mut buffer = vec![0u8; 8192]; // 8KB buffer
    
    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        if bytes_read == 0 {
            break;
        }
        
        md5_hasher.update(&buffer[..bytes_read]);
        sha256_hasher.update(&buffer[..bytes_read]);
    }
    
    let md5_hash = format!("{:x}", md5_hasher.finalize());
    let sha256_hash = format!("{:x}", sha256_hasher.finalize());
    
    Ok((md5_hash, sha256_hash))
}

// Hash checking has been moved to the dedicated hash_scan module
// Media scanning now only displays media files, hash matching is separate

/// Generate thumbnail for image
fn generate_thumbnail(
    image_path: &Path,
    temp_dir: &Path,
    size: u32,
) -> Result<String, String> {
    // Use image crate to generate thumbnail
    let img = image::open(image_path)
        .map_err(|e| format!("Failed to open image: {}", e))?;

    let thumbnail = img.thumbnail(size, size);

    let thumb_filename = format!(
        "{}.jpg",
        uuid::Uuid::new_v4()
    );
    let thumb_path = temp_dir.join(thumb_filename);

    thumbnail.save(&thumb_path)
        .map_err(|e| format!("Failed to save thumbnail: {}", e))?;

    Ok(thumb_path.to_string_lossy().to_string())
}

/// Generate video thumbnail by extracting first frame using ffmpeg
fn generate_video_thumbnail(
    video_path: &Path,
    temp_dir: &Path,
    size: u32,
) -> Result<String, String> {
    // Generate unique filename for thumbnail
    let thumb_filename = format!("{}.jpg", uuid::Uuid::new_v4());
    let thumb_path = temp_dir.join(&thumb_filename);
    
    // Get path to bundled ffmpeg executable
    let ffmpeg_path = get_ffmpeg_path()?;
    
    // Build command with CREATE_NO_WINDOW flag on Windows to suppress console windows
    let mut cmd = std::process::Command::new(&ffmpeg_path);
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    // Extract frame at 1 second (or first frame if video is shorter)
    // Use ffmpeg to extract a single frame and resize it
    let output = cmd
        .arg("-i")
        .arg(video_path)
        .arg("-ss")
        .arg("00:00:01") // Seek to 1 second
        .arg("-vframes")
        .arg("1") // Extract 1 frame
        .arg("-vf")
        .arg(format!("scale={}:{}:force_original_aspect_ratio=decrease", size, size)) // Scale to thumbnail size
        .arg("-y") // Overwrite output file
        .arg(&thumb_path)
        .output()
        .map_err(|e| format!("Failed to execute ffmpeg: {}", e))?;
    
    if !output.status.success() {
        // If seeking to 1 second failed, try to get the very first frame
        let mut cmd_first = std::process::Command::new(&ffmpeg_path);
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd_first.creation_flags(CREATE_NO_WINDOW);
        }
        
        let output_first = cmd_first
            .arg("-i")
            .arg(video_path)
            .arg("-vframes")
            .arg("1") // Extract first frame only
            .arg("-vf")
            .arg(format!("scale={}:{}:force_original_aspect_ratio=decrease", size, size))
            .arg("-y")
            .arg(&thumb_path)
            .output()
            .map_err(|e| format!("Failed to execute ffmpeg (first frame): {}", e))?;
        
        if !output_first.status.success() {
            let stderr = String::from_utf8_lossy(&output_first.stderr);
            return Err(format!("ffmpeg failed: {}", stderr));
        }
    }
    
    // Verify the thumbnail was created
    if !thumb_path.exists() {
        return Err("Thumbnail file was not created".to_string());
    }
    
    Ok(thumb_path.to_string_lossy().to_string())
}

/// Get temporary directory for thumbnails
fn get_temp_thumbnail_dir() -> Result<PathBuf, String> {
    let temp = std::env::temp_dir();
    let thumb_dir = temp.join("hindsight_thumbnails");
    
    if !thumb_dir.exists() {
        fs::create_dir_all(&thumb_dir)
            .map_err(|e| format!("Failed to create thumbnail directory: {}", e))?;
    }

    Ok(thumb_dir)
}

/// Get path to bundled ffmpeg executable
fn get_ffmpeg_path() -> Result<String, String> {
    // Try to get the bundled ffmpeg from external folder
    let exe_dir = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe directory: {}", e))?
        .parent()
        .ok_or("Failed to get parent directory")?
        .to_path_buf();
    
    // Check for bundled ffmpeg in external/ffmpeg/ (direct path)
    let bundled_ffmpeg = exe_dir.join("external").join("ffmpeg").join("ffmpeg.exe");
    if bundled_ffmpeg.exists() {
        eprintln!("Found ffmpeg at: {}", bundled_ffmpeg.display());
        return Ok(bundled_ffmpeg.to_string_lossy().to_string());
    }
    
    // Check for ffmpeg in subdirectories (e.g., ffmpeg-8.0.1-essentials_build/bin/)
    let ffmpeg_dir = exe_dir.join("external").join("ffmpeg");
    if ffmpeg_dir.exists() {
        // Search for ffmpeg.exe in subdirectories
        if let Some(entry) = walkdir::WalkDir::new(&ffmpeg_dir)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name() == "ffmpeg.exe") 
        {
            let path = entry.path().to_path_buf();
            eprintln!("Found ffmpeg in subdirectory: {}", path.display());
            return Ok(path.to_string_lossy().to_string());
        }
    }
    
    // Fallback: check if ffmpeg is in PATH
    let ffmpeg_check = std::process::Command::new("ffmpeg")
        .arg("-version")
        .output();
    
    if ffmpeg_check.is_ok() {
        eprintln!("Using ffmpeg from system PATH");
        return Ok("ffmpeg".to_string());
    }
    
    Err("ffmpeg not found. Please install ffmpeg or ensure it's in the external/ffmpeg/ folder.".to_string())
}

/// Clear thumbnail cache
pub fn clear_thumbnail_cache() -> Result<(), String> {
    let thumb_dir = get_temp_thumbnail_dir()?;
    
    if thumb_dir.exists() {
        fs::remove_dir_all(&thumb_dir)
            .map_err(|e| format!("Failed to clear thumbnail cache: {}", e))?;
        
        fs::create_dir_all(&thumb_dir)
            .map_err(|e| format!("Failed to recreate thumbnail directory: {}", e))?;
    }

    Ok(())
}
