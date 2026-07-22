// High-performance thumbnail generator for forensic media scanning
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{BufReader, Write};
use image::{ImageFormat, DynamicImage, imageops::FilterType, GenericImageView};
use rayon::prelude::*;
use sha2::{Sha256, Digest};

const THUMBNAIL_SIZE: u32 = 300; // Optimized for gallery grid
const THUMBNAIL_QUALITY: u8 = 85; // Balance between quality and file size

/// Get the thumbnail cache directory
fn get_thumbnail_cache_dir() -> Result<PathBuf, String> {
    let cache_dir = std::env::temp_dir().join("datapilot_scout_thumbnails");
    
    if !cache_dir.exists() {
        fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("Failed to create thumbnail cache directory: {}", e))?;
    }
    
    Ok(cache_dir)
}

/// Generate a unique cache key from file path and modification time
fn get_cache_key(file_path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(file_path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    
    let modified = metadata.modified()
        .map_err(|e| format!("Failed to get modification time: {}", e))?;
    
    let timestamp = modified.duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Invalid modification time: {}", e))?
        .as_secs();
    
    // Hash: file_path + size + modified_time
    let mut hasher = Sha256::new();
    hasher.update(file_path.to_string_lossy().as_bytes());
    hasher.update(metadata.len().to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    
    Ok(format!("{:x}", hasher.finalize()))
}

/// Check if a cached thumbnail exists and is valid
fn get_cached_thumbnail(file_path: &Path) -> Result<Option<PathBuf>, String> {
    let cache_key = get_cache_key(file_path)?;
    let cache_dir = get_thumbnail_cache_dir()?;
    let thumbnail_path = cache_dir.join(format!("{}.jpg", cache_key));
    
    if thumbnail_path.exists() {
        eprintln!("[Thumbnail] Cache hit: {:?}", file_path.file_name());
        Ok(Some(thumbnail_path))
    } else {
        Ok(None)
    }
}

/// Generate a thumbnail for an image file
fn generate_image_thumbnail(file_path: &Path) -> Result<DynamicImage, String> {
    eprintln!("[Thumbnail] Generating for image: {:?}", file_path);
    
    let img = image::open(file_path)
        .map_err(|e| format!("Failed to open image: {}", e))?;
    
    // Calculate thumbnail dimensions maintaining aspect ratio
    let (width, height) = img.dimensions();
    let (thumb_width, thumb_height) = if width > height {
        let ratio = THUMBNAIL_SIZE as f32 / width as f32;
        (THUMBNAIL_SIZE, (height as f32 * ratio) as u32)
    } else {
        let ratio = THUMBNAIL_SIZE as f32 / height as f32;
        ((width as f32 * ratio) as u32, THUMBNAIL_SIZE)
    };
    
    eprintln!("[Thumbnail] Original: {}x{}, Thumbnail: {}x{}", width, height, thumb_width, thumb_height);
    
    // Use high-quality Lanczos3 filter for best results
    Ok(img.resize(thumb_width, thumb_height, FilterType::Lanczos3))
}

/// Generate a video thumbnail using ffmpeg
#[cfg(target_os = "windows")]
fn generate_video_thumbnail(file_path: &Path) -> Result<DynamicImage, String> {
    eprintln!("[Thumbnail] Generating for video: {:?}", file_path);
    
    let cache_dir = get_thumbnail_cache_dir()?;
    let temp_output = cache_dir.join(format!("temp_frame_{}.jpg", std::process::id()));
    
    // Try to find ffmpeg in multiple locations
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));
    
    let mut ffmpeg_paths = vec![
        PathBuf::from("ffmpeg.exe"),
        PathBuf::from("C:\\ProgramData\\chocolatey\\bin\\ffmpeg.exe"),
    ];
    
    if let Some(ref dir) = exe_dir {
        ffmpeg_paths.push(dir.join("external/ffmpeg.exe"));
        ffmpeg_paths.push(dir.join("external/ffmpeg/ffmpeg.exe"));
        ffmpeg_paths.push(dir.join("external/ffmpeg/bin/ffmpeg.exe"));
        // Walk up to project root for dev mode (target/debug -> src-tauri -> project)
        if let Some(project_root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
            ffmpeg_paths.push(project_root.join("external/ffmpeg/ffmpeg.exe"));
            ffmpeg_paths.push(project_root.join("external/ffmpeg/bin/ffmpeg.exe"));
            // dist-demo bundled ffmpeg
            ffmpeg_paths.push(project_root.join("dist-demo/external/ffmpeg/ffmpeg-8.0.1-essentials_build/bin/ffmpeg.exe"));
        }
    }
    
    // Also check common install locations
    ffmpeg_paths.push(PathBuf::from("C:\\ffmpeg\\bin\\ffmpeg.exe"));
    
    let ffmpeg_path = ffmpeg_paths.iter()
        .find(|p| p.exists())
        .ok_or_else(|| "ffmpeg not found. Please install ffmpeg or place it in external/ folder".to_string())?;
    
    eprintln!("[Thumbnail] Using ffmpeg at: {:?}", ffmpeg_path);
    
    // Extract frame at 1 second (or 10% into video, whichever is less)
    let scale_filter = format!("scale={}:-1", THUMBNAIL_SIZE);
    let file_path_str = file_path.to_string_lossy().to_string();
    let temp_output_str = temp_output.to_string_lossy().to_string();
    
    let mut cmd = std::process::Command::new(ffmpeg_path);
    cmd.args(&[
            "-ss", "1",              // Seek to 1 second
            "-i", &file_path_str,
            "-vframes", "1",         // Extract 1 frame
            "-vf", &scale_filter, // Scale to thumbnail size
            "-q:v", "2",             // High quality
            "-y",                    // Overwrite
            &temp_output_str,
        ]);
    
    // Hide console window on Windows
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    let output = cmd.output()
        .map_err(|e| format!("Failed to run ffmpeg: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("[Thumbnail] ffmpeg error: {}", stderr);
        return Err(format!("ffmpeg failed: {}", stderr));
    }
    
    if !temp_output.exists() {
        return Err("ffmpeg did not generate thumbnail".to_string());
    }
    
    // Load the generated frame
    let img = image::open(&temp_output)
        .map_err(|e| format!("Failed to open generated frame: {}", e))?;
    
    // Clean up temp file
    let _ = fs::remove_file(&temp_output);
    
    Ok(img)
}

#[cfg(not(target_os = "windows"))]
fn generate_video_thumbnail(_file_path: &Path) -> Result<DynamicImage, String> {
    Err("Video thumbnail generation not supported on this platform".to_string())
}

/// Save a thumbnail to the cache
fn save_thumbnail_to_cache(file_path: &Path, thumbnail: &DynamicImage) -> Result<PathBuf, String> {
    let cache_key = get_cache_key(file_path)?;
    let cache_dir = get_thumbnail_cache_dir()?;
    let thumbnail_path = cache_dir.join(format!("{}.jpg", cache_key));
    
    thumbnail.save_with_format(&thumbnail_path, ImageFormat::Jpeg)
        .map_err(|e| format!("Failed to save thumbnail: {}", e))?;
    
    eprintln!("[Thumbnail] Saved to cache: {:?}", thumbnail_path);
    Ok(thumbnail_path)
}

/// Generate or retrieve cached thumbnail for a file
pub fn get_or_generate_thumbnail(file_path: &Path, media_type: &str) -> Result<String, String> {
    // Check cache first
    if let Some(cached_path) = get_cached_thumbnail(file_path)? {
        return Ok(cached_path.to_string_lossy().to_string());
    }
    
    // Generate new thumbnail
    let thumbnail = match media_type {
        "image" => generate_image_thumbnail(file_path)?,
        "video" => generate_video_thumbnail(file_path)?,
        _ => return Err(format!("Unsupported media type: {}", media_type)),
    };
    
    // Save to cache
    let cached_path = save_thumbnail_to_cache(file_path, &thumbnail)?;
    Ok(cached_path.to_string_lossy().to_string())
}

/// Batch generate thumbnails in parallel
pub fn batch_generate_thumbnails(files: Vec<(String, String)>) -> Vec<Result<String, String>> {
    eprintln!("[Thumbnail] Batch generating {} thumbnails", files.len());
    
    files.par_iter()
        .map(|(file_path, media_type)| {
            let path = Path::new(file_path);
            get_or_generate_thumbnail(path, media_type)
        })
        .collect()
}

/// Clear the thumbnail cache
pub fn clear_thumbnail_cache() -> Result<(), String> {
    let cache_dir = get_thumbnail_cache_dir()?;
    
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)
            .map_err(|e| format!("Failed to clear cache: {}", e))?;
        
        // Recreate the directory
        fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("Failed to recreate cache directory: {}", e))?;
    }
    
    eprintln!("[Thumbnail] Cache cleared");
    Ok(())
}

/// Get cache statistics
#[derive(serde::Serialize)]
pub struct ThumbnailCacheStats {
    pub total_thumbnails: usize,
    pub total_size_bytes: u64,
    pub cache_directory: String,
}

pub fn get_cache_stats() -> Result<ThumbnailCacheStats, String> {
    let cache_dir = get_thumbnail_cache_dir()?;
    
    let mut total_thumbnails = 0;
    let mut total_size_bytes = 0u64;
    
    if cache_dir.exists() {
        for entry in fs::read_dir(&cache_dir)
            .map_err(|e| format!("Failed to read cache directory: {}", e))? 
        {
            if let Ok(entry) = entry {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        total_thumbnails += 1;
                        total_size_bytes += metadata.len();
                    }
                }
            }
        }
    }
    
    Ok(ThumbnailCacheStats {
        total_thumbnails,
        total_size_bytes,
        cache_directory: cache_dir.to_string_lossy().to_string(),
    })
}

/// Tauri command to generate a single thumbnail
#[tauri::command]
pub async fn generate_thumbnail(file_path: String, media_type: String) -> Result<String, String> {
    let path = Path::new(&file_path);
    get_or_generate_thumbnail(path, &media_type)
}

/// Tauri command: read an already-generated (cached) thumbnail off disk and
/// return it as a `data:image/jpeg;base64,...` URL.
///
/// WHY THIS EXISTS: rendering 250 cached thumbnails per page through Tauri's
/// asset:// protocol saturates WebView2's ~6-connections-per-origin pool, so
/// most tiles stall at opacity:0 (blank). Cached thumbnails are tiny (~10KB),
/// so serving them as inline data URLs sidesteps the connection pool entirely
/// and they render instantly. Lean on purpose: no logging (called at scale),
/// assumes JPEG (all cached thumbs are saved as .jpg by save_thumbnail_to_cache).
#[tauri::command]
pub async fn get_thumbnail_data_url(path: String) -> Result<String, String> {
    use base64::Engine;
    let p = Path::new(&path);
    // Guard against oversized reads — a real thumbnail is a few KB. Anything
    // over 8MB is not one of ours; refuse rather than inline a huge payload.
    let meta = fs::metadata(p).map_err(|e| format!("thumb stat failed: {}", e))?;
    if meta.len() > 8 * 1024 * 1024 {
        return Err("thumbnail too large to inline".to_string());
    }
    let bytes = fs::read(p).map_err(|e| format!("thumb read failed: {}", e))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(format!("data:image/jpeg;base64,{}", b64))
}

/// Read a cached thumbnail file off disk and return it as a data URL.
/// Shared by the single and batch commands.
fn read_thumb_as_data_url(path: &Path) -> Result<String, String> {
    use base64::Engine;
    let meta = fs::metadata(path).map_err(|e| format!("thumb stat failed: {}", e))?;
    if meta.len() > 8 * 1024 * 1024 {
        return Err("thumbnail too large to inline".to_string());
    }
    let bytes = fs::read(path).map_err(|e| format!("thumb read failed: {}", e))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(format!("data:image/jpeg;base64,{}", b64))
}

/// One tile's request in a batch read.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThumbBatchReq {
    /// Opaque id echoed back so the frontend can match responses (filePath).
    pub key: String,
    /// Previously-generated cached thumbnail path, if the frontend has one.
    pub thumb_path: Option<String>,
    /// Original media file — used to regenerate the thumbnail if the cached
    /// one is missing (self-healing after a %TEMP% clear or a failed scan).
    pub source_path: Option<String>,
    /// "image" or "video" — required to regenerate from source.
    pub media_type: Option<String>,
}

/// One tile's result in a batch read.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThumbBatchResp {
    pub key: String,
    /// data:image/jpeg;base64,... or null if it could not be produced.
    pub data_url: Option<String>,
    /// The resolved/generated cached path, so the frontend can persist it.
    pub thumb_path: Option<String>,
}

/// Tauri command: resolve + read many thumbnails in ONE IPC round-trip.
///
/// For each item: if a cached thumbnail exists it is read and inlined as a
/// data URL; otherwise, when a source path + media type are supplied, the
/// thumbnail is regenerated from the original file first (self-healing).
/// Work is parallelized with rayon. Batching collapses the per-tile invoke
/// overhead that made large galleries fill in slowly, and the viewport-aware
/// caller ensures only on-screen tiles are requested.
#[tauri::command]
pub async fn get_thumbnails_batch(
    items: Vec<ThumbBatchReq>,
) -> Result<Vec<ThumbBatchResp>, String> {
    let results = items
        .par_iter()
        .map(|it| {
            // 1. Resolve a usable thumbnail path (regenerate from source if needed).
            let resolved: Option<String> = match &it.thumb_path {
                Some(tp) if !tp.is_empty() && Path::new(tp).exists() => Some(tp.clone()),
                _ => match (&it.source_path, &it.media_type) {
                    (Some(sp), Some(mt)) if !sp.is_empty() && Path::new(sp).exists() => {
                        get_or_generate_thumbnail(Path::new(sp), mt).ok()
                    }
                    _ => None,
                },
            };
            // 2. Read it as a data URL.
            let data_url = resolved
                .as_ref()
                .and_then(|p| read_thumb_as_data_url(Path::new(p)).ok());
            ThumbBatchResp {
                key: it.key.clone(),
                data_url,
                thumb_path: resolved,
            }
        })
        .collect();
    Ok(results)
}

/// Tauri command to batch generate thumbnails
#[tauri::command]
pub async fn batch_generate_thumbnails_command(
    files: Vec<(String, String)>
) -> Result<Vec<Option<String>>, String> {
    let results = batch_generate_thumbnails(files);
    
    // Convert Result to Option for easier frontend handling
    Ok(results.into_iter().map(|r| r.ok()).collect())
}

/// Tauri command to clear thumbnail cache
#[tauri::command]
pub async fn clear_thumbnail_cache_command() -> Result<(), String> {
    clear_thumbnail_cache()
}

/// Tauri command to get cache statistics
#[tauri::command]
pub async fn get_thumbnail_cache_stats() -> Result<ThumbnailCacheStats, String> {
    get_cache_stats()
}
