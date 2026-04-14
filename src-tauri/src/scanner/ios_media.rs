use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use chrono::{DateTime, Utc};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a Command that runs without showing a window on Windows
fn create_hidden_command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    cmd
}

/// Get path to libimobiledevice tools
fn get_tool_path(tool_name: &str) -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    let bundled_path = exe_dir.join("external").join("libimobiledevice").join(tool_name);
    
    if bundled_path.exists() {
        bundled_path
    } else {
        PathBuf::from(tool_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosMediaFile {
    pub path: String,
    pub filename: String,
    pub size_bytes: u64,
    pub file_type: String, // "Image" or "Video"
    pub created_date: String,
    pub modified_date: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration: Option<f64>,
}

/// Scan iOS device media using Windows MTP + AFC fallback
pub fn scan_ios_media(udid: &str, progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>) 
    -> Result<Vec<serde_json::Value>, String> 
{
    eprintln!("[iOS Media] Starting media scan for device: {}", udid);
    
    // First, verify device is trusted
    if !verify_device_trust(udid)? {
        return Err("Device is not trusted. Please unlock device and tap 'Trust This Computer'".to_string());
    }
    
    // Strategy 1: Try Windows MTP access (most reliable on Windows)
    eprintln!("[iOS Media] Attempting Windows MTP access...");
    match scan_ios_via_windows_mtp(udid, progress_callback.as_ref()) {
        Ok(files) if !files.is_empty() => {
            eprintln!("[iOS Media] Successfully scanned {} files via MTP", files.len());
            return Ok(files);
        }
        Ok(_) => eprintln!("[iOS Media] MTP access succeeded but found no files"),
        Err(e) => eprintln!("[iOS Media] MTP access failed: {}", e),
    }
    
    // Strategy 2: Try iTunes backup method
    eprintln!("[iOS Media] Attempting iTunes backup analysis...");
    match find_and_scan_latest_backup(udid) {
        Ok(files) if !files.is_empty() => {
            eprintln!("[iOS Media] Found {} files in iTunes backup", files.len());
            return Ok(files);
        }
        Ok(_) => eprintln!("[iOS Media] No iTunes backup found"),
        Err(e) => eprintln!("[iOS Media] Backup scan failed: {}", e),
    }
    
    // If both methods fail, provide helpful error
    Err(format!(
        "Unable to access iOS media files.\n\n\
        Recommended solutions:\n\
        1. Use 'USB Drive' mode: Navigate to 'This PC > Apple iPhone > Internal Storage > DCIM'\n\
        2. Create iTunes backup first: Open iTunes, select device, click 'Back Up Now'\n\
        3. Ensure device is unlocked and trusted\n\n\
        Device UDID: {}", udid
    ))
}

/// Scan iOS device via Windows MTP (This PC\iPhone)
#[cfg(target_os = "windows")]
fn scan_ios_via_windows_mtp(
    udid: &str,
    progress_callback: Option<&Box<dyn Fn(usize, usize) + Send>>
) -> Result<Vec<serde_json::Value>, String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    
    eprintln!("[iOS Media] Scanning Windows portable device paths...");
    
    // Windows shows iPhone as portable device
    // Typically at: This PC\Apple iPhone\Internal Storage\DCIM
    let portable_device_base = PathBuf::from(r"\\?\");
    
    // Try to find iPhone in portable devices
    let iphone_path = find_iphone_mtp_path()?;
    
    eprintln!("[iOS Media] Found iPhone at: {:?}", iphone_path);
    
    // Scan DCIM directory
    let dcim_path = iphone_path.join("Internal Storage").join("DCIM");
    
    if !dcim_path.exists() {
        return Err("DCIM directory not accessible. Ensure iPhone is unlocked.".to_string());
    }
    
    eprintln!("[iOS Media] Scanning DCIM: {:?}", dcim_path);
    
    let mut media_files = Vec::new();
    scan_directory_recursive(&dcim_path, &mut media_files, progress_callback)?;
    
    Ok(media_files)
}

#[cfg(not(target_os = "windows"))]
fn scan_ios_via_windows_mtp(
    _udid: &str,
    _progress_callback: Option<&Box<dyn Fn(usize, usize) + Send>>
) -> Result<Vec<serde_json::Value>, String> {
    Err("MTP scanning only available on Windows".to_string())
}

/// Find iPhone MTP path in Windows
#[cfg(target_os = "windows")]
fn find_iphone_mtp_path() -> Result<PathBuf, String> {
    // Check common locations where iPhone appears
    let possible_paths = vec![
        PathBuf::from(r"\\?\Apple iPhone"),
        PathBuf::from(r"\\?\iPhone"),
    ];
    
    for path in possible_paths {
        if path.exists() {
            return Ok(path);
        }
    }
    
    // Try scanning This PC for portable devices
    // This requires WMI or shell COM interface access
    // For now, instruct user to use USB Drive mode
    
    Err("iPhone not found in Windows portable devices. Use 'USB Drive' mode instead.".to_string())
}

#[cfg(not(target_os = "windows"))]
fn find_iphone_mtp_path() -> Result<PathBuf, String> {
    Err("MTP path detection only available on Windows".to_string())
}

/// Recursively scan directory for media files
fn scan_directory_recursive(
    dir: &Path,
    media_files: &mut Vec<serde_json::Value>,
    progress_callback: Option<&Box<dyn Fn(usize, usize) + Send>>
) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory {:?}: {}", dir, e))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        
        if path.is_dir() {
            // Recursive scan
            scan_directory_recursive(&path, media_files, progress_callback)?;
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                
                // Check if it's a media file
                let is_image = matches!(ext_lower.as_str(), "jpg" | "jpeg" | "png" | "heic" | "gif" | "bmp" | "webp");
                let is_video = matches!(ext_lower.as_str(), "mov" | "mp4" | "m4v" | "avi" | "mpg" | "mpeg" | "3gp");
                
                if is_image || is_video {
                    if let Ok(metadata) = fs::metadata(&path) {
                        let filename = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        
                        let mut media_file = serde_json::Map::new();
                        media_file.insert("path".to_string(), serde_json::Value::String(path.to_string_lossy().to_string()));
                        media_file.insert("filename".to_string(), serde_json::Value::String(filename));
                        media_file.insert("sizeBytes".to_string(), serde_json::Value::Number(metadata.len().into()));
                        media_file.insert("fileType".to_string(), serde_json::Value::String(
                            if is_image { "Image" } else { "Video" }.to_string()
                        ));
                        
                        // Get timestamps
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(datetime) = modified.duration_since(std::time::UNIX_EPOCH) {
                                let dt = DateTime::<Utc>::from(std::time::UNIX_EPOCH + datetime);
                                media_file.insert("modifiedDate".to_string(), 
                                    serde_json::Value::String(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()));
                            }
                        }
                        
                        media_files.push(serde_json::Value::Object(media_file));
                        
                        if let Some(callback) = progress_callback {
                            callback(media_files.len(), media_files.len());
                        }
                        
                        // Limit to prevent overwhelming
                        if media_files.len() >= 10000 {
                            eprintln!("[iOS Media] Reached 10,000 file limit");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Find and scan the latest iTunes backup for this device
fn find_and_scan_latest_backup(udid: &str) -> Result<Vec<serde_json::Value>, String> {
    let username = std::env::var("USERNAME").unwrap_or_default();
    let backup_base = PathBuf::from(format!(
        r"C:\Users\{}\AppData\Roaming\Apple Computer\MobileSync\Backup",
        username
    ));
    
    if !backup_base.exists() {
        return Err("iTunes backup directory not found".to_string());
    }
    
    // Find backup directory for this UDID
    let entries = fs::read_dir(&backup_base)
        .map_err(|e| format!("Failed to read backup directory: {}", e))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let backup_dir = entry.path();
        
        // Check if this backup is for our device
        // Backup directory names are usually the UDID
        if backup_dir.is_dir() {
            let dir_name = backup_dir.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            
            if dir_name.contains(udid) || check_backup_info_for_udid(&backup_dir, udid) {
                eprintln!("[iOS Media] Found backup for device at: {:?}", backup_dir);
                return scan_ios_backup_media(&backup_dir);
            }
        }
    }
    
    Err(format!("No iTunes backup found for device {}", udid))
}

/// Check if backup Info.plist contains matching UDID
fn check_backup_info_for_udid(backup_dir: &Path, udid: &str) -> bool {
    let info_plist = backup_dir.join("Info.plist");
    if !info_plist.exists() {
        return false;
    }
    
    // Read Info.plist and check for UDID
    if let Ok(content) = fs::read_to_string(&info_plist) {
        content.contains(udid)
    } else {
        false
    }
}

/// Verify device trust status
fn verify_device_trust(udid: &str) -> Result<bool, String> {
    let pair_tool = get_tool_path("idevicepair.exe");
    
    let output = create_hidden_command(&pair_tool)
        .arg("-u")
        .arg(udid)
        .arg("validate")
        .output()
        .map_err(|e| format!("Failed to check trust status: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let is_trusted = stdout.contains("SUCCESS");
    
    if !is_trusted {
        eprintln!("[iOS Media] Device not trusted. User needs to accept trust dialog.");
    } else {
        eprintln!("[iOS Media] Device is trusted");
    }
    
    Ok(is_trusted)
}

/// Extract media files using AFC protocol
fn extract_media_via_afc(
    udid: &str,
    temp_dir: &Path,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>
) -> Result<Vec<serde_json::Value>, String> {
    eprintln!("[iOS Media] Accessing device filesystem via AFC...");
    
    // Use idevicebackup2 info to check accessibility
    let backup_tool = get_tool_path("idevicebackup2.exe");
    
    // First, check if we can access the device
    let info_output = create_hidden_command(&backup_tool)
        .arg("-u")
        .arg(udid)
        .arg("info")
        .arg(temp_dir.to_str().unwrap())
        .output()
        .map_err(|e| format!("Failed to query device: {}", e))?;
    
    if !info_output.status.success() {
        let stderr = String::from_utf8_lossy(&info_output.stderr);
        eprintln!("[iOS Media] AFC access check failed: {}", stderr);
        
        // Fallback: Try direct file listing approach
        return extract_media_direct_listing(udid);
    }
    
    // Parse the backup info to understand device structure
    let stdout = String::from_utf8_lossy(&info_output.stdout);
    eprintln!("[iOS Media] Device info retrieved successfully");
    
    // Now scan for media files
    // iOS media is typically in:
    // - /DCIM/
    // - /PhotoData/
    // - Media/DCIM/
    
    scan_media_directories(udid, temp_dir, progress_callback)
}

/// Direct file listing approach (fallback)
fn extract_media_direct_listing(udid: &str) -> Result<Vec<serde_json::Value>, String> {
    eprintln!("[iOS Media] Using direct file listing method");
    
    // For now, return informative error about limitations
    // In production, we would use ifuse or similar AFC mounting
    Err(format!(
        "AFC media extraction requires additional setup. \n\
        Please use one of these methods:\n\
        1. Create iTunes backup first, then scan backup\n\
        2. Use USB Drive mode: This PC > iPhone > DCIM\n\
        3. Install iFuse (Windows) for direct AFC mounting"
    ))
}

/// Scan media directories on iOS device
fn scan_media_directories(
    udid: &str,
    temp_dir: &Path,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>
) -> Result<Vec<serde_json::Value>, String> {
    let mut media_files = Vec::new();
    
    // Known iOS media paths
    let media_paths = vec![
        "DCIM",
        "PhotoData", 
        "Media/DCIM",
    ];
    
    eprintln!("[iOS Media] Scanning media directories...");
    
    // For each path, try to extract and scan
    for media_path in media_paths {
        eprintln!("[iOS Media] Checking path: {}", media_path);
        
        // Try to create a targeted backup that includes this path
        let files = scan_specific_path(udid, media_path, temp_dir)?;
        media_files.extend(files);
        
        if let Some(ref callback) = progress_callback {
            callback(media_files.len(), media_files.len());
        }
    }
    
    if media_files.is_empty() {
        eprintln!("[iOS Media] No media files found via AFC protocol");
        return Err(
            "No media files accessible via AFC. \n\
            This may be due to:\n\
            1. iOS restrictions (iOS 13+ restricts full filesystem access)\n\
            2. Device needs to be unlocked\n\
            3. Backup encryption settings\n\n\
            Recommended: Use 'USB Drive' mode to access DCIM folder directly via Windows.".to_string()
        );
    }
    
    Ok(media_files)
}

/// Scan a specific path on iOS device
fn scan_specific_path(udid: &str, path: &str, temp_dir: &Path) -> Result<Vec<serde_json::Value>, String> {
    let mut files = Vec::new();
    
    // For Windows + libimobiledevice, the most reliable method is:
    // 1. Create a partial backup that includes the media
    // 2. Extract files from the backup
    // 3. Parse the media files
    
    // However, libimobiledevice's idevicebackup2 on Windows has limitations
    // The best approach for media extraction is actually through Windows MTP
    // or creating a full iTunes backup and parsing it
    
    // For now, we'll document this and provide alternative method
    eprintln!("[iOS Media] AFC path {} requires backup-based extraction", path);
    
    Ok(files)
}

/// Alternative: Parse media from iTunes backup
pub fn scan_ios_backup_media(backup_path: &Path) -> Result<Vec<serde_json::Value>, String> {
    eprintln!("[iOS Media] Scanning iTunes backup for media files");
    eprintln!("[iOS Media] Backup path: {:?}", backup_path);
    
    let mut media_files = Vec::new();
    
    // iTunes backups store files with hashed names
    // We need to parse the Manifest.db to map file paths to backup files
    let manifest_db = backup_path.join("Manifest.db");
    
    if !manifest_db.exists() {
        return Err("Invalid backup: Manifest.db not found".to_string());
    }
    
    // Parse manifest database using SQLite
    parse_backup_manifest(&manifest_db, backup_path, &mut media_files)?;
    
    eprintln!("[iOS Media] Found {} media files in backup", media_files.len());
    Ok(media_files)
}

/// Parse iTunes backup manifest to find media files
fn parse_backup_manifest(
    manifest_db: &Path,
    backup_path: &Path,
    media_files: &mut Vec<serde_json::Value>
) -> Result<(), String> {
    use rusqlite::{Connection, OpenFlags};
    
    let conn = Connection::open_with_flags(
        manifest_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY
    ).map_err(|e| format!("Failed to open manifest: {}", e))?;
    
    // Query for media files (DCIM, PhotoData, etc.)
    let mut stmt = conn.prepare(
        "SELECT fileID, domain, relativePath, flags FROM Files \
         WHERE (domain LIKE '%Camera%' OR domain LIKE '%Photo%' OR relativePath LIKE '%DCIM%') \
         AND (relativePath LIKE '%.jpg' OR relativePath LIKE '%.jpeg' OR \
              relativePath LIKE '%.png' OR relativePath LIKE '%.heic' OR \
              relativePath LIKE '%.mov' OR relativePath LIKE '%.mp4' OR \
              relativePath LIKE '%.m4v')"
    ).map_err(|e| format!("Failed to prepare query: {}", e))?;
    
    let mut rows = stmt.query([]).map_err(|e| format!("Query failed: {}", e))?;
    
    while let Ok(Some(row)) = rows.next() {
        let file_id: String = row.get(0).unwrap_or_default();
        let domain: String = row.get(1).unwrap_or_default();
        let relative_path: String = row.get(2).unwrap_or_default();
        
        // Backup files are stored as fileID (first 2 chars as directory)
        let backup_file_path = if file_id.len() >= 2 {
            backup_path.join(&file_id[0..2]).join(&file_id)
        } else {
            backup_path.join(&file_id)
        };
        
        if !backup_file_path.exists() {
            continue;
        }
        
        // Get file metadata
        let metadata = fs::metadata(&backup_file_path).ok();
        let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        
        let filename = relative_path.split('/').last().unwrap_or("unknown").to_string();
        let ext = filename.split('.').last().unwrap_or("").to_lowercase();
        
        let file_type = match ext.as_str() {
            "jpg" | "jpeg" | "png" | "heic" | "gif" | "bmp" => "Image",
            "mov" | "mp4" | "m4v" | "avi" | "mpg" | "mpeg" => "Video",
            _ => "Unknown"
        };
        
        let mut media_file = serde_json::Map::new();
        media_file.insert("path".to_string(), serde_json::Value::String(backup_file_path.to_string_lossy().to_string()));
        media_file.insert("filename".to_string(), serde_json::Value::String(filename));
        media_file.insert("sizeBytes".to_string(), serde_json::Value::Number(file_size.into()));
        media_file.insert("fileType".to_string(), serde_json::Value::String(file_type.to_string()));
        media_file.insert("originalPath".to_string(), serde_json::Value::String(relative_path));
        media_file.insert("domain".to_string(), serde_json::Value::String(domain));
        media_file.insert("createdDate".to_string(), serde_json::Value::String("Unknown".to_string()));
        media_file.insert("modifiedDate".to_string(), serde_json::Value::String("Unknown".to_string()));
        
        media_files.push(serde_json::Value::Object(media_file));
    }
    
    Ok(())
}

/// Convert HEIC to JPEG for viewing (requires conversion library)
pub fn convert_heic_to_jpeg(heic_path: &Path) -> Result<PathBuf, String> {
    // HEIC conversion options:
    // 1. Use imagemagick (external tool)
    // 2. Use libheif (C library binding)
    // 3. Return HEIC as-is and let frontend handle it
    
    eprintln!("[iOS Media] HEIC file detected: {:?}", heic_path);
    eprintln!("[iOS Media] Note: HEIC viewing requires conversion or browser support");
    
    // For now, return the original path
    // Modern browsers (Chrome, Edge) support HEIC natively
    // Firefox may need conversion
    
    Ok(heic_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tool_path() {
        let path = get_tool_path("idevice_id.exe");
        assert!(path.to_string_lossy().contains("idevice_id"));
    }
}
