use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;
use rayon::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordMatch {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub matched_keywords: Vec<String>,
    pub match_locations: Vec<MatchLocation>,
    pub date_modified: Option<String>,
    pub date_created: Option<String>,
    pub file_extension: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchLocation {
    pub keyword: String,
    pub location: MatchType,
    pub context: String, // surrounding text for context
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchType {
    FileName,
    FilePath,
    FileContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordScanOptions {
    pub scan_paths: Vec<String>,
    pub keyword_lists: Vec<KeywordList>,
    pub scan_file_names: bool,
    pub scan_file_paths: bool,
    pub scan_file_contents: bool,
    pub case_sensitive: bool,
    pub max_file_size_mb: u64, // Don't scan file contents if larger than this
    pub file_extensions: Vec<String>, // Empty = scan all files
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordList {
    pub name: String,
    pub keywords: Vec<String>,
    pub enabled: bool,
}

/// Load keyword lists from a directory
pub fn load_keyword_lists_from_dir(dir: &Path) -> Result<Vec<KeywordList>, Box<dyn std::error::Error>> {
    let mut lists = Vec::new();

    if !dir.exists() {
        return Ok(lists);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("txt") {
            let list_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Unknown")
                .to_string();

            let content = fs::read_to_string(&path)?;
            let keywords: Vec<String> = content
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();

            let keyword_count = keywords.len();
            lists.push(KeywordList {
                name: list_name.clone(),
                keywords,
                enabled: true,
            });

            eprintln!("Loaded keyword list '{}' with {} keywords", list_name, keyword_count);
        }
    }

    Ok(lists)
}

/// Helper function to determine if a path should be scanned
fn should_scan_path(path_str: &str, explicitly_scanning_recycle_bin: bool) -> bool {
    let upper = path_str.to_uppercase();
    
    // Always skip Windows and Program Files
    if upper.contains("\\WINDOWS\\") || 
       upper.contains("\\PROGRAM FILES\\") ||
       upper.contains("\\PROGRAMDATA\\") {
        return false;
    }
    
    // Only skip Recycle Bin if we're NOT explicitly scanning it
    if !explicitly_scanning_recycle_bin && upper.contains("\\$RECYCLE.BIN") {
        return false;
    }
    
    // Skip other system paths (but allow Recycle Bin if explicitly requested)
    if upper.starts_with("$") && !explicitly_scanning_recycle_bin {
        return false;
    }
    
    true
}

/// Scan for keyword matches
pub fn scan_keywords(options: KeywordScanOptions) -> Result<Vec<KeywordMatch>, Box<dyn std::error::Error>> {
    let mut all_matches = Vec::new();

    // Collect all enabled keywords
    let all_keywords: Vec<String> = options
        .keyword_lists
        .iter()
        .filter(|list| list.enabled)
        .flat_map(|list| list.keywords.clone())
        .collect();

    if all_keywords.is_empty() {
        return Ok(all_matches);
    }

    eprintln!("Scanning with {} keywords from {} lists", 
        all_keywords.len(), 
        options.keyword_lists.iter().filter(|l| l.enabled).count()
    );

    // Scan each path
    for scan_path in &options.scan_paths {
        let path = PathBuf::from(scan_path);
        if !path.exists() {
            eprintln!("Warning: Path does not exist: {}", scan_path);
            continue;
        }

        eprintln!("Scanning path: {}", scan_path);

        // Determine if we're explicitly scanning Recycle Bin
        let scanning_recycle_bin = scan_path.to_uppercase().contains("$RECYCLE.BIN");

        // Collect all files to scan (skip system directories to prevent crashes)
        let files: Vec<PathBuf> = WalkDir::new(&path)
            .follow_links(false)
            .max_depth(10) // Limit depth to avoid infinite loops
            .into_iter()
            .filter_entry(|e| {
                let path_str = e.path().to_string_lossy();
                should_scan_path(&path_str, scanning_recycle_bin)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        eprintln!("Found {} files to scan", files.len());

        // Process files in parallel
        let matches: Vec<KeywordMatch> = files
            .par_iter()
            .filter_map(|file_path| {
                scan_file(file_path, &all_keywords, &options).ok().flatten()
            })
            .collect();

        all_matches.extend(matches);
    }

    eprintln!("Total keyword matches found: {}", all_matches.len());
    Ok(all_matches)
}

/// Scan for keyword matches with progress reporting
pub fn scan_keywords_with_progress<F>(
    options: KeywordScanOptions,
    progress_callback: F,
) -> Result<Vec<KeywordMatch>, Box<dyn std::error::Error>>
where
    F: Fn(usize, usize, String) + Send + Sync,
{
    let mut all_matches = Vec::new();

    // Collect all enabled keywords
    let all_keywords: Vec<String> = options
        .keyword_lists
        .iter()
        .filter(|list| list.enabled)
        .flat_map(|list| list.keywords.clone())
        .collect();

    if all_keywords.is_empty() {
        return Ok(all_matches);
    }

    eprintln!("Scanning with {} keywords from {} lists", 
        all_keywords.len(), 
        options.keyword_lists.iter().filter(|l| l.enabled).count()
    );

    // First pass: count total files
    let mut total_files = 0;
    for scan_path in &options.scan_paths {
        let path = PathBuf::from(scan_path);
        if !path.exists() {
            eprintln!("Warning: Path does not exist: {}", scan_path);
            continue;
        }

        let file_count = WalkDir::new(&path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count();
        
        total_files += file_count;
    }

    eprintln!("Total files to scan: {}", total_files);
    
    let mut processed = 0;
    
    // Scan each path
    for scan_path in &options.scan_paths {
        let path = PathBuf::from(scan_path);
        if !path.exists() {
            continue;
        }

        eprintln!("Scanning path: {}", scan_path);

        // Determine if we're explicitly scanning Recycle Bin
        let scanning_recycle_bin = scan_path.to_uppercase().contains("$RECYCLE.BIN");

        // Collect all files to scan (skip system directories to prevent crashes)
        let files: Vec<PathBuf> = WalkDir::new(&path)
            .follow_links(false)
            .max_depth(10) // Limit depth to avoid infinite loops
            .into_iter()
            .filter_entry(|e| {
                let path_str = e.path().to_string_lossy();
                should_scan_path(&path_str, scanning_recycle_bin)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        // Process files sequentially to maintain progress order
        for (idx, file_path) in files.iter().enumerate() {
            if let Ok(Some(keyword_match)) = scan_file(file_path, &all_keywords, &options) {
                all_matches.push(keyword_match);
            }
            
            processed += 1;
            
            // Report progress every 100 files or at the end
            if processed % 100 == 0 || processed == total_files {
                let current_file = file_path.to_string_lossy().to_string();
                progress_callback(processed, total_files, current_file);
            }
        }
    }

    eprintln!("Total keyword matches found: {}", all_matches.len());
    Ok(all_matches)
}

/// Scan a single file for keyword matches
fn scan_file(
    file_path: &Path,
    keywords: &[String],
    options: &KeywordScanOptions,
) -> Result<Option<KeywordMatch>, Box<dyn std::error::Error>> {
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    let file_path_str = file_path.to_string_lossy().to_string();
    
    let extension = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    // Filter by file extension if specified
    if !options.file_extensions.is_empty() {
        let ext_lower = extension.to_lowercase();
        if !options.file_extensions.iter().any(|e| e.to_lowercase() == ext_lower) {
            return Ok(None);
        }
    }

    let mut matched_keywords = Vec::new();
    let mut match_locations = Vec::new();

    // Check file name
    if options.scan_file_names {
        let search_text = if options.case_sensitive {
            file_name.clone()
        } else {
            file_name.to_lowercase()
        };

        for keyword in keywords {
            let search_keyword = if options.case_sensitive {
                keyword.clone()
            } else {
                keyword.to_lowercase()
            };

            if search_text.contains(&search_keyword) {
                if !matched_keywords.contains(keyword) {
                    matched_keywords.push(keyword.clone());
                }
                match_locations.push(MatchLocation {
                    keyword: keyword.clone(),
                    location: MatchType::FileName,
                    context: file_name.clone(),
                });
            }
        }
    }

    // Check file path
    if options.scan_file_paths {
        let search_text = if options.case_sensitive {
            file_path_str.clone()
        } else {
            file_path_str.to_lowercase()
        };

        for keyword in keywords {
            let search_keyword = if options.case_sensitive {
                keyword.clone()
            } else {
                keyword.to_lowercase()
            };

            if search_text.contains(&search_keyword) {
                if !matched_keywords.contains(keyword) {
                    matched_keywords.push(keyword.clone());
                }
                match_locations.push(MatchLocation {
                    keyword: keyword.clone(),
                    location: MatchType::FilePath,
                    context: file_path_str.clone(),
                });
            }
        }
    }

    // Check file contents
    if options.scan_file_contents {
        // Get file metadata (skip on error - might be permission issue)
        if let Ok(metadata) = fs::metadata(file_path) {
            let file_size_mb = metadata.len() / (1024 * 1024);
            
            // Only scan content if file is small enough
            if file_size_mb <= options.max_file_size_mb {
                // Try to read as text (will fail for binary files - that's ok)
                match fs::read_to_string(file_path) {
                    Ok(content) => {
                    let search_text = if options.case_sensitive {
                        content.clone()
                    } else {
                        content.to_lowercase()
                    };

                    for keyword in keywords {
                        let search_keyword = if options.case_sensitive {
                            keyword.clone()
                        } else {
                            keyword.to_lowercase()
                        };

                        if let Some(pos) = search_text.find(&search_keyword) {
                            if !matched_keywords.contains(keyword) {
                                matched_keywords.push(keyword.clone());
                            }

                            // Extract context (50 chars before and after)
                            let start = pos.saturating_sub(50);
                            let end = (pos + search_keyword.len() + 50).min(content.len());
                            let context = content[start..end].to_string();

                            match_locations.push(MatchLocation {
                                keyword: keyword.clone(),
                                location: MatchType::FileContent,
                                context,
                            });
                        }
                    }
                    }
                    Err(_) => {
                        // Skip files we can't read (binary files, permission errors, etc.)
                    }
                }
            }
        }
    }

    // If we found matches, create a KeywordMatch
    if !matched_keywords.is_empty() {
        let metadata = fs::metadata(file_path)?;
        let file_size = metadata.len();

        // Get file times
        let date_modified = metadata
            .modified()
            .ok()
            .and_then(|t| {
                let duration = t.duration_since(std::time::UNIX_EPOCH).ok()?;
                chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
            })
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

        let date_created = metadata
            .created()
            .ok()
            .and_then(|t| {
                let duration = t.duration_since(std::time::UNIX_EPOCH).ok()?;
                chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
            })
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

        Ok(Some(KeywordMatch {
            file_path: file_path_str,
            file_name,
            file_size,
            matched_keywords,
            match_locations,
            date_modified,
            date_created,
            file_extension: extension,
        }))
    } else {
        Ok(None)
    }
}

/// Get default scan paths (common hiding places)
pub fn get_default_scan_paths() -> Vec<String> {
    let mut paths = Vec::new();

    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        // User directories - prioritized locations for media/documents
        paths.push(format!("{}\\Documents", user_profile));
        paths.push(format!("{}\\Downloads", user_profile));
        paths.push(format!("{}\\Desktop", user_profile));
        paths.push(format!("{}\\Pictures", user_profile));
        paths.push(format!("{}\\Videos", user_profile));
        paths.push(format!("{}\\Music", user_profile));
        
        // OneDrive locations
        paths.push(format!("{}\\OneDrive", user_profile));
        paths.push(format!("{}\\OneDrive - Personal", user_profile));
    }

    // Recycle Bin - all drives
    paths.push("C:\\$Recycle.Bin".to_string());

    // Filter to only existing paths
    paths.into_iter().filter(|p| Path::new(p).exists()).collect()
}

/// Get scan paths for specific drives — triage-priority subdirectories
/// Instead of scanning the entire drive (slow), target locations where
/// user media is actually stored. The hash scanner's directory skip list
/// handles filtering if a full drive path is passed.
pub fn get_scan_paths_for_drives(drive_letters: Vec<String>) -> Vec<String> {
    let mut paths = Vec::new();

    for drive in drive_letters {
        let drive_root = if drive.ends_with(':') {
            format!("{}\\", drive)
        } else if drive.ends_with('\\') {
            drive.clone()
        } else {
            format!("{}\\", drive)
        };

        if !Path::new(&drive_root).exists() {
            continue;
        }

        // For the system drive (typically C:), target user-media locations
        // For non-system drives (D:, E:, USB), scan the full drive
        let is_system_drive = drive_root.to_uppercase().starts_with("C:");
        
        if is_system_drive {
            // Triage-priority user directories
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                let user_dirs = [
                    "Downloads", "Pictures", "Videos", "Desktop",
                    "Documents", "Music", "OneDrive",
                    "AppData\\Local\\Temp",
                ];
                for dir in &user_dirs {
                    let p = format!("{}\\{}", user_profile, dir);
                    if Path::new(&p).exists() {
                        paths.push(p);
                    }
                }
            }
            // Also scan all user profiles (not just current user)
            let users_dir = format!("{}Users", drive_root);
            if Path::new(&users_dir).exists() {
                if let Ok(entries) = std::fs::read_dir(&users_dir) {
                    for entry in entries.flatten() {
                        let uname = entry.file_name().to_string_lossy().to_string();
                        // Skip system profiles
                        if ["Public", "Default", "Default User", "All Users"]
                            .contains(&uname.as_str()) {
                            continue;
                        }
                        let user_path = entry.path();
                        for dir in &["Downloads", "Pictures", "Videos", "Desktop", "Documents"] {
                            let p = user_path.join(dir);
                            if p.exists() {
                                let ps = p.to_string_lossy().to_string();
                                if !paths.contains(&ps) {
                                    paths.push(ps);
                                }
                            }
                        }
                    }
                }
            }
            // Recycle Bin
            let recycle = format!("{}$Recycle.Bin", drive_root);
            if Path::new(&recycle).exists() {
                paths.push(recycle);
            }
        } else {
            // Non-system drive: scan the whole thing (the skip list handles filtering)
            paths.push(drive_root);
        }
    }

    eprintln!("[Scan Paths] Resolved {} triage paths: {:?}", paths.len(), paths);
    paths
}
