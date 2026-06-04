use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(rename = "officer_name", alias = "officerName")]
    pub officer_name: Option<String>,
    #[serde(rename = "agency_name", alias = "agencyName")]
    pub agency_name: Option<String>,
    #[serde(rename = "badge_number", alias = "badgeNumber", default)]
    pub badge_number: Option<String>,
    #[serde(rename = "keywordLists", alias = "keyword_lists")]
    pub keyword_lists: Vec<KeywordList>,
    #[serde(rename = "hashLists", alias = "hash_lists")]
    pub hash_lists: Vec<HashList>,
    #[serde(rename = "customApps", alias = "custom_apps")]
    pub custom_apps: Vec<CustomAppDefinition>,
    #[serde(rename = "scanOptions", alias = "scan_options")]
    pub scan_options: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordList {
    pub id: String,
    pub name: String,
    pub description: String,
    pub keywords: Vec<String>,
    pub enabled: bool,
    #[serde(rename = "caseSensitive")]
    pub case_sensitive: bool,
    #[serde(rename = "useRegex")]
    pub use_regex: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "modifiedAt")]
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashList {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "hashType")]
    pub hash_type: HashType,
    pub hashes: Vec<HashEntry>,
    pub enabled: bool,
    pub source: String,
    #[serde(rename = "hashCount", default)]
    pub hash_count: usize,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "modifiedAt")]
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    pub hash: String,
    pub description: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAppDefinition {
    pub id: String,
    pub name: String,
    pub category: String,
    pub patterns: Vec<String>,
    pub description: String,
    pub enabled: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "modifiedAt")]
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    #[serde(rename = "enableQuestionableApps")]
    pub enable_questionable_apps: bool,
    #[serde(rename = "enableBrowserHistory")]
    pub enable_browser_history: bool,
    #[serde(rename = "enableKeywordSearch")]
    pub enable_keyword_search: bool,
    #[serde(rename = "enableMediaScan")]
    pub enable_media_scan: bool,
    #[serde(rename = "enableHashMatching")]
    pub enable_hash_matching: bool,
    #[serde(rename = "scanDepth")]
    pub scan_depth: ScanDepth,
    #[serde(rename = "includeSystemDirs")]
    pub include_system_dirs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanDepth {
    Quick,
    Standard,
    Deep,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            officer_name: None,
            agency_name: None,
            badge_number: None,
            keyword_lists: Vec::new(),
            hash_lists: Vec::new(),
            custom_apps: Vec::new(),
            scan_options: ScanOptions::default(),
        }
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            enable_questionable_apps: true,
            enable_browser_history: false,
            enable_keyword_search: false,
            enable_media_scan: false,
            enable_hash_matching: false,
            scan_depth: ScanDepth::Standard,
            include_system_dirs: false,
        }
    }
}

/// Get the base Hindsight directory path
fn get_base_dir() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "Could not find APPDATA directory".to_string())?;
    
    let mut path = PathBuf::from(app_data);
    path.push("Hindsight");
    Ok(path)
}

/// Initialize all required directories for Hindsight
pub fn initialize_directories() -> Result<(), String> {
    let base_dir = get_base_dir()?;
    
    // Create base directory
    if !base_dir.exists() {
        fs::create_dir_all(&base_dir)
            .map_err(|e| format!("Failed to create Hindsight directory: {}", e))?;
    }
    
    // Create keyword_lists directory
    let keyword_dir = base_dir.join("keyword_lists");
    if !keyword_dir.exists() {
        fs::create_dir_all(&keyword_dir)
            .map_err(|e| format!("Failed to create keyword_lists directory: {}", e))?;
    }
    
    // Create hash_lists directory
    let hash_dir = base_dir.join("hash_lists");
    if !hash_dir.exists() {
        fs::create_dir_all(&hash_dir)
            .map_err(|e| format!("Failed to create hash_lists directory: {}", e))?;
    }
    
    // Create custom_apps directory
    let apps_dir = base_dir.join("custom_apps");
    if !apps_dir.exists() {
        fs::create_dir_all(&apps_dir)
            .map_err(|e| format!("Failed to create custom_apps directory: {}", e))?;
    }
    
    // Create reports directory
    let reports_dir = base_dir.join("reports");
    if !reports_dir.exists() {
        fs::create_dir_all(&reports_dir)
            .map_err(|e| format!("Failed to create reports directory: {}", e))?;
    }
    
    // Create thumbnails directory
    let thumbnails_dir = base_dir.join("thumbnails");
    if !thumbnails_dir.exists() {
        fs::create_dir_all(&thumbnails_dir)
            .map_err(|e| format!("Failed to create thumbnails directory: {}", e))?;
    }
    
    Ok(())
}

/// Get the path to the settings file
fn get_settings_path() -> Result<PathBuf, String> {
    let base_dir = get_base_dir()?;
    
    // Create directory if it doesn't exist
    if !base_dir.exists() {
        fs::create_dir_all(&base_dir)
            .map_err(|e| format!("Failed to create settings directory: {}", e))?;
    }
    
    let mut path = base_dir.clone();
    path.push("settings.json");
    Ok(path)
}

/// Load settings from disk
pub fn load_settings() -> Result<AppSettings, String> {
    let path = get_settings_path()?;
    
    if !path.exists() {
        // Return default settings if file doesn't exist
        return Ok(AppSettings::default());
    }
    
    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read settings file: {}", e))?;
    
    let settings: AppSettings = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse settings: {}", e))?;
    
    Ok(settings)
}

/// Save settings to disk
pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    let path = get_settings_path()?;
    
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {}", e))?;
    
    fs::write(&path, json)
        .map_err(|e| format!("Failed to write settings file: {}", e))?;
    
    Ok(())
}

/// Import Project VIC JSON hash list
pub fn import_project_vic(json_path: String) -> Result<HashList, String> {
    eprintln!("=== IMPORTING HASH LIST ===");
    eprintln!("File: {}", json_path);
    
    let contents = fs::read_to_string(&json_path)
        .map_err(|e| format!("Failed to read VIC file: {}", e))?;
    
    eprintln!("File size: {} bytes", contents.len());
    
    let vic_data: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse VIC JSON: {}", e))?;
    
    eprintln!("JSON parsed successfully");
    eprintln!("Root type: {}", match vic_data {
        serde_json::Value::Array(_) => "Array",
        serde_json::Value::Object(_) => "Object",
        _ => "Other"
    });
    
    // Parse Project VIC format (structure may vary)
    let mut hashes = Vec::new();
    
    // Try direct array format
    if let Some(entries) = vic_data.as_array() {
        eprintln!("Processing array with {} entries", entries.len());
        for (idx, entry) in entries.iter().enumerate() {
            // Try different hash field names
            let hash_value = entry.get("hash")
                .or_else(|| entry.get("Hash"))
                .or_else(|| entry.get("SHA256"))
                .or_else(|| entry.get("sha256"))
                .or_else(|| entry.get("MD5"))
                .or_else(|| entry.get("md5"))
                .and_then(|h| h.as_str());
            
            if let Some(hash) = hash_value {
                let description = entry.get("description")
                    .or_else(|| entry.get("Description"))
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string());
                
                let category = entry.get("category")
                    .or_else(|| entry.get("Category"))
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string());
                
                hashes.push(HashEntry {
                    hash: hash.to_string(),
                    description,
                    category,
                });
            } else if idx < 3 {
                // Log first few entries for debugging
                eprintln!("Entry {} has no hash field: {:?}", idx, entry);
            }
        }
    }
    // Try object with array of hashes
    else if let Some(obj) = vic_data.as_object() {
        eprintln!("Processing object with keys: {:?}", obj.keys().collect::<Vec<_>>());
        
        // Try different possible array names (including "value" for OData format)
        let hash_array = obj.get("value")
            .or_else(|| obj.get("Value"))
            .or_else(|| obj.get("hashes"))
            .or_else(|| obj.get("Hashes"))
            .or_else(|| obj.get("entries"))
            .or_else(|| obj.get("Entries"))
            .or_else(|| obj.get("data"))
            .or_else(|| obj.get("Data"));
        
        if let Some(entries) = hash_array.and_then(|v| v.as_array()) {
            eprintln!("Found hash array with {} entries", entries.len());
            
            // Process each entry and extract all available hashes (MD5, SHA1, SHA256)
            for (idx, entry) in entries.iter().enumerate() {
                // Get series info
                let series = entry.get("Series")
                    .or_else(|| entry.get("series"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());
                
                // Get category (as number or string)
                let category = if let Some(cat_num) = entry.get("Category").and_then(|c| c.as_i64()) {
                    Some(format!("Category {}", cat_num))
                } else {
                    entry.get("category")
                        .or_else(|| entry.get("Category"))
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string())
                };
                
                // Use series as description if no explicit description
                let description = entry.get("description")
                    .or_else(|| entry.get("Description"))
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string())
                    .or(series.clone());
                
                // Extract MD5 hash if available
                if let Some(md5) = entry.get("MD5").or_else(|| entry.get("md5")).and_then(|h| h.as_str()) {
                    if !md5.is_empty() {
                        hashes.push(HashEntry {
                            hash: md5.to_lowercase(),
                            description: description.clone(),
                            category: category.clone(),
                        });
                    }
                }
                
                // Extract SHA1 hash if available
                if let Some(sha1) = entry.get("SHA1").or_else(|| entry.get("sha1")).and_then(|h| h.as_str()) {
                    if !sha1.is_empty() {
                        hashes.push(HashEntry {
                            hash: sha1.to_lowercase(),
                            description: description.clone(),
                            category: category.clone(),
                        });
                    }
                }
                
                // Extract SHA256 hash if available
                if let Some(sha256) = entry.get("SHA256").or_else(|| entry.get("sha256")).and_then(|h| h.as_str()) {
                    if !sha256.is_empty() {
                        hashes.push(HashEntry {
                            hash: sha256.to_lowercase(),
                            description: description.clone(),
                            category: category.clone(),
                        });
                    }
                }
                
                // Fallback: try generic "hash" field
                if let Some(hash) = entry.get("hash").or_else(|| entry.get("Hash")).and_then(|h| h.as_str()) {
                    if !hash.is_empty() {
                        hashes.push(HashEntry {
                            hash: hash.to_lowercase(),
                            description: description.clone(),
                            category: category.clone(),
                        });
                    }
                }
                
                // Log if no hash found in first few entries
                if idx < 3 {
                    let has_hash = entry.get("MD5").is_some() || entry.get("SHA1").is_some() || 
                                   entry.get("SHA256").is_some() || entry.get("hash").is_some();
                    if !has_hash {
                        eprintln!("Entry {} has no hash field: {:?}", idx, entry);
                    }
                }
            }
        }
    }
    
    eprintln!("Imported {} hashes", hashes.len());
    
    // Auto-detect hash type from first hash
    let detected_hash_type = if let Some(first_hash) = hashes.first() {
        match first_hash.hash.len() {
            32 => HashType::MD5,
            40 => HashType::SHA1,
            64 => HashType::SHA256,
            _ => HashType::SHA256, // default
        }
    } else {
        HashType::SHA256
    };
    
    eprintln!("Detected hash type: {:?}", detected_hash_type);
    eprintln!("=== IMPORT COMPLETE ===");
    
    let hash_list = HashList {
        id: chrono::Utc::now().timestamp().to_string(),
        name: "Project VIC Import".to_string(),
        description: format!("Imported from {}", json_path),
        hash_type: detected_hash_type,
        hash_count: hashes.len(),
        hashes,
        enabled: true,
        source: "Project VIC".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        modified_at: chrono::Utc::now().to_rfc3339(),
    };
    
    Ok(hash_list)
}
