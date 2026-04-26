// Report Generation Module for Project Hindsight

pub mod pdf;
pub mod pdf_simple;

#[cfg(test)]
mod test_pdf_gen;

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub case_number: String,
    pub assigned_detective: String,
    pub officer_name: Option<String>,
    pub agency_name: Option<String>,
    pub generated_date: String,
    pub device_name: Option<String>,
    pub operating_system: Option<String>,
    pub drive_scanned: Option<String>,
    pub scan_parameters: Option<ScanParameters>,
    pub scan_duration: Option<String>,
    pub triage_start_time: Option<String>,
    pub triage_end_time: Option<String>,
    pub total_flags: Option<u32>,
    pub generate_datapilot_file: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanParameters {
    pub applications_scanned: bool,
    pub browser_history_scanned: bool,
    pub keyword_search_performed: bool,
    pub hash_matching_performed: bool,
    pub media_scan_performed: bool,
    pub intrusion_detection_performed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReportScope {
    All,
    Flagged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPayload {
    pub metadata: ReportMetadata,
    pub scope: ReportScope,
    pub formats: Vec<String>,
    pub flagged_item_ids: Vec<String>,
    pub all_data: AllDataPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllDataPayload {
    pub apps: serde_json::Value,
    pub keywords: serde_json::Value,
    pub csam: serde_json::Value,
    pub browsers: serde_json::Value,
    pub intrusion: serde_json::Value,
    pub system_info: serde_json::Value,
    #[serde(default)]
    pub hash_matches: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGenerationResult {
    pub success: bool,
    pub pdf_path: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportListItem {
    pub filename: String,
    pub full_path: String,
    pub case_number: String,
    pub date_generated: String,
    pub file_size: u64,
    pub file_size_mb: f64,
}

/// Get the reports directory path (stored in AppData for security)
pub fn get_reports_dir() -> Result<PathBuf, Box<dyn Error>> {
    // Use AppData for secure storage - only accessible through authenticated app
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "Could not find APPDATA directory")?;
    
    // Create reports folder in AppData\Hindsight\reports
    let reports_dir = PathBuf::from(app_data).join("Hindsight").join("reports");
    
    // Create the directory if it doesn't exist
    if !reports_dir.exists() {
        std::fs::create_dir_all(&reports_dir)?;
        eprintln!("✓ Created reports directory: {}", reports_dir.display());
    }
    
    Ok(reports_dir)
}

/// Generate a report filename with timestamp
pub fn generate_report_filename(case_number: &str, format: &str) -> String {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let sanitized_case = case_number.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    format!("Hindsight_Report_{}_{}. {}", sanitized_case, timestamp, format)
}

/// Generate PDF report based on the provided payload
/// Now generates to memory only and returns the PDF data for encryption
pub fn generate_reports(payload: ReportPayload) -> Result<ReportGenerationResult, Box<dyn Error>> {
    let mut result = ReportGenerationResult {
        success: true,
        pdf_path: None,
        error: None,
    };
    
    let reports_dir = get_reports_dir()?;
    
    // Generate PDF report - returns path to temp file
    match pdf::generate_pdf(&payload, &reports_dir) {
        Ok(path) => {
            result.pdf_path = Some(path.to_string_lossy().to_string());
        }
        Err(e) => {
            result.success = false;
            result.error = Some(format!("PDF generation failed: {}", e));
            return Ok(result);
        }
    }
    
    // Generate Datapilot hash file if requested
    if payload.metadata.generate_datapilot_file.unwrap_or(false) {
        match generate_datapilot_hashlist(&payload, &reports_dir) {
            Ok(datapilot_path) => {
                eprintln!("✓ Generated Datapilot hash file: {}", datapilot_path.display());
            }
            Err(e) => {
                eprintln!("⚠ Failed to generate Datapilot hash file: {}", e);
                // Don't fail the entire report generation, just warn
            }
        }
    }
    
    Ok(result)
}

/// Generate PDF report and return raw bytes for encryption
pub fn generate_report_bytes(payload: ReportPayload) -> Result<Vec<u8>, Box<dyn Error>> {
    // Create a temporary in-memory buffer for the PDF
    let reports_dir = get_reports_dir()?;
    let pdf_path = pdf::generate_pdf(&payload, &reports_dir)?;
    
    // Read the PDF file
    let pdf_data = std::fs::read(&pdf_path)?;
    
    // Delete the temporary unencrypted file
    std::fs::remove_file(&pdf_path).ok();
    
    Ok(pdf_data)
}

/// List all reports in the AppData reports directory
pub fn list_reports() -> Result<Vec<ReportListItem>, Box<dyn Error>> {
    let reports_dir = get_reports_dir()?;
    let mut reports = Vec::new();
    
    if !reports_dir.exists() {
        return Ok(reports);
    }
    
    for entry in std::fs::read_dir(&reports_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        // Only process PDF files
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("pdf") {
            let metadata = std::fs::metadata(&path)?;
            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string();
            
            // Extract case number from filename (format: Hindsight_Report_CASE_TIMESTAMP.pdf)
            let case_number = filename
                .strip_prefix("Hindsight_Report_")
                .and_then(|s| s.split('_').next())
                .unwrap_or("Unknown")
                .to_string();
            
            // Get file modified time
            let modified = metadata.modified()?;
            let datetime: chrono::DateTime<chrono::Local> = modified.into();
            let date_generated = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
            
            let file_size = metadata.len();
            let file_size_mb = file_size as f64 / 1_048_576.0; // Convert to MB
            
            reports.push(ReportListItem {
                filename,
                full_path: path.to_string_lossy().to_string(),
                case_number,
                date_generated,
                file_size,
                file_size_mb,
            });
        }
    }
    
    // Sort by date (newest first)
    reports.sort_by(|a, b| b.date_generated.cmp(&a.date_generated));
    
    Ok(reports)
}

/// Open a report file in the system's default PDF viewer
pub fn open_report(file_path: &str) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(file_path);
    
    // Verify the file exists
    if !path.exists() {
        return Err("Report file not found".into());
    }
    
    // Verify the file is in the reports directory (security check)
    let reports_dir = get_reports_dir()?;
    if !path.starts_with(&reports_dir) {
        return Err("Security: Report file must be in the reports directory".into());
    }
    
    // Open with system default PDF viewer
    #[cfg(target_os = "windows")]
    {
        let path_str = path.to_string_lossy().to_string();
        std::process::Command::new("cmd")
            .args(&["/C", "start", "", &path_str])
            .spawn()?;
    }
    
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&path)
            .spawn()?;
    }
    
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&path)
            .spawn()?;
    }
    
    Ok(())
}

/// Delete a report file
pub fn delete_report(file_path: &str) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(file_path);
    
    // Verify the file exists
    if !path.exists() {
        return Err("Report file not found".into());
    }
    
    // Verify the file is in the reports directory (security check)
    let reports_dir = get_reports_dir()?;
    if !path.starts_with(&reports_dir) {
        return Err("Security: Report file must be in the reports directory".into());
    }
    
    // Delete the file
    std::fs::remove_file(&path)?;
    
    Ok(())
}

/// Generate Datapilot hash list file from flagged evidence (public wrapper for lib.rs)
pub fn generate_datapilot_hashlist_public(payload: &ReportPayload, reports_dir: &PathBuf) -> Result<PathBuf, Box<dyn Error>> {
    generate_datapilot_hashlist(payload, reports_dir)
}

/// Generate Datapilot hash list file from flagged evidence
fn generate_datapilot_hashlist(payload: &ReportPayload, reports_dir: &PathBuf) -> Result<PathBuf, Box<dyn Error>> {
    use std::io::Write;
    use std::collections::HashSet;
    
    eprintln!("Generating Datapilot hash list...");
    
    let mut hashes = HashSet::new();
    let mut files_processed = 0;
    let mut files_with_hash = 0;
    let mut files_computed = 0;
    let mut files_skipped = 0;
    
    // Determine which items to include based on scope
    let include_all = matches!(payload.scope, ReportScope::All);
    
    // Process media files (CSAM data)
    if let Some(media_array) = payload.all_data.csam.as_array() {
        eprintln!("  → Processing {} media files for hash list", media_array.len());
        
        for (idx, item) in media_array.iter().enumerate() {
            let is_flagged = item.get("isFlagged")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            
            // Include if: (all scope) OR (flagged scope AND item is flagged)
            if include_all || is_flagged {
                files_processed += 1;
                
                // Try to get existing hash (check both camelCase and snake_case)
                let existing_hash = item.get("sha256Hash")
                    .or_else(|| item.get("sha256_hash"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty());
                
                if let Some(hash) = existing_hash {
                    hashes.insert(hash.to_uppercase());
                    files_with_hash += 1;
                    continue;
                }
                
                // If no hash exists, try to compute it (but don't fail if file doesn't exist)
                if let Some(file_path) = item.get("filePath").and_then(|v| v.as_str()) {
                    match compute_file_hash(file_path) {
                        Ok(hash) => {
                            hashes.insert(hash.to_uppercase());
                            files_computed += 1;
                        }
                        Err(e) => {
                            eprintln!("    ⚠ Skipping file {} (cannot compute hash): {}", idx + 1, e);
                            files_skipped += 1;
                        }
                    }
                } else {
                    eprintln!("    ⚠ Skipping file {} (no file path)", idx + 1);
                    files_skipped += 1;
                }
            }
        }
    }
    
    // Process CSAM hash match results (Android/standalone hash scan hits)
    if let Some(hash_array) = payload.all_data.hash_matches.as_array() {
        eprintln!("  → Processing {} hash match results for hash list", hash_array.len());
        
        for item in hash_array.iter() {
            let is_flagged = item.get("isFlagged")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            
            if include_all || is_flagged {
                files_processed += 1;
                
                // Hash matches already have computed hashes — use matchedHash, md5Hash, or sha256Hash
                let hash = item.get("matchedHash").and_then(|v| v.as_str())
                    .or_else(|| item.get("sha256Hash").and_then(|v| v.as_str()))
                    .or_else(|| item.get("sha256_hash").and_then(|v| v.as_str()))
                    .or_else(|| item.get("md5Hash").and_then(|v| v.as_str()))
                    .or_else(|| item.get("md5_hash").and_then(|v| v.as_str()))
                    .filter(|s| !s.is_empty());
                
                if let Some(h) = hash {
                    hashes.insert(h.to_uppercase());
                    files_with_hash += 1;
                } else {
                    files_skipped += 1;
                }
            }
        }
    }
    
    if hashes.is_empty() {
        return Err(format!(
            "No hashes available for Datapilot list. Processed {} files, {} had pre-computed hashes, {} were computed, {} were skipped.",
            files_processed, files_with_hash, files_computed, files_skipped
        ).into());
    }
    
    // Generate filename
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let sanitized_case = payload.metadata.case_number.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let filename = format!("Datapilot_HashList_{}_{}.txt", sanitized_case, timestamp);
    let output_path = reports_dir.join(&filename);
    
    // Write hashes to file (one per line)
    let mut file = std::fs::File::create(&output_path)?;
    let mut sorted_hashes: Vec<_> = hashes.into_iter().collect();
    sorted_hashes.sort();
    
    let hash_count = sorted_hashes.len();
    
    for hash in sorted_hashes {
        writeln!(file, "{}", hash)?;
    }
    
    eprintln!("✓ Generated Datapilot hash list: {} unique hashes", hash_count);
    eprintln!("  → {} files processed, {} pre-computed, {} computed, {} skipped", 
        files_processed, files_with_hash, files_computed, files_skipped);
    
    Ok(output_path)
}

/// Compute SHA-256 hash of a file
fn compute_file_hash(file_path: &str) -> Result<String, Box<dyn Error>> {
    use std::fs::File;
    use std::io::Read;
    use sha2::{Sha256, Digest};
    
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

/// Export a report to a user-selected location
pub fn export_report(file_path: &str, destination: &str) -> Result<(), Box<dyn Error>> {
    let source = PathBuf::from(file_path);
    let dest = PathBuf::from(destination);
    
    // Verify source exists and is in reports directory
    if !source.exists() {
        return Err("Source report file not found".into());
    }
    
    let reports_dir = get_reports_dir()?;
    if !source.starts_with(&reports_dir) {
        return Err("Security: Source file must be in the reports directory".into());
    }
    
    // Copy the file
    std::fs::copy(&source, &dest)?;
    
    Ok(())
}

/// List all Datapilot hash list files in the reports directory
pub fn list_datapilot_files() -> Result<Vec<ReportListItem>, Box<dyn Error>> {
    let reports_dir = get_reports_dir()?;
    let mut files = Vec::new();
    
    if !reports_dir.exists() {
        return Ok(files);
    }
    
    for entry in std::fs::read_dir(&reports_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        // Only process .txt files that start with "Datapilot_HashList_"
        if path.is_file() && 
           path.extension().and_then(|s| s.to_str()) == Some("txt") {
            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            
            if filename.starts_with("Datapilot_HashList_") {
                let metadata = std::fs::metadata(&path)?;
                
                // Extract case number from filename (format: Datapilot_HashList_CASE_TIMESTAMP.txt)
                let case_number = filename
                    .strip_prefix("Datapilot_HashList_")
                    .and_then(|s| s.split('_').next())
                    .unwrap_or("Unknown")
                    .to_string();
                
                // Get file modified time
                let modified = metadata.modified()?;
                let datetime: chrono::DateTime<chrono::Local> = modified.into();
                let date_generated = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                
                let file_size = metadata.len();
                let file_size_mb = file_size as f64 / 1_048_576.0; // Convert to MB
                
                files.push(ReportListItem {
                    filename,
                    full_path: path.to_string_lossy().to_string(),
                    case_number,
                    date_generated,
                    file_size,
                    file_size_mb,
                });
            }
        }
    }
    
    // Sort by date (newest first)
    files.sort_by(|a, b| b.date_generated.cmp(&a.date_generated));
    
    Ok(files)
}
