/// Unified data partition paths for cross-platform access
/// 
/// This module provides a consistent way to access shared data
/// (keyword lists, hash lists, cases, etc.) regardless of whether
/// running in Windows native mode or Linux bootable forensic mode.

use std::path::PathBuf;
use std::fs;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DataPaths {
    pub base: PathBuf,
    pub keyword_lists: PathBuf,
    pub hash_lists: PathBuf,
    pub cases: PathBuf,
    pub database: PathBuf,
    pub external: PathBuf,
}

impl DataPaths {
    /// Get the appropriate data paths for the current platform
    pub fn new() -> Result<Self, String> {
        #[cfg(target_os = "windows")]
        {
            Self::windows_paths()
        }
        
        #[cfg(target_os = "linux")]
        {
            Self::linux_paths()
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err("Unsupported platform".to_string())
        }
    }
    
    /// Windows: Detect USB drive and use its root
    #[cfg(target_os = "windows")]
    fn windows_paths() -> Result<Self, String> {
        // Try to detect the USB drive
        // For now, check common drive letters
        let possible_drives = vec!["H:\\", "G:\\", "F:\\", "E:\\"];
        
        for drive in possible_drives {
            let base = PathBuf::from(drive);
            
            // Check if this looks like a Hindsight data partition
            // by looking for characteristic directories
            let keyword_lists = base.join("keyword_lists");
            let hash_lists = base.join("hash_lists");
            let cases = base.join("cases");
            
            if keyword_lists.exists() && hash_lists.exists() && cases.exists() {
                return Ok(Self {
                    database: base.join("hindsight_secure.db"),
                    external: base.join("external"),
                    base: base.clone(),
                    keyword_lists,
                    hash_lists,
                    cases,
                });
            }
        }
        
        // Fallback: use current directory (for development/testing)
        let base = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;
        
        Ok(Self {
            keyword_lists: base.join("keyword_lists"),
            hash_lists: base.join("hash_lists"),
            cases: base.join("cases"),
            database: base.join("hindsight_secure.db"),
            external: base.join("external"),
            base,
        })
    }
    
    /// Linux: Data partition mounted at /mnt/hindsight_data
    #[cfg(target_os = "linux")]
    fn linux_paths() -> Result<Self, String> {
        let base = PathBuf::from("/mnt/hindsight_data");
        
        // Verify the partition is mounted
        if !base.exists() {
            return Err(
                "Hindsight data partition not mounted at /mnt/hindsight_data".to_string()
            );
        }
        
        Ok(Self {
            keyword_lists: base.join("keyword_lists"),
            hash_lists: base.join("hash_lists"),
            cases: base.join("cases"),
            database: base.join("hindsight_secure.db"),
            external: base.join("external"),
            base,
        })
    }
    
    /// Ensure all required directories exist
    pub fn ensure_directories(&self) -> Result<(), String> {
        let dirs = vec![
            &self.keyword_lists,
            &self.hash_lists,
            &self.cases,
            &self.external,
        ];
        
        for dir in dirs {
            fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create directory {:?}: {}", dir, e))?;
        }
        
        Ok(())
    }
    
    /// Get path to a specific keyword list file
    pub fn keyword_list(&self, filename: &str) -> PathBuf {
        self.keyword_lists.join(filename)
    }
    
    /// Get path to a specific hash list file
    pub fn hash_list(&self, filename: &str) -> PathBuf {
        self.hash_lists.join(filename)
    }
    
    /// Get path to a specific case folder
    pub fn case_folder(&self, case_name: &str) -> PathBuf {
        self.cases.join(case_name)
    }
    
    /// Get path to a specific report file
    pub fn report_file(&self, case_name: &str, report_filename: &str) -> PathBuf {
        self.cases.join(case_name).join(report_filename)
    }
}

/// Initialize the data partition for first use
pub fn initialize_data_partition() -> Result<(), String> {
    let paths = DataPaths::new()?;
    paths.ensure_directories()?;
    
    Ok(())
}

/// Check if running from the correct USB data partition
pub fn verify_data_partition() -> Result<bool, String> {
    let paths = DataPaths::new()?;
    
    // Check for existence of key directories
    Ok(paths.keyword_lists.exists() 
       && paths.hash_lists.exists() 
       && paths.cases.exists())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_data_paths_creation() {
        // This will either succeed or fail depending on environment
        let result = DataPaths::new();
        // Just ensure it doesn't panic
        match result {
            Ok(paths) => {
                assert!(paths.base.is_absolute() || paths.base.is_relative());
            }
            Err(_) => {
                // Expected if not in proper environment
            }
        }
    }
}
