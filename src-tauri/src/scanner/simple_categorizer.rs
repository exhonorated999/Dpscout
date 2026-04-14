use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryMappings {
    pub version: String,
    pub categories: Vec<String>,
    pub mappings: HashMap<String, String>,
}

impl CategoryMappings {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let app_path = std::env::current_exe()?;
        let app_dir = app_path.parent().unwrap();
        
        eprintln!("=== LOADING CATEGORY MAPPINGS ===");
        eprintln!("App exe: {}", app_path.display());
        eprintln!("App dir: {}", app_dir.display());
        eprintln!("Current dir: {}", std::env::current_dir()?.display());
        
        // Try multiple locations
        let possible_paths = vec![
            app_dir.join("app_categories.json"),
            PathBuf::from("app_categories.json"),
            PathBuf::from("../app_categories.json"),
            PathBuf::from("../../app_categories.json"),
        ];
        
        eprintln!("Trying paths:");
        for path in &possible_paths {
            eprintln!("  - {} (exists: {})", path.display(), path.exists());
            if path.exists() {
                eprintln!("✓ FOUND! Loading category mappings from: {}", path.display());
                let content = fs::read_to_string(path)?;
                let mappings: CategoryMappings = serde_json::from_str(&content)?;
                eprintln!("✓✓✓ LOADED {} category mappings successfully! ✓✓✓", mappings.mappings.len());
                return Ok(mappings);
            }
        }
        
        eprintln!("❌ WARNING: app_categories.json NOT FOUND in any location!");
        eprintln!("Using minimal defaults with only {} mappings", Self::default().mappings.len());
        Ok(Self::default())
    }
    
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let app_path = std::env::current_exe()?;
        let app_dir = app_path.parent().unwrap();
        let path = app_dir.join("app_categories.json");
        
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        eprintln!("✓ Saved category mappings to: {}", path.display());
        Ok(())
    }
    
    pub fn default() -> Self {
        let mut mappings = HashMap::new();
        
        // Essential defaults
        mappings.insert("tor".to_string(), "ANONYMITY_ANTI_FORENSICS".to_string());
        mappings.insert("torrent".to_string(), "DARKWEB_P2P".to_string());
        mappings.insert("vpn".to_string(), "VPN_REMOTE_ACCESS".to_string());
        mappings.insert("bitcoin".to_string(), "CRYPTOCURRENCY".to_string());
        mappings.insert("signal".to_string(), "COMMUNICATIONS".to_string());
        
        CategoryMappings {
            version: "1.0".to_string(),
            categories: vec![
                "ANONYMITY_ANTI_FORENSICS".to_string(),
                "DARKWEB_P2P".to_string(),
                "VPN_REMOTE_ACCESS".to_string(),
                "CRYPTOCURRENCY".to_string(),
                "COMMUNICATIONS".to_string(),
                "GENERAL_PRODUCTIVITY".to_string(),
            ],
            mappings,
        }
    }
    
    /// Categorize an app by checking if any mapping keyword appears in the combined text
    pub fn categorize(&self, app_name: &str, publisher: &Option<String>, install_path: &str) -> (String, f32) {
        let empty_string = String::new();
        let combined = format!("{} {} {}", 
            app_name.to_lowercase(),
            publisher.as_ref().unwrap_or(&empty_string).to_lowercase(),
            install_path.to_lowercase()
        );
        
        // Check each mapping keyword
        for (keyword, category) in &self.mappings {
            if combined.contains(&keyword.to_lowercase()) {
                return (category.clone(), 0.9); // High confidence for keyword match
            }
        }
        
        // Check if it's a Microsoft/Google/Apple product
        let publisher_lower = publisher.as_ref()
            .map(|p| p.to_lowercase())
            .unwrap_or_default();
        
        if publisher_lower.contains("microsoft") || 
           publisher_lower.contains("google") || 
           publisher_lower.contains("apple") {
            return ("GENERAL_PRODUCTIVITY".to_string(), 0.6);
        }
        
        // Default: unknown
        ("UNKNOWN".to_string(), 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_categorization() {
        let mappings = CategoryMappings::default();
        
        let (cat, conf) = mappings.categorize(
            "Tor Browser",
            &Some("The Tor Project".to_string()),
            "C:\\Program Files\\Tor"
        );
        assert_eq!(cat, "ANONYMITY_ANTI_FORENSICS");
        assert!(conf > 0.5);
    }
}
