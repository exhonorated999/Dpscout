/// Chrome extension manifest parser for forensic scanning
/// 
/// Parses Chrome extension manifest.json files to extract extension metadata

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChromeExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub manifest_version: i32,
    pub author: Option<String>,
    pub homepage_url: Option<String>,
    pub install_path: String,
}

#[derive(Debug, Deserialize)]
struct ManifestJson {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    manifest_version: Option<i32>,
    author: Option<String>,
    homepage_url: Option<String>,
    // Chrome Web Store specific
    update_url: Option<String>,
    // Optional permissions (Chrome extensions v3)
    optional_permissions: Option<Vec<String>>,
    host_permissions: Option<Vec<String>>,
}

/// Parse Chrome extensions from a user profile
pub fn parse_chrome_extensions(extensions_dir: &Path) -> Result<Vec<ChromeExtension>, String> {
    if !extensions_dir.exists() {
        return Err("Extensions directory not found".to_string());
    }
    
    let mut extensions = Vec::new();
    
    // Each extension has its own directory with ID as folder name
    for entry in fs::read_dir(extensions_dir)
        .map_err(|e| format!("Failed to read extensions dir: {}", e))? 
    {
        if let Ok(entry) = entry {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            
            let extension_id = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string();
            
            // Look for manifest.json in version subdirectories
            if let Ok(version_dirs) = fs::read_dir(&path) {
                for version_entry in version_dirs.flatten() {
                    let version_path = version_entry.path();
                    if !version_path.is_dir() {
                        continue;
                    }
                    
                    let manifest_path = version_path.join("manifest.json");
                    if manifest_path.exists() {
                        if let Ok(ext) = parse_extension_manifest(&manifest_path, &extension_id) {
                            extensions.push(ext);
                            break; // Only take the first valid manifest per extension
                        }
                    }
                }
            }
        }
    }
    
    Ok(extensions)
}

/// Parse a single extension's manifest.json
pub fn parse_extension_manifest(manifest_path: &Path, extension_id: &str) -> Result<ChromeExtension, String> {
    let content = fs::read_to_string(manifest_path)
        .map_err(|e| format!("Failed to read manifest: {}", e))?;
    
    let manifest: ManifestJson = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse manifest JSON: {}", e))?;
    
    // Collect all permissions
    let mut permissions = manifest.permissions.unwrap_or_default();
    if let Some(optional) = manifest.optional_permissions {
        permissions.extend(optional);
    }
    if let Some(host) = manifest.host_permissions {
        permissions.extend(host);
    }
    
    Ok(ChromeExtension {
        id: extension_id.to_string(),
        name: manifest.name.unwrap_or_else(|| "Unknown Extension".to_string()),
        version: manifest.version.unwrap_or_else(|| "Unknown".to_string()),
        description: manifest.description.unwrap_or_default(),
        permissions,
        manifest_version: manifest.manifest_version.unwrap_or(2),
        author: manifest.author,
        homepage_url: manifest.homepage_url,
        install_path: manifest_path.parent()
            .unwrap_or(manifest_path)
            .to_string_lossy()
            .to_string(),
    })
}

/// Categorize extension by permissions (security analysis)
pub fn categorize_extension_risk(extension: &ChromeExtension) -> ExtensionRiskLevel {
    let dangerous_permissions = vec![
        "<all_urls>",
        "webRequest",
        "webRequestBlocking",
        "proxy",
        "debugger",
        "management",
        "downloads",
        "privacy",
        "cookies",
    ];
    
    let sensitive_permissions = vec![
        "tabs",
        "history",
        "bookmarks",
        "clipboardRead",
        "clipboardWrite",
        "geolocation",
        "notifications",
    ];
    
    let dangerous_count = extension.permissions.iter()
        .filter(|p| dangerous_permissions.iter().any(|dp| p.contains(dp)))
        .count();
    
    let sensitive_count = extension.permissions.iter()
        .filter(|p| sensitive_permissions.iter().any(|sp| p.contains(sp)))
        .count();
    
    if dangerous_count >= 2 {
        ExtensionRiskLevel::High
    } else if dangerous_count >= 1 || sensitive_count >= 3 {
        ExtensionRiskLevel::Medium
    } else if sensitive_count >= 1 {
        ExtensionRiskLevel::Low
    } else {
        ExtensionRiskLevel::Minimal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtensionRiskLevel {
    High,
    Medium,
    Low,
    Minimal,
}

/// Get detailed permission descriptions
pub fn get_permission_description(permission: &str) -> String {
    match permission {
        "<all_urls>" => "Access all websites (very broad permission)".to_string(),
        "webRequest" => "Monitor and modify network requests".to_string(),
        "webRequestBlocking" => "Block or modify network requests".to_string(),
        "proxy" => "Control browser proxy settings".to_string(),
        "debugger" => "Access debugging protocols".to_string(),
        "management" => "Manage other extensions".to_string(),
        "downloads" => "Manage browser downloads".to_string(),
        "privacy" => "Access and modify privacy settings".to_string(),
        "cookies" => "Access browser cookies".to_string(),
        "tabs" => "View and manipulate browser tabs".to_string(),
        "history" => "Read and modify browsing history".to_string(),
        "bookmarks" => "Read and modify bookmarks".to_string(),
        "clipboardRead" => "Read clipboard contents".to_string(),
        "clipboardWrite" => "Modify clipboard contents".to_string(),
        "geolocation" => "Access device location".to_string(),
        "notifications" => "Display notifications".to_string(),
        _ => {
            if permission.starts_with("http") {
                format!("Access to: {}", permission)
            } else {
                permission.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_risk_categorization() {
        let high_risk = ChromeExtension {
            id: "test1".to_string(),
            name: "Test Extension".to_string(),
            version: "1.0".to_string(),
            description: "".to_string(),
            permissions: vec![
                "<all_urls>".to_string(),
                "webRequestBlocking".to_string(),
            ],
            manifest_version: 3,
            author: None,
            homepage_url: None,
            install_path: "".to_string(),
        };
        
        assert!(matches!(
            categorize_extension_risk(&high_risk),
            ExtensionRiskLevel::High
        ));
    }
    
    #[test]
    fn test_permission_description() {
        let desc = get_permission_description("cookies");
        assert!(desc.contains("cookies"));
    }
}
