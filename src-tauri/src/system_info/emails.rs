use std::collections::HashSet;
use std::path::PathBuf;
use std::fs;

/// Discover email addresses from various sources
pub fn discover_emails() -> Result<Vec<String>, String> {
    let mut emails = HashSet::new();
    
    // Source 1: Windows Registry (Outlook, Mail apps)
    emails.extend(get_emails_from_registry());
    
    // Source 2: Browser profiles
    emails.extend(get_emails_from_browsers());
    
    // Source 3: Windows Mail app
    emails.extend(get_emails_from_windows_mail());
    
    // Source 4: Thunderbird
    emails.extend(get_emails_from_thunderbird());
    
    // Convert to sorted vector
    let mut email_vec: Vec<String> = emails.into_iter().collect();
    email_vec.sort();
    
    Ok(email_vec)
}

/// Get emails from Windows Registry
fn get_emails_from_registry() -> Vec<String> {
    let mut emails = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        
        // Check Outlook profiles
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        // Outlook email accounts
        if let Ok(outlook_key) = hkcu.open_subkey("Software\\Microsoft\\Office\\Outlook\\Settings\\Accounts") {
            for value_name in outlook_key.enum_values().flatten() {
                if let Ok(value) = outlook_key.get_value::<String, _>(&value_name.0) {
                    if let Some(email) = extract_email_from_string(&value) {
                        emails.push(email);
                    }
                }
            }
        }
        
        // Windows Mail
        if let Ok(mail_key) = hkcu.open_subkey("Software\\Microsoft\\Windows Mail") {
            if let Ok(email) = mail_key.get_value::<String, _>("DefaultAccount") {
                if is_valid_email(&email) {
                    emails.push(email);
                }
            }
        }
        
        // Check for registered email in Windows
        if let Ok(identity_key) = hkcu.open_subkey("Software\\Microsoft\\IdentityCRL\\UserExtendedProperties") {
            for subkey_name in identity_key.enum_keys().flatten() {
                if let Ok(subkey) = identity_key.open_subkey(&subkey_name) {
                    if let Ok(email) = subkey.get_value::<String, _>("Email") {
                        if is_valid_email(&email) {
                            emails.push(email);
                        }
                    }
                }
            }
        }
    }
    
    emails
}

/// Get emails from browser profiles
fn get_emails_from_browsers() -> Vec<String> {
    let mut emails = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            // Chrome preferences
            let chrome_path = PathBuf::from(&local_appdata)
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Preferences");
            
            if let Ok(prefs) = fs::read_to_string(&chrome_path) {
                emails.extend(extract_emails_from_json(&prefs));
            }
            
            // Edge preferences
            let edge_path = PathBuf::from(&local_appdata)
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("Preferences");
            
            if let Ok(prefs) = fs::read_to_string(&edge_path) {
                emails.extend(extract_emails_from_json(&prefs));
            }
        }
        
        // Firefox profiles
        if let Ok(appdata) = std::env::var("APPDATA") {
            let firefox_profiles = PathBuf::from(&appdata)
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles");
            
            if let Ok(entries) = fs::read_dir(&firefox_profiles) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        // Check prefs.js
                        let prefs_path = entry.path().join("prefs.js");
                        if let Ok(prefs) = fs::read_to_string(&prefs_path) {
                            emails.extend(extract_emails_from_text(&prefs));
                        }
                    }
                }
            }
        }
    }
    
    emails
}

/// Get emails from Windows Mail app
fn get_emails_from_windows_mail() -> Vec<String> {
    let mut emails = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let mail_path = PathBuf::from(&local_appdata)
                .join("Packages")
                .join("microsoft.windowscommunicationsapps_8wekyb3d8bbwe")
                .join("LocalState")
                .join("IndexedDB");
            
            if mail_path.exists() {
                // Try to read any text files in the directory
                if let Ok(entries) = fs::read_dir(&mail_path) {
                    for entry in entries.flatten() {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            emails.extend(extract_emails_from_text(&content));
                        }
                    }
                }
            }
        }
    }
    
    emails
}

/// Get emails from Thunderbird
fn get_emails_from_thunderbird() -> Vec<String> {
    let mut emails = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let thunderbird_path = PathBuf::from(&appdata)
                .join("Thunderbird")
                .join("Profiles");
            
            if let Ok(entries) = fs::read_dir(&thunderbird_path) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        // Check prefs.js
                        let prefs_path = entry.path().join("prefs.js");
                        if let Ok(prefs) = fs::read_to_string(&prefs_path) {
                            emails.extend(extract_emails_from_text(&prefs));
                        }
                    }
                }
            }
        }
    }
    
    emails
}

/// Extract email from a string value
fn extract_email_from_string(text: &str) -> Option<String> {
    // Simple regex-like pattern matching for email
    let words: Vec<&str> = text.split(&['<', '>', ' ', ',', ';', '\n', '\r'][..]).collect();
    
    for word in words {
        if is_valid_email(word) {
            return Some(word.to_string());
        }
    }
    
    None
}

/// Extract all emails from JSON content
fn extract_emails_from_json(json: &str) -> Vec<String> {
    extract_emails_from_text(json)
}

/// Extract all emails from text content
fn extract_emails_from_text(text: &str) -> Vec<String> {
    let mut emails = Vec::new();
    
    // Split on common delimiters
    let words: Vec<&str> = text.split(&['<', '>', ' ', ',', ';', '\n', '\r', '"', '\'', ':', '{', '}', '[', ']'][..]).collect();
    
    for word in words {
        if is_valid_email(word) {
            emails.push(word.to_string());
        }
    }
    
    emails
}

/// Validate if string is a valid email address
fn is_valid_email(email: &str) -> bool {
    if email.is_empty() || email.len() < 5 {
        return false;
    }
    
    // Must contain @ symbol
    if !email.contains('@') {
        return false;
    }
    
    // Must have parts before and after @
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let local = parts[0];
    let domain = parts[1];
    
    // Local part must not be empty
    if local.is_empty() {
        return false;
    }
    
    // Domain must contain a dot and have valid structure
    if !domain.contains('.') {
        return false;
    }
    
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if domain_parts.len() < 2 {
        return false;
    }
    
    // TLD must be at least 2 characters
    if let Some(tld) = domain_parts.last() {
        if tld.len() < 2 {
            return false;
        }
    }
    
    // Must only contain valid characters
    for c in email.chars() {
        if !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_' && c != '+' {
            return false;
        }
    }
    
    true
}
