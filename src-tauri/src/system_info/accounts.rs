use super::UserAccount;
use std::path::Path;
use chrono::{DateTime, Local};

/// Get all Windows user accounts
pub fn get_user_accounts() -> Result<Vec<UserAccount>, String> {
    let mut accounts = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        // Method 1: Scan user profile directories
        if let Ok(profiles_dir) = std::env::var("SYSTEMDRIVE") {
            let users_path = format!("{}\\Users", profiles_dir);
            if let Ok(entries) = std::fs::read_dir(&users_path) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_dir() {
                            let username = entry.file_name().to_string_lossy().to_string();
                            
                            // Skip system folders
                            if username == "Public" || username == "Default" || username == "Default User" {
                                continue;
                            }
                            
                            let profile_path = entry.path().to_string_lossy().to_string();
                            let last_login = get_last_login_from_ntuser(&entry.path());
                            
                            accounts.push(UserAccount {
                                username: username.clone(),
                                full_name: None, // Will try to get from registry
                                profile_path,
                                last_login,
                                account_type: "Local".to_string(),
                            });
                        }
                    }
                }
            }
        }
        
        // Method 2: Get additional info from registry
        enhance_accounts_from_registry(&mut accounts)?;
    }
    
    Ok(accounts)
}

/// Get last login time from NTUSER.DAT modification time
fn get_last_login_from_ntuser(profile_path: &Path) -> Option<String> {
    let ntuser_path = profile_path.join("NTUSER.DAT");
    if let Ok(metadata) = std::fs::metadata(&ntuser_path) {
        if let Ok(modified) = metadata.modified() {
            let datetime: DateTime<Local> = modified.into();
            return Some(datetime.format("%Y-%m-%d %H:%M:%S").to_string());
        }
    }
    None
}

/// Enhance account information from Windows registry
#[cfg(target_os = "windows")]
fn enhance_accounts_from_registry(accounts: &mut Vec<UserAccount>) -> Result<(), String> {
    use winreg::enums::*;
    use winreg::RegKey;
    
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    
    // Try to get ProfileList
    if let Ok(profile_list) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList") {
        for key_name in profile_list.enum_keys().flatten() {
            if let Ok(profile_key) = profile_list.open_subkey(&key_name) {
                if let Ok(profile_path) = profile_key.get_value::<String, _>("ProfileImagePath") {
                    // Extract username from path
                    if let Some(username) = Path::new(&profile_path).file_name() {
                        let username = username.to_string_lossy().to_string();
                        
                        // Find matching account and enhance it
                        if let Some(account) = accounts.iter_mut().find(|a| a.username == username) {
                            // Try to get full name from SAM
                            account.full_name = get_full_name_from_sam(&username);
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Try to get full name from SAM (Security Account Manager)
#[cfg(target_os = "windows")]
fn get_full_name_from_sam(username: &str) -> Option<String> {
    use std::process::Command;
    
    // Use WMIC to query user account details
    let mut cmd = Command::new("wmic");
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    let where_clause = format!("name='{}'", username);
    if let Ok(output) = cmd
        .args(&["useraccount", "where", &where_clause, "get", "fullname"])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            // Parse output (skip header line)
            for line in text.lines().skip(1) {
                let name = line.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    
    None
}

#[cfg(not(target_os = "windows"))]
fn enhance_accounts_from_registry(_accounts: &mut Vec<UserAccount>) -> Result<(), String> {
    Ok(())
}
