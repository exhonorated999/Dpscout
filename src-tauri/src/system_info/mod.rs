use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

mod accounts;
mod hardware;
mod emails;
mod usb_history;

pub use accounts::*;
pub use hardware::*;
pub use emails::*;
pub use usb_history::*;

/// Complete system identification information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub scan_id: String,
    pub scan_timestamp: String,
    pub scan_duration_secs: Option<u64>,
    pub computer_name: String,
    pub os_version: String,
    pub registered_owner: Option<String>,
    pub registered_organization: Option<String>,
    pub product_id: Option<String>,
    pub domain: Option<String>,
    pub user_accounts: Vec<UserAccount>,
    pub emails: Vec<String>,
    pub hardware: HardwareInfo,
    pub network: NetworkInfo,
    pub usb_history: Vec<UsbDeviceHistory>,
}

/// Windows user account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub full_name: Option<String>,
    pub profile_path: String,
    pub last_login: Option<String>,
    pub account_type: String,
}

/// Hardware identification details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub drives: Vec<DriveInfo>,
    pub motherboard_serial: Option<String>,
    pub bios_serial: Option<String>,
    pub system_uuid: Option<String>,
}

/// Individual drive information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveInfo {
    pub letter: String,
    pub label: String,
    pub serial_number: String,
    pub filesystem: String,
    pub total_space: u64,
    pub free_space: u64,
}

/// Network identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub mac_addresses: Vec<String>,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub public_ip: Option<String>,
}

/// Collect all system identification information
pub fn collect_system_info() -> Result<SystemInfo, String> {
    let scan_id = uuid::Uuid::new_v4().to_string();
    let scan_timestamp = Utc::now().to_rfc3339();
    
    let computer_name = get_computer_name()?;
    let os_version = get_os_version()?;
    let (registered_owner, registered_organization, product_id) = get_windows_registration_info();
    let domain = get_domain();
    
    let user_accounts = get_user_accounts()?;
    let emails = discover_emails()?;
    let hardware = get_hardware_info()?;
    let network = get_network_info()?;
    let usb_history = match get_detailed_usb_history() {
        Ok(history) => {
            eprintln!("USB history collected: {} devices", history.len());
            history
        },
        Err(e) => {
            eprintln!("USB history collection failed: {}", e);
            Vec::new()
        }
    };
    
    Ok(SystemInfo {
        scan_id,
        scan_timestamp,
        scan_duration_secs: None, // Will be set by scan command after completion
        computer_name,
        os_version,
        registered_owner,
        registered_organization,
        product_id,
        domain,
        user_accounts,
        emails,
        hardware,
        network,
        usb_history,
    })
}

/// Get computer name
fn get_computer_name() -> Result<String, String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map_err(|_| "Failed to get computer name".to_string())
}

/// Get OS version
fn get_os_version() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let cur_ver = hklm
            .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
            .map_err(|e| format!("Failed to open registry key: {}", e))?;
        
        let mut product_name: String = cur_ver
            .get_value("ProductName")
            .unwrap_or_else(|_| "Unknown".to_string());
        
        let build: String = cur_ver
            .get_value("CurrentBuild")
            .unwrap_or_else(|_| "Unknown".to_string());
        
        // Windows 11 detection: Build 22000+ or check DisplayVersion
        // Windows 11 still reports as "Windows 10" in ProductName
        if let Ok(build_num) = build.parse::<u32>() {
            if build_num >= 22000 {
                // This is Windows 11
                product_name = product_name.replace("Windows 10", "Windows 11");
            }
        }
        
        // Also check DisplayVersion which explicitly shows "11" on Windows 11
        if let Ok(display_version) = cur_ver.get_value::<String, _>("DisplayVersion") {
            // DisplayVersion contains values like "21H2", "22H2", "23H2" etc.
            // For Windows 11, we can include this in the output
            Ok(format!("{} {} (Build {})", product_name, display_version, build))
        } else {
            Ok(format!("{} (Build {})", product_name, build))
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Ok("Non-Windows OS".to_string())
    }
}

/// Get Windows registration information (owner, organization, product ID)
fn get_windows_registration_info() -> (Option<String>, Option<String>, Option<String>) {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
            let registered_owner = key.get_value::<String, _>("RegisteredOwner").ok();
            let registered_organization = key.get_value::<String, _>("RegisteredOrganization").ok();
            let product_id = key.get_value::<String, _>("ProductId").ok();
            
            return (registered_owner, registered_organization, product_id);
        }
    }
    
    (None, None, None)
}

/// Get domain name if joined to domain
fn get_domain() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters") {
            if let Ok(domain) = key.get_value::<String, _>("Domain") {
                if !domain.is_empty() {
                    return Some(domain);
                }
            }
        }
    }
    
    None
}

/// Get network information
fn get_network_info() -> Result<NetworkInfo, String> {
    let hostname = get_computer_name().unwrap_or_else(|_| "Unknown".to_string());
    let mac_addresses = get_mac_addresses();
    let ip_addresses = get_ip_addresses();
    let public_ip = get_public_ip();
    
    Ok(NetworkInfo {
        mac_addresses,
        hostname,
        ip_addresses,
        public_ip,
    })
}

/// Get MAC addresses of network interfaces
fn get_mac_addresses() -> Vec<String> {
    let mut macs = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        let mut cmd = Command::new("getmac");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        if let Ok(output) = cmd
            .arg("/FO")
            .arg("CSV")
            .arg("/NH")
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines() {
                    if let Some(mac) = line.split(',').next() {
                        let mac = mac.trim_matches('"').trim();
                        if !mac.is_empty() && mac.contains('-') {
                            macs.push(mac.to_string());
                        }
                    }
                }
            }
        }
    }
    
    macs
}

/// Get IP addresses
fn get_ip_addresses() -> Vec<String> {
    let mut ips = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        let mut cmd = Command::new("ipconfig");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        if let Ok(output) = cmd.output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines() {
                    if line.contains("IPv4 Address") {
                        if let Some(ip) = line.split(':').nth(1) {
                            let ip = ip.trim();
                            if !ip.is_empty() {
                                ips.push(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    ips
}

/// Get public IP address from external API
fn get_public_ip() -> Option<String> {
    // Try multiple services for reliability
    let services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ];
    
    for service in &services {
        if let Ok(response) = ureq::get(service)
            .timeout(std::time::Duration::from_secs(5))
            .call()
        {
            if let Ok(ip) = response.into_string() {
                let ip = ip.trim().to_string();
                if !ip.is_empty() {
                    eprintln!("✓ Retrieved public IP: {}", ip);
                    return Some(ip);
                }
            }
        }
    }
    
    eprintln!("⚠ Failed to retrieve public IP address");
    None
}
