use super::{HardwareInfo, DriveInfo};
use std::process::Command;

/// Get hardware identification information
pub fn get_hardware_info() -> Result<HardwareInfo, String> {
    let drives = get_drive_info()?;
    let motherboard_serial = get_motherboard_serial();
    let bios_serial = get_bios_serial();
    let system_uuid = get_system_uuid();
    
    Ok(HardwareInfo {
        drives,
        motherboard_serial,
        bios_serial,
        system_uuid,
    })
}

/// Get information about all drives
fn get_drive_info() -> Result<Vec<DriveInfo>, String> {
    let mut drives = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        use std::path::Path;
        
        // Check common drive letters
        for letter in 'A'..='Z' {
            let drive_path = format!("{}:\\", letter);
            let path = Path::new(&drive_path);
            
            if path.exists() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    // Get drive info using WMI
                    let letter_str = letter.to_string();
                    if let Ok(info) = get_drive_details(&letter_str) {
                        drives.push(info);
                    }
                }
            }
        }
    }
    
    Ok(drives)
}

/// Get detailed drive information using WMIC
#[cfg(target_os = "windows")]
fn get_drive_details(letter: &str) -> Result<DriveInfo, String> {
    // Get volume information
    let mut cmd = Command::new("wmic");
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    let where_clause = format!("DriveLetter='{}':", letter);
    let volume_output = cmd
        .args(&["volume", "where", &where_clause, "get", "Label,FileSystem,Capacity,FreeSpace", "/format:csv"])
        .output()
        .map_err(|e| format!("Failed to execute wmic: {}", e))?;
    
    let volume_text = String::from_utf8_lossy(&volume_output.stdout);
    
    let mut label = String::new();
    let mut filesystem = String::new();
    let mut total_space = 0u64;
    let mut free_space = 0u64;
    
    // Parse CSV output (skip header)
    for line in volume_text.lines().skip(1) {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 5 {
            if let Ok(capacity) = parts[1].trim().parse::<u64>() {
                total_space = capacity;
            }
            filesystem = parts[2].trim().to_string();
            if let Ok(free) = parts[3].trim().parse::<u64>() {
                free_space = free;
            }
            label = parts[4].trim().to_string();
        }
    }
    
    // Get serial number
    let serial_number = get_volume_serial_number(letter).unwrap_or_else(|_| "Unknown".to_string());
    
    Ok(DriveInfo {
        letter: format!("{}:", letter),
        label,
        serial_number,
        filesystem,
        total_space,
        free_space,
    })
}

/// Get volume serial number
#[cfg(target_os = "windows")]
fn get_volume_serial_number(letter: &str) -> Result<String, String> {
    let mut cmd = Command::new("cmd");
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    let drive_path = format!("{}:", letter);
    let output = cmd
        .args(&["/C", "vol", &drive_path])
        .output()
        .map_err(|e| format!("Failed to get volume serial: {}", e))?;
    
    let text = String::from_utf8_lossy(&output.stdout);
    
    // Parse serial number from output
    // Example: "Volume Serial Number is 1234-5678"
    for line in text.lines() {
        if line.contains("Serial Number") {
            if let Some(serial) = line.split("is").nth(1) {
                return Ok(serial.trim().to_string());
            }
        }
    }
    
    Err("Serial number not found".to_string())
}

/// Get motherboard serial number
fn get_motherboard_serial() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        if let Ok(output) = cmd
            .args(&["baseboard", "get", "serialnumber"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Skip header line
                for line in text.lines().skip(1) {
                    let serial = line.trim();
                    if !serial.is_empty() && serial != "SerialNumber" {
                        return Some(serial.to_string());
                    }
                }
            }
        }
    }
    
    None
}

/// Get BIOS serial number
fn get_bios_serial() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        if let Ok(output) = cmd
            .args(&["bios", "get", "serialnumber"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Skip header line
                for line in text.lines().skip(1) {
                    let serial = line.trim();
                    if !serial.is_empty() && serial != "SerialNumber" {
                        return Some(serial.to_string());
                    }
                }
            }
        }
    }
    
    None
}

/// Get system UUID
fn get_system_uuid() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        if let Ok(output) = cmd
            .args(&["csproduct", "get", "uuid"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Skip header line
                for line in text.lines().skip(1) {
                    let uuid = line.trim();
                    if !uuid.is_empty() && uuid != "UUID" {
                        return Some(uuid.to_string());
                    }
                }
            }
        }
    }
    
    None
}
