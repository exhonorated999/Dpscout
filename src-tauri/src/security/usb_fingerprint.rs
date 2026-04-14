use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbFingerprint {
    pub serial_number: String,
    pub volume_id: String,
    pub drive_letter: String,
}

/// Get USB device fingerprint (serial number + volume ID)
/// This binds the installation to a specific USB drive
#[cfg(windows)]
pub fn get_usb_fingerprint() -> Result<UsbFingerprint, String> {
    use winapi::um::fileapi::GetVolumeInformationW;

    // Get the drive where the executable is located
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    
    // Extract the drive letter (e.g., "C:", "E:", etc.)
    let drive_letter = exe_path
        .to_str()
        .and_then(|s| s.chars().take(2).collect::<String>().into())
        .ok_or("Failed to extract drive letter")?;

    eprintln!("Fingerprinting USB drive: {}", drive_letter);

    // Get volume serial number using Windows API
    // THIS IS THE KEY IDENTIFIER - unique to this USB drive
    let root_path = format!("{}\\", drive_letter);
    let mut root_path_wide: Vec<u16> = root_path.encode_utf16().chain(Some(0)).collect();
    
    let mut volume_name = vec![0u16; 256];
    let mut serial_number: u32 = 0;
    let mut max_component_length: u32 = 0;
    let mut file_system_flags: u32 = 0;
    let mut file_system_name = vec![0u16; 256];

    unsafe {
        let result = GetVolumeInformationW(
            root_path_wide.as_mut_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
            &mut serial_number,
            &mut max_component_length,
            &mut file_system_flags,
            file_system_name.as_mut_ptr(),
            file_system_name.len() as u32,
        );

        if result == 0 {
            return Err("Failed to get volume information".to_string());
        }
    }

    // Get physical drive serial number via WMI
    let physical_serial = get_physical_drive_serial(&drive_letter)?;

    Ok(UsbFingerprint {
        serial_number: physical_serial,
        volume_id: format!("{:08X}", serial_number),
        drive_letter: drive_letter.to_string(),
    })
}

/// Get physical drive serial number using WMI
#[cfg(windows)]
fn get_physical_drive_serial(drive_letter: &str) -> Result<String, String> {
    use wmi::{COMLibrary, WMIConnection};
    
    // Try to initialize COM - if it fails, use fallback
    eprintln!("Attempting to get physical drive serial...");
    
    let com_result = COMLibrary::new();
    if let Err(e) = com_result {
        eprintln!("⚠️ WMI COM initialization failed: {}", e);
        eprintln!("Using volume-based identifier instead");
        // Use drive letter as fallback identifier
        return Ok(format!("DRIVE_{}", drive_letter.trim_end_matches('\\').trim_end_matches(':')));
    }
    
    let com_con = com_result.unwrap();
    
    let wmi_result = WMIConnection::new(com_con);
    if let Err(e) = wmi_result {
        eprintln!("⚠️ WMI connection failed: {}", e);
        eprintln!("Using volume-based identifier instead");
        return Ok(format!("DRIVE_{}", drive_letter.trim_end_matches('\\').trim_end_matches(':')));
    }
    
    let wmi_con = wmi_result.unwrap();

    // Get the logical disk to find associated physical drive
    let query = format!(
        "SELECT * FROM Win32_LogicalDisk WHERE DeviceID = '{}'",
        drive_letter.trim_end_matches('\\').trim_end_matches(':')
    );

    let results: Vec<std::collections::HashMap<String, wmi::Variant>> = match wmi_con.raw_query(&query) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("⚠️ WMI query failed: {}", e);
            eprintln!("Using volume-based identifier");
            return Ok(format!("DRIVE_{}", drive_letter.trim_end_matches('\\').trim_end_matches(':')));
        }
    };

    if results.is_empty() {
        eprintln!("⚠️ Drive not found in WMI");
        eprintln!("Using volume-based identifier");
        return Ok(format!("DRIVE_{}", drive_letter.trim_end_matches('\\').trim_end_matches(':')));
    }

    // Try to get USB device serial via Win32_USBHub or use volume serial as fallback
    let usb_query = "SELECT * FROM Win32_USBHub";
    let usb_results: Vec<std::collections::HashMap<String, wmi::Variant>> = wmi_con
        .raw_query(usb_query)
        .unwrap_or_default();

    if let Some(usb_hub) = usb_results.first() {
        if let Some(wmi::Variant::String(serial)) = usb_hub.get("DeviceID") {
            eprintln!("✓ Got USB device serial from WMI");
            return Ok(serial.clone());
        }
    }

    // Fallback: use a combination of volume serial and drive letter
    eprintln!("✓ Using volume-based identifier");
    Ok(format!("USB_{}", drive_letter.replace(":", "").replace("\\", "")))
}

/// Verify that the current USB matches the registered fingerprint
/// Now searches all removable drives, not just the current drive letter
pub fn verify_usb_fingerprint(registered: &UsbFingerprint) -> Result<bool, String> {
    eprintln!("Verifying USB fingerprint:");
    eprintln!("  Looking for: {} / {}", registered.serial_number, registered.volume_id);
    
    // Try to get fingerprint from current executable location first
    match get_usb_fingerprint() {
        Ok(current) => {
            eprintln!("  Found on current drive: {} / {}", current.serial_number, current.volume_id);
            if current.serial_number == registered.serial_number && current.volume_id == registered.volume_id {
                eprintln!("✓ USB matched on current drive");
                return Ok(true);
            }
        }
        Err(e) => {
            eprintln!("  Current drive check failed: {}", e);
        }
    }
    
    // Search all removable drives for the matching USB
    eprintln!("  Searching all removable drives...");
    let found = search_all_removable_drives_for_match(registered)?;
    
    if found {
        eprintln!("✓ USB device found and matched");
    } else {
        eprintln!("✗ USB device not found on any removable drive");
    }
    
    Ok(found)
}

/// Search all removable drives for a matching USB fingerprint
#[cfg(windows)]
fn search_all_removable_drives_for_match(registered: &UsbFingerprint) -> Result<bool, String> {
    use winapi::um::fileapi::{GetDriveTypeW, GetVolumeInformationW};
    use winapi::um::winbase::DRIVE_REMOVABLE;
    
    // Check drives A-Z
    for letter in b'A'..=b'Z' {
        let drive_letter = format!("{}:", letter as char);
        let root_path = format!("{}\\", drive_letter);
        let mut root_path_wide: Vec<u16> = root_path.encode_utf16().chain(Some(0)).collect();
        
        // Check if this is a removable drive
        let drive_type = unsafe { GetDriveTypeW(root_path_wide.as_ptr()) };
        if drive_type != DRIVE_REMOVABLE {
            continue;
        }
        
        eprintln!("    Checking removable drive: {}", drive_letter);
        
        // Get volume information
        let mut volume_name = vec![0u16; 256];
        let mut serial_number: u32 = 0;
        let mut max_component_length: u32 = 0;
        let mut file_system_flags: u32 = 0;
        let mut file_system_name = vec![0u16; 256];

        unsafe {
            let result = GetVolumeInformationW(
                root_path_wide.as_mut_ptr(),
                volume_name.as_mut_ptr(),
                volume_name.len() as u32,
                &mut serial_number,
                &mut max_component_length,
                &mut file_system_flags,
                file_system_name.as_mut_ptr(),
                file_system_name.len() as u32,
            );

            if result == 0 {
                continue; // Skip drives we can't read
            }
        }
        
        let volume_id = format!("{:08X}", serial_number);
        
        // Try to get physical drive serial
        let physical_serial = match get_physical_drive_serial(&drive_letter) {
            Ok(s) => s,
            Err(_) => continue,
        };
        
        eprintln!("      Found: {} / {}", physical_serial, volume_id);
        
        // Check if this matches the registered fingerprint
        // Only match on volume ID for portability across computers
        if volume_id == registered.volume_id {
            eprintln!("      ✓ MATCH FOUND on {} (Volume ID: {})", drive_letter, volume_id);
            return Ok(true);
        }
    }
    
    Ok(false)
}

#[cfg(not(windows))]
pub fn get_usb_fingerprint() -> Result<UsbFingerprint, String> {
    Err("USB fingerprinting only supported on Windows".to_string())
}

#[cfg(not(windows))]
pub fn verify_usb_fingerprint(_registered: &UsbFingerprint) -> Result<bool, String> {
    Err("USB fingerprinting only supported on Windows".to_string())
}
