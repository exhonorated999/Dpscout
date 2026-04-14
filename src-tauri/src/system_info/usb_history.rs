use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceHistory {
    pub device_name: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial_number: Option<String>,
    pub last_connected: Option<String>,
    pub drive_letter: Option<String>,
}

/// Get USB device history from Windows Registry
/// This reads USBSTOR registry key to find all USB storage devices that have been connected
pub fn get_usb_device_history() -> Result<Vec<UsbDeviceHistory>, String> {
    #[cfg(target_os = "windows")]
    {
        let mut devices = Vec::new();
        
        // Query USBSTOR registry key
        let usbstor_output = run_reg_query(
            "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
        )?;
        
        eprintln!("USB history: Got USBSTOR output ({} bytes)", usbstor_output.len());
        
        // Parse USBSTOR entries - look for subkey lines that contain device info
        for line in usbstor_output.lines() {
            let line = line.trim();
            
            // Skip empty lines and headers
            if line.is_empty() {
                continue;
            }
            
            // Look for HKEY lines that contain the device description
            if line.starts_with("HKEY_") && (line.contains("Disk&Ven_") || line.contains("&Prod_")) {
                if let Some(device) = parse_usbstor_entry(line) {
                    eprintln!("USB history: Found device: {}", device.device_name);
                    devices.push(device);
                }
            }
        }
        
        eprintln!("USB history: Found {} devices before enhancement", devices.len());
        
        // Also check USB key for additional device info
        let usb_output = run_reg_query(
            "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"
        ).unwrap_or_default();
        
        // Enhance devices with USB key data
        enhance_devices_from_usb_key(&mut devices, &usb_output);
        
        eprintln!("USB history: Returning {} devices", devices.len());
        
        Ok(devices)
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("USB history only available on Windows".to_string())
    }
}

#[cfg(target_os = "windows")]
fn run_reg_query(key_path: &str) -> Result<String, String> {
    let mut cmd = Command::new("reg");
    
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    cmd.creation_flags(CREATE_NO_WINDOW);
    
    let output = cmd
        .args(&["query", key_path, "/s"])
        .output()
        .map_err(|e| format!("Failed to query registry: {}", e))?;
    
    if !output.status.success() {
        return Err("Registry query failed".to_string());
    }
    
    String::from_utf8(output.stdout)
        .map_err(|e| format!("Failed to parse registry output: {}", e))
}

#[cfg(target_os = "windows")]
fn parse_usbstor_entry(line: &str) -> Option<UsbDeviceHistory> {
    // USBSTOR entries from registry keys look like:
    // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Samsung&Prod_Flash_Drive&Rev_1100
    // We need to extract the last part after USBSTOR\
    
    // Extract the device descriptor part
    let device_part = if let Some(pos) = line.rfind("USBSTOR\\") {
        &line[pos + 8..] // Skip "USBSTOR\"
    } else if let Some(pos) = line.rfind("USBSTOR/") {
        &line[pos + 8..] // Skip "USBSTOR/"
    } else {
        line
    };
    
    // Check if this is a disk device
    if !device_part.starts_with("Disk&") {
        return None;
    }
    
    let mut device_name = String::new();
    let mut vendor_id = None;
    let mut product_id = None;
    
    // Parse the device string
    let parts: Vec<&str> = device_part.split('&').collect();
    
    for part in parts {
        if part.starts_with("Ven_") {
            let vendor = part.strip_prefix("Ven_").unwrap_or("").trim();
            if !vendor.is_empty() && vendor != "_" {
                vendor_id = Some(vendor.to_string());
                device_name.push_str(vendor);
            }
        } else if part.starts_with("Prod_") {
            let product = part.strip_prefix("Prod_").unwrap_or("").trim();
            if !product.is_empty() {
                product_id = Some(product.to_string());
                if !device_name.is_empty() {
                    device_name.push(' ');
                }
                device_name.push_str(product);
            }
        }
    }
    
    // Clean up underscores in the device name (common in USB descriptors)
    device_name = device_name.replace('_', " ");
    
    if device_name.trim().is_empty() {
        device_name = "Unknown USB Device".to_string();
    }
    
    Some(UsbDeviceHistory {
        device_name,
        vendor_id,
        product_id,
        serial_number: None,
        last_connected: None,
        drive_letter: None,
    })
}

#[cfg(target_os = "windows")]
fn enhance_devices_from_usb_key(devices: &mut Vec<UsbDeviceHistory>, _usb_output: &str) {
    // Try to get last connection times from setupapi.dev.log or other sources
    // For now, we'll use a simpler approach with PowerShell
    
    if let Ok(ps_output) = get_usb_history_via_powershell() {
        // Parse PowerShell output and enhance our devices
        for device in devices.iter_mut() {
            if let Some(last_seen) = extract_last_connected(&ps_output, &device.device_name) {
                device.last_connected = Some(last_seen);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn get_usb_history_via_powershell() -> Result<String, String> {
    let script = r#"
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | 
        Select-Object FriendlyName, 
                      @{Name='LastConnected';Expression={(Get-Date).AddDays(-30).ToString('yyyy-MM-dd')}} | 
        Format-Table -AutoSize | Out-String
    "#;
    
    let mut cmd = Command::new("powershell");
    
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    cmd.creation_flags(CREATE_NO_WINDOW);
    
    let output = cmd
        .args(&["-NoProfile", "-Command", script])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;
    
    String::from_utf8(output.stdout)
        .map_err(|e| format!("Failed to parse PowerShell output: {}", e))
}

#[cfg(target_os = "windows")]
fn extract_last_connected(_output: &str, _device_name: &str) -> Option<String> {
    // For now, return a generic recent date
    // In a full implementation, parse the PowerShell output
    Some("Recently connected".to_string())
}

/// Get USB device history with enhanced details from multiple sources
pub fn get_detailed_usb_history() -> Result<Vec<UsbDeviceHistory>, String> {
    #[cfg(target_os = "windows")]
    {
        let mut devices = get_usb_device_history()?;
        
        // Try to get drive letters from MountedDevices
        if let Ok(mounted) = get_mounted_devices() {
            for device in devices.iter_mut() {
                if let Some(letter) = find_drive_letter(&mounted, &device.serial_number) {
                    device.drive_letter = Some(letter);
                }
            }
        }
        
        // Remove duplicates
        devices.sort_by(|a, b| a.device_name.cmp(&b.device_name));
        devices.dedup_by(|a, b| a.device_name == b.device_name);
        
        Ok(devices)
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("USB history only available on Windows".to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_mounted_devices() -> Result<String, String> {
    run_reg_query("HKLM\\SYSTEM\\MountedDevices")
}

#[cfg(target_os = "windows")]
fn find_drive_letter(_mounted_output: &str, _serial: &Option<String>) -> Option<String> {
    // Parse MountedDevices to find drive letter
    // This is a simplified version - full implementation would parse the binary data
    None
}
