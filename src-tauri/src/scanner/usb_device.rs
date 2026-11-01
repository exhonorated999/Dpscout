use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::Path;

/// USB device information for forensic scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub drive_letter: String,
    pub drive_name: String,
    pub make: Option<String>,
    pub model: Option<String>,
    pub capacity_gb: f64,
    pub used_space_gb: f64,
    pub free_space_gb: f64,
    pub file_count: usize,
    pub serial_number: String,
    pub volume_id: String,
}

/// Get USB device information for a specific drive (Windows drive letter).
/// macOS uses [`get_usb_device_info_macos`].
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn get_usb_device_info(drive_letter: &str) -> Result<UsbDeviceInfo, String> {
    // Validate drive exists
    let drive_path = format!("{}:\\", drive_letter.chars().next().unwrap());
    let path = Path::new(&drive_path);
    
    if !path.exists() {
        return Err(format!("Drive {} does not exist", drive_letter));
    }
    
    // Get drive name (label) via GetVolumeInformationW — instant, no WMIC
    let drive_name = get_drive_label_fast(drive_letter)
        .unwrap_or_else(|_| format!("{}: Drive", drive_letter));
    
    // Get capacity info via GetDiskFreeSpaceExW — instant
    let (capacity_gb, free_space_gb, used_space_gb) = match get_drive_capacity(drive_letter) {
        Ok((total_bytes, free_bytes)) => {
            let capacity = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let free = free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let used = capacity - free;
            (capacity, free, used)
        }
        Err(_) => (0.0, 0.0, 0.0),
    };
    
    // Get serial number and volume ID via GetVolumeInformationW — instant
    let (serial_number, volume_id) = get_drive_identifiers_fast(drive_letter)
        .unwrap_or_else(|_| ("Unknown".to_string(), "Unknown".to_string()));
    
    // DO NOT count files — it walks the entire drive and can take minutes
    let file_count = 0;
    
    Ok(UsbDeviceInfo {
        drive_letter: drive_letter.to_string(),
        drive_name,
        make: None,
        model: None,
        capacity_gb,
        used_space_gb,
        free_space_gb,
        file_count,
        serial_number,
        volume_id,
    })
}

/// macOS portable: `UsbDeviceInfo` for an attached volume (`/Volumes/X`) from
/// `diskutil info -plist <mount>`, with `df` sizes as the fallback.
/// `drive_letter` carries the mount path. `serial_number` is the VolumeUUID
/// and `volume_id` is the BSD device (`disk4s1`). Pure, so it is tested on Windows.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn usb_info_from_diskutil(xml: &[u8], mount: &str, df_total: u64, df_free: u64) -> UsbDeviceInfo {
    let d = crate::system_info::macos::parse_diskutil_info(xml, mount, df_total, df_free);
    let dict = plist::Value::from_reader_xml(xml).ok().and_then(|v| v.into_dictionary());
    let s = |k: &str| {
        dict.as_ref()
            .and_then(|d| d.get(k))
            .and_then(|v| v.as_string())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let capacity_gb = d.total_space as f64 / GB;
    let free_space_gb = d.free_space as f64 / GB;
    UsbDeviceInfo {
        drive_letter: mount.to_string(),
        drive_name: d.label,
        make: None,
        model: s("MediaName"),
        capacity_gb,
        used_space_gb: (capacity_gb - free_space_gb).max(0.0),
        free_space_gb,
        file_count: 0,
        serial_number: if d.serial_number.is_empty() { "Unknown".to_string() } else { d.serial_number },
        volume_id: s("DeviceIdentifier").unwrap_or_else(|| "Unknown".to_string()),
    }
}

/// macOS portable: device info for a USB/external volume mounted under `/Volumes`.
/// Read-only, unprivileged (`df`, `diskutil info`) — nothing is written to the host.
#[cfg(target_os = "macos")]
pub fn get_usb_device_info_macos(mount: &str) -> Result<UsbDeviceInfo, String> {
    if !mount.starts_with("/Volumes/") || !Path::new(mount).is_dir() {
        return Err(format!("{} is not a mounted volume", mount));
    }
    let (total, free) = Command::new("/bin/df")
        .args(["-kP", mount])
        .output()
        .ok()
        .map(|o| crate::system_info::macos::parse_df(&String::from_utf8_lossy(&o.stdout)))
        .and_then(|v| v.into_iter().next())
        .map(|(_, t, f)| (t, f))
        .unwrap_or((0, 0));
    let xml = Command::new("/usr/sbin/diskutil")
        .args(["info", "-plist", mount])
        .output()
        .map(|o| o.stdout)
        .unwrap_or_default();
    Ok(usb_info_from_diskutil(&xml, mount, total, free))
}

/// Get drive label using GetVolumeInformationW — instant, no subprocess
fn get_drive_label_fast(letter: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::fileapi::GetVolumeInformationW;
        
        let root = format!("{}:\\", letter);
        let root_wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
        
        let mut name_buf: [u16; 256] = [0; 256];
        let mut serial: u32 = 0;
        
        let result = unsafe {
            GetVolumeInformationW(
                root_wide.as_ptr(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        
        if result != 0 {
            let len = name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len());
            let label = String::from_utf16_lossy(&name_buf[..len]);
            if label.is_empty() {
                Ok(format!("{}: Drive", letter))
            } else {
                Ok(label)
            }
        } else {
            Ok(format!("{}: Drive", letter))
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("Only supported on Windows".to_string())
    }
}

/// Get drive serial/volume ID using GetVolumeInformationW — instant, no subprocess
fn get_drive_identifiers_fast(letter: &str) -> Result<(String, String), String> {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::fileapi::GetVolumeInformationW;
        
        let root = format!("{}:\\", letter);
        let root_wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
        
        let mut name_buf: [u16; 256] = [0; 256];
        let mut serial: u32 = 0;
        let mut fs_buf: [u16; 64] = [0; 64];
        
        let result = unsafe {
            GetVolumeInformationW(
                root_wide.as_ptr(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs_buf.as_mut_ptr(),
                fs_buf.len() as u32,
            )
        };
        
        if result != 0 {
            Ok((format!("{:08X}", serial), format!("VOL-{:08X}", serial)))
        } else {
            Err("GetVolumeInformationW failed".to_string())
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("Only supported on Windows".to_string())
    }
}

/// Get drive label/name
fn get_drive_label(letter: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        let where_clause = format!("DriveLetter='{}:'", letter);
        let output = cmd
            .args(&["volume", "where", &where_clause, "get", "Label", "/format:csv"])
            .output()
            .map_err(|e| format!("Failed to get drive label: {}", e))?;
        
        let text = String::from_utf8_lossy(&output.stdout);
        
        // Parse CSV output (skip header)
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let label = parts[1].trim();
                if !label.is_empty() {
                    return Ok(label.to_string());
                }
            }
        }
        
        // Default name if no label
        Ok(format!("{}: Drive", letter))
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("USB device info only supported on Windows".to_string())
    }
}

/// Get drive make and model from physical disk info
fn get_drive_make_model(letter: &str) -> (Option<String>, Option<String>) {
    #[cfg(target_os = "windows")]
    {
        // First, map drive letter to physical disk number
        let disk_number = match get_physical_disk_number(letter) {
            Some(num) => num,
            None => return (None, None),
        };
        
        // Get physical disk model
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        let where_clause = format!("Index={}", disk_number);
        if let Ok(output) = cmd
            .args(&["diskdrive", "where", &where_clause, "get", "Caption,Manufacturer,Model", "/format:csv"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 4 {
                        let manufacturer = parts[2].trim();
                        let model = parts[3].trim();
                        
                        let make = if !manufacturer.is_empty() && manufacturer != "Manufacturer" {
                            Some(manufacturer.to_string())
                        } else {
                            None
                        };
                        
                        let model_name = if !model.is_empty() && model != "Model" {
                            Some(model.to_string())
                        } else {
                            None
                        };
                        
                        return (make, model_name);
                    }
                }
            }
        }
    }
    
    (None, None)
}

/// Map drive letter to physical disk number
fn get_physical_disk_number(letter: &str) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        let where_clause = format!("DriveLetter='{}:'", letter);
        if let Ok(output) = cmd
            .args(&["partition", "where", &where_clause, "get", "DiskIndex", "/format:csv"])
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        if let Ok(disk_num) = parts[1].trim().parse::<u32>() {
                            return Some(disk_num);
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Get drive capacity and free space
fn get_drive_capacity(letter: &str) -> Result<(u64, u64), String> {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::fileapi::GetDiskFreeSpaceExW;
        use winapi::um::winnt::ULARGE_INTEGER;
        
        let root = format!("{}:\\", letter);
        let root_wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
        
        let mut free_bytes_available: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
        let mut total_bytes: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
        let mut total_free_bytes: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
        
        let result = unsafe {
            GetDiskFreeSpaceExW(
                root_wide.as_ptr(),
                &mut free_bytes_available,
                &mut total_bytes,
                &mut total_free_bytes,
            )
        };
        
        if result != 0 {
            let capacity = unsafe { *total_bytes.QuadPart() };
            let free = unsafe { *total_free_bytes.QuadPart() };
            Ok((capacity, free))
        } else {
            Err("GetDiskFreeSpaceExW failed".to_string())
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("USB device info only supported on Windows".to_string())
    }
}

/// Get drive serial number and volume ID
fn get_drive_identifiers(letter: &str) -> Result<(String, String), String> {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("wmic");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        
        let where_clause = format!("DriveLetter='{}:'", letter);
        let output = cmd
            .args(&["volume", "where", &where_clause, "get", "SerialNumber", "/format:csv"])
            .output()
            .map_err(|e| format!("Failed to get drive identifiers: {}", e))?;
        
        let text = String::from_utf8_lossy(&output.stdout);
        
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let serial = parts[1].trim();
                if !serial.is_empty() && serial != "SerialNumber" {
                    // Volume serial is in hex format
                    let volume_id = format!("{:08X}", serial.parse::<u32>().unwrap_or(0));
                    return Ok((serial.to_string(), volume_id));
                }
            }
        }
        
        // Fallback to using Windows API for volume serial
        use winapi::um::fileapi::GetVolumeInformationW;
        
        let root_path = format!("{}:\\", letter);
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

            if result != 0 {
                let volume_id = format!("{:08X}", serial_number);
                return Ok((serial_number.to_string(), volume_id));
            }
        }
        
        Err("Could not determine drive identifiers".to_string())
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        Err("USB device info only supported on Windows".to_string())
    }
}

/// Count files using fast parallel directory walking (jwalk)
/// Caps at 1,000,000 to avoid hanging on huge drives
fn count_files_recursive(path: &Path) -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    const MAX_FILES_TO_COUNT: usize = 1_000_000;
    
    let count = AtomicUsize::new(0);
    
    for entry in jwalk::WalkDir::new(path)
        .skip_hidden(false)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_dir() {
            let c = count.fetch_add(1, Ordering::Relaxed);
            if c >= MAX_FILES_TO_COUNT {
                break;
            }
        }
    }
    
    count.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diskutil_volume_maps_to_usb_info() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>VolumeName</key><string>EVIDENCE</string>
<key>FilesystemName</key><string>ExFAT</string>
<key>VolumeUUID</key><string>0E239BC6-F960-3107-89CF-1C97F78BB46B</string>
<key>DeviceIdentifier</key><string>disk4s1</string>
<key>MediaName</key><string> SanDisk Ultra </string>
<key>TotalSize</key><integer>68719476736</integer>
<key>FreeSpace</key><integer>17179869184</integer>
</dict></plist>"#;
        let u = usb_info_from_diskutil(xml, "/Volumes/EVIDENCE", 1, 1);
        assert_eq!(u.drive_letter, "/Volumes/EVIDENCE");
        assert_eq!(u.drive_name, "EVIDENCE");
        assert_eq!(u.model.as_deref(), Some("SanDisk Ultra"));
        assert_eq!(u.serial_number, "0E239BC6-F960-3107-89CF-1C97F78BB46B");
        assert_eq!(u.volume_id, "disk4s1");
        assert!((u.capacity_gb - 64.0).abs() < 1e-9);
        assert!((u.free_space_gb - 16.0).abs() < 1e-9);
        assert!((u.used_space_gb - 48.0).abs() < 1e-9);
        assert_eq!(u.file_count, 0);
    }

    #[test]
    fn diskutil_garbage_falls_back_to_df_and_mount_name() {
        let gb = 1024u64 * 1024 * 1024;
        let u = usb_info_from_diskutil(b"not a plist", "/Volumes/NO NAME", 8 * gb, 2 * gb);
        assert_eq!(u.drive_name, "NO NAME");
        assert_eq!(u.model, None);
        assert_eq!(u.serial_number, "Unknown");
        assert_eq!(u.volume_id, "Unknown");
        assert!((u.capacity_gb - 8.0).abs() < 1e-9);
        assert!((u.used_space_gb - 6.0).abs() < 1e-9);
    }
}
