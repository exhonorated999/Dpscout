/// Forensic system detection and partition mounting for bootable mode

use super::TargetSystem;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct BlockDevice {
    name: String,
    fstype: Option<String>,
    label: Option<String>,
    size: String,
    #[serde(rename = "type")]
    dev_type: String,
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

/// Detect all potential target systems (Windows, Chrome OS)
pub fn detect_target_systems() -> Result<Vec<TargetSystem>, String> {
    let mut targets = Vec::new();
    
    // Get all block devices using lsblk
    let output = Command::new("lsblk")
        .args(&["-J", "-o", "NAME,FSTYPE,LABEL,SIZE,TYPE"])
        .output()
        .map_err(|e| format!("Failed to execute lsblk: {}", e))?;
    
    if !output.status.success() {
        return Err("lsblk command failed".to_string());
    }
    
    let lsblk: LsblkOutput = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse lsblk output: {}", e))?;
    
    // Scan each device
    for device in lsblk.blockdevices {
        // Skip if it's Hindsight's own USB (avoid scanning ourselves)
        if let Some(ref label) = device.label {
            if label == "HINDSIGHT_BOOT" || label == "HINDSIGHT_DATA" {
                continue;
            }
        }
        
        let device_path = format!("/dev/{}", device.name);
        
        // Check for Windows partitions (NTFS)
        if device.fstype.as_deref() == Some("ntfs") {
            if let Ok(target) = detect_windows_partition(&device_path) {
                targets.push(target);
            }
        }
        
        // Chrome OS detection removed - not forensically viable
        // (requires Developer Mode which erases all data)
    }
    
    Ok(targets)
}

/// Detect and mount a Windows partition
fn detect_windows_partition(partition: &str) -> Result<TargetSystem, String> {
    let mount_point = PathBuf::from(format!("/mnt/target_windows_{}", 
        partition.replace("/dev/", "")));
    
    // Create mount point
    fs::create_dir_all(&mount_point)
        .map_err(|e| format!("Failed to create mount point: {}", e))?;
    
    // Mount NTFS read-only
    let mount_point_str = mount_point.to_str().unwrap();
    let status = Command::new("mount")
        .args(&["-t", "ntfs-3g", "-o", "ro,noexec,nosuid", partition, 
                mount_point_str])
        .status()
        .map_err(|e| format!("Failed to mount: {}", e))?;
    
    if !status.success() {
        return Err(format!("Failed to mount partition {}", partition));
    }
    
    // Verify it's actually a Windows partition
    let windows_dir = mount_point.join("Windows");
    if !windows_dir.exists() {
        // Unmount and return error
        Command::new("umount").arg(&mount_point).status().ok();
        return Err("Not a Windows partition".to_string());
    }
    
    // Detect Windows version
    let version = detect_windows_version(&mount_point)
        .unwrap_or_else(|_| "Unknown".to_string());
    
    Ok(TargetSystem::Windows {
        partition: partition.to_string(),
        version,
        mount_point,
    })
}

/// Detect Windows version from mounted partition
fn detect_windows_version(mount_point: &Path) -> Result<String, String> {
    // Try to read version from SOFTWARE registry hive
    let software_hive = mount_point.join("Windows/System32/config/SOFTWARE");
    
    if software_hive.exists() {
        if let Ok(version) = super::registry::get_windows_version_from_hive(&software_hive) {
            return Ok(version);
        }
    }
    
    // Fallback: check for system files
    let system32 = mount_point.join("Windows/System32");
    if !system32.exists() {
        return Ok("Windows (Unknown Version)".to_string());
    }
    
    Ok("Windows".to_string())
}

// Chrome OS detection removed - not forensically viable
// (requires Developer Mode which erases all data)

/// Unmount a target system safely
pub fn unmount_target(target: &TargetSystem) -> Result<(), String> {
    let mount_point = match target {
        TargetSystem::Windows { mount_point, .. } => mount_point,
        TargetSystem::Unknown => return Ok(()),
    };
    
    // Sync filesystems first
    Command::new("sync")
        .status()
        .map_err(|e| format!("Failed to sync: {}", e))?;
    
    // Unmount
    let status = Command::new("umount")
        .arg(mount_point)
        .status()
        .map_err(|e| format!("Failed to unmount: {}", e))?;
    
    if !status.success() {
        return Err(format!("Failed to unmount {:?}", mount_point));
    }
    
    // Remove mount point directory
    fs::remove_dir(mount_point)
        .map_err(|e| format!("Failed to remove mount point: {}", e))?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_systems() {
        // This test would require root and actual partitions
        // For now, just ensure it doesn't crash
        if unsafe { libc::geteuid() } == 0 {
            let result = detect_target_systems();
            assert!(result.is_ok());
        }
    }
}
