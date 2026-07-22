use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;

/// Detect iPhone connected via Windows MTP/PTP (shows in File Explorer)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtpIosDevice {
    pub device_path: String,
    pub device_name: String,
    pub is_accessible: bool,
    pub instructions: String,
}

/// Detect iPhones connected as portable devices in Windows
/// These show up in "This PC" and can be browsed in File Explorer
pub fn detect_mtp_ios_devices() -> Result<Vec<MtpIosDevice>, String> {
    let mut devices = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        eprintln!("[iOS MTP] Checking for iPhone/iPad via Windows portable devices...");
        
        // Try to enumerate portable devices via PowerShell
        // This checks if iPhone appears in the system
        if let Ok(output) = std::process::Command::new("powershell")
            .args(&[
                "-Command",
                "Get-PnpDevice -PresentOnly | Where-Object {($_.Class -eq 'WPD' -or $_.Class -eq 'Image') -and ($_.FriendlyName -like '*iPhone*' -or $_.FriendlyName -like '*iPad*' -or $_.FriendlyName -like '*Apple*')} | Select-Object -ExpandProperty FriendlyName"
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                eprintln!("[iOS MTP] PowerShell output: {}", stdout);
                
                for line in stdout.lines() {
                    let device_name = line.trim();
                    if !device_name.is_empty() {
                        eprintln!("[iOS MTP] ✓ Found iOS device: {}", device_name);
                        
                        let instructions = format!(
                            "iPhone detected in Windows!\n\n\
                            To scan this device:\n\
                            1. Open File Explorer\n\
                            2. Click on '{}' under This PC\n\
                            3. Navigate to Internal Storage → DCIM\n\
                            4. You can now scan media files directly\n\n\
                            Or use the 'Scan as USB Drive' option below.",
                            device_name
                        );
                        
                        let device = MtpIosDevice {
                            device_path: device_name.to_string(),
                            device_name: device_name.to_string(),
                            is_accessible: true,
                            instructions,
                        };
                        devices.push(device);
                    }
                }
            } else {
                eprintln!("[iOS MTP] PowerShell command failed");
            }
        }
        
        // Also check via WMI for Apple Mobile Device USB Driver
        if devices.is_empty() {
            if let Ok(output) = std::process::Command::new("powershell")
                .args(&[
                    "-Command",
                    "Get-WmiObject Win32_PnPEntity | Where-Object {$_.Name -like '*Apple*' -or $_.Name -like '*iPhone*' -or $_.Name -like '*iPad*'} | Select-Object -ExpandProperty Name"
                ])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    eprintln!("[iOS MTP] WMI output: {}", stdout);
                    
                    if stdout.contains("Apple") || stdout.contains("iPhone") || stdout.contains("iPad") {
                        eprintln!("[iOS MTP] ✓ Found Apple device via WMI");
                        
                        let device = MtpIosDevice {
                            device_path: "Apple Mobile Device".to_string(),
                            device_name: "iPhone/iPad (via USB)".to_string(),
                            is_accessible: true,
                            instructions: "iPhone detected! Open File Explorer and navigate to your iPhone under 'This PC' to access media files.".to_string(),
                        };
                        devices.push(device);
                    }
                }
            }
        }
    }
    
    if devices.is_empty() {
        eprintln!("[iOS MTP] ✗ No iOS devices found");
        return Err("No iPhone or iPad detected via USB.\n\nPlease ensure:\n1. Device is connected via USB cable\n2. Device is unlocked\n3. 'Trust This Computer' is tapped on the device\n4. Device appears in File Explorer under 'This PC'".to_string());
    }
    
    eprintln!("[iOS MTP] Found {} iOS device(s)", devices.len());
    Ok(devices)
}

/// Get media files from iPhone via MTP (File Explorer accessible DCIM folder)
/// Copies files from iPhone to temp directory for scanning
pub fn scan_iphone_media_via_mtp(device_name: &str) -> Result<Vec<IosMediaFile>, String> {
    let mut media_files = Vec::new();
    #[allow(unused_mut, unused_assignments)]
    let mut mtp_diag = String::from("Diagnostic unavailable (MTP walk did not report status).");
    
    #[cfg(target_os = "windows")]
    {
        eprintln!("[iOS MTP] Scanning iPhone media files via MTP...");
        
        // Create temp directory for iPhone media
        let temp_dir = std::env::temp_dir().join("hindsight_ios_mtp");
        let _ = fs::remove_dir_all(&temp_dir); // Clean up any previous files
        let _ = fs::create_dir_all(&temp_dir);
        
        eprintln!("[iOS MTP] Temp directory: {:?}", temp_dir);
        
        // PowerShell script to copy media from iPhone DCIM to temp folder
        let ps_script = format!(
            r#"
$tempDir = "{}"
Write-Host "Temp directory: $tempDir"

$shell = New-Object -ComObject Shell.Application
$computer = $shell.Namespace(17)

$found = $false
$foundStorage = $false
$foundDcim = $false
$totalCopied = 0

# CopyHere on MTP devices is ASYNCHRONOUS — it queues the copy and returns
# immediately. Without waiting, the temp dir is listed before copies finish,
# producing an empty/partial result. This helper blocks until the destination
# file exists and its size stops changing (copy finished), or a timeout hits.
function Wait-ForCopy($destFolder, $fileName, $timeoutSec) {{
    $target = Join-Path $destFolder $fileName
    $elapsedMs = 0
    $lastSize = -1
    $stableCount = 0
    while ($elapsedMs -lt ($timeoutSec * 1000)) {{
        if (Test-Path -LiteralPath $target) {{
            $size = (Get-Item -LiteralPath $target -ErrorAction SilentlyContinue).Length
            if ($size -ne $null -and $size -gt 0 -and $size -eq $lastSize) {{
                $stableCount++
                if ($stableCount -ge 2) {{ return $true }}
            }} else {{
                $stableCount = 0
            }}
            $lastSize = $size
        }}
        Start-Sleep -Milliseconds 150
        $elapsedMs += 150
    }}
    return (Test-Path -LiteralPath $target)
}}

# Helper function to copy media files from a Shell folder
# NOTE: MTP devices often strip file extensions from Shell.Application Name property,
# so we copy ALL non-folder files (iPhone Internal Storage only contains media anyway).
# We use GetDetailsOf column 1 (Type) to identify file types when extension is missing.
function Copy-MediaFromFolder($shellFolder, $destBase) {{
    $copied = 0
    foreach ($item in $shellFolder.Items()) {{
        if ($item.IsFolder) {{
            # Recurse into subfolders (e.g. DCIM/100APPLE or 202405_a)
            $subName = $item.Name
            Write-Host "Processing folder: $subName"
            $subDest = Join-Path $destBase $subName
            New-Item -ItemType Directory -Force -Path $subDest | Out-Null
            $subFolder = $item.GetFolder()
            $subCopied = 0
            foreach ($file in $subFolder.Items()) {{
                if (-not $file.IsFolder) {{
                    $fileName = $file.Name
                    # Get file type from Shell details (column 1 = Type on MTP)
                    $fileType = $subFolder.GetDetailsOf($file, 1)
                    # Accept known media types, or copy everything if type info is available
                    $isMedia = ($fileType -match '(JPG|JPEG|PNG|HEIC|HEIF|MOV|MP4|M4V|AVI|GIF|TIFF?|BMP|WEBP|3GP|AAE)\s+File')
                    # Also accept by extension if present
                    $ext = [System.IO.Path]::GetExtension($fileName).ToLower()
                    $hasMediaExt = ($ext -match '^\.(jpg|jpeg|png|heic|heif|mp4|mov|m4v|avi|aae|gif|tif|tiff|bmp|webp|3gp)$')
                    # If no type info and no extension, copy it anyway (likely media on iPhone)
                    $noInfo = ([string]::IsNullOrEmpty($fileType) -and [string]::IsNullOrEmpty($ext))
                    
                    if ($isMedia -or $hasMediaExt -or $noInfo) {{
                        try {{
                            $shell.Namespace($subDest).CopyHere($file, 0x14)
                            if (Wait-ForCopy $subDest $fileName 30) {{
                                $subCopied++
                                $script:totalCopied++
                                if ($subCopied % 50 -eq 0) {{
                                    Write-Host "  Copied $subCopied files from $subName ($($script:totalCopied) total)..."
                                }}
                            }} else {{
                                Write-Host "  Timed out copying $fileName"
                            }}
                        }} catch {{
                            Write-Host "Error copying $fileName : $_"
                        }}
                    }}
                }}
            }}
            Write-Host "  Copied $subCopied files from $subName"
        }} else {{
            # Direct file in the folder — copy all non-folder items
            $fileName = $item.Name
            try {{
                $shell.Namespace($destBase).CopyHere($item, 0x14)
                if (Wait-ForCopy $destBase $fileName 30) {{
                    $copied++
                    $script:totalCopied++
                }} else {{
                    Write-Host "Timed out copying $fileName"
                }}
            }} catch {{
                Write-Host "Error copying $fileName : $_"
            }}
        }}
    }}
    return $copied
}}

foreach ($item in $computer.Items()) {{
    if ($item.Name -like '*iPhone*' -or $item.Name -like '*iPad*' -or $item.Name -like '*Apple*') {{
        Write-Host "Found device: $($item.Name)"
        $found = $true
        $device = $item.GetFolder()
        
        foreach ($storage in $device.Items()) {{
            if ($storage.Name -eq 'Internal Storage') {{
                Write-Host "Found Internal Storage"
                $script:foundStorage = $true
                $storageFolder = $storage.GetFolder()
                
                # Check if DCIM folder exists
                $dcimFound = $false
                foreach ($folder in $storageFolder.Items()) {{
                    if ($folder.Name -eq 'DCIM') {{
                        Write-Host "Found DCIM folder — scanning subfolders"
                        $dcimFound = $true
                        $script:foundDcim = $true
                        $dcimFolder = $folder.GetFolder()
                        Copy-MediaFromFolder $dcimFolder $tempDir
                        break
                    }}
                }}
                
                # No DCIM? Scan all subfolders under Internal Storage directly
                if (-not $dcimFound) {{
                    Write-Host "No DCIM folder found — scanning Internal Storage subfolders directly"
                    Copy-MediaFromFolder $storageFolder $tempDir
                }}
            }}
        }}
    }}
}}

Write-Host "Total files copied: $totalCopied"
Write-Host ("DIAG|found=" + $found + "|storage=" + $foundStorage + "|dcim=" + $foundDcim + "|copied=" + $totalCopied)

if (-not $found) {{
    Write-Error "No iPhone/iPad found in This PC"
    exit 1
}}

# List all copied files
Get-ChildItem -Path $tempDir -Recurse -File | ForEach-Object {{
    Write-Output $_.FullName
}}
"#,
            temp_dir.display().to_string().replace("\\", "\\\\")
        );
        
        eprintln!("[iOS MTP] Executing PowerShell script to copy media files...");
        
        match std::process::Command::new("powershell")
            .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                eprintln!("[iOS MTP] PowerShell output:\n{}", stdout);
                if !stderr.is_empty() {
                    eprintln!("[iOS MTP] PowerShell errors:\n{}", stderr);
                }

                // Parse the DIAG marker line for an actionable failure message.
                if let Some(diag_line) = stdout.lines().find(|l| l.trim_start().starts_with("DIAG|")) {
                    let get = |key: &str| -> String {
                        diag_line
                            .split('|')
                            .find_map(|kv| kv.strip_prefix(key).map(|v| v.to_string()))
                            .unwrap_or_else(|| "?".to_string())
                    };
                    let found = get("found=");
                    let storage = get("storage=");
                    let dcim = get("dcim=");
                    let copied = get("copied=");
                    mtp_diag = if found != "True" {
                        "iPhone was not detected under 'This PC'. Reconnect the cable and unlock the device.".to_string()
                    } else if storage != "True" {
                        "iPhone was detected but its 'Internal Storage' is not accessible yet — unlock the phone and tap 'Trust This Computer', then wait a few seconds and retry.".to_string()
                    } else if copied == "0" {
                        if dcim == "True" {
                            "iPhone storage opened but no photos/videos could be copied. If photos are stored in iCloud (Optimize Storage), they are not on the device. Otherwise unlock the phone and retry.".to_string()
                        } else {
                            "iPhone storage opened but no DCIM/media folder was found. If photos are stored in iCloud (Optimize Storage), they are not on the device.".to_string()
                        }
                    } else {
                        format!("MTP copied {} file(s) but none were readable for scanning.", copied)
                    };
                }
                
                // Check if PowerShell script succeeded
                if !output.status.success() {
                    return Err("iPhone not found in File Explorer. Ensure device is unlocked and appears under 'This PC'.".to_string());
                }
                
                // Scan the temp directory for copied files
                for line in stdout.lines() {
                    let path_str = line.trim();
                    let path = Path::new(path_str);
                    
                    if path.exists() && path.is_file() {
                        if let Ok(metadata) = fs::metadata(path) {
                            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                                let ext = path.extension()
                                    .and_then(|e| e.to_str())
                                    .unwrap_or("")
                                    .to_lowercase();
                                
                                let file_type = match ext.as_str() {
                                    "mp4" | "mov" | "m4v" | "avi" => "video",
                                    _ => "image",
                                };
                                
                                media_files.push(IosMediaFile {
                                    file_name: file_name.to_string(),
                                    file_path: path_str.to_string(),
                                    file_size: metadata.len(),
                                    file_type: file_type.to_string(),
                                });
                            }
                        }
                    }
                }
                
                eprintln!("[iOS MTP] Successfully copied {} media files", media_files.len());
            }
            Err(e) => {
                eprintln!("[iOS MTP] PowerShell command failed: {}", e);
                return Err(format!("Failed to execute PowerShell: {}", e));
            }
        }
    }
    
    if media_files.is_empty() {
        return Err(format!(
            "Unable to access iOS media files.\n\n{}\n\nEnsure:\n1. Device is unlocked and appears in File Explorer under 'This PC'\n2. Tap 'Trust This Computer' if prompted\n3. Media files (photos/videos) exist on the device",
            mtp_diag
        ));
    }
    
    Ok(media_files)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IosMediaFile {
    pub file_name: String,
    pub file_path: String,
    pub file_size: u64,
    pub file_type: String, // "image" or "video"
}

/// Result of an MTP live scan — includes temp directory path for downstream scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtpScanResult {
    pub media_files: Vec<IosMediaFile>,
    pub temp_directory: String,
    pub total_files: usize,
    pub total_size_bytes: u64,
}

/// Scan iPhone media via MTP and return result with temp directory path
pub fn scan_iphone_media_mtp_full(device_name: &str) -> Result<MtpScanResult, String> {
    let temp_dir = std::env::temp_dir().join("hindsight_ios_mtp");
    let media_files = scan_iphone_media_via_mtp(device_name)?;
    let total_size: u64 = media_files.iter().map(|f| f.file_size).sum();
    let total_files = media_files.len();
    
    Ok(MtpScanResult {
        media_files,
        temp_directory: temp_dir.to_string_lossy().to_string(),
        total_files,
        total_size_bytes: total_size,
    })
}

/// Alternative: Provide instructions to copy files manually
pub fn get_manual_copy_instructions() -> String {
    r#"
To scan iPhone media files:

1. Open File Explorer
2. Navigate to 'This PC' → Your iPhone
3. Go to Internal Storage → DCIM
4. Copy the photo/video folders to a local folder
5. Use the 'USB Drive' scan mode to scan that folder

This provides full forensic access to all media files.
    "#.to_string()
}
