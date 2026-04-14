use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::env;

/// iOS device information from Python script
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PythonIosDevice {
    pub udid: String,
    pub device_name: String,
    pub device_model: String,
    pub product_type: String,
    pub ios_version: String,
    pub build_version: String,
    pub serial_number: String,
    pub imei: String,
    pub phone_number: String,
    pub wifi_address: String,
    pub bluetooth_address: String,
    pub hardware_model: String,
    pub device_color: String,
    pub device_class: String,
    pub connection_type: String,
    pub is_trusted: bool,
    pub battery_level: String,
    pub total_capacity: String,
    pub available_capacity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Backup progress update from Python script
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BackupProgress {
    #[serde(default)]
    pub status: String,  // "connecting", "connected", "starting", "backing_up", "complete", "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_completed: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_total: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ios_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Get path to Python scripts directory
fn get_scripts_dir() -> PathBuf {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    eprintln!("[iOS Python] Executable directory: {:?}", exe_dir);
    
    // Development: exe is at src-tauri/target/debug/ (or release/)
    // Workspace root is three levels up: src-tauri/target/debug -> src-tauri -> workspace
    // Scripts live at workspace_root/scripts/
    let candidates = [
        // Dev: target/debug/../../.. -> workspace root
        exe_dir.join("..").join("..").join("..").join("scripts"),
        // Dev: target/debug/../.. -> src-tauri (in case scripts were copied here)
        exe_dir.join("..").join("..").join("scripts"),
        // Production: scripts bundled next to executable
        exe_dir.join("scripts"),
        // Fallback: current working directory
        PathBuf::from("scripts"),
    ];
    
    for candidate in &candidates {
        if candidate.exists() {
            let resolved = candidate.canonicalize().unwrap_or_else(|_| candidate.clone());
            eprintln!("[iOS Python] Found scripts at: {:?}", resolved);
            return resolved;
        }
        eprintln!("[iOS Python] Not found: {:?}", candidate);
    }
    
    // Last resort — return prod path so the error message is useful
    let fallback = exe_dir.join("scripts");
    eprintln!("[iOS Python] WARNING: No scripts directory found, using: {:?}", fallback);
    fallback
}

/// Find Python executable
fn get_python_cmd() -> String {
    // On Windows, 'python' might be an app execution alias that opens Microsoft Store
    // We need to actually test if Python can execute code
    // Priority: py (Windows launcher) > python3 > python
    let python_commands = if cfg!(target_os = "windows") {
        vec!["py", "python3", "python"]
    } else {
        vec!["python3", "python", "py"]
    };
    
    for cmd in python_commands {
        eprintln!("[iOS Python] Testing Python command: {}", cmd);
        
        // Test by running a simple Python command
        match Command::new(cmd)
            .arg("-c")
            .arg("print('OK')")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.trim() == "OK" {
                        eprintln!("[iOS Python] ✓ Using Python command: {}", cmd);
                        return cmd.to_string();
                    } else {
                        eprintln!("[iOS Python] ✗ Command '{}' succeeded but output incorrect: {}", cmd, stdout.trim());
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("[iOS Python] ✗ Command '{}' failed with status: {}, stderr: {}", cmd, output.status, stderr.trim());
                }
            }
            Err(e) => {
                eprintln!("[iOS Python] ✗ Failed to execute '{}': {}", cmd, e);
            }
        }
    }
    
    eprintln!("[iOS Python] ⚠ No working Python found, defaulting to 'py' (will likely fail)");
    "py".to_string() // Default to Windows launcher as last resort
}

/// Detect connected iOS devices using Python script
pub fn detect_ios_devices_python() -> Result<Vec<PythonIosDevice>, String> {
    eprintln!("[iOS Python] Detecting iOS devices...");
    
    let scripts_dir = get_scripts_dir();
    let script_path = scripts_dir.join("ios_device_info.py");
    
    if !script_path.exists() {
        return Err(format!(
            "iOS device info script not found at: {:?}\n\
            Please ensure scripts/ios_device_info.py exists.\n\
            Run scripts/setup_ios_environment.ps1 to set up iOS support.",
            script_path
        ));
    }
    
    let python_cmd = get_python_cmd();
    
    let output = Command::new(&python_cmd)
        .arg(script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute Python script: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Python script failed: {}", stderr));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("[iOS Python] Script output: {}", stdout);
    
    // Parse JSON output
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse JSON output: {}", e))?;
    
    let devices: Vec<PythonIosDevice> = serde_json::from_value(result["devices"].clone())
        .map_err(|e| format!("Failed to parse devices array: {}", e))?;
    
    eprintln!("[iOS Python] Found {} device(s)", devices.len());
    
    Ok(devices)
}

/// Get detailed info for a specific iOS device
pub fn get_ios_device_info_python(udid: &str) -> Result<PythonIosDevice, String> {
    eprintln!("[iOS Python] Getting device info for UDID: {}", udid);
    
    let scripts_dir = get_scripts_dir();
    let script_path = scripts_dir.join("ios_device_info.py");
    
    if !script_path.exists() {
        return Err(format!("iOS device info script not found at: {:?}", script_path));
    }
    
    let python_cmd = get_python_cmd();
    
    let output = Command::new(&python_cmd)
        .arg(script_path)
        .arg(udid)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute Python script: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Python script failed: {}", stderr));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let device_info: PythonIosDevice = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse JSON output: {}", e))?;
    
    Ok(device_info)
}

/// Start iOS backup with progress tracking (Arsenic method)
/// 
/// Returns a channel that emits progress updates
pub fn start_ios_backup_python(
    udid: &str,
    output_dir: Option<&str>,
    password: &str,
    progress_callback: Option<Box<dyn Fn(BackupProgress) + Send>>
) -> Result<BackupProgress, String> {
    eprintln!("[iOS Python] Starting backup for device: {}", udid);
    
    let scripts_dir = get_scripts_dir();
    // Use Arsenic-style backup script (known to work)
    let script_path = scripts_dir.join("ios_backup_arsenic.py");
    
    if !script_path.exists() {
        return Err(format!(
            "iOS backup script not found at: {:?}\n\
            Please ensure scripts/ios_backup_arsenic.py exists.",
            script_path
        ));
    }
    
    let python_cmd = get_python_cmd();
    
    // Build command arguments
    let mut cmd = Command::new(&python_cmd);
    cmd.arg(&script_path).arg(udid);
    
    // Python script expects: <udid> [output_dir] [password]
    // When output_dir is None, we must still pass a placeholder so password
    // doesn't land in the output_dir position.
    match output_dir {
        Some(dir) => { cmd.arg(dir); }
        None => { cmd.arg(""); }  // Empty string = use default directory in Python
    }
    
    cmd.arg(password);
    
    // Spawn process with piped output for progress tracking
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped());
    
    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to start backup process: {}", e))?;
    
    // Read stdout line by line for progress updates
    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    
    let mut final_result: Option<BackupProgress> = None;
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Error reading output: {}", e))?;
        
        eprintln!("[iOS Backup] {}", line);
        
        // Parse JSON progress update
        if let Ok(progress) = serde_json::from_str::<BackupProgress>(&line) {
            // Call progress callback if provided
            if let Some(ref callback) = progress_callback {
                callback(progress.clone());
            }
            
            // Store final result
            if progress.status == "complete" || progress.status == "error" {
                final_result = Some(progress.clone());
            }
        }
    }
    
    // Read any remaining stderr for diagnostics
    let stderr_output = if let Some(mut stderr) = child.stderr.take() {
        let mut buf = String::new();
        use std::io::Read;
        stderr.read_to_string(&mut buf).ok();
        buf
    } else {
        String::new()
    };
    
    if !stderr_output.is_empty() {
        eprintln!("[iOS Backup] stderr: {}", stderr_output);
        
        // Try to parse error JSON from stderr (Python script writes errors there)
        if let Ok(err_progress) = serde_json::from_str::<BackupProgress>(&stderr_output) {
            if err_progress.status == "error" {
                return Err(err_progress.message.unwrap_or_else(|| "Backup failed".to_string()));
            }
        }
    }
    
    // Wait for process to complete
    let status = child.wait()
        .map_err(|e| format!("Failed to wait for backup process: {}", e))?;
    
    if !status.success() && final_result.is_none() {
        return Err(format!(
            "Backup process exited with code {}. {}",
            status.code().unwrap_or(-1),
            if stderr_output.is_empty() { "No error details available.".to_string() } else { stderr_output }
        ));
    }
    
    // Check if the final result was an error
    if let Some(ref result) = final_result {
        if result.status == "error" {
            return Err(result.message.clone().unwrap_or_else(|| "Backup failed".to_string()));
        }
    }
    
    final_result.ok_or_else(|| "Backup completed but no final status received".to_string())
}

/// Decrypt an encrypted iOS backup using iphone_backup_decrypt.
/// Returns the path to the decrypted backup directory.
pub fn decrypt_ios_backup(
    backup_path: &str,
    password: &str,
    output_dir: Option<&str>,
) -> Result<BackupProgress, String> {
    eprintln!("[iOS Python] Decrypting backup at: {}", backup_path);
    
    let scripts_dir = get_scripts_dir();
    let script_path = scripts_dir.join("ios_decrypt_backup.py");
    
    if !script_path.exists() {
        return Err(format!(
            "iOS decrypt script not found at: {:?}",
            script_path
        ));
    }
    
    let python_cmd = get_python_cmd();
    
    let mut cmd = Command::new(&python_cmd);
    cmd.arg(&script_path).arg(backup_path).arg(password);
    
    if let Some(dir) = output_dir {
        cmd.arg(dir);
    }
    
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    
    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to start decryption process: {}", e))?;
    
    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    
    let mut final_result: Option<BackupProgress> = None;
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Error reading decrypt output: {}", e))?;
        eprintln!("[iOS Decrypt] {}", line);
        
        // Try to parse as JSON with decryptedPath field
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            // Check for error
            if val.get("status").and_then(|s| s.as_str()) == Some("error") {
                let error_code = val.get("error").and_then(|e| e.as_str()).unwrap_or("unknown");
                let message = val.get("message").and_then(|m| m.as_str()).unwrap_or("Decryption failed");
                
                if error_code == "incorrect_password" {
                    return Err(format!("WRONG_PASSWORD: {}", message));
                }
                return Err(message.to_string());
            }
            
            // Check for completion with decrypted path
            if val.get("status").and_then(|s| s.as_str()) == Some("complete") {
                let decrypted_path = val.get("decryptedPath")
                    .and_then(|p| p.as_str())
                    .unwrap_or(backup_path)
                    .to_string();
                    
                final_result = Some(BackupProgress {
                    status: "complete".to_string(),
                    success: Some(true),
                    backup_path: Some(decrypted_path),
                    message: val.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()),
                    ..Default::default()
                });
            }
        }
    }
    
    let status = child.wait()
        .map_err(|e| format!("Failed to wait for decryption process: {}", e))?;
    
    if !status.success() && final_result.is_none() {
        return Err("Decryption process failed".to_string());
    }
    
    final_result.ok_or_else(|| "Decryption completed but no result received".to_string())
}

/// Check if Python iOS tools are installed
pub fn check_ios_python_available() -> Result<bool, String> {
    let python_cmd = get_python_cmd();
    
    // Try to import pymobiledevice3 and verify the version
    let output = Command::new(&python_cmd)
        .arg("-c")
        .arg("import pymobiledevice3; print(pymobiledevice3.__version__)")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to check Python packages: {}", e))?;
    
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() && !stdout.contains("Error") {
            eprintln!("[iOS Python] pymobiledevice3 v{} is installed", stdout);
            return Ok(true);
        }
    }
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("[iOS Python] pymobiledevice3 not available. stderr: {}", stderr.trim());
    eprintln!("[iOS Python] Install with: scripts\\setup_ios_environment.ps1");
    
    Ok(false)
}

/// Check if Python scripts directory exists and contains expected files
pub fn check_ios_scripts_available() -> Result<bool, String> {
    let scripts_dir = get_scripts_dir();
    let device_script = scripts_dir.join("ios_device_info.py");
    let backup_script = scripts_dir.join("ios_backup_arsenic.py");
    
    let device_ok = device_script.exists();
    let backup_ok = backup_script.exists();
    
    eprintln!("[iOS Python] Scripts directory: {:?}", scripts_dir);
    eprintln!("[iOS Python]   ios_device_info.py: {}", if device_ok { "found" } else { "MISSING" });
    eprintln!("[iOS Python]   ios_backup_arsenic.py: {}", if backup_ok { "found" } else { "MISSING" });
    
    Ok(device_ok && backup_ok)
}
