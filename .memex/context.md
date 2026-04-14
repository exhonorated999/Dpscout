# Hindsight Project Rules

## Project Overview

Hindsight is a forensic analysis tool built with Tauri (Rust + React) that operates in two modes:
1. **Windows Live Mode**: Native Windows application for live system scanning
2. **Windows PE Forensic Mode**: Bootable USB with Windows PE for offline forensic analysis

Both modes share the same codebase and data partition for seamless workflow.

**Note**: Chrome OS bootable mode was removed because it requires Developer Mode which erases all user data (not forensically sound). Chrome OS devices can still be scanned when accessible as USB storage.

---

## Architecture Principles

### Platform Abstraction

**Pattern**: All platform-specific code must be isolated in the `platform` module with trait-based abstractions.

**Structure**:
```
src-tauri/src/platform/
├── mod.rs              - Trait definitions and common types
├── windows.rs          - Windows live scanning (WMI, registry APIs)
├── linux.rs            - Linux forensic scanning (offline parsing)
├── forensics.rs        - Target detection and mounting
├── registry.rs         - Offline Windows registry parsing
├── browser_parser.rs   - SQLite browser database parsing
├── extension_parser.rs - Chrome extension analysis
├── apk_parser.rs       - Android APK parsing
├── forensic_scan.rs    - Scan orchestration
├── forensic_report.rs  - Report generation
└── paths.rs            - Unified data partition access
```

**Key Trait**:
```rust
pub trait PlatformScanner {
    fn get_installed_apps(&self) -> Result<Vec<AppInfo>, String>;
    fn get_system_info(&self) -> Result<SystemInfo, String>;
    fn get_browser_history(&self) -> Result<Vec<BrowserHistoryEntry>, String>;
    fn get_user_accounts(&self) -> Result<Vec<String>, String>;
}
```

### Conditional Compilation

**Pattern**: Use feature flags and target OS checks consistently.

```rust
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

// Always provide stubs for Tauri commands
#[cfg(target_os = "linux")]
#[tauri::command]
fn forensic_command() -> Result<T, String> { /* implementation */ }

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn forensic_command() -> Result<T, String> {
    Err("Feature only available in forensic mode".to_string())
}
```

---

## Forensic Mode Conventions

### Read-Only Mounting

**Rule**: All target filesystem mounts MUST be read-only with security flags.

```rust
mount -o ro,noexec,nosuid /dev/sdX /mnt/target
```

**Never**:
- Write to target filesystems
- Execute binaries from target
- Allow setuid on target

### Data Partition Structure

**Location**:
- Windows: Auto-detected USB drive letter (H:\, G:\, F:\, etc.)
- Linux: `/mnt/hindsight_data`

**Structure**:
```
HINDSIGHT_DATA/
├── cases/              - All forensic reports (shared)
├── keyword_lists/      - Search term databases (shared)
├── hash_lists/         - CSAM/Project VIC hashes (shared)
├── external/           - Tools (ffmpeg, libimobiledevice)
├── hindsight_secure.db - Security/settings database
└── HindsightSetup.exe  - Windows native installer
```

### Logging for Chain of Custody

**Pattern**: Log all forensic operations with timestamps.

```rust
log!("[{}] Mounting partition: {}", 
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    partition
);
```

**Log Locations**:
- System operations: `journalctl -xe`
- Mount operations: `/var/log/hindsight-mount.log`
- Application errors: stderr/journal

---

## Android Device Scanning

### Overview

Android devices can be scanned when connected via USB with ADB (Android Debug Bridge). The application supports:
- Application inventory
- **Browser history extraction** (Chrome)
- SMS message extraction
- Media file scanning
- **CSAM Hash Scanning**

### Android Browser History Implementation

**Purpose**: Extract Chrome browsing history from Android devices using the same UI as Windows scanning.

**Location**: `src-tauri/src/scanner/android.rs`

**Key Functions**:
```rust
pub fn get_chrome_history(
    app_handle: &tauri::AppHandle,
    serial: &str
) -> Result<AndroidBrowserData, String>

pub fn scan_android_browsers(
    app_handle: &tauri::AppHandle,
    serial: &str
) -> Result<Vec<serde_json::Value>, String>
```

**Access Methods** (in order of attempt):
1. **Direct ADB pull**: `adb pull /data/data/com.android.chrome/app_chrome/Default/History`
2. **Run-as method**: `adb shell run-as com.android.chrome cat app_chrome/Default/History > /sdcard/temp.db`
3. Clear error message if both fail

**Data Conversion**:
- Android `AndroidBrowserData` format → Windows `BrowserData` format
- Chrome timestamps (microseconds since 1601) → UTC datetime strings
- History entries map to Windows history structure
- Compatible with unified dashboard display

**Database Location**: `/data/data/com.android.chrome/app_chrome/Default/History`

**SQL Query**:
```sql
SELECT url, title, visit_count, last_visit_time, typed_count 
FROM urls 
ORDER BY last_visit_time DESC 
LIMIT 1000
```

**Timestamp Conversion**:
```rust
fn convert_chrome_timestamp(timestamp: i64) -> String {
    const EPOCH_DIFF: i64 = 11644473600; // Seconds between 1601 and 1970
    let unix_seconds = (timestamp / 1_000_000) - EPOCH_DIFF;
    // Convert to "YYYY-MM-DD HH:MM:SS UTC" format
}
```

**UI Integration**:
- Enabled in ScanConfig for Android (`browserHistory: true`)
- Integrated into Android scan workflow in App.tsx
- Displays in unified dashboard Browser History tab
- Same UI as Windows browser scanning
- Shows as "Chrome (Android)" in browser selector

### Android Device Information

**Storage Formatting**: Always display storage in human-readable format

**Pattern**:
```rust
// Try dumpsys diskstats first (returns MB values)
if let Ok(output) = adb_shell("dumpsys diskstats") {
    let used_mb = parse_mb_value(output);
    let used_gb = used_mb / 1024.0;
    format!("{:.1} GB", used_gb)  // "52.1 GB"
}

// Fallback to df command (returns KB values)
if let Ok(output) = adb_shell("df /data") {
    let used_kb = parse_kb_value(output);
    let used_gb = used_kb / 1024.0 / 1024.0;
    format!("{:.1} GB", used_gb)  // "52.1 GB"
}
```

**Display Format**:
- Always include unit (GB)
- One decimal place precision
- Handle missing data gracefully

**Device Info Fields**:
- Device Model
- Manufacturer
- Android Version
- SDK Version
- **Storage Used** (formatted as GB, NOT device codename)
- Serial Number
- Build ID

### Android Hash Scanning Implementation

**Purpose**: Scan media files on Android devices for known CSAM hashes without full forensic imaging.

**Location**: `src-tauri/src/scanner/android.rs`

**Key Functions**:
```rust
pub fn scan_android_media_hashes(
    app_handle: &tauri::AppHandle,
    serial: &str,
    progress_callback: Option<Box<dyn Fn(AndroidHashScanProgress) + Send>>
) -> Result<Vec<AndroidHashMatch>, String>
```

**Process**:
1. Get list of media files from device
2. Verify hash database has hashes loaded
3. Create temporary directory for pulled files
4. For each media file:
   - Pull file from device via ADB
   - Compute MD5 and SHA256 hashes
   - Check against hash database
   - **Immediately delete pulled file** (no persistence)
   - Record matches
5. Clean up temporary directory
6. Return match results

**Data Structures**:
```rust
pub struct AndroidHashMatch {
    pub file_path: String,        // Path on Android device
    pub file_name: String,
    pub file_size: u64,
    pub md5_hash: String,
    pub sha256_hash: String,
    pub matched_hash: String,     // The hash that matched
    pub hash_type: String,        // "MD5" or "SHA256"
    pub list_name: String,        // Hash list source
    pub list_source: String,
    pub description: Option<String>,
    pub severity: String,         // Always "Critical"
}
```

**Safety Features**:
- Read-only access to device
- Files pulled temporarily and deleted immediately after hashing
- Never writes to device
- 500MB file size limit to prevent memory issues
- Graceful error handling

**UI Integration**:
- Enabled in ScanConfig (`hashMatching: true`)
- Red "Hash Scan (CSAM)" button in Android device actions (standalone)
- Integrated into main scan workflow
- Displays in CSAM Hash Hits tab in unified dashboard
- Critical styling (red theme) for severity
- Success state (green) when no matches found
- Detailed match cards with expandable hash details

**Scan Workflow Integration**:
```typescript
if (modules.hashMatching) {
  const matches = await invoke("scan_android_media_hashes", { serial });
  setHashMatches(matches);
  // Update media files with flags if media was scanned
  // Display in unified dashboard
}
```

**Two Access Methods**:
1. **Integrated Scan**: Part of main scan workflow via ScanConfig
2. **Standalone Scan**: Red button in AndroidView for quick checks

### Multi-Platform Unified Dashboard

**Pattern**: The unified dashboard must support both Windows and Android with the same UI.

**Platform Detection**:
```typescript
// In UnifiedDashboard component
if (deviceType === 'android') {
  // Show Android-specific device info
  // Use androidInfo.storageUsed, etc.
}
```

**Tab Visibility Logic**:
```typescript
// Browser History - both Windows and Android
if ((deviceType === 'windows' || deviceType === 'android') && scannedModules.browserHistory) {
  items.push({ id: 'browser-history', ... });
}

// Hash Matching - all platforms that support it
if (scannedModules.hashMatching) {
  const hashCount = hashMatches.length > 0 
    ? hashMatches.length 
    : media.filter(m => m.flags?.some(f => f.flagType === 'HashMatch')).length;
  items.push({ id: 'csam-hash', count: hashCount, ... });
}
```

**Data Format Compatibility**:
- Android browser data converted to Windows BrowserData format
- Android hash matches can display alongside media file flags
- Consistent field naming across platforms (camelCase)

---

## Parsing Conventions

### Offline Registry Parsing

**Library**: `nt-hive2` crate for Windows registry hives

**Pattern**:
```rust
// Read entire hive into memory
let mut buffer = Vec::new();
file.read_to_end(&mut buffer)?;

// Parse with nt-hive2
let hive = nt_hive2::Hive::new(&buffer)?;

// Navigate to keys
let key = hive.root_key_node()?
    .subpath("Microsoft\\Windows\\CurrentVersion")?;

// Extract values
let value = key.value("ProductName")?;
```

**Graceful Fallback**: If registry parsing fails, fall back to directory scanning.

### SQLite Browser Parsing

**Library**: `rusqlite` with read-only flags

**Pattern**:
```rust
let conn = Connection::open_with_flags(
    db_path,
    OpenFlags::SQLITE_OPEN_READ_ONLY
)?;

let mut stmt = conn.prepare(
    "SELECT url, title, visit_count, last_visit_time FROM urls"
)?;
```

**Timestamp Conversion**:
- Chrome: Windows FILETIME (microseconds since 1601-01-01)
- Firefox: Microseconds since 1970-01-01

```rust
const EPOCH_DIFF: i64 = 11644473600; // Seconds between 1601 and 1970
let unix_seconds = (chrome_time / 1_000_000) - EPOCH_DIFF;
```

### Hash Computing

**Libraries**: `sha2`, `md5` crates

**Pattern for Files**:
```rust
use sha2::{Sha256, Digest};
use md5::Md5;
use std::io::Read;

fn compute_file_hashes(path: &Path) -> Result<(String, String), String> {
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    let mut md5_hasher = Md5::new();
    let mut sha256_hasher = Sha256::new();
    
    md5_hasher.update(&buffer);
    sha256_hasher.update(&buffer);
    
    let md5_hash = format!("{:x}", md5_hasher.finalize());
    let sha256_hash = format!("{:x}", sha256_hasher.finalize());
    
    Ok((md5_hash, sha256_hash))
}
```

**Hash Database Integration**:
```rust
use crate::hash_db::HashDatabase;

let hash_db = HashDatabase::new()?;

// Check hash
if let Ok(Some(match_data)) = hash_db.check_hash(&sha256, "SHA256") {
    // Handle match
    eprintln!("Hash match found: {:?}", match_data);
}
```

### Extension/APK Manifest Parsing

**Format**: JSON manifests

**Risk Categorization**:
```rust
pub fn categorize_risk(permissions: &[String]) -> RiskLevel {
    let dangerous = ["<all_urls>", "webRequest", "proxy", "debugger"];
    let dangerous_count = permissions.iter()
        .filter(|p| dangerous.iter().any(|d| p.contains(d)))
        .count();
    
    if dangerous_count >= 2 { RiskLevel::High }
    else if dangerous_count >= 1 { RiskLevel::Medium }
    else { RiskLevel::Low }
}
```

---

## Integration Patterns

### Scan Orchestration

**Pattern**: Centralized coordinator with configurable options.

```rust
pub struct ForensicScanConfig {
    pub target: TargetSystem,
    pub scan_apps: bool,
    pub scan_browser: bool,
    pub scan_media: bool,
    pub scan_keywords: bool,
    pub check_hashes: bool,
    pub generate_thumbnails: bool,
}

pub fn perform_forensic_scan(config: ForensicScanConfig) 
    -> Result<ForensicScanResults, String>
```

**Error Handling**: If one scan component fails, continue with others.

```rust
if config.scan_media {
    match scan_forensic_media(...) {
        Ok(files) => media_files = files,
        Err(e) => {
            eprintln!("Media scan failed: {}", e);
            media_files = Vec::new(); // Continue
        }
    }
}
```

### Report Generation

**Pattern**: Convert scan results to standard report payload.

```rust
pub fn create_forensic_report_payload(
    results: ForensicScanResults,
    case_number: String,
    detective: String,
    // ...
) -> ReportPayload
```

**Forensic Indicators**: Always include scan mode metadata.

```json
{
    "forensicMode": true,
    "scanMode": "Read-Only Forensic",
    "targetType": "Windows",
    "partition": "/dev/sda2",
    "mountPoint": "/mnt/target_windows"
}
```

---

## Build & Deployment

### Linux Cross-Compilation

**Target**: `x86_64-unknown-linux-gnu`

```bash
cd src-tauri
cargo build --release --target x86_64-unknown-linux-gnu
```

**Dependencies** (Cargo.toml):
```toml
[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.29", features = ["mount", "user"] }
libc = "0.2"
nt-hive2 = "0.3"

[dependencies]
chrono = "0.4"  # Required for timestamp conversion
```

### Bootable ISO Building

**Base**: Ubuntu 22.04 (jammy) minimal

**Tool**: `debootstrap` + `squashfs-tools` + `grub`

**Script**: `build-bootable-iso.sh`

**Process**:
1. Bootstrap minimal Ubuntu
2. Install forensic tools (ntfs-3g, exfat-fuse, aapt, ffmpeg)
3. Install Hindsight binary + dependencies
4. Configure auto-start (systemd + LightDM + Openbox)
5. Create squashfs (~800MB compressed)
6. Generate bootable ISO (~1.2GB)

**Build Time**: 20-40 minutes

### USB Dual-Partition Setup

**Script**: `setup-forensic-usb.sh`

**Layout**:
```
/dev/sdX
├── /dev/sdX1 (4GB, FAT32, HINDSIGHT_BOOT)  - Bootable ISO
└── /dev/sdX2 (remaining, exFAT, HINDSIGHT_DATA) - Shared data
```

**Safety**: Requires typing "YES" to confirm destructive operation.

---

## Code Quality Standards

### Error Handling

**Pattern**: Return `Result<T, String>` for all fallible operations.

```rust
pub fn parse_registry_hive(path: &Path) -> Result<Vec<AppInfo>, String> {
    if !path.exists() {
        return Err(format!("Registry hive not found: {:?}", path));
    }
    // ...
}
```

**Graceful Degradation**: Provide fallbacks when primary method fails.

### Performance Optimization

**Parallel Processing**: Use `rayon` for CPU-bound operations.

```rust
use rayon::prelude::*;

let results: Vec<_> = files.par_iter()
    .map(|file| process_file(file))
    .collect();
```

**Limits**: Set reasonable limits for forensic scans.

```rust
// Media scanner
max_file_size: 500 * 1024 * 1024, // 500 MB

// Keyword scanner  
max_file_size: 100 * 1024 * 1024, // 100 MB

// Browser history
LIMIT 1000 // Top 1000 entries

// Android hash scanning
max_file_size: 500 * 1024 * 1024, // 500 MB per file
max_files: 10_000 // Total file limit
```

### Logging & Debugging

**Pattern**: Use `eprintln!` for stderr logging.

```rust
eprintln!("Failed to parse Chrome history for {}: {}", user_name, e);
```

**Android Hash Scanning Logs**:
```rust
eprintln!("[Android Hash Scan] Starting hash scan for device {}", serial);
eprintln!("[Android Hash Scan] Found {} media files to check", total_files);
eprintln!("[Android Hash Scan] [{}/{}] Checking: {}", index + 1, total_files, filename);
eprintln!("  ✓ HASH MATCH FOUND (SHA256): {}", filename);
eprintln!("[Android Hash Scan] Scan complete. Found {} matches", matches.len());
```

**Android Browser Logs**:
```rust
eprintln!("[Android Browser] Starting browser scan for device {}", serial);
eprintln!("[Android Browser] Attempting to access Chrome history database...");
eprintln!("[Android Browser] Successfully scanned Chrome: {} history entries", count);
```

**Timestamps**: Always use UTC for forensic accuracy.

```rust
chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
```

---

## Testing Requirements

### Unit Tests

**Location**: In same file as implementation.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chrome_timestamp_conversion() {
        let chrome_time = 13318932000000000i64;
        let result = convert_chrome_timestamp(chrome_time);
        assert!(result.contains("2022"));
    }
}
```

### Integration Tests

**VM Testing**: Use `test-bootable-iso.sh` for automated testing.

**Checklist**:
- [ ] ISO boots in QEMU/VirtualBox
- [ ] Hindsight auto-launches
- [ ] Target detection works
- [ ] Full scan completes
- [ ] Report generates successfully

### Android Hash Scanning Tests

**Test Scenarios**:
- [ ] Successful scan with no matches
- [ ] Successful scan with matches
- [ ] Error: No hash lists loaded
- [ ] Error: Device disconnected
- [ ] Large file handling (>500MB)
- [ ] Many files handling (>1000)
- [ ] Empty device (no media files)

**Test Files**:
- See `TEST_ANDROID_HASH_SCANNING.md` for detailed test procedures

### Android Browser History Tests

**Test Scenarios**:
- [ ] Chrome history accessible on device
- [ ] Direct pull method works
- [ ] Run-as fallback method works
- [ ] Timestamp conversion accurate
- [ ] Browser tab appears in dashboard
- [ ] History entries display correctly
- [ ] Export to PDF includes browser data

### Hardware Testing

**Required before production**:
- Test on Dell, HP, Lenovo laptops
- Verify BIOS/UEFI compatibility
- Test USB 2.0 and 3.0 performance
- Validate Windows 10/11 detection
- Test Android device compatibility (various manufacturers)
- Test with rooted and non-rooted devices
- Test Chrome data access on various Android versions

---

## Security Considerations

### Forensic Integrity

**Mount Options**: Always use read-only with security flags.

```bash
mount -o ro,noexec,nosuid [device] [mount_point]
```

**Android Scanning**: Read-only access via ADB.
- Never writes to device
- Pulls files temporarily only
- Immediate cleanup after hashing/parsing

**Verification**: Log all operations for chain of custody.

**Write Protection**: Only write to data partition reports directory.

### User Credentials

**Forensic Mode Default**:
- Username: `forensic`
- Password: `forensic`
- Sudo access: Required for mounting

**Production Recommendation**: Change default password before deployment.

### Data Protection

**USB Storage**:
- Reports: Unencrypted (consider disk encryption)
- Hash lists: Only hashes, no actual content
- Keyword lists: Visible plaintext

**Android Scanning**:
- No persistence of pulled files
- Only hash values stored in matches
- Browser databases deleted after parsing
- Critical findings flagged clearly

**Recommendation**: Store USB in secure location, consider full-disk encryption.

---

## Documentation Standards

### User-Facing Documentation

**Format**: Markdown with clear sections and examples.

**Required Sections**:
- Overview
- Prerequisites  
- Step-by-step instructions
- Troubleshooting
- Performance expectations

### Code Documentation

**Pattern**: Doc comments for public APIs.

```rust
/// Scan Android media files for known CSAM hashes
/// 
/// # Arguments
/// * `app_handle` - Tauri application handle
/// * `serial` - Android device serial number
/// * `progress_callback` - Optional callback for progress updates
/// 
/// # Returns
/// Vector of hash matches or error message
/// 
/// # Process
/// 1. Gets media file list from device
/// 2. Verifies hash database is loaded
/// 3. Pulls each file temporarily
/// 4. Computes and checks hashes
/// 5. Cleans up immediately
pub fn scan_android_media_hashes(
    app_handle: &tauri::AppHandle,
    serial: &str,
    progress_callback: Option<Box<dyn Fn(AndroidHashScanProgress) + Send>>
) -> Result<Vec<AndroidHashMatch>, String>
```

### Build Scripts

**Pattern**: Colored output with progress indicators.

```bash
echo -e "${GREEN}[3/10] Installing packages...${NC}"
```

**Error Messages**: Clear and actionable.

---

## Common Patterns

### Path Detection by Target OS

```rust
fn get_scan_paths(mount_point: &Path, target: &TargetSystem) -> Vec<PathBuf> {
    match target {
        TargetSystem::Windows { .. } => {
            vec![
                mount_point.join("Users/[Username]/Pictures"),
                mount_point.join("Users/[Username]/Downloads"),
            ]
        }
        TargetSystem::ChromeOS { .. } => {
            vec![
                mount_point.join("home/chronos/user/Downloads"),
                mount_point.join("home/chronos/user/MyFiles"),
            ]
        }
        _ => Vec::new()
    }
}
```

### Android Media Paths

```rust
// Common Android media locations
let media_paths = vec![
    "/sdcard/DCIM",
    "/sdcard/Camera",
    "/sdcard/Pictures",
    "/sdcard/Download",
    "/sdcard/Downloads",
    "/sdcard/Movies",
    "/sdcard/Video",
    "/sdcard/WhatsApp/Media/WhatsApp Images",
    "/sdcard/WhatsApp/Media/WhatsApp Video",
];
```

### Risk Categorization

```rust
pub enum RiskLevel {
    High,      // 2+ dangerous permissions/indicators
    Medium,    // 1 dangerous or 3+ sensitive
    Low,       // 1+ sensitive permissions
    Minimal,   // Basic permissions only
}

// For hash matches, always Critical
pub enum HashMatchSeverity {
    Critical,  // All CSAM hash matches
}
```

### Auto-Start Configuration

**Layers** (execute in order):
1. Systemd service (mount data partition)
2. LightDM auto-login (no password)
3. Openbox autostart (launch application)

---

## File Naming Conventions

### Scripts
- Bash scripts: `kebab-case.sh` (e.g., `build-bootable-iso.sh`)
- Executable permission: `chmod +x script.sh`

### Rust Modules
- Module files: `snake_case.rs` (e.g., `forensic_scan.rs`)
- Trait names: `PascalCase` (e.g., `PlatformScanner`)
- Function names: `snake_case` (e.g., `scan_android_media_hashes`)

### Documentation
- Markdown: `SCREAMING_SNAKE_CASE.md` (e.g., `PHASE2_COMPLETE.md`)
- User guides: `DESCRIPTIVE_NAME.md` (e.g., `BOOTABLE_QUICK_START.md`)
- Implementation docs: `FEATURE_IMPLEMENTED.md` (e.g., `ANDROID_HASH_SCANNING_IMPLEMENTED.md`)
- Test guides: `TEST_FEATURE.md` (e.g., `TEST_ANDROID_HASH_SCANNING.md`)

---

## Directory Structure

### Source Code
```
src-tauri/src/
├── platform/        - Platform abstraction (cross-platform code)
├── scanner/         - Scanning modules (media, browser, keyword, android)
├── reporter/        - Report generation (PDF)
├── security/        - Authentication, encryption
├── settings/        - Configuration management
└── system_info/     - System information gathering
```

### Build Artifacts
```
hindsight/
├── bootable_build/  - ISO build workspace (temporary)
├── dist/            - Frontend build output
├── src-tauri/target/release/hindsight-app - Binary
└── hindsight-forensic-v1.0.iso - Bootable ISO
```

### USB Structure
```
HINDSIGHT_DATA/
├── cases/           - Forensic reports (both modes)
├── keyword_lists/   - Search terms
├── hash_lists/      - CSAM databases
├── external/        - Binary tools
└── hindsight_secure.db - App database
```

---

## Conversation Starters

- "How do I add support for a new target OS type?"
- "How can I add a new forensic parser (e.g., for Safari history)?"
- "What's the process for updating the bootable ISO?"
- "How do I test forensic mode without real hardware?"
- "Can you explain the dual-partition USB structure?"
- "How does Android hash scanning work?"
- "How do I add progress tracking to Android hash scanning?"
- "How can I optimize Android hash scanning performance?"
- "How do I add support for Firefox or Samsung Internet browser on Android?"
- "How do I format data sizes to be human-readable for users?"