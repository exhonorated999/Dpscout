//! Deleted-media forensic triage — fast detection/estimation without recovery.
//!
//! Investigators need to know **whether** deleted media files are still physically
//! present on a USB/SD card and **how many** there may be, without doing a full
//! carve (which is slow).  This module answers those two questions.
//!
//! Two complementary methods:
//!   A. Metadata residue — named files from directory/MFT entries that survive deletion.
//!   B. Unallocated header scan — magic-signature counts in free clusters.
//!
//! We NEVER reconstruct, validate, or extract file contents.  The UI tells the
//! examiner to use PhotoRec for actual recovery.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Public data contract — must match frontend byte-for-byte
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedMediaSummary {
    pub drive_letter: String,
    pub fs_type: String,              // "FAT32" | "exFAT" | "NTFS" | "Unknown"
    pub scan_completed: bool,         // false if cancelled or capped early
    pub cancelled: bool,
    pub deleted_media_found: bool,    // the headline yes/no
    pub named_files: Vec<DeletedFile>,        // Method A results
    pub named_image_count: u64,
    pub named_video_count: u64,
    pub header_hits: Vec<HeaderHitCount>,     // Method B results, per signature
    pub unallocated_image_headers: u64,
    pub unallocated_video_headers: u64,
    pub estimated_total: u64,         // best single number for "how many"
    pub free_bytes: u64,
    pub scanned_bytes: u64,
    pub cluster_size: u32,
    pub duration_ms: u64,
    pub notes: Vec<String>,           // caveats/warnings shown verbatim in UI
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedFile {
    pub file_name: String,
    pub extension: String,
    pub size_bytes: u64,
    pub media_type: String,     // "image" | "video"
    pub source: String,         // "dir_entry" | "mft"
    pub start_cluster: u64,
    pub likely_recoverable: bool, // true when start cluster is currently free
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderHitCount {
    pub signature: String,   // e.g. "JPEG", "PNG", "MP4"
    pub media_type: String,  // "image" | "video"
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedMediaScanOptions {
    #[serde(default = "default_true")]  pub scan_metadata_residue: bool, // Method A
    #[serde(default = "default_true")]  pub scan_unallocated: bool,      // Method B
    #[serde(default)]                   pub max_bytes_to_scan: u64,      // 0 = no cap
    #[serde(default = "default_max_named")] pub max_named_files: usize,  // default 5000
}

fn default_true() -> bool { true }
fn default_max_named() -> usize { 5000 }

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn scan_deleted_media<F>(
    drive_letter: &str,
    options: DeletedMediaScanOptions,
    cancel: Arc<AtomicBool>,
    mut progress: F,
) -> Result<DeletedMediaSummary, String>
where
    F: FnMut(u8, u64, u64, &str) + Send,
{
    #[cfg(target_os = "windows")]
    {
        scan_deleted_media_windows(drive_letter, options, cancel, progress)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (drive_letter, options, cancel, progress);
        Err("Unallocated-space scanning is only supported on Windows".to_string())
    }
}

#[cfg(target_os = "windows")]
fn scan_deleted_media_windows<F>(
    drive_letter: &str,
    options: DeletedMediaScanOptions,
    cancel: Arc<AtomicBool>,
    mut progress: F,
) -> Result<DeletedMediaSummary, String>
where
    F: FnMut(u8, u64, u64, &str) + Send,
{
    use winapi::um::fileapi::GetDiskFreeSpaceExW;
    use winapi::um::winnt::ULARGE_INTEGER;

    let start = Instant::now();

    // Elevation check
    if !crate::security::elevation::is_elevated() {
        return Err("ELEVATION_REQUIRED".to_string());
    }

    let letter = drive_letter.chars().next().unwrap_or('C').to_ascii_uppercase();
    let volume_path = format!("\\\\.\\{}:", letter);

    // Get free-space info via normal API (doesn't need raw handle)
    let root = format!("{}:\\", letter);
    let root_wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
    let mut free_bytes_ui: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    let mut total_bytes_ui: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    let mut total_free_ui: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    unsafe {
        GetDiskFreeSpaceExW(
            root_wide.as_ptr(),
            &mut free_bytes_ui,
            &mut total_bytes_ui,
            &mut total_free_ui,
        );
    }
    let free_bytes = unsafe { *free_bytes_ui.QuadPart() };
    let total_bytes = unsafe { *total_bytes_ui.QuadPart() };

    let mut summary = DeletedMediaSummary {
        drive_letter: drive_letter.to_string(),
        fs_type: "Unknown".to_string(),
        scan_completed: false,
        cancelled: false,
        deleted_media_found: false,
        named_files: Vec::new(),
        named_image_count: 0,
        named_video_count: 0,
        header_hits: Vec::new(),
        unallocated_image_headers: 0,
        unallocated_video_headers: 0,
        estimated_total: 0,
        free_bytes,
        scanned_bytes: 0,
        cluster_size: 0,
        duration_ms: 0,
        notes: Vec::new(),
    };

    let mut notes: Vec<String> = Vec::new();

    // Open raw volume
    let mut reader = match VolumeReader::open(&volume_path) {
        Ok(r) => r,
        Err(e) => {
            notes.push(format!("Could not open raw volume: {}", e));
            summary.notes = notes;
            summary.duration_ms = start.elapsed().as_millis() as u64;
            return Ok(summary);
        }
    };

    // Read boot sector and detect filesystem
    let mut boot = vec![0u8; 512];
    if let Err(e) = reader.read_at(0, &mut boot) {
        notes.push(format!("Could not read boot sector: {}", e));
        summary.notes = notes;
        summary.duration_ms = start.elapsed().as_millis() as u64;
        return Ok(summary);
    }

    let fs = detect_filesystem(&boot);
    summary.fs_type = fs.name().to_string();
    summary.cluster_size = fs.cluster_size;

    // Diagnostic: record detected geometry up front so a zero-result run is
    // still actionable (wrong FS detection vs. genuinely-empty unallocated space).
    notes.push(format!(
        "Detected {} · cluster {} bytes · {} total clusters.",
        fs.name(),
        fs.cluster_size,
        fs.total_clusters,
    ));

    // --- Method A: metadata residue -----------------------------------------
    if options.scan_metadata_residue {
        let _ = progress_throttled(
            &mut progress,
            0,
            0,
            free_bytes,
            "Scanning metadata residue…",
            &mut summary.scanned_bytes,
        );

        match fs.kind {
            FsKind::Fat32 => {
                match fat32_scan_deleted(&mut reader, &fs, &options, &cancel) {
                    Ok(files) => summary.named_files = files,
                    Err(e) => notes.push(format!("FAT32 metadata scan: {}", e)),
                }
            }
            FsKind::ExFat => {
                match exfat_scan_deleted(&mut reader, &fs, &options, &cancel) {
                    Ok(files) => summary.named_files = files,
                    Err(e) => notes.push(format!("exFAT metadata scan: {}", e)),
                }
            }
            FsKind::Ntfs => {
                match ntfs_scan_deleted(&mut reader, &fs, &options, &cancel) {
                    Ok(files) => summary.named_files = files,
                    Err(e) => notes.push(format!("NTFS metadata scan: {}", e)),
                }
                if summary.named_files.is_empty() {
                    notes.push("NTFS metadata residue parsing is limited in this version; header scan results still apply.".to_string());
                }
            }
            FsKind::Unknown => {
                notes.push("Could not determine filesystem type; metadata residue scan skipped.".to_string());
            }
        }
    }

    // --- Method B: unallocated header count --------------------------------
    if options.scan_unallocated {
        let _ = progress_throttled(
            &mut progress,
            0,
            0,
            free_bytes,
            "Scanning unallocated space for headers…",
            &mut summary.scanned_bytes,
        );

        match scan_unallocated_headers(&mut reader, &fs, &options, &cancel, &mut progress, free_bytes, &mut summary.scanned_bytes) {
            Ok(hits) => summary.header_hits = hits,
            Err(e) => notes.push(format!("Unallocated header scan: {}", e)),
        }
    }

    // --- Post-processing ----------------------------------------------------
    summary.scan_completed = !cancel.load(Ordering::Relaxed);
    summary.cancelled = cancel.load(Ordering::Relaxed);

    // Count named files by media type
    for f in &summary.named_files {
        match f.media_type.as_str() {
            "image" => summary.named_image_count += 1,
            "video" => summary.named_video_count += 1,
            _ => {}
        }
    }

    // Count header hits by media type
    for h in &summary.header_hits {
        match h.media_type.as_str() {
            "image" => summary.unallocated_image_headers += h.count,
            "video" => summary.unallocated_video_headers += h.count,
            _ => {}
        }
    }

    // estimated_total: use max of the two methods because the same physical
    // file is frequently counted by BOTH methods.  Summing would double-count.
    let named_total = summary.named_files.len() as u64;
    let header_total = summary.unallocated_image_headers + summary.unallocated_video_headers;
    summary.estimated_total = named_total.max(header_total);
    summary.deleted_media_found = summary.estimated_total > 0;

    // Standard caveats
    notes.push("Counts are estimates, not guarantees. Embedded thumbnails and partial overwrites may inflate or deflate results.".to_string());
    notes.push("Fragmented files may be missed. Scout detects but does not recover — use PhotoRec or similar tools for actual extraction.".to_string());
    if summary.header_hits.iter().any(|h| h.signature == "BMP") {
        notes.push("BMP headers have weaker confidence (only 2-byte magic); counts may include false positives.".to_string());
    }
    if summary.fs_type == "FAT32" {
        notes.push("FAT32: first character of deleted file names is overwritten by the 0xE5 marker; names are prefixed with '_' as a placeholder.".to_string());
    }

    summary.notes = notes;
    summary.duration_ms = start.elapsed().as_millis() as u64;

    Ok(summary)
}

// ---------------------------------------------------------------------------
// VolumeReader — raw, read-only, sector-aligned
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
struct VolumeReader {
    handle: winapi::um::winnt::HANDLE,
    sector_size: u32,
}

#[cfg(target_os = "windows")]
impl VolumeReader {
    fn open(path: &str) -> Result<Self, String> {
        use winapi::um::fileapi::CreateFileW;
        use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, HANDLE};

        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let handle: HANDLE = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                winapi::um::fileapi::OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(format!(
                "Failed to open raw volume {} (error {}). Ensure the drive letter is correct and the process is elevated.",
                path,
                unsafe { winapi::um::errhandlingapi::GetLastError() }
            ));
        }

        // Query sector size via IOCTL_DISK_GET_DRIVE_GEOMETRY
        let mut dg: winapi::um::winioctl::DISK_GEOMETRY = unsafe { std::mem::zeroed() };
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            winapi::um::ioapiset::DeviceIoControl(
                handle,
                winapi::um::winioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY,
                std::ptr::null_mut(),
                0,
                &mut dg as *mut _ as *mut _,
                std::mem::size_of::<winapi::um::winioctl::DISK_GEOMETRY>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        let sector_size = if ok != 0 {
            unsafe { dg.BytesPerSector }
        } else {
            512 // safe fallback
        };

        Ok(VolumeReader {
            handle,
            sector_size,
        })
    }

    /// Read an arbitrary byte range from the volume.
    /// Internally rounds down to sector boundaries and copies out the
    /// requested slice.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        use winapi::um::fileapi::{ReadFile, SetFilePointerEx};

        if buf.is_empty() {
            return Ok(());
        }

        let sector = self.sector_size as u64;
        let start_sector = offset / sector;
        let end_byte = offset + buf.len() as u64;
        let end_sector = (end_byte + sector - 1) / sector;
        let aligned_len = ((end_sector - start_sector) * sector) as usize;
        let aligned_offset = start_sector * sector;
        let skip = (offset - aligned_offset) as usize;

        let mut scratch = vec![0u8; aligned_len];

        unsafe {
            // LARGE_INTEGER is a winapi union — build it via the QuadPart_mut()
            // accessor rather than assigning an i64 directly.
            let mut distance: winapi::um::winnt::LARGE_INTEGER = std::mem::zeroed();
            *distance.QuadPart_mut() = aligned_offset as i64;
            let mut pos: winapi::um::winnt::LARGE_INTEGER = std::mem::zeroed();
            let ok = SetFilePointerEx(
                self.handle,
                distance,
                &mut pos,
                winapi::um::winbase::FILE_BEGIN,
            );
            if ok == 0 {
                return Err(format!(
                    "SetFilePointerEx failed (error {})",
                    winapi::um::errhandlingapi::GetLastError()
                ));
            }

            let mut read_bytes: u32 = 0;
            let ok = ReadFile(
                self.handle,
                scratch.as_mut_ptr() as *mut winapi::ctypes::c_void,
                scratch.len() as u32,
                &mut read_bytes,
                std::ptr::null_mut(),
            );
            if ok == 0 {
                return Err(format!(
                    "ReadFile failed (error {})",
                    winapi::um::errhandlingapi::GetLastError()
                ));
            }
            if (read_bytes as usize) < skip + buf.len() {
                return Err("Short read at end of volume".to_string());
            }
        }

        buf.copy_from_slice(&scratch[skip..skip + buf.len()]);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for VolumeReader {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            unsafe {
                winapi::um::handleapi::CloseHandle(self.handle);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem detection & geometry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum FsKind {
    Fat32,
    ExFat,
    Ntfs,
    Unknown,
}

#[derive(Debug, Clone)]
struct FsInfo {
    kind: FsKind,
    name: &'static str,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    cluster_size: u32,
    total_sectors: u64,
    total_clusters: u64,
    // FAT32 / exFAT
    fat_offset: u64,
    fat_size_sectors: u64,
    data_offset: u64,
    root_cluster: u32,
    // NTFS
    mft_lcn: u64,
    mft_record_size: u32,
}

impl FsInfo {
    fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(target_os = "windows")]
fn detect_filesystem(boot: &[u8]) -> FsInfo {
    // exFAT: bytes 3..11 == "EXFAT   "
    if boot.len() >= 11 && &boot[3..11] == b"EXFAT   " {
        return parse_exfat(boot);
    }
    // NTFS: bytes 3..11 == "NTFS    "
    if boot.len() >= 11 && &boot[3..11] == b"NTFS    " {
        return parse_ntfs(boot);
    }
    // FAT32: bytes 82..90 == "FAT32   "
    if boot.len() >= 90 && &boot[82..90] == b"FAT32   " {
        return parse_fat32(boot);
    }
    // FAT16/FAT12: bytes 54..62 == "FAT" prefix
    if boot.len() >= 62 && &boot[54..57] == b"FAT" {
        return parse_fat32(boot); // generic FAT parser works for 12/16 too
    }

    FsInfo {
        kind: FsKind::Unknown,
        name: "Unknown",
        bytes_per_sector: 512,
        sectors_per_cluster: 1,
        cluster_size: 512,
        total_sectors: 0,
        total_clusters: 0,
        fat_offset: 0,
        fat_size_sectors: 0,
        data_offset: 0,
        root_cluster: 0,
        mft_lcn: 0,
        mft_record_size: 1024,
    }
}

#[cfg(target_os = "windows")]
fn parse_fat32(boot: &[u8]) -> FsInfo {
    let bps = u16_from_le(boot, 11).max(512) as u32;
    let spc = boot[13] as u32;
    let reserved = u16_from_le(boot, 14) as u32;
    let fat_count = boot[16] as u32;
    let root_entries = u16_from_le(boot, 17) as u32;
    let total_sectors_16 = u16_from_le(boot, 19) as u64;
    let total_sectors_32 = u32_from_le(boot, 32) as u64;
    let fat_size_16 = u16_from_le(boot, 22) as u32;
    let fat_size_32 = u32_from_le(boot, 36);

    let total_sectors = if total_sectors_32 != 0 {
        total_sectors_32
    } else {
        total_sectors_16
    };

    let fat_size = if fat_size_32 != 0 {
        fat_size_32 as u64
    } else {
        fat_size_16 as u64
    };

    let root_dir_sectors = ((root_entries * 32) + (bps - 1)) / bps;
    let data_start = (reserved as u64) + (fat_count as u64 * fat_size) + root_dir_sectors as u64;
    let data_sectors = total_sectors.saturating_sub(data_start);
    let total_clusters = if spc == 0 {
        0
    } else {
        data_sectors / (spc as u64)
    };

    let root_cluster = u32_from_le(boot, 44);
    let fat_offset = reserved as u64;

    let kind = if total_clusters > 65525 {
        FsKind::Fat32
    } else if total_clusters > 4085 {
        FsKind::Fat32 // FAT16
    } else {
        FsKind::Fat32 // FAT12 — treat generically
    };

    let name = if total_clusters > 65525 {
        "FAT32"
    } else if total_clusters > 4085 {
        "FAT16"
    } else {
        "FAT12"
    };

    FsInfo {
        kind,
        name,
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        cluster_size: bps * spc,
        total_sectors,
        total_clusters,
        fat_offset,
        fat_size_sectors: fat_size,
        data_offset: data_start * (bps as u64),
        root_cluster,
        mft_lcn: 0,
        mft_record_size: 1024,
    }
}

#[cfg(target_os = "windows")]
fn parse_exfat(boot: &[u8]) -> FsInfo {
    let bps = 1u32 << boot[108]; // bytes per sector = 2^P
    let spc = 1u32 << boot[109]; // sectors per cluster = 2^S
    let cluster_count = u32_from_le(boot, 84);
    let cluster_heap_offset = u32_from_le(boot, 88);
    let fat_offset = u32_from_le(boot, 80);
    let fat_length = u32_from_le(boot, 92);
    let root_cluster = u32_from_le(boot, 96);

    let total_sectors = (cluster_count as u64) * (spc as u64) + (cluster_heap_offset as u64);

    FsInfo {
        kind: FsKind::ExFat,
        name: "exFAT",
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        cluster_size: bps * spc,
        total_sectors,
        total_clusters: cluster_count as u64,
        fat_offset: (fat_offset as u64) * (bps as u64),
        fat_size_sectors: fat_length as u64,
        data_offset: (cluster_heap_offset as u64) * (bps as u64),
        root_cluster,
        mft_lcn: 0,
        mft_record_size: 1024,
    }
}

#[cfg(target_os = "windows")]
fn parse_ntfs(boot: &[u8]) -> FsInfo {
    let bps = u16_from_le(boot, 11).max(512) as u32;
    let spc = boot[13] as u32;
    let total_sectors = u64_from_le(boot, 40);
    let mft_lcn = u64_from_le(boot, 48);
    let mft_record_size_raw = i8_from_le(boot, 64);
    let mft_record_size = if mft_record_size_raw < 0 {
        1u32 << (-mft_record_size_raw as u32)
    } else {
        mft_record_size_raw as u32
    };

    FsInfo {
        kind: FsKind::Ntfs,
        name: "NTFS",
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        cluster_size: bps * spc,
        total_sectors,
        total_clusters: total_sectors / (spc as u64),
        fat_offset: 0,
        fat_size_sectors: 0,
        data_offset: 0,
        root_cluster: 0,
        mft_lcn,
        mft_record_size,
    }
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

fn u16_from_le(buf: &[u8], off: usize) -> u16 {
    if buf.len() < off + 2 {
        return 0;
    }
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn u32_from_le(buf: &[u8], off: usize) -> u32 {
    if buf.len() < off + 4 {
        return 0;
    }
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64_from_le(buf: &[u8], off: usize) -> u64 {
    if buf.len() < off + 8 {
        return 0;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

fn i8_from_le(buf: &[u8], off: usize) -> i8 {
    if buf.len() < off + 1 {
        return 0;
    }
    buf[off] as i8
}

// ---------------------------------------------------------------------------
// Media extension / type helpers
// ---------------------------------------------------------------------------

const IMAGE_EXTS: &[&str] = &[
    "JPG", "JPEG", "PNG", "GIF", "BMP", "TIF", "TIFF", "HEIC", "HEIF", "WEBP", "RAW",
    "CR2", "NEF", "ARW", "DNG", "ORF", "RW2", "PEF", "SR2", "RAF", "ERF", "3FR", "MEF",
    "KDC", "DCR", "IIQ", "X3F", "NRW", "JPE", "JFIF", "JIF", "JFI",
];

const VIDEO_EXTS: &[&str] = &[
    "MP4", "MOV", "AVI", "WMV", "MKV", "FLV", "WEBM", "M4V", "3GP", "3G2", "MPG", "MPEG",
    "MPE", "MPV", "OGV", "TS", "M2TS", "MTS", "VOB", "ASF", "DIVX", "XVID", "MXF", "DV",
    "QT", "F4V", "SWF", "M2V", "MLV", "R3D", "ARI", "DRC",
];

fn media_type_from_ext(ext: &str) -> Option<&'static str> {
    let up = ext.to_ascii_uppercase();
    if IMAGE_EXTS.contains(&up.as_str()) {
        Some("image")
    } else if VIDEO_EXTS.contains(&up.as_str()) {
        Some("video")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Signature matching (testable, no I/O)
// ---------------------------------------------------------------------------

/// Test a buffer (expected to be cluster-aligned start) against known media
/// magic signatures.  Returns `(signature_name, media_type)` or `None`.
///
/// `drive_size` is used for BMP plausibility checking.
pub(crate) fn match_signature(buf: &[u8], drive_size: u64) -> Option<(&'static str, &'static str)> {
    if buf.len() < 12 {
        return None;
    }

    // JPEG
    if buf[0..3] == [0xFF, 0xD8, 0xFF] {
        return Some(("JPEG", "image"));
    }

    // PNG
    if buf[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(("PNG", "image"));
    }

    // GIF
    if buf[0..4] == [0x47, 0x49, 0x46, 0x38] {
        return Some(("GIF", "image"));
    }

    // BMP — 2-byte magic, so add plausibility check on file size field
    if buf[0..2] == [0x42, 0x4D] {
        if buf.len() >= 6 {
            let size = u32_from_le(buf, 2) as u64;
            if size > 100 && size < drive_size {
                return Some(("BMP", "image"));
            }
        }
    }

    // TIFF little-endian
    if buf[0..4] == [0x49, 0x49, 0x2A, 0x00] {
        return Some(("TIFF", "image"));
    }
    // TIFF big-endian
    if buf[0..4] == [0x4D, 0x4D, 0x00, 0x2A] {
        return Some(("TIFF", "image"));
    }

    // HEIC/HEIF — ftyp box at offset 4
    if buf.len() >= 16 && &buf[4..8] == b"ftyp" {
        let brand = std::str::from_utf8(&buf[8..12]).unwrap_or("");
        let heic_brands = ["heic", "heix", "hevc", "mif1", "msf1"];
        if heic_brands.contains(&brand) {
            return Some(("HEIC", "image"));
        }
    }

    // MP4/MOV/3GP — ftyp box at offset 4
    if buf.len() >= 16 && &buf[4..8] == b"ftyp" {
        let brand = std::str::from_utf8(&buf[8..12]).unwrap_or("");
        let mp4_brands = ["isom", "iso2", "mp41", "mp42", "avc1", "qt  ", "3gp", "M4V"];
        if mp4_brands.contains(&brand) {
            return Some(("MP4", "video"));
        }
    }

    // AVI — RIFF....AVI
    if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"AVI " {
        return Some(("AVI", "video"));
    }

    // ASF/WMV
    if buf.len() >= 16
        && buf[0..16]
            == [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00,
                0x62, 0xCE, 0x6C]
    {
        return Some(("WMV", "video"));
    }

    // MKV/WEBM — EBML header: 1A 45 DF A3
    if buf.len() >= 4 && buf[0..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return Some(("MKV", "video"));
    }

    None
}

// ---------------------------------------------------------------------------
// Progress throttling
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn progress_throttled<F>(
    progress: &mut F,
    percent: u8,
    scanned: u64,
    free: u64,
    phase: &str,
    scanned_acc: &mut u64,
) -> Result<(), String>
where
    F: FnMut(u8, u64, u64, &str) + Send,
{
    *scanned_acc = scanned;
    progress(percent, scanned, free, phase);
    Ok(())
}

// ---------------------------------------------------------------------------
// Method A — FAT32 deleted directory entries
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn fat32_scan_deleted(
    reader: &mut VolumeReader,
    fs: &FsInfo,
    options: &DeletedMediaScanOptions,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<DeletedFile>, String> {
    let mut files = Vec::new();
    let mut visited_clusters: HashSet<u32> = HashSet::new();
    const MAX_DIRS: usize = 10_000;
    let mut dirs_visited = 0;

    // Read the FAT ONCE up front and reuse it for every chain-follow and the
    // free-cluster map.  (Previously each follow_chain re-read the whole FAT
    // from the USB, which made the metadata phase appear to hang.)
    let fat_buf = read_full_fat(reader, fs)?;

    // Build free-cluster map for likely_recoverable
    let free_clusters = fat32_read_free_clusters(fs, &fat_buf)?;

    // Start at root cluster
    let root = fs.root_cluster;
    fat32_walk_directory(
        reader,
        fs,
        &fat_buf,
        root,
        &mut files,
        &mut visited_clusters,
        &mut dirs_visited,
        MAX_DIRS,
        &free_clusters,
        options,
        cancel,
    )?;

    Ok(files)
}

/// Read the entire FAT region into memory in a single volume read.
/// Returns an empty vec if the filesystem has no FAT (e.g. NTFS).
#[cfg(target_os = "windows")]
fn read_full_fat(reader: &VolumeReader, fs: &FsInfo) -> Result<Vec<u8>, String> {
    let fat_bytes = fs.fat_size_sectors * (fs.bytes_per_sector as u64);
    if fat_bytes == 0 {
        return Ok(Vec::new());
    }
    let mut fat_buf = vec![0u8; fat_bytes as usize];
    reader.read_at(fs.fat_offset, &mut fat_buf)?;
    Ok(fat_buf)
}

#[cfg(target_os = "windows")]
fn fat32_read_free_clusters(fs: &FsInfo, fat_buf: &[u8]) -> Result<HashSet<u32>, String> {
    let mut free = HashSet::new();

    // FAT32 entries are 32-bit; FAT16 are 16-bit
    let is_fat32 = fs.total_clusters > 4085;
    let max_entry = fs.total_clusters as u32;

    if is_fat32 {
        for i in 0..max_entry {
            let off = (i as usize) * 4;
            if off + 4 > fat_buf.len() {
                break;
            }
            let entry = u32_from_le(fat_buf, off) & 0x0FFF_FFFF;
            if entry == 0 {
                free.insert(i);
            }
        }
    } else {
        // FAT16
        for i in 0..max_entry {
            let off = (i as usize) * 2;
            if off + 2 > fat_buf.len() {
                break;
            }
            let entry = u16_from_le(fat_buf, off);
            if entry == 0 {
                free.insert(i);
            }
        }
    }

    Ok(free)
}

#[cfg(target_os = "windows")]
fn fat32_walk_directory(
    reader: &mut VolumeReader,
    fs: &FsInfo,
    fat_buf: &[u8],
    start_cluster: u32,
    files: &mut Vec<DeletedFile>,
    visited: &mut HashSet<u32>,
    dirs_visited: &mut usize,
    max_dirs: usize,
    free_clusters: &HashSet<u32>,
    options: &DeletedMediaScanOptions,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    if start_cluster < 2 || !visited.insert(start_cluster) {
        return Ok(());
    }
    *dirs_visited += 1;
    if *dirs_visited > max_dirs {
        return Ok(());
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(());
    }

    let cluster_size = fs.cluster_size as u64;
    let data_offset = fs.data_offset;

    // Read the cluster chain for this directory
    let clusters = fat32_follow_chain(fs, fat_buf, start_cluster, cancel);

    for cluster in clusters {
        let offset = data_offset + ((cluster as u64 - 2) * cluster_size);
        let mut cluster_buf = vec![0u8; fs.cluster_size as usize];
        reader.read_at(offset, &mut cluster_buf)?;

        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Parse 32-byte directory entries
        let entries = cluster_buf.len() / 32;
        let mut lfn_parts: Vec<(u8, String)> = Vec::new();

        for i in (0..entries).rev() {
            let off = i * 32;
            let entry = &cluster_buf[off..off + 32];
            let attr = entry[11];

            if entry[0] == 0x00 {
                // End of directory
                lfn_parts.clear();
                continue;
            }
            if entry[0] == 0xE5 {
                // Deleted entry
                let ext = std::str::from_utf8(&entry[8..11])
                    .unwrap_or("")
                    .trim()
                    .to_ascii_uppercase();
                let size = u32_from_le(entry, 28) as u64;
                let start_lo = u16_from_le(entry, 26) as u32;
                let start_hi = u16_from_le(entry, 20) as u32;
                let start_cluster = (start_hi << 16) | start_lo;

                if let Some(mt) = media_type_from_ext(&ext) {
                    let name = if !lfn_parts.is_empty() {
                        lfn_parts.sort_by_key(|(seq, _)| *seq);
                        let name_str: String = lfn_parts.iter().map(|(_, s)| s.as_str()).collect();
                        name_str.trim().to_string()
                    } else {
                        let base = std::str::from_utf8(&entry[1..8])
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        format!("_{}. {}", base, ext)
                    };

                    files.push(DeletedFile {
                        file_name: name,
                        extension: ext.clone(),
                        size_bytes: size,
                        media_type: mt.to_string(),
                        source: "dir_entry".to_string(),
                        start_cluster: start_cluster as u64,
                        likely_recoverable: free_clusters.contains(&start_cluster),
                    });

                    if files.len() >= options.max_named_files {
                        return Ok(());
                    }
                }
                lfn_parts.clear();
            } else if attr == 0x0F {
                // LFN entry — read in reverse order, so accumulate
                let seq = entry[0] & 0x1F;
                let mut name_chars = String::new();
                // UTF-16LE name characters at offsets 1, 3, 5... 10 (5 chars)
                // then 14, 16... 24 (6 chars)
                // then 28, 30 (2 chars)
                for j in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
                    let c = u16_from_le(entry, j);
                    if c == 0x0000 || c == 0xFFFF {
                        break;
                    }
                    if let Some(ch) = char::from_u32(c as u32) {
                        name_chars.push(ch);
                    }
                }
                lfn_parts.push((seq, name_chars));
            } else {
                lfn_parts.clear();

                // Active directory entry — check if it's a subdirectory we should recurse into
                if attr & 0x10 != 0 && entry[0] != 0x2E {
                    let start_lo = u16_from_le(entry, 26) as u32;
                    let start_hi = u16_from_le(entry, 20) as u32;
                    let sub_cluster = (start_hi << 16) | start_lo;
                    if sub_cluster >= 2 {
                        fat32_walk_directory(
                            reader,
                            fs,
                            fat_buf,
                            sub_cluster,
                            files,
                            visited,
                            dirs_visited,
                            max_dirs,
                            free_clusters,
                            options,
                            cancel,
                        )?;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn fat32_follow_chain(
    fs: &FsInfo,
    fat_buf: &[u8],
    start: u32,
    cancel: &Arc<AtomicBool>,
) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut current = start;
    let max_clusters = fs.total_clusters as u32;
    let mut visited = HashSet::new();

    let is_fat32 = fs.total_clusters > 4085;

    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if current < 2 || !visited.insert(current) || current > max_clusters {
            break;
        }
        chain.push(current);

        let next = if is_fat32 {
            let off = (current as usize) * 4;
            if off + 4 > fat_buf.len() {
                break;
            }
            u32_from_le(fat_buf, off) & 0x0FFF_FFFF
        } else {
            let off = (current as usize) * 2;
            if off + 2 > fat_buf.len() {
                break;
            }
            u16_from_le(fat_buf, off) as u32
        };

        if next == 0 || next >= 0x0FFF_FFF8 {
            break;
        }
        current = next;
    }

    chain
}

// ---------------------------------------------------------------------------
// Method A — exFAT deleted directory entries
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn exfat_scan_deleted(
    reader: &mut VolumeReader,
    fs: &FsInfo,
    options: &DeletedMediaScanOptions,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<DeletedFile>, String> {
    let mut files = Vec::new();
    let mut visited_clusters: HashSet<u32> = HashSet::new();
    const MAX_DIRS: usize = 10_000;
    let mut dirs_visited = 0;

    // Read the FAT once and reuse it everywhere.
    let fat_buf = read_full_fat(reader, fs)?;

    // Build free-cluster map
    let free_clusters = exfat_read_free_clusters(reader, fs, &fat_buf, cancel)?;

    exfat_walk_directory(
        reader,
        fs,
        &fat_buf,
        fs.root_cluster,
        &mut files,
        &mut visited_clusters,
        &mut dirs_visited,
        MAX_DIRS,
        &free_clusters,
        options,
        cancel,
    )?;

    Ok(files)
}

#[cfg(target_os = "windows")]
fn exfat_read_free_clusters(
    reader: &VolumeReader,
    fs: &FsInfo,
    fat_buf: &[u8],
    cancel: &Arc<AtomicBool>,
) -> Result<HashSet<u32>, String> {
    let mut free = HashSet::new();

    // First, find the Allocation Bitmap system file in the root directory
    let root_clusters = exfat_follow_chain(fs, fat_buf, fs.root_cluster, cancel);
    let mut bitmap_cluster: Option<u32> = None;
    let mut bitmap_len: u64 = 0;

    for cluster in &root_clusters {
        let offset = fs.data_offset + ((*cluster as u64 - 2) * (fs.cluster_size as u64));
        let mut buf = vec![0u8; fs.cluster_size as usize];
        reader.read_at(offset, &mut buf)?;

        let entries = buf.len() / 32;
        for i in 0..entries {
            let off = i * 32;
            let entry = &buf[off..off + 32];
            let etype = entry[0];

            // Allocation Bitmap entry type = 0x81
            if etype == 0x81 {
                bitmap_cluster = Some(u32_from_le(entry, 20));
                bitmap_len = u64_from_le(entry, 24);
                break;
            }
        }
        if bitmap_cluster.is_some() {
            break;
        }
    }

    let bitmap_cluster = bitmap_cluster.ok_or("Could not find exFAT Allocation Bitmap")?;
    let bitmap_clusters = exfat_follow_chain(fs, fat_buf, bitmap_cluster, cancel);

    let mut bitmap_data = Vec::new();
    for cluster in &bitmap_clusters {
        let offset = fs.data_offset + ((*cluster as u64 - 2) * (fs.cluster_size as u64));
        let mut buf = vec![0u8; fs.cluster_size as usize];
        reader.read_at(offset, &mut buf)?;
        bitmap_data.extend_from_slice(&buf);
    }

    let total_clusters = fs.total_clusters as usize;
    for i in 0..total_clusters {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < bitmap_data.len() {
            let bit = (bitmap_data[byte_idx] >> bit_idx) & 1;
            if bit == 0 {
                free.insert(i as u32);
            }
        }
    }

    Ok(free)
}

#[cfg(target_os = "windows")]
fn exfat_walk_directory(
    reader: &mut VolumeReader,
    fs: &FsInfo,
    fat_buf: &[u8],
    start_cluster: u32,
    files: &mut Vec<DeletedFile>,
    visited: &mut HashSet<u32>,
    dirs_visited: &mut usize,
    max_dirs: usize,
    free_clusters: &HashSet<u32>,
    options: &DeletedMediaScanOptions,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    if start_cluster < 2 || !visited.insert(start_cluster) {
        return Ok(());
    }
    *dirs_visited += 1;
    if *dirs_visited > max_dirs {
        return Ok(());
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(());
    }

    let cluster_size = fs.cluster_size as u64;
    let data_offset = fs.data_offset;

    let clusters = exfat_follow_chain(fs, fat_buf, start_cluster, cancel);

    for cluster in clusters {
        let offset = data_offset + ((cluster as u64 - 2) * cluster_size);
        let mut buf = vec![0u8; fs.cluster_size as usize];
        reader.read_at(offset, &mut buf)?;

        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }

        let entries = buf.len() / 32;
        let mut i = 0;
        while i < entries {
            let off = i * 32;
            let entry = &buf[off..off + 32];
            let etype = entry[0];

            // Deleted entries have the high bit (0x80) clear
            if etype == 0x05 {
                // Deleted file directory entry
                // Next entries should be stream extension (0xC0) and file name (0xC1)
                if i + 2 < entries {
                    let stream = &buf[off + 32..off + 64];

                    if stream[0] == 0xC0 || stream[0] == 0x40 {
                        // Stream extension (possibly deleted)
                        let name_len = stream[3] as usize;
                        let valid_data_len = u64_from_le(stream, 8);
                        let first_cluster = u32_from_le(stream, 20);

                        // Collect name entries
                        let mut name = String::new();
                        let name_entry_count = ((name_len + 14) / 15).min(17); // max 17 name entries
                        for j in 0..name_entry_count {
                            let ne_off = off + 64 + j * 32;
                            if ne_off + 32 > buf.len() {
                                break;
                            }
                            let ne = &buf[ne_off..ne_off + 32];
                            if ne[0] == 0xC1 || ne[0] == 0x41 {
                                // File name entry (possibly deleted)
                                for k in (2..32).step_by(2) {
                                    let c = u16_from_le(ne, k);
                                    if c == 0x0000 {
                                        break;
                                    }
                                    if let Some(ch) = char::from_u32(c as u32) {
                                        name.push(ch);
                                    }
                                }
                            } else {
                                break;
                            }
                        }

                        // Extract extension from name
                        let ext = name
                            .rsplit('.')
                            .next()
                            .unwrap_or("")
                            .to_ascii_uppercase();

                        if let Some(mt) = media_type_from_ext(&ext) {
                            files.push(DeletedFile {
                                file_name: name.clone(),
                                extension: ext,
                                size_bytes: valid_data_len,
                                media_type: mt.to_string(),
                                source: "dir_entry".to_string(),
                                start_cluster: first_cluster as u64,
                                likely_recoverable: free_clusters.contains(&first_cluster),
                            });

                            if files.len() >= options.max_named_files {
                                return Ok(());
                            }
                        }

                        i += 2 + name_entry_count;
                        continue;
                    }
                }
            } else if etype == 0x85 || etype == 0x05 {
                // File directory entry (active or deleted)
                // Check if it's a directory for recursion
                let secondary_count = entry[1];
                let attr = u16_from_le(entry, 4);
                if attr & 0x10 != 0 && etype == 0x85 {
                    // Active directory — find stream extension for first cluster
                    if i + 1 < entries {
                        let stream = &buf[off + 32..off + 64];
                        if stream[0] == 0xC0 {
                            let first_cluster = u32_from_le(stream, 20);
                            if first_cluster >= 2 {
                                exfat_walk_directory(
                                    reader,
                                    fs,
                                    fat_buf,
                                    first_cluster,
                                    files,
                                    visited,
                                    dirs_visited,
                                    max_dirs,
                                    free_clusters,
                                    options,
                                    cancel,
                                )?;
                            }
                        }
                    }
                }
            }

            i += 1;
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn exfat_follow_chain(
    fs: &FsInfo,
    fat_buf: &[u8],
    start: u32,
    cancel: &Arc<AtomicBool>,
) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut current = start;
    let max_clusters = fs.total_clusters as u32;
    let mut visited = HashSet::new();

    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if current < 2 || !visited.insert(current) || current > max_clusters {
            break;
        }
        chain.push(current);

        let off = (current as usize) * 4;
        if off + 4 > fat_buf.len() {
            break;
        }
        let next = u32_from_le(fat_buf, off);
        if next == 0 || next >= 0xFFFF_FFFF {
            break;
        }
        current = next;
    }

    chain
}

// ---------------------------------------------------------------------------
// Method A — NTFS best-effort
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn ntfs_scan_deleted(
    reader: &mut VolumeReader,
    fs: &FsInfo,
    options: &DeletedMediaScanOptions,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<DeletedFile>, String> {
    let mut files = Vec::new();
    let mft_start = fs.mft_lcn * (fs.cluster_size as u64);
    let record_size = fs.mft_record_size as usize;

    // Read a reasonable number of MFT records (first 64 MB worth)
    let max_records = (64 * 1024 * 1024) / record_size;
    let mut buf = vec![0u8; record_size];

    for i in 0..max_records {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if files.len() >= options.max_named_files {
            break;
        }

        let offset = mft_start + (i as u64) * (record_size as u64);
        reader.read_at(offset, &mut buf)?;

        // FILE record signature
        if &buf[0..4] != b"FILE" {
            // Could be the end of the MFT, or a non-resident extent
            continue;
        }

        // Apply fixup array
        let usa_offset = u16_from_le(&buf, 4) as usize;
        let usa_count = u16_from_le(&buf, 6) as usize;
        if usa_offset > 0 && usa_count > 0 {
            let usa_size = usa_count * 2;
            if usa_offset + usa_size <= buf.len() {
                let usa_bytes = buf[usa_offset..usa_offset + usa_size].to_vec();
                let sequence = u16_from_le(&usa_bytes, 0);
                for j in 1..usa_count {
                    let stride_off = j * 512 - 2;
                    if stride_off + 2 <= buf.len() {
                        let fixup_bytes = u16_from_le(&usa_bytes, j * 2);
                        buf[stride_off] = (fixup_bytes & 0xFF) as u8;
                        buf[stride_off + 1] = ((fixup_bytes >> 8) & 0xFF) as u8;
                    }
                }
            }
        }

        // Flags at offset 22: bit 0 = IN_USE
        let flags = u16_from_le(&buf, 22);
        let in_use = flags & 0x01 != 0;
        if in_use {
            continue; // not deleted
        }

        // Parse attributes
        let attr_offset = u16_from_le(&buf, 20) as usize;
        let mut off = attr_offset;
        let mut file_name: Option<String> = None;
        let mut data_size: u64 = 0;

        while off + 16 <= buf.len() {
            let attr_type = u32_from_le(&buf, off);
            if attr_type == 0xFFFFFFFF {
                break;
            }
            if attr_type == 0 {
                break;
            }

            let attr_len = u32_from_le(&buf, off + 4) as usize;
            if attr_len == 0 || off + attr_len > buf.len() {
                break;
            }

            if attr_type == 0x30 {
                // $FILE_NAME
                let name_len = buf[off + 64] as usize;
                let name_off = off + 66;
                if name_off + name_len * 2 <= buf.len() {
                    let name_bytes = &buf[name_off..name_off + name_len * 2];
                    let name_wide: Vec<u16> = name_bytes
                        .chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect();
                    if let Ok(name) = String::from_utf16(&name_wide) {
                        file_name = Some(name);
                    }
                }
            } else if attr_type == 0x80 {
                // $DATA
                let non_resident = buf[off + 8] != 0;
                if non_resident {
                    data_size = u64_from_le(&buf, off + 48);
                } else {
                    data_size = u32_from_le(&buf, off + 16) as u64;
                }
            }

            off += attr_len;
        }

        if let Some(name) = file_name {
            let ext = name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            if let Some(mt) = media_type_from_ext(&ext) {
                files.push(DeletedFile {
                    file_name: name,
                    extension: ext,
                    size_bytes: data_size,
                    media_type: mt.to_string(),
                    source: "mft".to_string(),
                    start_cluster: 0, // not easily available from MFT record alone
                    likely_recoverable: false, // would need $Bitmap check
                });
            }
        }
    }

    Ok(files)
}

// ---------------------------------------------------------------------------
// Method B — unallocated header scan
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn scan_unallocated_headers<F>(
    reader: &mut VolumeReader,
    fs: &FsInfo,
    options: &DeletedMediaScanOptions,
    cancel: &Arc<AtomicBool>,
    progress: &mut F,
    free_bytes_total: u64,
    scanned_acc: &mut u64,
) -> Result<Vec<HeaderHitCount>, String>
where
    F: FnMut(u8, u64, u64, &str) + Send,
{
    let cluster_size = fs.cluster_size as u64;
    if cluster_size == 0 {
        return Err("Invalid cluster size".to_string());
    }

    // Build free-cluster list (read the FAT once for FAT/exFAT)
    let fat_buf = read_full_fat(reader, fs)?;
    let free_clusters = match fs.kind {
        FsKind::Fat32 => fat32_read_free_clusters(fs, &fat_buf)?,
        FsKind::ExFat => exfat_read_free_clusters(reader, fs, &fat_buf, cancel)?,
        FsKind::Ntfs => ntfs_read_free_clusters(reader, fs)?,
        FsKind::Unknown => {
            return Err("Cannot scan unallocated space: unknown filesystem".to_string());
        }
    };

    if free_clusters.is_empty() {
        return Ok(Vec::new());
    }

    // Coalesce adjacent free clusters into contiguous runs for throughput
    let mut free_sorted: Vec<u32> = free_clusters.into_iter().collect();
    free_sorted.sort_unstable();

    let mut runs: Vec<(u32, u32)> = Vec::new(); // (start, end inclusive)
    if !free_sorted.is_empty() {
        let mut start = free_sorted[0];
        let mut prev = free_sorted[0];
        for &c in &free_sorted[1..] {
            if c == prev + 1 {
                prev = c;
            } else {
                runs.push((start, prev));
                start = c;
                prev = c;
            }
        }
        runs.push((start, prev));
    }

    let total_free_clusters = free_sorted.len() as u64;
    let mut scanned_clusters: u64 = 0;
    let mut hits: HashMap<&'static str, (u64, &'static str)> = HashMap::new();
    let drive_size = fs.total_sectors * (fs.bytes_per_sector as u64);

    // Read in 4 MB chunks (or smaller for short runs)
    const CHUNK_CLUSTERS: u32 = 128; // 128 clusters ≈ 4 MB at 32 KB cluster

    let mut last_progress = Instant::now();

    for (run_start, run_end) in runs {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let mut current = run_start;
        while current <= run_end {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let chunk_end = (current + CHUNK_CLUSTERS - 1).min(run_end);
            let chunk_len = (chunk_end - current + 1) as usize;
            let chunk_bytes = chunk_len * (cluster_size as usize);

            let offset = fs.data_offset + ((current as u64 - 2) * cluster_size);
            let mut buf = vec![0u8; chunk_bytes];
            if let Err(_e) = reader.read_at(offset, &mut buf) {
                // Partial failure — skip this chunk
                current = chunk_end + 1;
                continue;
            }

            // Test cluster-aligned starts only.  This mirrors how carvers
            // begin extraction and suppresses the huge false-positive rate from
            // embedded EXIF thumbnails (a JPEG header sitting mid-cluster is
            // almost always an embedded thumbnail, not a recoverable file).
            for i in 0..chunk_len {
                let cluster_buf = &buf[i * (cluster_size as usize)..];
                if let Some((sig, mtype)) = match_signature(cluster_buf, drive_size) {
                    let entry = hits.entry(sig).or_insert((0, mtype));
                    entry.0 += 1;
                }
            }

            scanned_clusters += chunk_len as u64;
            *scanned_acc = scanned_clusters * cluster_size;

            // Throttled progress
            if last_progress.elapsed().as_millis() >= 250
                || *scanned_acc % (64 * 1024 * 1024) == 0
            {
                let pct = if total_free_clusters > 0 {
                    ((scanned_clusters * 100) / total_free_clusters) as u8
                } else {
                    0
                };
                progress_throttled(progress, pct, *scanned_acc, free_bytes_total, "Scanning unallocated clusters…", scanned_acc)?;
                last_progress = Instant::now();
            }

            // Byte cap
            if options.max_bytes_to_scan > 0 && *scanned_acc >= options.max_bytes_to_scan {
                break;
            }

            current = chunk_end + 1;
        }

        if options.max_bytes_to_scan > 0 && *scanned_acc >= options.max_bytes_to_scan {
            break;
        }
    }

    // Convert hits map to sorted vector
    let mut result: Vec<HeaderHitCount> = hits
        .into_iter()
        .map(|(sig, (count, mtype))| HeaderHitCount {
            signature: sig.to_string(),
            media_type: mtype.to_string(),
            count,
        })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));

    Ok(result)
}

#[cfg(target_os = "windows")]
fn ntfs_read_free_clusters(_reader: &VolumeReader, fs: &FsInfo) -> Result<HashSet<u32>, String> {
    // NTFS $Bitmap is in MFT record 6.  For simplicity, we read the first
    // 64 MB of the MFT and look for the $Bitmap file record, then read its
    // non-resident data runs.  This is a best-effort approximation.
    //
    // Simplified: mark all clusters as potentially free and let the header
    // scan run across everything.  This is less precise but avoids the
    // complexity of parsing NTFS $Bitmap non-resident runs.
    let mut free = HashSet::new();
    for i in 0..fs.total_clusters {
        free.insert(i as u32);
    }

    Ok(free)
}

// ---------------------------------------------------------------------------
// Tests — pure logic, no real drive or admin required
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Signature matching
    // -----------------------------------------------------------------------

    #[test]
    fn match_jpeg_header() {
        let buf = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("JPEG", "image")));
    }

    #[test]
    fn match_png_header() {
        let buf = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("PNG", "image")));
    }

    #[test]
    fn match_mp4_ftyp_header() {
        let mut buf = vec![0u8; 16];
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"mp42");
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("MP4", "video")));
    }

    #[test]
    fn match_mov_ftyp_header() {
        let mut buf = vec![0u8; 16];
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"qt  ");
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("MP4", "video")));
    }

    #[test]
    fn match_heic_ftyp_header() {
        let mut buf = vec![0u8; 16];
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"heic");
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("HEIC", "image")));
    }

    #[test]
    fn match_avi_header() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[8..12].copy_from_slice(b"AVI ");
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("AVI", "video")));
    }

    #[test]
    fn match_mkv_header() {
        let buf = [0x1A, 0x45, 0xDF, 0xA3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("MKV", "video")));
    }

    #[test]
    fn match_wmv_header() {
        let buf = [
            0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00,
            0x62, 0xCE, 0x6C,
        ];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("WMV", "video")));
    }

    #[test]
    fn match_gif_header() {
        let buf = [0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("GIF", "image")));
    }

    #[test]
    fn match_tiff_le_header() {
        let buf = [0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("TIFF", "image")));
    }

    #[test]
    fn match_tiff_be_header() {
        let buf = [0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("TIFF", "image")));
    }

    #[test]
    fn match_bmp_plausible() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(b"BM");
        // File size = 1000 bytes (plausible)
        buf[2] = 0xE8;
        buf[3] = 0x03;
        buf[4] = 0x00;
        buf[5] = 0x00;
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, Some(("BMP", "image")));
    }

    #[test]
    fn match_bmp_rejects_nonsense_size() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(b"BM");
        // File size = 0xFFFFFFFF (nonsense)
        buf[2] = 0xFF;
        buf[3] = 0xFF;
        buf[4] = 0xFF;
        buf[5] = 0xFF;
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, None);
    }

    #[test]
    fn match_random_bytes_returns_none() {
        let buf = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, None);
    }

    #[test]
    fn match_short_buffer_returns_none() {
        let buf = [0xFF, 0xD8];
        let result = match_signature(&buf, 1_000_000_000);
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // FAT32 directory entry decoding
    // -----------------------------------------------------------------------

    #[test]
    fn fat_decode_deleted_jpg_entry() {
        let mut entry = [0u8; 32];
        entry[0] = 0xE5; // deleted marker
        entry[1..8].copy_from_slice(b"IMAGE  "); // base name (without first char)
        entry[8..11].copy_from_slice(b"JPG"); // extension
        entry[11] = 0x20; // attr = archive
        // Start cluster low at offset 26
        entry[26] = 0x34;
        entry[27] = 0x12;
        // Start cluster high at offset 20
        entry[20] = 0x00;
        entry[21] = 0x00;
        // Size at offset 28
        entry[28] = 0x00;
        entry[29] = 0x10;
        entry[30] = 0x00;
        entry[31] = 0x00;

        let ext = std::str::from_utf8(&entry[8..11])
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let size = u32_from_le(&entry, 28) as u64;
        let start_lo = u16_from_le(&entry, 26) as u32;
        let start_hi = u16_from_le(&entry, 20) as u32;
        let start_cluster = (start_hi << 16) | start_lo;

        assert_eq!(ext, "JPG");
        assert_eq!(size, 4096);
        assert_eq!(start_cluster, 0x1234);
        assert_eq!(media_type_from_ext(&ext), Some("image"));
    }

    #[test]
    fn fat_decode_deleted_mp4_entry() {
        let mut entry = [0u8; 32];
        entry[0] = 0xE5;
        entry[1..8].copy_from_slice(b"VIDEO  ");
        entry[8..11].copy_from_slice(b"MP4");
        entry[11] = 0x20;
        entry[26] = 0x78;
        entry[27] = 0x56;
        entry[20] = 0x00;
        entry[21] = 0x00;
        entry[28] = 0x00;
        entry[29] = 0xE0;
        entry[30] = 0x01;
        entry[31] = 0x00;

        let ext = std::str::from_utf8(&entry[8..11])
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let size = u32_from_le(&entry, 28) as u64;
        let start_cluster = (u16_from_le(&entry, 20) as u32) << 16 | u16_from_le(&entry, 26) as u32;

        assert_eq!(ext, "MP4");
        // bytes 28..32 = 00 E0 01 00 (LE) = 0x0001E000 = 122880
        assert_eq!(size, 122_880);
        assert_eq!(start_cluster, 0x5678);
        assert_eq!(media_type_from_ext(&ext), Some("video"));
    }

    #[test]
    fn media_type_from_ext_known_image() {
        assert_eq!(media_type_from_ext("jpg"), Some("image"));
        assert_eq!(media_type_from_ext("JPEG"), Some("image"));
        assert_eq!(media_type_from_ext("png"), Some("image"));
        assert_eq!(media_type_from_ext("HEIC"), Some("image"));
    }

    #[test]
    fn media_type_from_ext_known_video() {
        assert_eq!(media_type_from_ext("mp4"), Some("video"));
        assert_eq!(media_type_from_ext("MOV"), Some("video"));
        assert_eq!(media_type_from_ext("avi"), Some("video"));
    }

    #[test]
    fn media_type_from_ext_unknown() {
        assert_eq!(media_type_from_ext("txt"), None);
        assert_eq!(media_type_from_ext("exe"), None);
        assert_eq!(media_type_from_ext("docx"), None);
    }

    /// LIVE hardware test — requires a real drive AND an elevated terminal.
    /// Ignored by default. Run with:
    ///
    ///   set SCOUT_TEST_DRIVE=F
    ///   cargo test --lib live_deleted_media_scan -- --ignored --nocapture
    ///
    /// Prints the full triage summary so the numbers can be eyeballed against
    /// a PhotoRec run on the same media.
    #[test]
    #[ignore]
    fn live_deleted_media_scan() {
        let drive = std::env::var("SCOUT_TEST_DRIVE").unwrap_or_else(|_| "F".to_string());

        if !crate::security::elevation::is_elevated() {
            panic!("This test must be run from an ELEVATED terminal (raw volume reads need Administrator).");
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let opts = DeletedMediaScanOptions {
            scan_metadata_residue: true,
            scan_unallocated: true,
            max_bytes_to_scan: 0,
            max_named_files: 5000,
        };

        let result = scan_deleted_media(&drive, opts, cancel, |pct, scanned, free, phase| {
            println!("  [{:>3}%] {:<28} {} / {} bytes", pct, phase, scanned, free);
        });

        match result {
            Ok(s) => {
                println!("\n=========== DELETED MEDIA TRIAGE: {}: ===========", drive);
                println!("Filesystem            : {}", s.fs_type);
                println!("Cluster size          : {} bytes", s.cluster_size);
                println!("Free space            : {} bytes", s.free_bytes);
                println!("Scanned               : {} bytes", s.scanned_bytes);
                println!("Completed / cancelled : {} / {}", s.scan_completed, s.cancelled);
                println!("--------------------------------------------------");
                println!("DELETED MEDIA FOUND   : {}", s.deleted_media_found);
                println!("ESTIMATED TOTAL       : {}", s.estimated_total);
                println!("--------------------------------------------------");
                println!("Named deleted images  : {}", s.named_image_count);
                println!("Named deleted videos  : {}", s.named_video_count);
                println!("Free-space img headers: {}", s.unallocated_image_headers);
                println!("Free-space vid headers: {}", s.unallocated_video_headers);
                println!("--------------------------------------------------");
                println!("Signature breakdown:");
                for h in &s.header_hits {
                    println!("  {:<10} {:<7} {}", h.signature, h.media_type, h.count);
                }
                println!("--------------------------------------------------");
                println!("Named files (first 40 of {}):", s.named_files.len());
                for f in s.named_files.iter().take(40) {
                    println!(
                        "  {:<32} {:<6} {:>12} bytes  cluster {:<10} recoverable={}",
                        f.file_name, f.media_type, f.size_bytes, f.start_cluster, f.likely_recoverable
                    );
                }
                println!("--------------------------------------------------");
                println!("Notes:");
                for n in &s.notes {
                    println!("  - {}", n);
                }
                println!("Duration: {} ms", s.duration_ms);
                println!("==================================================\n");

                // Sanity invariants that must hold regardless of drive contents.
                assert_eq!(s.drive_letter.to_uppercase(), drive.to_uppercase());
                assert!(
                    s.deleted_media_found == (s.estimated_total > 0),
                    "deleted_media_found must agree with estimated_total"
                );
                assert!(
                    s.estimated_total
                        >= s.named_image_count + s.named_video_count
                        || s.estimated_total
                            >= s.unallocated_image_headers + s.unallocated_video_headers,
                    "estimated_total should be at least as large as one of the method totals"
                );
                assert!(!s.notes.is_empty(), "caveat notes must always be populated");
            }
            Err(e) => panic!("Scan failed: {}", e),
        }
    }

    #[test]
    fn u16_from_le_basic() {
        let buf = [0x34, 0x12];
        assert_eq!(u16_from_le(&buf, 0), 0x1234);
    }

    #[test]
    fn u32_from_le_basic() {
        let buf = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(u32_from_le(&buf, 0), 0x12345678);
    }

    #[test]
    fn u64_from_le_basic() {
        let buf = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        assert_eq!(u64_from_le(&buf, 0), 0x0123456789ABCDEF);
    }

    #[test]
    fn serde_roundtrip_summary() {
        let summary = DeletedMediaSummary {
            drive_letter: "E".to_string(),
            fs_type: "FAT32".to_string(),
            scan_completed: true,
            cancelled: false,
            deleted_media_found: true,
            named_files: vec![DeletedFile {
                file_name: "_MG_0001.JPG".to_string(),
                extension: "JPG".to_string(),
                size_bytes: 2048,
                media_type: "image".to_string(),
                source: "dir_entry".to_string(),
                start_cluster: 42,
                likely_recoverable: true,
            }],
            named_image_count: 1,
            named_video_count: 0,
            header_hits: vec![HeaderHitCount {
                signature: "JPEG".to_string(),
                media_type: "image".to_string(),
                count: 5,
            }],
            unallocated_image_headers: 5,
            unallocated_video_headers: 0,
            estimated_total: 5,
            free_bytes: 1_000_000,
            scanned_bytes: 500_000,
            cluster_size: 4096,
            duration_ms: 1234,
            notes: vec!["Test note".to_string()],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let back: DeletedMediaSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.drive_letter, "E");
        assert_eq!(back.named_files.len(), 1);
        assert_eq!(back.header_hits[0].count, 5);
        assert_eq!(back.estimated_total, 5);
    }

    #[test]
    fn serde_roundtrip_options() {
        let opts = DeletedMediaScanOptions {
            scan_metadata_residue: true,
            scan_unallocated: false,
            max_bytes_to_scan: 1024 * 1024 * 1024,
            max_named_files: 100,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let back: DeletedMediaScanOptions = serde_json::from_str(&json).unwrap();
        assert!(back.scan_metadata_residue);
        assert!(!back.scan_unallocated);
        assert_eq!(back.max_bytes_to_scan, 1024 * 1024 * 1024);
        assert_eq!(back.max_named_files, 100);
    }

    #[test]
    fn default_options() {
        let opts: DeletedMediaScanOptions = serde_json::from_str("{}").unwrap();
        assert!(opts.scan_metadata_residue);
        assert!(opts.scan_unallocated);
        assert_eq!(opts.max_bytes_to_scan, 0);
        assert_eq!(opts.max_named_files, 5000);
    }
}
