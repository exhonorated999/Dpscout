//! BitLocker discovery — volume protection state, recovery passwords, and a
//! sweep for recovery-key artifacts left on disk.
//!
//! # Why this exists
//!
//! An officer triaging a live machine needs the 48-digit recovery password
//! *before* they can image an encrypted volume, or re-mount it later. Scout
//! already reports drive letters and filesystems (`system_info/hardware.rs`)
//! but said nothing about encryption.
//!
//! # Clean-room notice
//!
//! This module was written from Microsoft's published documentation for the
//! `Win32_EncryptableVolume` WMI provider and the documented recovery-password
//! format. It is deliberately **not** derived from
//! `northloopforensics/Bitlocker_Key_Finder`, which is CC BY-NC 4.0 and whose
//! terms are incompatible with Scout being sold commercially. No code from
//! that project was read, copied, or translated while writing this.
//!
//! # Elevation
//!
//! Measured on Windows 11 24H2/25H2, unelevated: `Get-CimInstance
//! Win32_EncryptableVolume`, `Get-BitLockerVolume` and `manage-bde -status`
//! all return *Access denied* — even a `Get-CimClass` schema lookup does.
//! So the entire live-volume side (status **and** key) is admin-gated, not
//! just the key. Only the file sweep works without elevation, which is why
//! the two are reported separately.
//!
//! # Why WMI rather than `manage-bde`
//!
//! `manage-bde` output is localized; a German or Spanish Windows would break
//! any text parser. WMI returns integers we map ourselves. It also avoids a
//! subprocess and a console-window flash, and adds no new `wmic` caller
//! (`wmic` is being removed from Windows — see `docs/WMIC_REMOVAL_BACKLOG.md`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// How much of the disk to sweep for stray key files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepScope {
    /// No file sweep at all.
    None,
    /// User profiles and the usual dumping grounds. Cheap enough to run
    /// inline during a normal scan.
    Targeted,
    /// Whole drives. Minutes long — runs only from the dedicated streaming
    /// command so it never holds the Device Info tab hostage.
    Full,
}

impl SweepScope {
    fn as_str(self) -> &'static str {
        match self {
            SweepScope::None => "none",
            SweepScope::Targeted => "targeted",
            SweepScope::Full => "full",
        }
    }
}

/// Top-level BitLocker result attached to every Windows scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitLockerFindings {
    /// False on non-Windows, or when the volume-encryption provider is absent.
    pub supported: bool,
    /// Whether Scout could read the live-volume state. Drives the UI notice.
    pub elevated: bool,
    /// Headline state for the report: `Enabled`, `Not Enabled`,
    /// `Requires Administrator`, or `Not Supported`.
    pub status: String,
    /// One-line human explanation of `status`.
    pub status_detail: String,
    pub volumes: Vec<BitLockerVolume>,
    pub key_files: Vec<BitLockerKeyFile>,
    /// `none` | `targeted` | `full`
    pub sweep_scope: String,
    /// Set when collection failed outright, rather than merely finding nothing.
    pub error: Option<String>,
}

impl BitLockerFindings {
    fn empty(scope: SweepScope) -> Self {
        BitLockerFindings {
            supported: cfg!(target_os = "windows"),
            elevated: false,
            status: STATUS_UNSUPPORTED.to_string(),
            status_detail: "BitLocker reporting is only available on Windows.".to_string(),
            volumes: Vec::new(),
            key_files: Vec::new(),
            sweep_scope: scope.as_str().to_string(),
            error: None,
        }
    }

    /// True when at least one volume reports protection on.
    pub fn any_protected(&self) -> bool {
        self.volumes.iter().any(|v| v.protected)
    }

    /// Every recovery password recovered, from volumes and from files.
    pub fn recovered_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for v in &self.volumes {
            if let Some(k) = &v.recovery_password {
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }
        for f in &self.key_files {
            for k in &f.recovery_passwords {
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }
        keys
    }
}

/// A single encryptable volume as reported by WMI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitLockerVolume {
    pub drive_letter: Option<String>,
    pub device_id: Option<String>,
    pub persistent_volume_id: Option<String>,
    /// Convenience flag so the UI does not have to string-match.
    pub protected: bool,
    pub protection_status: String,
    pub lock_status: String,
    pub conversion_status: String,
    pub encryption_method: String,
    pub encryption_percentage: Option<u32>,
    /// GUID identifying which recovery password unlocks this volume.
    pub recovery_key_id: Option<String>,
    /// The 48-digit recovery password. `None` when not elevated, when the
    /// volume has no numerical-password protector, or when the call failed.
    pub recovery_password: Option<String>,
    /// Populated when a specific WMI call failed for this volume only.
    pub note: Option<String>,
}

/// A recovery-key artifact found on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitLockerKeyFile {
    pub path: String,
    /// `BEK` | `TXT` | `CSV` | `RTF` | `DOCX` | `XLSX`
    pub file_type: String,
    pub recovery_key_id: Option<String>,
    /// Every 48-digit password found in this file.
    pub recovery_passwords: Vec<String>,
    /// True when every recovered password satisfies BitLocker's published
    /// divisible-by-11 group check. A structurally valid but checksum-failing
    /// string is still reported — it may be a transcription error worth
    /// showing an examiner — but it is flagged.
    pub checksum_valid: bool,
    pub modified: Option<String>,
    pub size_bytes: Option<u64>,
}

pub const STATUS_ENABLED: &str = "Enabled";
pub const STATUS_NOT_ENABLED: &str = "Not Enabled";
pub const STATUS_NEEDS_ADMIN: &str = "Requires Administrator";
pub const STATUS_UNSUPPORTED: &str = "Not Supported";

// ---------------------------------------------------------------------------
// Recovery-password parsing
// ---------------------------------------------------------------------------
//
// A BitLocker recovery password is 8 groups of 6 digits joined by hyphens:
//
//     123456-123456-123456-123456-123456-123456-123456-123456
//
// 48 digits + 7 hyphens = 55 characters. Microsoft additionally documents
// that each group is divisible by 11 and that group/11 fits in 16 bits, which
// makes an excellent false-positive filter when sweeping documents that are
// full of unrelated long numbers.
//
// Hand-rolled rather than pulling in the `regex` crate: the grammar is fixed
// and trivial, and a forensics binary is better off with one less dependency.

/// Number of digit groups in a recovery password.
const GROUPS: usize = 8;
/// Digits per group.
const GROUP_LEN: usize = 6;
/// Full rendered length, including hyphens.
pub const RECOVERY_PASSWORD_LEN: usize = GROUPS * GROUP_LEN + (GROUPS - 1);

/// True when `s` is exactly 8 hyphen-separated groups of 6 ASCII digits.
pub fn is_recovery_password_shape(s: &str) -> bool {
    if s.len() != RECOVERY_PASSWORD_LEN {
        return false;
    }
    let mut groups = 0;
    for part in s.split('-') {
        if part.len() != GROUP_LEN || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        groups += 1;
    }
    groups == GROUPS
}

/// BitLocker's published validity rule: every 6-digit group is divisible by
/// 11, and the quotient fits in 16 bits.
///
/// Assumes `s` already passed [`is_recovery_password_shape`].
pub fn recovery_password_checksum_ok(s: &str) -> bool {
    if !is_recovery_password_shape(s) {
        return false;
    }
    s.split('-').all(|part| match part.parse::<u32>() {
        Ok(n) => n % 11 == 0 && (n / 11) <= 0xFFFF,
        Err(_) => false,
    })
}

/// Pull every recovery password out of arbitrary text.
///
/// Scans for runs of digits and hyphens and tests each candidate, so it works
/// whether the key sits on its own line, is indented inside Microsoft's
/// standard recovery `.txt`, or is embedded mid-sentence in a note.
/// Only checksum-passing keys are returned when `require_checksum` is set.
pub fn find_recovery_passwords(text: &str, require_checksum: bool) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Walk the maximal digit/hyphen run starting here.
        let start = i;
        let mut j = i;
        while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'-') {
            j += 1;
        }
        // A run can be longer than one key (e.g. two keys separated by a
        // hyphen, or trailing punctuation), so slide a fixed window over it.
        if j - start >= RECOVERY_PASSWORD_LEN {
            let run = &text[start..j];
            let run_bytes = run.as_bytes();
            let mut k = 0usize;
            while k + RECOVERY_PASSWORD_LEN <= run_bytes.len() {
                let cand = &run[k..k + RECOVERY_PASSWORD_LEN];
                if is_recovery_password_shape(cand)
                    && (!require_checksum || recovery_password_checksum_ok(cand))
                {
                    let owned = cand.to_string();
                    if !out.contains(&owned) {
                        out.push(owned);
                    }
                    k += RECOVERY_PASSWORD_LEN;
                    continue;
                }
                k += 1;
            }
        }
        i = j.max(start + 1);
    }
    out
}

/// Extract a BitLocker recovery Key ID (a GUID) from text or a filename.
///
/// Microsoft's recovery `.txt` labels it `Identifier:`, and `.BEK` files are
/// named for it. Accepts the GUID with or without surrounding braces.
///
/// Matches ANY GUID, so it is only safe on input that is already known to be
/// about BitLocker — a filename that says so, or a `.BEK` stem. For arbitrary
/// file contents use [`find_labelled_key_id`]: ordinary logs, configs and CSVs
/// are full of GUIDs, and treating every one of them as a key artifact buries
/// the real hits under hundreds of false positives.
pub fn find_key_id(text: &str) -> Option<String> {
    scan_guids(text, true).into_iter().next().map(|(_, g)| g)
}

/// Markers that, on their own, are enough to read a nearby GUID as a
/// BitLocker recovery Key ID.
const KEY_ID_STRONG_MARKERS: [&str; 3] = ["bitlocker", "recovery key", "recovery password"];

/// Markers that are suggestive but far too common to trust alone. `identifier`
/// is the word Microsoft's recovery file uses directly above the value, but it
/// is also ordinary English that appears next to a GUID in any application log
/// (`ScanRequest(identifier: …`). These only count when the file mentions
/// BitLocker somewhere — which Microsoft's file does, in its first line.
const KEY_ID_WEAK_MARKERS: [&str; 3] = ["identifier", "key id", "keyid"];

/// How far back to look for a marker. Wide enough to span a label and the
/// whitespace Windows puts after it, narrow enough that an unrelated mention
/// elsewhere in the file cannot vouch for a GUID hundreds of characters away.
const KEY_ID_CONTEXT_WINDOW: usize = 160;

/// Like [`find_key_id`], but only accepts a GUID that nearby text labels as a
/// BitLocker identifier. Use this on file *contents* that have not otherwise
/// identified themselves.
pub fn find_labelled_key_id(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    // One lowercase pass for the document-wide test. Only used for a
    // `contains`, so a length change from `to_lowercase` is harmless here.
    let mentions_bitlocker = text.to_lowercase().contains("bitlocker");

    for (idx, guid) in scan_guids(text, false) {
        let start = idx.saturating_sub(KEY_ID_CONTEXT_WINDOW);
        // Lowercase only the window, not the whole file: `to_lowercase` can
        // change a string's length, so a parallel lowercased copy would not
        // line up with the offsets `scan_guids` reports.
        let window: String = chars[start..idx].iter().collect::<String>().to_lowercase();

        let strong = KEY_ID_STRONG_MARKERS.iter().any(|m| window.contains(m));
        let weak = mentions_bitlocker && KEY_ID_WEAK_MARKERS.iter().any(|m| window.contains(m));
        if strong || weak {
            return Some(guid);
        }
    }
    None
}

/// Every 8-4-4-4-12 GUID in `text`, as (char offset, uppercased GUID).
///
/// `first_only` short-circuits after one match for the common case.
fn scan_guids(text: &str, first_only: bool) -> Vec<(usize, String)> {
    const SHAPE: [usize; 5] = [8, 4, 4, 4, 12];
    let chars: Vec<char> = text.chars().collect();
    let total: usize = SHAPE.iter().sum::<usize>() + SHAPE.len() - 1;
    let mut out: Vec<(usize, String)> = Vec::new();

    let mut i = 0usize;
    while i + total <= chars.len() {
        let window: String = chars[i..i + total].iter().collect();
        if is_guid_shape(&window, &SHAPE) {
            // Reject a match that is really part of a longer hex run.
            let prev_ok = i == 0 || !chars[i - 1].is_ascii_hexdigit();
            let next_ok = i + total >= chars.len() || !chars[i + total].is_ascii_hexdigit();
            if prev_ok && next_ok {
                out.push((i, window.to_uppercase()));
                if first_only {
                    return out;
                }
                i += total;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_guid_shape(s: &str, shape: &[usize]) -> bool {
    let mut parts = s.split('-');
    for &len in shape {
        match parts.next() {
            Some(p) if p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()) => {}
            _ => return false,
        }
    }
    parts.next().is_none()
}

// ---------------------------------------------------------------------------
// Text decoding
// ---------------------------------------------------------------------------

/// Decode a file's bytes to text, honouring UTF-16 BOMs.
///
/// This matters more than it looks: the `BitLocker Recovery Key *.txt` file
/// Windows itself writes is **UTF-16LE with a BOM**. Reading it as UTF-8
/// yields digits interleaved with NUL bytes, and every parser downstream
/// silently finds nothing. Missing this would make the feature appear to work
/// while failing on the single most important artifact it exists to find.
pub fn decode_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 {
        // UTF-16LE BOM
        if bytes[0] == 0xFF && bytes[1] == 0xFE {
            return decode_utf16(&bytes[2..], true);
        }
        // UTF-16BE BOM
        if bytes[0] == 0xFE && bytes[1] == 0xFF {
            return decode_utf16(&bytes[2..], false);
        }
    }
    // UTF-8 BOM
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    // Heuristic: BOM-less UTF-16LE ASCII shows up as every other byte NUL.
    if bytes.len() >= 16 {
        let sample = &bytes[..bytes.len().min(512)];
        let nuls = sample.iter().filter(|&&b| b == 0).count();
        if nuls * 3 > sample.len() {
            return decode_utf16(bytes, true);
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

// ---------------------------------------------------------------------------
// WMI enum → display string
// ---------------------------------------------------------------------------
// Values per Microsoft's Win32_EncryptableVolume documentation. Mapped here
// rather than parsed from localized tool output.

pub fn protection_status_str(v: u32) -> &'static str {
    match v {
        0 => "Protection Off",
        1 => "Protection On",
        2 => "Protection Unknown",
        _ => "Unrecognized",
    }
}

pub fn lock_status_str(v: u32) -> &'static str {
    match v {
        0 => "Unlocked",
        1 => "Locked",
        _ => "Unrecognized",
    }
}

pub fn conversion_status_str(v: u32) -> &'static str {
    match v {
        0 => "Fully Decrypted",
        1 => "Fully Encrypted",
        2 => "Encryption In Progress",
        3 => "Decryption In Progress",
        4 => "Encryption Paused",
        5 => "Decryption Paused",
        _ => "Unrecognized",
    }
}

pub fn encryption_method_str(v: u32) -> &'static str {
    match v {
        0 => "None",
        1 => "AES 128 with Diffuser",
        2 => "AES 256 with Diffuser",
        3 => "AES 128",
        4 => "AES 256",
        5 => "Hardware Encryption",
        6 => "XTS-AES 128",
        7 => "XTS-AES 256",
        _ => "Unrecognized",
    }
}

/// Key-protector type IDs. 3 is the 48-digit numerical password we want.
pub const KEY_PROTECTOR_NUMERICAL_PASSWORD: u32 = 3;

// ---------------------------------------------------------------------------
// File sweep
// ---------------------------------------------------------------------------

/// Largest file we will read looking for a key. Recovery notes are tiny; this
/// only exists to stop the sweep choking on a multi-gigabyte log.
const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;

/// Decide whether a path is worth opening, based on name and extension alone.
///
/// Kept separate from any I/O so it can be unit-tested directly and so the
/// full-drive walk can reject the overwhelming majority of files without a
/// syscall beyond the directory read.
pub fn classify_candidate(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();

    if name.ends_with(".bek") {
        return Some("BEK");
    }
    // Microsoft's default filename, in any language pack that keeps the
    // English stem, plus the common manual variants officers actually create.
    let looks_like_key_note = name.starts_with("bitlocker recovery key")
        || name.starts_with("bitlocker-recovery-key")
        || (name.contains("bitlocker") && name.contains("key"))
        || (name.contains("bitlocker") && name.contains("recovery"));

    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "txt" | "csv" | "rtf" | "log" => Some(match ext.as_str() {
            "txt" => "TXT",
            "csv" => "CSV",
            "rtf" => "RTF",
            _ => "LOG",
        }),
        "docx" => Some("DOCX"),
        "xlsx" => Some("XLSX"),
        _ if looks_like_key_note => Some("TXT"),
        _ => None,
    }
}

/// Inspect one candidate file. Returns `None` when nothing was found.
///
/// `require_checksum` should be true for broad sweeps (to suppress false
/// positives from documents full of numbers) and false for files whose *name*
/// already says they are BitLocker keys.
pub fn inspect_file(path: &Path, file_type: &str) -> Option<BitLockerKeyFile> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let size = meta.len();

    let name_is_explicit = path
        .file_name()
        .map(|n| {
            let n = n.to_string_lossy().to_ascii_lowercase();
            n.contains("bitlocker") || n.ends_with(".bek")
        })
        .unwrap_or(false);

    // A file that announces itself as a BitLocker key gets the benefit of the
    // doubt; a random spreadsheet has to pass the checksum.
    let require_checksum = !name_is_explicit;

    // Same asymmetry for the Key ID. In a file already named for BitLocker,
    // a bare GUID is almost certainly the identifier. In an arbitrary file it
    // is almost certainly not — GUIDs are everywhere in logs, configs and
    // exports — so there it has to be labelled as one.
    let read_key_id: fn(&str) -> Option<String> = if name_is_explicit {
        find_key_id
    } else {
        find_labelled_key_id
    };

    let mut passwords: Vec<String> = Vec::new();
    let mut key_id: Option<String> = None;

    match file_type {
        "BEK" => {
            // A .BEK holds an external startup key, not a recovery password —
            // there is nothing printable to recover. Its value to an examiner
            // is its existence and the Key ID in its filename.
            key_id = path.file_stem().and_then(|s| find_key_id(&s.to_string_lossy()));
        }
        "DOCX" => {
            if size <= MAX_ARCHIVE_BYTES {
                if let Some(text) = read_ooxml_text(path, &["word/document.xml"]) {
                    passwords = find_recovery_passwords(&text, require_checksum);
                    key_id = read_key_id(&text);
                }
            }
        }
        "XLSX" => {
            if size <= MAX_ARCHIVE_BYTES {
                if let Some(text) =
                    read_ooxml_text(path, &["xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"])
                {
                    passwords = find_recovery_passwords(&text, require_checksum);
                    key_id = read_key_id(&text);
                }
            }
        }
        _ => {
            if size <= MAX_TEXT_BYTES {
                let bytes = std::fs::read(path).ok()?;
                let text = decode_text(&bytes);
                passwords = find_recovery_passwords(&text, require_checksum);
                key_id = read_key_id(&text);
            }
        }
    }

    // Nothing of interest: no key, no id, and not a .BEK.
    if passwords.is_empty() && key_id.is_none() && file_type != "BEK" {
        return None;
    }

    let checksum_valid = passwords.iter().all(|p| recovery_password_checksum_ok(p));

    let modified = meta.modified().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });

    Some(BitLockerKeyFile {
        path: path.to_string_lossy().to_string(),
        file_type: file_type.to_string(),
        recovery_key_id: key_id,
        recovery_passwords: passwords,
        checksum_valid,
        modified,
        size_bytes: Some(size),
    })
}

/// Pull text out of selected parts of an OOXML package, stripping tags.
fn read_ooxml_text(path: &Path, parts: &[&str]) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut zip = zip::ZipArchive::new(file).ok()?;
    let mut combined = String::new();

    for part in parts {
        if let Ok(mut entry) = zip.by_name(part) {
            use std::io::Read;
            let mut buf = Vec::new();
            if entry.read_to_end(&mut buf).is_ok() {
                combined.push_str(&strip_xml_tags(&String::from_utf8_lossy(&buf)));
                combined.push('\n');
            }
        }
    }
    if combined.trim().is_empty() {
        None
    } else {
        Some(combined)
    }
}

/// Crude but sufficient tag stripper. We only need the digit runs.
fn strip_xml_tags(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len() / 2);
    let mut in_tag = false;
    for c in xml.chars() {
        match c {
            '<' => in_tag = true,
            // Emit a separator so `<a>123</a><b>456</b>` cannot fuse into one run.
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Directories that are never worth walking during a full sweep.
pub fn is_excluded_dir(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "$recycle.bin"
            | "system volume information"
            | "windows"
            | "winsxs"
            | "node_modules"
            | "$windows.~bt"
            | "$windows.~ws"
            | "programdata"
            | "program files"
            | "program files (x86)"
    )
}

/// The targeted sweep roots: each user's profile plus the usual dumping
/// grounds, and the root of every removable volume.
fn targeted_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();

    // Reuse the account enumeration the rest of system_info already does
    // rather than re-deriving profile paths.
    if let Ok(accounts) = super::get_user_accounts() {
        for a in accounts {
            let profile = PathBuf::from(&a.profile_path);
            if profile.as_os_str().is_empty() {
                continue;
            }
            for sub in [
                "Desktop",
                "Documents",
                "Downloads",
                "OneDrive",
                "OneDrive/Documents",
                "OneDrive/Desktop",
            ] {
                roots.push(profile.join(sub));
            }
            roots.push(profile);
        }
    }

    // Removable volumes: officers routinely save the key straight to a stick.
    #[cfg(target_os = "windows")]
    {
        for letter in b'A'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            if is_removable_drive(&root) {
                roots.push(PathBuf::from(root));
            }
        }
    }

    roots.sort();
    roots.dedup();
    roots
}

#[cfg(target_os = "windows")]
fn is_removable_drive(root: &str) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetDriveTypeW;

    const DRIVE_REMOVABLE: u32 = 2;
    let wide: Vec<u16> = std::ffi::OsStr::new(root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOVABLE }
}

/// Walk `roots` to a bounded depth looking for key artifacts.
///
/// `max_depth` keeps the targeted sweep inline-cheap; the full sweep passes a
/// large value. `cancelled` lets the existing Cancel button stop the walk.
pub fn sweep_roots(
    roots: &[PathBuf],
    max_depth: usize,
    cancelled: &dyn Fn() -> bool,
    mut on_found: impl FnMut(&BitLockerKeyFile),
) -> Vec<BitLockerKeyFile> {
    let mut found: Vec<BitLockerKeyFile> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for root in roots {
        if cancelled() {
            break;
        }
        if !root.exists() {
            continue;
        }

        // `skip_hidden(false)` is essential: `.BEK` files are created hidden,
        // and so is the folder Windows writes them to. Default settings would
        // silently miss every external key on the machine.
        let walker = jwalk::WalkDir::new(root)
            .skip_hidden(false)
            .max_depth(max_depth)
            .process_read_dir(|_, _, _, children| {
                children.retain(|entry| match entry {
                    Ok(e) => {
                        if e.file_type().is_dir() {
                            !is_excluded_dir(&e.file_name().to_string_lossy())
                        } else {
                            true
                        }
                    }
                    Err(_) => false,
                });
            });

        for entry in walker {
            if cancelled() {
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let Some(kind) = classify_candidate(&path) else {
                continue;
            };
            let key = path.to_string_lossy().to_ascii_lowercase();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);

            if let Some(hit) = inspect_file(&path, kind) {
                on_found(&hit);
                found.push(hit);
            }
        }
    }
    found
}

/// Roots for a full sweep of the given drives.
pub fn full_sweep_roots(drives: &[String]) -> Vec<PathBuf> {
    drives
        .iter()
        .map(|d| {
            let d = d.trim();
            if d.ends_with('\\') || d.ends_with('/') {
                PathBuf::from(d)
            } else if d.len() <= 2 {
                PathBuf::from(format!("{}\\", d))
            } else {
                PathBuf::from(d)
            }
        })
        .collect()
}

/// Run a full-drive sweep. Used by the streaming Tauri command.
pub fn sweep_full(
    drives: &[String],
    cancelled: &dyn Fn() -> bool,
    on_found: impl FnMut(&BitLockerKeyFile),
) -> Vec<BitLockerKeyFile> {
    let roots = full_sweep_roots(drives);
    sweep_roots(&roots, usize::MAX, cancelled, on_found)
}

// ---------------------------------------------------------------------------
// Live volume interrogation (Windows, elevated)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod live {
    use super::*;
    use serde::Deserialize;

    const NAMESPACE: &str = r"root\CIMV2\Security\MicrosoftVolumeEncryption";

    // The struct name must match the WMI class name — the `wmi` crate derives
    // the class from the Rust type name for both queries and method calls.
    #[derive(Deserialize, Debug)]
    #[allow(non_camel_case_types, non_snake_case)]
    struct Win32_EncryptableVolume {
        __Path: String,
        DeviceID: Option<String>,
        DriveLetter: Option<String>,
        PersistentVolumeID: Option<String>,
        ProtectionStatus: Option<u32>,
    }

    #[derive(serde::Serialize)]
    #[allow(non_snake_case)]
    struct GetKeyProtectorsIn {
        KeyProtectorType: u32,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct GetKeyProtectorsOut {
        ReturnValue: Option<u32>,
        VolumeKeyProtectorID: Option<Vec<String>>,
    }

    #[derive(serde::Serialize)]
    #[allow(non_snake_case)]
    struct GetNumericalPasswordIn {
        VolumeKeyProtectorID: String,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct GetNumericalPasswordOut {
        ReturnValue: Option<u32>,
        NumericalPassword: Option<String>,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct GetConversionStatusOut {
        ReturnValue: Option<u32>,
        ConversionStatus: Option<u32>,
        EncryptionPercentage: Option<u32>,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct GetEncryptionMethodOut {
        ReturnValue: Option<u32>,
        EncryptionMethod: Option<u32>,
    }

    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct GetLockStatusOut {
        ReturnValue: Option<u32>,
        LockStatus: Option<u32>,
    }

    /// Query every encryptable volume and, where possible, its recovery key.
    ///
    /// Returns `Err` only when the provider itself is unreachable; a failure
    /// affecting one volume is recorded in that volume's `note`.
    pub fn collect_volumes() -> Result<Vec<BitLockerVolume>, String> {
        use wmi::{COMLibrary, WMIConnection};

        let com = COMLibrary::new().map_err(|e| format!("COM init failed: {}", e))?;
        let conn = WMIConnection::with_namespace_path(NAMESPACE, com).map_err(|e| {
            format!(
                "Cannot reach the volume-encryption provider ({}): {}",
                NAMESPACE, e
            )
        })?;

        let rows: Vec<Win32_EncryptableVolume> = conn
            .query()
            .map_err(|e| format!("Win32_EncryptableVolume query failed: {}", e))?;

        let mut volumes = Vec::with_capacity(rows.len());
        for row in rows {
            volumes.push(describe_volume(&conn, row));
        }
        Ok(volumes)
    }

    fn describe_volume(
        conn: &wmi::WMIConnection,
        row: Win32_EncryptableVolume,
    ) -> BitLockerVolume {
        let path = row.__Path.clone();
        let mut notes: Vec<String> = Vec::new();

        let protection = row.ProtectionStatus.unwrap_or(2);

        let lock = match conn.exec_instance_method::<Win32_EncryptableVolume, _, GetLockStatusOut>(
            "GetLockStatus",
            &path,
            (),
        ) {
            Ok(o) => o.LockStatus,
            Err(e) => {
                notes.push(format!("lock status unavailable: {}", e));
                None
            }
        };

        let (conversion, percent) = match conn
            .exec_instance_method::<Win32_EncryptableVolume, _, GetConversionStatusOut>(
                "GetConversionStatus",
                &path,
                (),
            ) {
            Ok(o) => (o.ConversionStatus, o.EncryptionPercentage),
            Err(e) => {
                notes.push(format!("conversion status unavailable: {}", e));
                (None, None)
            }
        };

        let method = match conn
            .exec_instance_method::<Win32_EncryptableVolume, _, GetEncryptionMethodOut>(
                "GetEncryptionMethod",
                &path,
                (),
            ) {
            Ok(o) => o.EncryptionMethod,
            Err(e) => {
                notes.push(format!("encryption method unavailable: {}", e));
                None
            }
        };

        // Recovery password: enumerate numerical-password protectors, then ask
        // for the password behind the first one that yields it.
        let mut key_id: Option<String> = None;
        let mut password: Option<String> = None;

        match conn.exec_instance_method::<Win32_EncryptableVolume, _, GetKeyProtectorsOut>(
            "GetKeyProtectors",
            &path,
            GetKeyProtectorsIn {
                KeyProtectorType: KEY_PROTECTOR_NUMERICAL_PASSWORD,
            },
        ) {
            Ok(out) => {
                let ids = out.VolumeKeyProtectorID.unwrap_or_default();
                if ids.is_empty() && out.ReturnValue.unwrap_or(0) == 0 {
                    notes.push("no numerical-password protector on this volume".to_string());
                }
                for id in ids {
                    if key_id.is_none() {
                        key_id = Some(id.trim_matches(|c| c == '{' || c == '}').to_uppercase());
                    }
                    match conn
                        .exec_instance_method::<Win32_EncryptableVolume, _, GetNumericalPasswordOut>(
                            "GetKeyProtectorNumericalPassword",
                            &path,
                            GetNumericalPasswordIn {
                                VolumeKeyProtectorID: id.clone(),
                            },
                        ) {
                        Ok(p) => {
                            if let Some(pw) = p.NumericalPassword {
                                let pw = pw.trim().to_string();
                                if is_recovery_password_shape(&pw) {
                                    password = Some(pw);
                                    break;
                                }
                            }
                        }
                        Err(e) => notes.push(format!("recovery password unavailable: {}", e)),
                    }
                }
            }
            Err(e) => notes.push(format!("key protector enumeration failed: {}", e)),
        }

        BitLockerVolume {
            drive_letter: row.DriveLetter.map(|d| d.trim().to_string()),
            device_id: row.DeviceID,
            persistent_volume_id: row.PersistentVolumeID,
            protected: protection == 1,
            protection_status: protection_status_str(protection).to_string(),
            lock_status: lock.map(|v| lock_status_str(v).to_string()).unwrap_or_else(|| "Unknown".into()),
            conversion_status: conversion
                .map(|v| conversion_status_str(v).to_string())
                .unwrap_or_else(|| "Unknown".into()),
            encryption_method: method
                .map(|v| encryption_method_str(v).to_string())
                .unwrap_or_else(|| "Unknown".into()),
            encryption_percentage: percent,
            recovery_key_id: key_id,
            recovery_password: password,
            note: if notes.is_empty() {
                None
            } else {
                Some(notes.join("; "))
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Collect BitLocker findings for a scan.
///
/// Never returns `Err` — a BitLocker problem must not fail the whole scan, so
/// failures are reported inside the struct (mirroring how `collect_system_info`
/// already treats USB history).
pub fn collect(scope: SweepScope) -> BitLockerFindings {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = scope;
        return BitLockerFindings::empty(scope);
    }

    #[cfg(target_os = "windows")]
    {
        let mut findings = BitLockerFindings::empty(scope);
        findings.supported = true;
        findings.elevated = crate::security::elevation::is_elevated();

        if findings.elevated {
            match live::collect_volumes() {
                Ok(volumes) => {
                    let protected = volumes.iter().any(|v| v.protected);
                    findings.volumes = volumes;
                    if findings.volumes.is_empty() {
                        findings.status = STATUS_NOT_ENABLED.to_string();
                        findings.status_detail =
                            "No encryptable volumes were reported by Windows.".to_string();
                    } else if protected {
                        let n = findings.volumes.iter().filter(|v| v.protected).count();
                        findings.status = STATUS_ENABLED.to_string();
                        findings.status_detail = format!(
                            "BitLocker is enabled on {} of {} volume{}.",
                            n,
                            findings.volumes.len(),
                            if findings.volumes.len() == 1 { "" } else { "s" }
                        );
                    } else {
                        findings.status = STATUS_NOT_ENABLED.to_string();
                        findings.status_detail = format!(
                            "BitLocker is not enabled on any of the {} volume{} found.",
                            findings.volumes.len(),
                            if findings.volumes.len() == 1 { "" } else { "s" }
                        );
                    }
                }
                Err(e) => {
                    findings.status = STATUS_UNSUPPORTED.to_string();
                    findings.status_detail =
                        "The Windows volume-encryption provider could not be reached.".to_string();
                    findings.error = Some(e);
                }
            }
        } else {
            findings.status = STATUS_NEEDS_ADMIN.to_string();
            findings.status_detail = "Scout is not running as Administrator. Windows blocks \
                 all BitLocker volume status and recovery key access without elevation."
                .to_string();
        }

        // The file sweep needs no elevation, so it runs either way.
        if scope != SweepScope::None {
            let roots = targeted_roots();
            let depth = if scope == SweepScope::Full { usize::MAX } else { 4 };
            let cancelled = || crate::scanner::hash_scan::is_scan_cancelled();
            findings.key_files = sweep_roots(&roots, depth, &cancelled, |_| {});
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A structurally valid key whose groups are all divisible by 11.
    const GOOD: &str = "011011-022022-033033-044044-055055-066066-077077-088088";

    #[test]
    fn checksum_fixture_is_actually_valid() {
        // Guard the fixture itself, so a bad constant cannot silently make
        // the checksum tests vacuous.
        for g in GOOD.split('-') {
            let n: u32 = g.parse().unwrap();
            assert_eq!(n % 11, 0, "group {} is not divisible by 11", g);
        }
        assert!(recovery_password_checksum_ok(GOOD));
    }

    #[test]
    fn shape_accepts_a_well_formed_key() {
        assert!(is_recovery_password_shape(GOOD));
        assert_eq!(GOOD.len(), RECOVERY_PASSWORD_LEN);
    }

    #[test]
    fn shape_rejects_wrong_group_counts() {
        let seven = "011011-022022-033033-044044-055055-066066-077077";
        let nine = "011011-022022-033033-044044-055055-066066-077077-088088-099099";
        assert!(!is_recovery_password_shape(seven), "7 groups must fail");
        assert!(!is_recovery_password_shape(nine), "9 groups must fail");
    }

    #[test]
    fn shape_rejects_non_digits_and_bad_group_width() {
        assert!(!is_recovery_password_shape(
            "01101A-022022-033033-044044-055055-066066-077077-088088"
        ));
        assert!(!is_recovery_password_shape(
            "01101-0220222-033033-044044-055055-066066-077077-088088"
        ));
    }

    #[test]
    fn checksum_rejects_groups_not_divisible_by_eleven() {
        let bad = "123456-123456-123456-123456-123456-123456-123456-123456";
        assert!(is_recovery_password_shape(bad), "fixture must be well shaped");
        assert!(
            !recovery_password_checksum_ok(bad),
            "123456 is not divisible by 11, so this must fail the checksum"
        );
    }

    #[test]
    fn finds_key_inside_microsoft_recovery_note() {
        // Shape of the file Windows actually writes.
        let note = format!(
            "BitLocker Drive Encryption recovery key\r\n\r\n\
             To verify that this is the correct recovery key, compare ...\r\n\r\n\
             Identifier:\r\n\r\n\t2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0\r\n\r\n\
             Recovery Key:\r\n\r\n\t{}\r\n\r\n\
             If the above identifier doesn't match ...\r\n",
            GOOD
        );
        let keys = find_recovery_passwords(&note, true);
        assert_eq!(keys, vec![GOOD.to_string()]);
        assert_eq!(
            find_key_id(&note).as_deref(),
            Some("2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0")
        );
    }

    #[test]
    fn utf16le_recovery_note_is_decoded() {
        // Windows writes this file as UTF-16LE with a BOM. Reading it as
        // UTF-8 finds nothing, so this is the regression guard for the single
        // most important artifact the sweep exists to find.
        let text = format!("Recovery Key:\r\n\t{}\r\n", GOOD);
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        // Sanity: a naive UTF-8 read must NOT find the key.
        let naive = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            find_recovery_passwords(&naive, true).is_empty(),
            "precondition: raw UTF-8 read should miss a UTF-16 key"
        );

        let decoded = decode_text(&bytes);
        assert_eq!(find_recovery_passwords(&decoded, true), vec![GOOD.to_string()]);
    }

    #[test]
    fn utf16le_without_bom_is_still_decoded() {
        let text = format!("Recovery Key: {}", GOOD);
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_text(&bytes);
        assert_eq!(find_recovery_passwords(&decoded, true), vec![GOOD.to_string()]);
    }

    #[test]
    fn checksum_filter_suppresses_random_long_numbers() {
        // A spreadsheet full of unrelated digits must not produce hits.
        let noise = "410000-410000-410001-999999-123456-000001-424242-314159";
        assert!(is_recovery_password_shape(noise));
        assert!(
            find_recovery_passwords(noise, true).is_empty(),
            "checksum filter must reject non-key digit runs"
        );
        assert_eq!(find_recovery_passwords(noise, false).len(), 1);
    }

    #[test]
    fn two_keys_in_one_document_are_both_found() {
        let other = "099099-088088-077077-066066-055055-044044-033033-022022";
        let doc = format!("first {} then {} done", GOOD, other);
        let mut keys = find_recovery_passwords(&doc, true);
        keys.sort();
        let mut want = vec![GOOD.to_string(), other.to_string()];
        want.sort();
        assert_eq!(keys, want);
    }

    #[test]
    fn key_id_rejects_a_longer_hex_run() {
        // Must not slice a GUID out of the middle of a hash.
        let hash = "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe1234567890abcdef";
        assert_eq!(find_key_id(hash), None);
    }

    #[test]
    fn status_strings_cover_documented_values_and_fallback() {
        assert_eq!(protection_status_str(0), "Protection Off");
        assert_eq!(protection_status_str(1), "Protection On");
        assert_eq!(protection_status_str(2), "Protection Unknown");
        assert_eq!(protection_status_str(99), "Unrecognized");

        assert_eq!(lock_status_str(0), "Unlocked");
        assert_eq!(lock_status_str(1), "Locked");
        assert_eq!(lock_status_str(7), "Unrecognized");

        assert_eq!(conversion_status_str(1), "Fully Encrypted");
        assert_eq!(conversion_status_str(5), "Decryption Paused");
        assert_eq!(conversion_status_str(42), "Unrecognized");

        assert_eq!(encryption_method_str(6), "XTS-AES 128");
        assert_eq!(encryption_method_str(7), "XTS-AES 256");
        assert_eq!(encryption_method_str(255), "Unrecognized");
    }

    #[test]
    fn candidate_classification() {
        assert_eq!(
            classify_candidate(Path::new(r"C:\x\4D2A1B3C-0000-0000-0000-000000000001.BEK")),
            Some("BEK")
        );
        assert_eq!(
            classify_candidate(Path::new(
                r"C:\Users\a\Desktop\BitLocker Recovery Key 2CE6EE91.TXT"
            )),
            Some("TXT")
        );
        assert_eq!(classify_candidate(Path::new(r"C:\x\notes.docx")), Some("DOCX"));
        assert_eq!(classify_candidate(Path::new(r"C:\x\book.xlsx")), Some("XLSX"));
        assert_eq!(classify_candidate(Path::new(r"C:\x\photo.jpg")), None);
        assert_eq!(classify_candidate(Path::new(r"C:\x\app.exe")), None);
    }

    #[test]
    fn excluded_dirs_are_case_insensitive() {
        assert!(is_excluded_dir("$Recycle.Bin"));
        assert!(is_excluded_dir("System Volume Information"));
        assert!(is_excluded_dir("Windows"));
        assert!(!is_excluded_dir("Users"));
        assert!(!is_excluded_dir("Evidence"));
    }

    #[test]
    fn inspect_finds_key_in_a_real_temp_file() {
        let dir = std::env::temp_dir().join(format!("scout_bl_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("BitLocker Recovery Key 2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0.txt");

        // Write it the way Windows does: UTF-16LE + BOM.
        let text = format!(
            "BitLocker Drive Encryption recovery key\r\nIdentifier:\r\n\t\
             2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0\r\nRecovery Key:\r\n\t{}\r\n",
            GOOD
        );
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&path, &bytes).unwrap();

        let kind = classify_candidate(&path).expect("should classify as a candidate");
        let hit = inspect_file(&path, kind).expect("should find the key");
        assert_eq!(hit.recovery_passwords, vec![GOOD.to_string()]);
        assert_eq!(
            hit.recovery_key_id.as_deref(),
            Some("2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0")
        );
        assert!(hit.checksum_valid);
        assert_eq!(hit.file_type, "TXT");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A GUID on its own means nothing. Logs, configs, CSV exports and crash
    /// dumps are full of them, and reporting each one as a key artifact buries
    /// the real hits — the symptom was 272 "key artifacts" on a machine with
    /// BitLocker switched off.
    #[test]
    fn a_bare_guid_is_not_a_key_id() {
        let log = "2026-09-11 14:02:11 session 2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0 started";
        assert!(find_labelled_key_id(log).is_none());
        // The permissive finder still sees it — that is what filenames use.
        assert!(find_key_id(log).is_some());
    }

    /// Microsoft's own recovery file must keep working: it prints
    /// `Identifier:` on the line above the value.
    #[test]
    fn a_labelled_guid_is_a_key_id() {
        let text = "BitLocker Drive Encryption recovery key\r\n\
                    Identifier:\r\n\t2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0\r\n";
        assert_eq!(
            find_labelled_key_id(text).as_deref(),
            Some("2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0")
        );
    }

    /// The label has to be near the GUID. A file that mentions BitLocker in a
    /// paragraph at the top must not vouch for every GUID below it.
    #[test]
    fn a_distant_mention_does_not_label_a_guid() {
        let text = format!(
            "We rolled out BitLocker last quarter.\n{}\nsession 2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0",
            "x".repeat(KEY_ID_CONTEXT_WINDOW + 50)
        );
        assert!(find_labelled_key_id(&text).is_none());
    }

    /// A labelled GUID later in the file is still found — the scan must not
    /// stop at the first unlabelled one.
    #[test]
    fn a_later_labelled_guid_is_found_past_unlabelled_ones() {
        let text = "trace 11111111-2222-3333-4444-555555555555\n\
                    trace 66666666-7777-8888-9999-AAAAAAAAAAAA\n\
                    BitLocker recovery key identifier: 2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0\n";
        assert_eq!(
            find_labelled_key_id(text).as_deref(),
            Some("2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0")
        );
    }

    /// End to end: an ordinary log file with a GUID in it is not reported at
    /// all, while the same GUID in a file named for BitLocker is.
    #[test]
    fn an_ordinary_log_with_a_guid_is_not_reported() {
        let dir = std::env::temp_dir().join(format!("scout_bl_fp_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let noise = dir.join("update.log");
        std::fs::write(
            &noise,
            b"install id 2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0 completed ok\r\n",
        )
        .unwrap();
        let kind = classify_candidate(&noise).expect("a .log is still worth opening");
        assert!(
            inspect_file(&noise, kind).is_none(),
            "an unlabelled GUID in a log must not be reported as a key artifact"
        );

        // Same bytes, a name that announces itself: reported, because the
        // filename is the corroboration.
        let named = dir.join("bitlocker key backup.txt");
        std::fs::write(
            &named,
            b"install id 2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0 completed ok\r\n",
        )
        .unwrap();
        let kind = classify_candidate(&named).expect("should classify as a candidate");
        let hit = inspect_file(&named, kind).expect("a file named for BitLocker is reported");
        assert_eq!(
            hit.recovery_key_id.as_deref(),
            Some("2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0")
        );
        assert!(hit.recovery_passwords.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The word `identifier` alone is not enough — it sits next to a GUID in
    /// any application log. This exact shape produced 34 of the false
    /// positives measured on a real machine.
    #[test]
    fn identifier_alone_does_not_label_a_guid() {
        let log = "13:22:01 ScanController: adding ScanRequest(identifier: \
                   2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0)";
        assert!(find_labelled_key_id(log).is_none());
    }

    /// …but `identifier` in a file that also talks about BitLocker is the
    /// real Microsoft layout, where the header sits further back than the
    /// context window reaches.
    #[test]
    fn identifier_counts_when_the_file_mentions_bitlocker() {
        let text = "BitLocker Drive Encryption recovery key\r\n\r\n\
                    To verify that this is the correct recovery key, compare the start of the \
                    following identifier with the identifier value displayed on your PC.\r\n\r\n\
                    Identifier:\r\n\r\n\t2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0\r\n";
        assert_eq!(
            find_labelled_key_id(text).as_deref(),
            Some("2CE6EE91-CF9D-4CB8-B5FC-9B1F4B2A77D0")
        );
    }

    #[test]
    fn sweep_finds_a_seeded_key_and_honours_cancellation() {
        let dir = std::env::temp_dir().join(format!("scout_bl_sweep_{}", uuid::Uuid::new_v4()));
        let nested = dir.join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("BitLocker Recovery Key AAAA.txt"),
            format!("Recovery Key:\r\n{}\r\n", GOOD),
        )
        .unwrap();
        std::fs::write(dir.join("unrelated.jpg"), b"not a key").unwrap();

        let never = || false;
        let mut streamed = 0usize;
        let found = sweep_roots(&[dir.clone()], 8, &never, |_| streamed += 1);
        assert_eq!(found.len(), 1, "should find exactly the seeded key file");
        assert_eq!(streamed, 1, "callback should fire once per hit");
        assert_eq!(found[0].recovery_passwords, vec![GOOD.to_string()]);

        // Cancelling up front must produce nothing.
        let always = || true;
        let none = sweep_roots(&[dir.clone()], 8, &always, |_| {});
        assert!(none.is_empty(), "cancellation must stop the sweep");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn findings_helpers_aggregate_keys_without_duplicates() {
        let mut f = BitLockerFindings::empty(SweepScope::Targeted);
        f.volumes.push(BitLockerVolume {
            drive_letter: Some("C:".into()),
            device_id: None,
            persistent_volume_id: None,
            protected: true,
            protection_status: "Protection On".into(),
            lock_status: "Unlocked".into(),
            conversion_status: "Fully Encrypted".into(),
            encryption_method: "XTS-AES 128".into(),
            encryption_percentage: Some(100),
            recovery_key_id: None,
            recovery_password: Some(GOOD.to_string()),
            note: None,
        });
        f.key_files.push(BitLockerKeyFile {
            path: "x".into(),
            file_type: "TXT".into(),
            recovery_key_id: None,
            // Same key as the volume — must not be listed twice.
            recovery_passwords: vec![GOOD.to_string()],
            checksum_valid: true,
            modified: None,
            size_bytes: None,
        });
        assert!(f.any_protected());
        assert_eq!(f.recovered_keys(), vec![GOOD.to_string()]);
    }

    /// The elevation branch is the only *live* BitLocker behaviour that is
    /// observable on the dev box (Windows 11 Home cannot enable BitLocker at
    /// all), so pin it down.
    ///
    /// Written to hold under either privilege level rather than assuming the
    /// test runner is unelevated — a test that silently inverts when someone
    /// runs `cargo test` from an admin shell is worse than no test.
    #[test]
    #[cfg(target_os = "windows")]
    fn collect_reports_elevation_state_and_never_panics() {
        let f = collect(SweepScope::None);

        assert!(f.supported, "Windows must always report as supported");
        assert!(
            !f.status_detail.is_empty(),
            "every status must carry a human-readable explanation"
        );
        assert_eq!(
            f.sweep_scope,
            SweepScope::None.as_str(),
            "scope must round-trip into the findings"
        );
        assert!(
            f.key_files.is_empty(),
            "SweepScope::None must not touch the filesystem"
        );

        if f.elevated {
            assert!(
                [STATUS_ENABLED, STATUS_NOT_ENABLED, STATUS_UNSUPPORTED].contains(&f.status.as_str()),
                "elevated run produced an unexpected status: {}",
                f.status
            );
        } else {
            assert_eq!(
                f.status, STATUS_NEEDS_ADMIN,
                "unelevated run must ask for elevation rather than claim BitLocker is off"
            );
            assert!(
                f.volumes.is_empty(),
                "no volume data is obtainable without elevation"
            );
            // The distinction the UI and the PDF both depend on: "we were not
            // allowed to look" must never be reported as "not encrypted".
            assert_ne!(f.status, STATUS_NOT_ENABLED);
        }
    }
}
