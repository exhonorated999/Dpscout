//! One stick identity across Windows and macOS.
//!
//! The portable licence seat is keyed on `USB-VOL-%08X` — the FAT/exFAT/NTFS
//! volume serial of the partition the app runs from — hashed with SHA-256
//! (`machine_id_for_tag`). Windows reads that serial directly
//! (`GetVolumeInformationW`). macOS cannot: the serial lives in the boot
//! sector and `/dev/disk*` is root-only, and the portable build never asks
//! for elevation.
//!
//! What macOS *does* expose without privileges is the volume UUID, and for
//! FAT volumes Apple's msdosfs derives it from the serial
//! (`msdosfs_generate_volume_uuid`: MD5 v3 over a fixed namespace, the four
//! serial bytes and the little-endian total sector count). So a claimed serial
//! can be *verified* on the Mac even though it can't be *read* there.
//!
//! The claim comes from `ScoutData.noindex/stick-identity.json` on the stick:
//!   * Windows (portable) writes/refreshes it from the real serial at startup.
//!     The USB creator writes it when provisioning a stick.
//!   * macOS reads it and then:
//!       1. **Verified**: the volume UUID matches the msdosfs derivation of the
//!          claimed serial. This is the strong path.
//!       2. **Paired**: the file already records this volume's UUID from an
//!          earlier Mac run.
//!       3. **PairNow**: no Mac UUID recorded yet. We record it (trust on
//!          first use) and log it. This covers exFAT, whose kext is
//!          closed-source and may derive its UUID differently.
//!       4. **Rejected**: a different Mac UUID is recorded, meaning the file
//!          was copied from another stick.
//!
//! A Windows run always rewrites the claim from the real serial, so copying
//! the file between sticks only ever fools a Mac, and only before that stick
//! has paired. That sits within the existing threat model, where the server
//! already treats `machine_id` as an unauthenticated bearer value (see
//! `licensing.rs::get_legacy_machine_id`).
//!
//! Everything above the `live_*` modules is pure and unit-tested on every OS.

// The pure half is shared by both OS arms and tested everywhere, so on any one
// target some of it is legitimately unused.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Stick data folder. `.noindex` keeps Spotlight off it on macOS; on Windows
/// it is just a folder name.
pub const DATA_DIR: &str = "ScoutData.noindex";
pub const IDENTITY_FILE: &str = "stick-identity.json";
pub const IDENTITY_VERSION: u32 = 1;

/// `USB-VOL-%08X` — byte-for-byte what `licensing.rs` has always produced.
pub fn format_tag(serial: u32) -> String {
    format!("USB-VOL-{:08X}", serial)
}

pub fn parse_tag(tag: &str) -> Option<u32> {
    let hex = tag.trim().strip_prefix("USB-VOL-")?;
    if hex.len() != 8 {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

/// The portable machine id sent to the licence server.
pub fn machine_id_for_tag(tag: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Identity file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityFile {
    pub version: u32,
    /// `USB-VOL-%08X`, as read by Windows.
    pub volume_serial: String,
    /// File system name as Windows reported it (`exFAT`, `FAT32`, `NTFS`).
    #[serde(default)]
    pub filesystem: String,
    /// Volume UUID recorded by the first macOS run (TOFU pairing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_volume_uuid: Option<String>,
    #[serde(default)]
    pub written_by: String,
    #[serde(default)]
    pub updated_at: String,
}

pub fn parse_identity_file(text: &str) -> Option<IdentityFile> {
    let f: IdentityFile = serde_json::from_str(text).ok()?;
    parse_tag(&f.volume_serial)?;
    Some(f)
}

/// Windows side: what the identity file should become, given what is on the
/// stick now. `None` means the file is already correct and must not be touched.
///
/// A Mac pairing survives only while the serial *and* file system are
/// unchanged. Re-provisioning (e.g. NTFS → exFAT with the serial preserved)
/// gives the volume a new Mac UUID, so the pairing is dropped.
pub fn windows_refresh(
    existing: Option<&IdentityFile>,
    real_tag: &str,
    filesystem: &str,
    now: &str,
) -> Option<IdentityFile> {
    if let Some(e) = existing {
        if e.version == IDENTITY_VERSION
            && e.volume_serial == real_tag
            && e.filesystem.eq_ignore_ascii_case(filesystem)
        {
            return None;
        }
    }
    let keep_pairing = existing
        .filter(|e| e.volume_serial == real_tag && e.filesystem.eq_ignore_ascii_case(filesystem))
        .and_then(|e| e.mac_volume_uuid.clone());
    Some(IdentityFile {
        version: IDENTITY_VERSION,
        volume_serial: real_tag.to_string(),
        filesystem: filesystem.to_string(),
        mac_volume_uuid: keep_pairing,
        written_by: "windows".to_string(),
        updated_at: now.to_string(),
    })
}

// ---------------------------------------------------------------------------
// macOS verification
// ---------------------------------------------------------------------------

/// Apple msdosfs `msdosfs_generate_volume_uuid`, uppercase and hyphenated as
/// `diskutil` prints it. `volumeID` is the raw boot-sector bytes, which are
/// the little-endian encoding of the serial Windows reports.
pub fn msdos_volume_uuid(serial: u32, total_sectors: u32) -> String {
    use md5::{Digest, Md5};
    const NS: [u8; 16] = [
        0xB3, 0xE2, 0x0F, 0x39, 0xF2, 0x92, 0x11, 0xD6, 0x97, 0xA4, 0x00, 0x30, 0x65, 0x43, 0xEC,
        0xAC,
    ];
    let mut h = Md5::new();
    h.update(NS);
    h.update(serial.to_le_bytes());
    h.update(total_sectors.to_le_bytes());
    let mut d = [0u8; 16];
    d.copy_from_slice(&h.finalize());
    d[6] = (d[6] & 0x0F) | 0x30;
    d[8] = (d[8] & 0x3F) | 0x80;
    let x = hex::encode_upper(d);
    format!("{}-{}-{}-{}-{}", &x[0..8], &x[8..12], &x[12..16], &x[16..20], &x[20..32])
}

/// The total sector count isn't readable unprivileged either. The partition
/// size from `diskutil` matches the BPB count on any normally formatted
/// stick, so we try the common sector sizes against it.
pub fn uuid_matches_serial(observed_uuid: &str, serial: u32, partition_bytes: Option<u64>) -> bool {
    let Some(bytes) = partition_bytes else { return false };
    [512u64, 4096].iter().any(|&bps| {
        let sectors = bytes / bps;
        sectors > 0
            && sectors <= u32::MAX as u64
            && msdos_volume_uuid(serial, sectors as u32).eq_ignore_ascii_case(observed_uuid.trim())
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum MacDecision {
    /// UUID cryptographically matches the claimed serial.
    Verified { tag: String },
    /// UUID matches the one recorded on an earlier Mac run.
    Paired { tag: String },
    /// First Mac run for this stick: record `uuid`, then accept `tag`.
    PairNow { tag: String, uuid: String },
}

impl MacDecision {
    pub fn tag(&self) -> &str {
        match self {
            MacDecision::Verified { tag } | MacDecision::Paired { tag } | MacDecision::PairNow { tag, .. } => tag,
        }
    }
}

pub const NO_RECORD_MSG: &str = "This drive has no DataPilot Scout identity record yet. \
    Plug it into a Windows PC and start DataPilot Scout from it once, then try again on the Mac.";

pub fn decide_mac(
    file: Option<&IdentityFile>,
    observed_uuid: Option<&str>,
    partition_bytes: Option<u64>,
) -> Result<MacDecision, String> {
    let file = file.ok_or_else(|| NO_RECORD_MSG.to_string())?;
    let serial = parse_tag(&file.volume_serial)
        .ok_or_else(|| format!("Identity record is damaged ({}). {}", file.volume_serial, NO_RECORD_MSG))?;
    let tag = format_tag(serial);
    let observed = observed_uuid
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "Cannot read this drive's volume UUID".to_string())?;

    if uuid_matches_serial(observed, serial, partition_bytes) {
        return Ok(MacDecision::Verified { tag });
    }
    match file.mac_volume_uuid.as_deref() {
        Some(rec) if rec.trim().eq_ignore_ascii_case(observed) => Ok(MacDecision::Paired { tag }),
        Some(_) => Err("This drive's identity record belongs to a different drive \
            (it was probably copied). Plug this drive into a Windows PC and start \
            DataPilot Scout from it once to re-provision it."
            .to_string()),
        None => Ok(MacDecision::PairNow { tag, uuid: observed.to_uppercase() }),
    }
}

/// macOS: the volume root of a path under `/Volumes/<name>/…`.
pub fn volume_root_of(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut comps = path.components();
    use std::path::Component;
    match (comps.next(), comps.next(), comps.next()) {
        (Some(Component::RootDir), Some(Component::Normal(v)), Some(Component::Normal(name)))
            if v == "Volumes" =>
        {
            Some(std::path::Path::new("/Volumes").join(name))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Windows live
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod live_windows {
    use super::*;
    use std::path::PathBuf;

    /// Drive root of the running exe (e.g. `E:\`), derived exactly as
    /// `licensing.rs` always has — the machine id must not move.
    pub fn exe_drive_root() -> Result<String, String> {
        let exe_path = std::env::current_exe().map_err(|e| format!("Cannot find exe path: {}", e))?;
        let drive_root = exe_path
            .components()
            .next()
            .ok_or_else(|| "Cannot determine drive letter".to_string())?
            .as_os_str()
            .to_string_lossy()
            .to_string();
        Ok(if drive_root.ends_with('\\') { drive_root } else { format!("{}\\", drive_root) })
    }

    /// (serial, file system name) of a volume root.
    pub fn volume_info(root: &str) -> Result<(u32, String), String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = OsStr::new(root).encode_wide().chain(std::iter::once(0)).collect();
        let mut serial: u32 = 0;
        let mut fs_name = [0u16; 64];
        let ok = unsafe {
            winapi::um::fileapi::GetVolumeInformationW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs_name.as_mut_ptr(),
                fs_name.len() as u32,
            )
        };
        if ok == 0 {
            return Err(format!("GetVolumeInformationW failed for {}", root));
        }
        let len = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
        Ok((serial, String::from_utf16_lossy(&fs_name[..len])))
    }

    /// Never write the identity record to the system drive. A dev run of the
    /// portable feature from `C:\` must not litter `C:\ScoutData.noindex`.
    fn is_system_drive(root: &str) -> bool {
        let sys = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        root.to_ascii_uppercase().trim_start_matches(r"\\?\").starts_with(&sys.to_ascii_uppercase())
    }

    fn refresh_identity_file(root: &str, tag: &str, fs: &str) -> Result<(), String> {
        if is_system_drive(root) {
            return Ok(());
        }
        let dir = PathBuf::from(root).join(DATA_DIR);
        let path = dir.join(IDENTITY_FILE);
        let existing = std::fs::read_to_string(&path).ok().and_then(|t| parse_identity_file(&t));
        let now = chrono::Utc::now().to_rfc3339();
        if let Some(next) = windows_refresh(existing.as_ref(), tag, fs, &now) {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let body = serde_json::to_string_pretty(&next).map_err(|e| e.to_string())?;
            std::fs::write(&path, body).map_err(|e| e.to_string())?;
            eprintln!("[StickIdentity] wrote {} ({})", path.display(), tag);
        }
        Ok(())
    }

    /// `USB-VOL-%08X` for the stick the exe runs from. Also keeps the
    /// identity record current (once per process, best effort) so the Mac
    /// build can find the same seat.
    pub fn current_tag() -> Result<String, String> {
        let root = exe_drive_root()?;
        let (serial, fs) = volume_info(&root)?;
        let tag = format_tag(serial);
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            if let Err(e) = refresh_identity_file(&root, &tag, &fs) {
                eprintln!("[StickIdentity] could not update identity record: {}", e);
            }
        });
        Ok(tag)
    }
}

// ---------------------------------------------------------------------------
// macOS live
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod live_macos {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    #[derive(Debug, Default)]
    pub struct VolumeFacts {
        pub uuid: Option<String>,
        pub total_size: Option<u64>,
        pub fs_type: Option<String>,
    }

    /// `diskutil info -plist <mount>`. It is read-only and needs no
    /// privileges or TCC prompt.
    pub fn volume_facts(mount: &Path) -> VolumeFacts {
        let out = match std::process::Command::new("/usr/sbin/diskutil")
            .args(["info", "-plist"])
            .arg(mount)
            .output()
        {
            Ok(o) if o.status.success() => o.stdout,
            _ => return VolumeFacts::default(),
        };
        let Ok(plist::Value::Dictionary(d)) = plist::Value::from_reader(std::io::Cursor::new(out)) else {
            return VolumeFacts::default();
        };
        VolumeFacts {
            uuid: d.get("VolumeUUID").and_then(|v| v.as_string()).map(str::to_string),
            total_size: d.get("TotalSize").and_then(|v| v.as_unsigned_integer()),
            fs_type: d
                .get("FilesystemType")
                .and_then(|v| v.as_string())
                .map(str::to_string),
        }
    }

    /// Mount point of the stick the app runs from. Uses the exe path when
    /// it is under `/Volumes`. If Gatekeeper translocated the bundle, falls
    /// back to the single mounted volume that carries an identity record.
    pub fn stick_root() -> Result<PathBuf, String> {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(root) = volume_root_of(&exe) {
                return Ok(root);
            }
        }
        let mut hits: Vec<PathBuf> = std::fs::read_dir("/Volumes")
            .map_err(|e| format!("Cannot list /Volumes: {}", e))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join(DATA_DIR).join(IDENTITY_FILE).is_file())
            .collect();
        match hits.len() {
            1 => Ok(hits.remove(0)),
            0 => Err("DataPilot Scout must be run from its USB drive".to_string()),
            _ => Err("More than one DataPilot Scout drive is connected; unplug the others".to_string()),
        }
    }

    fn resolve() -> Result<String, String> {
        let root = stick_root()?;
        let path = root.join(DATA_DIR).join(IDENTITY_FILE);
        let file = std::fs::read_to_string(&path).ok().and_then(|t| parse_identity_file(&t));
        let facts = volume_facts(&root);
        let decision = decide_mac(file.as_ref(), facts.uuid.as_deref(), facts.total_size)?;
        match &decision {
            MacDecision::Verified { tag } => eprintln!("[StickIdentity] {} verified against volume UUID", tag),
            MacDecision::Paired { tag } => eprintln!("[StickIdentity] {} matched paired volume UUID", tag),
            MacDecision::PairNow { tag, uuid } => {
                eprintln!(
                    "[StickIdentity] {} not verifiable on {:?}; pairing volume UUID {} (first Mac use)",
                    tag, facts.fs_type, uuid
                );
                if let Some(mut f) = file.clone() {
                    f.mac_volume_uuid = Some(uuid.clone());
                    f.updated_at = chrono::Utc::now().to_rfc3339();
                    let body = serde_json::to_string_pretty(&f).map_err(|e| e.to_string())?;
                    // Write next to the original and rename it into place, so a
                    // yanked stick can't leave a half-written record behind.
                    let tmp = path.with_extension("json.tmp");
                    std::fs::write(&tmp, body)
                        .and_then(|_| std::fs::rename(&tmp, &path))
                        .map_err(|e| format!("Cannot record stick pairing: {}", e))?;
                }
            }
        }
        Ok(decision.tag().to_string())
    }

    /// Cached for the process: the answer can't change while the app runs
    /// from the same stick.
    pub fn current_tag() -> Result<String, String> {
        static CACHE: OnceLock<Result<String, String>> = OnceLock::new();
        CACHE.get_or_init(resolve).clone()
    }
}

/// `USB-VOL-%08X` for the stick the app runs from.
#[cfg(windows)]
pub fn current_tag() -> Result<String, String> {
    live_windows::current_tag()
}

#[cfg(target_os = "macos")]
pub fn current_tag() -> Result<String, String> {
    live_macos::current_tag()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn current_tag() -> Result<String, String> {
    Err("Portable USB identity is only supported on Windows and macOS".to_string())
}

/// Mount point / drive root of the stick, for display and path building.
#[cfg(windows)]
pub fn stick_root() -> Result<std::path::PathBuf, String> {
    live_windows::exe_drive_root().map(std::path::PathBuf::from)
}

#[cfg(target_os = "macos")]
pub fn stick_root() -> Result<std::path::PathBuf, String> {
    live_macos::stick_root()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn stick_root() -> Result<std::path::PathBuf, String> {
    Err("Portable USB identity is only supported on Windows and macOS".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_roundtrip_and_legacy_format() {
        assert_eq!(format_tag(0x1234ABCD), "USB-VOL-1234ABCD");
        assert_eq!(format_tag(0x0000_00FF), "USB-VOL-000000FF");
        assert_eq!(parse_tag("USB-VOL-1234ABCD"), Some(0x1234ABCD));
        assert_eq!(parse_tag("USB-VOL-1234abcd"), Some(0x1234ABCD));
        assert_eq!(parse_tag("USB-VOL-123"), None);
        assert_eq!(parse_tag("VOL-1234ABCD"), None);
    }

    /// Must equal what `licensing.rs` produced before this module existed
    /// (SHA-256 of the tag, lowercase hex). Oracle: Python hashlib.
    #[test]
    fn machine_id_unchanged() {
        assert_eq!(
            machine_id_for_tag("USB-VOL-1234ABCD"),
            "72a40d16b8cedb9dd96fed89bd8a901c9dc98fe28767b308bf84780c77791819"
        );
    }

    /// Oracle: Python transcription of Apple's msdosfs_generate_volume_uuid.
    #[test]
    fn msdos_uuid_matches_apple_derivation() {
        assert_eq!(msdos_volume_uuid(0x18E44FA7, 30_310_400), "5796D1CD-1CB4-39F0-A5FC-9D2C6ABF4B7E");
        assert_eq!(msdos_volume_uuid(0x1234ABCD, 62_521_344), "9DECD713-6880-3B59-A475-B4B780620A4C");
        let u = msdos_volume_uuid(1, 1);
        assert_eq!(&u[14..15], "3", "version nibble");
        assert!(matches!(&u[19..20], "8" | "9" | "A" | "B"), "variant bits");
    }

    #[test]
    fn uuid_match_tries_sector_sizes() {
        let bytes = 62_521_344u64 * 512;
        let u = msdos_volume_uuid(0x1234ABCD, 62_521_344);
        assert!(uuid_matches_serial(&u, 0x1234ABCD, Some(bytes)));
        assert!(uuid_matches_serial(&u.to_lowercase(), 0x1234ABCD, Some(bytes)));
        assert!(!uuid_matches_serial(&u, 0x1234ABCE, Some(bytes)));
        assert!(!uuid_matches_serial(&u, 0x1234ABCD, None));
        let u4k = msdos_volume_uuid(7, 1000);
        assert!(uuid_matches_serial(&u4k, 7, Some(1000 * 4096)));
    }

    fn file(tag: &str, mac: Option<&str>) -> IdentityFile {
        IdentityFile {
            version: IDENTITY_VERSION,
            volume_serial: tag.into(),
            filesystem: "exFAT".into(),
            mac_volume_uuid: mac.map(Into::into),
            written_by: "windows".into(),
            updated_at: "t0".into(),
        }
    }

    #[test]
    fn mac_verified_beats_recorded_pairing() {
        let u = msdos_volume_uuid(0x1234ABCD, 1_000_000);
        let f = file("USB-VOL-1234ABCD", Some("SOMETHING-ELSE"));
        assert_eq!(
            decide_mac(Some(&f), Some(&u), Some(1_000_000 * 512)),
            Ok(MacDecision::Verified { tag: "USB-VOL-1234ABCD".into() })
        );
    }

    #[test]
    fn mac_tofu_pair_then_match_then_reject_copy() {
        let f = file("USB-VOL-1234ABCD", None);
        let d = decide_mac(Some(&f), Some("aaaa-bbbb"), Some(1)).unwrap();
        assert_eq!(d, MacDecision::PairNow { tag: "USB-VOL-1234ABCD".into(), uuid: "AAAA-BBBB".into() });

        let paired = file("USB-VOL-1234ABCD", Some("AAAA-BBBB"));
        assert_eq!(
            decide_mac(Some(&paired), Some("aaaa-bbbb"), Some(1)),
            Ok(MacDecision::Paired { tag: "USB-VOL-1234ABCD".into() })
        );
        // Same record on a different stick (copied folder).
        assert!(decide_mac(Some(&paired), Some("CCCC-DDDD"), Some(1)).is_err());
    }

    #[test]
    fn mac_refuses_without_record_or_uuid() {
        assert_eq!(decide_mac(None, Some("X"), None), Err(NO_RECORD_MSG.to_string()));
        assert!(decide_mac(Some(&file("USB-VOL-1234ABCD", None)), None, None).is_err());
        assert!(decide_mac(Some(&file("USB-VOL-1234ABCD", None)), Some("  "), None).is_err());
        let bad = IdentityFile { volume_serial: "garbage".into(), ..file("x", None) };
        assert!(decide_mac(Some(&bad), Some("X"), None).is_err());
    }

    #[test]
    fn windows_refresh_rules() {
        // Fresh stick: write.
        let w = windows_refresh(None, "USB-VOL-00000001", "exFAT", "now").unwrap();
        assert_eq!(w.volume_serial, "USB-VOL-00000001");
        assert_eq!(w.mac_volume_uuid, None);
        // Up to date (fs case-insensitive): leave alone, pairing untouched.
        let cur = IdentityFile { filesystem: "EXFAT".into(), ..file("USB-VOL-00000001", Some("U")) };
        assert_eq!(windows_refresh(Some(&cur), "USB-VOL-00000001", "exFAT", "now"), None);
        // Copied from another stick: overwrite claim, drop pairing.
        let w = windows_refresh(Some(&cur), "USB-VOL-00000002", "exFAT", "now").unwrap();
        assert_eq!(w.volume_serial, "USB-VOL-00000002");
        assert_eq!(w.mac_volume_uuid, None);
        // Re-provisioned NTFS -> exFAT with serial preserved: drop pairing.
        let ntfs = IdentityFile { filesystem: "NTFS".into(), ..file("USB-VOL-00000001", Some("U")) };
        let w = windows_refresh(Some(&ntfs), "USB-VOL-00000001", "exFAT", "now").unwrap();
        assert_eq!(w.mac_volume_uuid, None);
        // Older record version, same stick: rewrite but keep pairing.
        let old = IdentityFile { version: 0, ..file("USB-VOL-00000001", Some("U")) };
        let w = windows_refresh(Some(&old), "USB-VOL-00000001", "exFAT", "now").unwrap();
        assert_eq!(w.mac_volume_uuid.as_deref(), Some("U"));
    }

    #[test]
    fn identity_file_json_roundtrip() {
        let f = file("USB-VOL-0A0B0C0D", Some("U"));
        let s = serde_json::to_string(&f).unwrap();
        assert_eq!(parse_identity_file(&s), Some(f));
        let no_mac = serde_json::to_string(&file("USB-VOL-0A0B0C0D", None)).unwrap();
        assert!(!no_mac.contains("mac_volume_uuid"));
        assert_eq!(parse_identity_file(r#"{"version":1,"volume_serial":"nope"}"#), None);
        assert_eq!(parse_identity_file("not json"), None);
    }

    #[test]
    fn volume_root_detection() {
        use std::path::Path;
        assert_eq!(
            volume_root_of(Path::new("/Volumes/SCOUT/DataPilot Scout.app/Contents/MacOS/datapilot-scout")),
            Some(Path::new("/Volumes/SCOUT").to_path_buf())
        );
        assert_eq!(volume_root_of(Path::new("/Applications/X.app/Contents/MacOS/x")), None);
        assert_eq!(volume_root_of(Path::new("/Volumes")), None);
    }
}
