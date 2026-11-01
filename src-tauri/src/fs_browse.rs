//! G10: read-only directory listing for the in-app file picker.
//!
//! On macOS the native NSOpenPanel / NSSavePanel write recent places,
//! sidebar state and panel preferences into the examined user's
//! `~/Library`, which breaks the zero-host-writes rule.  The Mac edition uses
//! an in-app picker instead, and this module is all it needs from the
//! backend: list a folder, and suggest a few starting places.
//!
//! Strictly read-only — `read_dir` and `metadata`, nothing else.  On a Mac
//! without Full Disk Access, TCC-protected folders are refused *before* they
//! are touched: opening `~/Desktop` would otherwise pop a consent prompt and
//! record the answer in the host's TCC database.

use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::scanner::walker::{classify_macos, MacClass};

/// More entries than this in one folder are cut off (and flagged).
const MAX_ENTRIES: usize = 20_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Milliseconds since the Unix epoch.
    pub modified: Option<i64>,
    pub hidden: bool,
    /// macOS: needs Full Disk Access, so the picker will not open it.
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FsListing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<FsEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FsPlace {
    pub label: String,
    pub path: String,
    /// "home" | "folder" | "drive" | "stick" | "root"
    pub kind: String,
    pub protected: bool,
}

/// Whether the host is a Mac without Full Disk Access (the only case that
/// refuses folders).
fn mac_without_fda() -> bool {
    cfg!(target_os = "macos") && !crate::scanner::walker::host_policy().full_disk_access()
}

/// Pure: should the picker refuse to open `dir`?  `Some(reason)` if so.
pub fn refuse_reason(dir: &Path, mac_no_fda: bool) -> Option<String> {
    if mac_no_fda && classify_macos(dir) == MacClass::Protected {
        return Some(format!(
            "{} is protected by macOS. Scout does not open it without Full Disk Access, \
             because asking would leave a permission record on this Mac.",
            dir.display()
        ));
    }
    None
}

/// Pure: sort folders first, then case-insensitive by name.
pub fn sort_entries(entries: &mut [FsEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
}

#[cfg(windows)]
fn is_hidden(name: &str, meta: Option<&std::fs::Metadata>) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    name.starts_with('.') || meta.map_or(false, |m| m.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0)
}

#[cfg(not(windows))]
fn is_hidden(name: &str, _meta: Option<&std::fs::Metadata>) -> bool {
    name.starts_with('.')
}

fn modified_ms(meta: &std::fs::Metadata) -> Option<i64> {
    let t = meta.modified().ok()?;
    let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(d.as_millis()).ok()
}

/// List one directory.  `mac_no_fda` is injected so tests can exercise the
/// refusal on any OS.
pub fn list_dir(dir: &Path, mac_no_fda: bool) -> Result<FsListing, String> {
    // Refusal first: it never touches the filesystem.
    if let Some(reason) = refuse_reason(dir, mac_no_fda) {
        return Err(reason);
    }
    if !dir.is_absolute() {
        return Err(format!("Not an absolute path: {}", dir.display()));
    }
    let rd = std::fs::read_dir(dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => {
            format!("Permission denied: {}", dir.display())
        }
        std::io::ErrorKind::NotFound => format!("Folder not found: {}", dir.display()),
        _ => format!("Cannot open {}: {}", dir.display(), e),
    })?;

    let mut entries = Vec::new();
    let mut truncated = false;
    for ent in rd.flatten() {
        if entries.len() >= MAX_ENTRIES {
            truncated = true;
            break;
        }
        let path = ent.path();
        let name = ent.file_name().to_string_lossy().to_string();
        // Follow symlinks for the type; fall back to the link itself.
        let meta = std::fs::metadata(&path).or_else(|_| ent.metadata()).ok();
        let is_dir = meta.as_ref().map_or(false, |m| m.is_dir());
        entries.push(FsEntry {
            hidden: is_hidden(&name, meta.as_ref()),
            protected: is_dir && refuse_reason(&path, mac_no_fda).is_some(),
            size: meta.as_ref().filter(|m| !m.is_dir()).map_or(0, |m| m.len()),
            modified: meta.as_ref().and_then(modified_ms),
            path: path.to_string_lossy().to_string(),
            name,
            is_dir,
        });
    }
    sort_entries(&mut entries);
    Ok(FsListing {
        path: dir.to_string_lossy().to_string(),
        parent: dir.parent().map(|p| p.to_string_lossy().to_string()),
        entries,
        truncated,
    })
}

fn place(label: &str, path: PathBuf, kind: &str, mac_no_fda: bool) -> FsPlace {
    FsPlace {
        protected: refuse_reason(&path, mac_no_fda).is_some(),
        label: label.to_string(),
        path: path.to_string_lossy().to_string(),
        kind: kind.to_string(),
    }
}

/// Starting points for the picker sidebar.  Never enters protected folders —
/// it only names them.
pub fn places() -> Vec<FsPlace> {
    let no_fda = mac_without_fda();
    let mut out = Vec::new();
    let stick = crate::security::stick_identity::stick_root().ok();
    if let Some(s) = &stick {
        out.push(place("Scout stick", s.clone(), "stick", no_fda));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(place("Home", home.clone(), "home", no_fda));
        for sub in ["Desktop", "Documents", "Downloads"] {
            out.push(place(sub, home.join(sub), "folder", no_fda));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(rd) = std::fs::read_dir("/Volumes") {
            let mut vols: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            vols.sort();
            for v in vols {
                if stick.as_ref() == Some(&v) {
                    continue;
                }
                let label = v.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if label.starts_with('.') {
                    continue;
                }
                out.push(place(&label, v, "drive", no_fda));
            }
        }
        out.push(place("Macintosh HD", PathBuf::from("/"), "root", no_fda));
    }

    #[cfg(windows)]
    {
        // GetLogicalDrives: no probing of empty card readers / optical drives.
        let mask = unsafe { winapi::um::fileapi::GetLogicalDrives() };
        for i in 0..26u32 {
            if mask & (1 << i) != 0 {
                let letter = (b'A' + i as u8) as char;
                let root = PathBuf::from(format!("{}:\\", letter));
                if stick.as_ref() == Some(&root) {
                    continue;
                }
                out.push(place(&format!("{}:", letter), root, "drive", no_fda));
            }
        }
    }
    out
}

#[tauri::command]
pub fn fs_list_dir(path: String) -> Result<FsListing, String> {
    list_dir(Path::new(&path), mac_without_fda())
}

#[tauri::command]
pub fn fs_places() -> Vec<FsPlace> {
    places()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!("fs_browse_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn lists_folders_first_then_files_by_name() {
        let d = scratch();
        std::fs::write(d.join("b.txt"), b"hello").unwrap();
        std::fs::write(d.join("A.txt"), b"x").unwrap();
        std::fs::create_dir(d.join("zeta")).unwrap();
        std::fs::write(d.join(".hidden"), b"").unwrap();
        let l = list_dir(&d, false).unwrap();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["zeta", ".hidden", "A.txt", "b.txt"]);
        assert!(l.entries[0].is_dir && l.entries[0].size == 0);
        assert_eq!(l.entries[3].size, 5);
        assert!(l.entries[1].hidden && !l.entries[2].hidden);
        assert!(l.entries[3].modified.is_some());
        assert!(!l.truncated);
        assert_eq!(l.parent.as_deref(), d.parent().map(|p| p.to_string_lossy()).as_deref());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn rejects_relative_and_missing() {
        assert!(list_dir(Path::new("relative/dir"), false).is_err());
        let missing = std::env::temp_dir().join(format!("nope_{}", uuid::Uuid::new_v4()));
        let err = list_dir(&missing, false).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn mac_protected_folders_refused_without_fda_only() {
        let desk = Path::new("/Users/jdoe/Desktop");
        assert!(refuse_reason(desk, true).unwrap().contains("Full Disk Access"));
        assert!(refuse_reason(desk, false).is_none());
        assert!(refuse_reason(Path::new("/Users/jdoe/Pictures"), true).is_none());
        assert!(refuse_reason(Path::new("/Volumes/EVIDENCE"), true).is_none());
        // Refused before any filesystem access, so this works on Windows too.
        let err = list_dir(Path::new("/Users/jdoe/Library/Safari"), true).unwrap_err();
        assert!(err.contains("protected by macOS"), "{err}");
    }
}
