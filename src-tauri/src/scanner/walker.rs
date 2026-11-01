//! Host-OS walk policy shared by the keyword, hash and media scans.
//!
//! Each scanner keeps its own name-based filters (they predate this module
//! and tune *what is interesting*).  This module decides *what is safe and
//! sensible to enter at all* for the OS Scout is running on:
//!
//! * **Windows / Linux** — pass-through.  Every existing walk behaves exactly
//!   as before; the scanners' own filters remain the only filters.
//! * **macOS** — prunes OS areas a walk from `/` would otherwise wander into
//!   (`/System` incl. the firmlinked `/System/Volumes/Data` duplicate of every
//!   user file, `/Volumes` incl. Scout's own stick, `/private`, `/dev`, code
//!   bundles …) and holds back TCC-protected user folders unless Scout has
//!   Full Disk Access.  Touching Desktop/Documents/Downloads without it pops a
//!   consent prompt *and* makes `tccd` record the answer on the host; the
//!   FDA-only folders (Mail, Messages, Safari …) just fail with EPERM.  Both
//!   are skipped and recorded so the UI can say "N protected locations were
//!   skipped — grant Full Disk Access to include them".
//!
//! A walk is always relative to a *root*.  A root the operator picked
//! explicitly (e.g. an external disk under `/Volumes`) is honoured even if a
//! walk from `/` would have pruned it; only bundle and TCC rules apply below
//! an explicit root.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// macOS classification of a directory, by path alone (no I/O).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacClass {
    /// Ordinary location — walk it.
    Allow,
    /// OS-owned area — never entered from a broader root.
    System,
    /// Code bundle (`.app`, `.framework` …) — icons and binaries, not evidence.
    Bundle,
    /// TCC-protected — needs Full Disk Access.
    Protected,
}

/// Top-level directories of a macOS boot volume that a walk from `/` skips.
const MAC_SYSTEM_TOP: &[&str] = &[
    "system", "volumes", "private", "dev", "cores", "usr", "bin", "sbin", "opt",
    "library", "applications", "network", "net", "home",
    // Symlinks into /private (followed when handed over as a walk root).
    "etc", "var",
    ".spotlight-v100", ".fseventsd", ".documentrevisions-v100", ".vol",
    ".mobilebackups", ".pkinstallsandboxmanager", ".pkinstallsandboxmanager-systemsoftware",
];

/// Directory extensions that mark a code bundle.  `.photoslibrary` is
/// deliberately absent: it is a package of the user's own photos.
const MAC_BUNDLE_EXTS: &[&str] = &[
    "app", "framework", "kext", "plugin", "appex", "xpc", "bundle", "dsym", "qlgenerator",
    "mdimporter", "prefpane", "saver", "systemextension", "driver",
];

/// Paths under a user's home (`/Users/<u>/…`) that TCC protects.  Matched as
/// case-insensitive component prefixes.
const MAC_TCC_HOME: &[&[&str]] = &[
    // Per-folder consent prompts.
    &["desktop"],
    &["documents"],
    &["downloads"],
    &["library", "mobile documents"], // iCloud Drive
    // Full Disk Access only (EPERM otherwise).
    &["library", "mail"],
    &["library", "messages"],
    &["library", "safari"],
    &["library", "cookies"],
    &["library", "homekit"],
    &["library", "identityservices"],
    &["library", "suggestions"],
    &["library", "personalizationportrait"],
    &["library", "calendars"],
    &["library", "reminders"],
    &["library", "biome"],
    &["library", "accounts"],
    &["library", "metadata", "corespotlight"],
    &["library", "application support", "com.apple.tcc"],
    &["library", "application support", "addressbook"],
    &["library", "application support", "callhistorydb"],
    &["library", "application support", "callhistorytransactions"],
    &["library", "application support", "knowledge"],
    &["library", "application support", "facetime"],
    &["library", "containers", "com.apple.mail"],
    &["library", "containers", "com.apple.safari"],
    &["library", "containers", "com.apple.notes"],
    &["library", "group containers", "group.com.apple.notes"],
];

fn normal_components(path: &Path) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut absolute = false;
    for c in path.components() {
        match c {
            Component::RootDir => absolute = true,
            Component::Normal(s) => out.push(s.to_string_lossy().to_lowercase()),
            Component::CurDir => {}
            // `..` or a Windows prefix: not a path we can reason about.
            _ => return None,
        }
    }
    absolute.then_some(out)
}

/// Classify a macOS directory path.  Pure; compiled on every OS so the rules
/// are unit-tested on the Windows dev box.
pub fn classify_macos(dir: &Path) -> MacClass {
    let Some(comps) = normal_components(dir) else {
        return MacClass::Allow;
    };
    if let Some(last) = comps.last() {
        if let Some((_, ext)) = last.rsplit_once('.') {
            if MAC_BUNDLE_EXTS.contains(&ext) {
                return MacClass::Bundle;
            }
        }
    }
    let Some(top) = comps.first() else {
        return MacClass::Allow; // "/" itself
    };
    if top == "private" && comps.get(1).map(String::as_str) == Some("tmp") {
        return MacClass::Allow;
    }
    if MAC_SYSTEM_TOP.contains(&top.as_str()) {
        return MacClass::System;
    }
    if top == "users" && comps.len() >= 3 && comps[1] != "shared" {
        let rel = &comps[2..];
        if rel.iter().any(|c| c.ends_with(".photoslibrary")) {
            return MacClass::Protected;
        }
        for prefix in MAC_TCC_HOME {
            if rel.len() >= prefix.len() && rel.iter().zip(prefix.iter()).all(|(a, b)| a == b) {
                return MacClass::Protected;
            }
        }
    }
    MacClass::Allow
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Passthrough,
    MacOs,
}

/// Process-wide policy for the host OS.
pub struct WalkPolicy {
    kind: Kind,
    full_disk_access: bool,
    /// Extra roots never entered (Scout's own stick on macOS).
    excluded: Vec<PathBuf>,
    skipped_protected: Mutex<BTreeSet<PathBuf>>,
}

impl WalkPolicy {
    pub fn passthrough() -> Self {
        Self {
            kind: Kind::Passthrough,
            full_disk_access: true,
            excluded: Vec::new(),
            skipped_protected: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn macos(full_disk_access: bool, excluded: Vec<PathBuf>) -> Self {
        Self {
            kind: Kind::MacOs,
            full_disk_access,
            excluded,
            skipped_protected: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn full_disk_access(&self) -> bool {
        self.full_disk_access
    }

    /// A scope for one walk rooted at `root`.  Owned and `'static` so it can
    /// move into jwalk's `process_read_dir` closure.
    pub fn scope(&'static self, root: &Path) -> WalkScope {
        let root_is_system = self.kind == Kind::MacOs && classify_macos(root) == MacClass::System;
        WalkScope {
            policy: self,
            root: root.to_path_buf(),
            root_is_system,
        }
    }

    /// Protected locations skipped since the last call (drains the record).
    pub fn take_skipped_protected(&self) -> Vec<PathBuf> {
        let mut set = self.skipped_protected.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *set).into_iter().collect()
    }

    pub fn record_protected(&self, dir: &Path) {
        let mut set = self.skipped_protected.lock().unwrap_or_else(|e| e.into_inner());
        if set.insert(dir.to_path_buf()) {
            eprintln!("[Walk] Skipped (needs Full Disk Access): {}", dir.display());
        }
    }
}

/// Policy applied to one walk.
#[derive(Clone)]
pub struct WalkScope {
    policy: &'static WalkPolicy,
    root: PathBuf,
    root_is_system: bool,
}

impl WalkScope {
    /// Whether the walk may enter `dir` (also call it on the root itself).
    pub fn allows_dir(&self, dir: &Path) -> bool {
        let p = self.policy;
        if p.kind == Kind::Passthrough {
            return true;
        }
        if p.excluded.iter().any(|x| dir.starts_with(x)) {
            return false;
        }
        match classify_macos(dir) {
            MacClass::Allow => true,
            MacClass::Bundle => dir == self.root,
            MacClass::System => self.root_is_system && dir.starts_with(&self.root),
            MacClass::Protected => {
                if p.full_disk_access {
                    true
                } else {
                    p.record_protected(dir);
                    false
                }
            }
        }
    }

    /// Convenience for `walkdir::filter_entry`: files always pass (their
    /// directory was already vetted), directories go through [`allows_dir`].
    pub fn allows_entry(&self, path: &Path, is_dir: bool) -> bool {
        !is_dir || self.allows_dir(path)
    }
}

/// True when Scout can read a file only Full Disk Access unlocks.  Opening it
/// never prompts; it just fails with EPERM when access is missing.
#[cfg(target_os = "macos")]
fn detect_full_disk_access() -> bool {
    let probes = [
        PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db"),
        dirs::home_dir()
            .map(|h| h.join("Library/Safari/History.db"))
            .unwrap_or_default(),
    ];
    probes.iter().any(|p| std::fs::File::open(p).is_ok())
}

/// The policy for the OS Scout is running on.
pub fn host_policy() -> &'static WalkPolicy {
    static POLICY: OnceLock<WalkPolicy> = OnceLock::new();
    POLICY.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            let fda = detect_full_disk_access();
            let excluded: Vec<PathBuf> = crate::security::stick_identity::stick_root()
                .ok()
                .into_iter()
                .collect();
            eprintln!("[Walk] macOS policy: full_disk_access={} excluded={:?}", fda, excluded);
            WalkPolicy::macos(fda, excluded)
        }
        #[cfg(not(target_os = "macos"))]
        {
            WalkPolicy::passthrough()
        }
    })
}

/// Shorthand: `host_policy().scope(root)`.
pub fn host_scope(root: &Path) -> WalkScope {
    host_policy().scope(root)
}

/// Real user homes under a macOS `/Users` dir, sorted by name.  Skips
/// `Shared`, `Guest` and dot entries (`.localized`).  Other users' homes are
/// listed but usually unreadable without root; callers just find nothing.
pub fn mac_home_dirs(users_root: &Path) -> Vec<(String, PathBuf)> {
    let mut homes: Vec<(String, PathBuf)> = match std::fs::read_dir(users_root) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with('.')
                    || name.eq_ignore_ascii_case("Shared")
                    || name.eq_ignore_ascii_case("Guest")
                {
                    return None;
                }
                let p = e.path();
                p.is_dir().then_some((name, p))
            })
            .collect(),
        Err(e) => {
            eprintln!("[Walk] Cannot list {}: {}", users_root.display(), e);
            Vec::new()
        }
    };
    homes.sort();
    homes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn leak(policy: WalkPolicy) -> &'static WalkPolicy {
        Box::leak(Box::new(policy))
    }

    #[test]
    fn classify_system_areas() {
        for s in [
            "/System",
            "/System/Volumes/Data/Users/bob",
            "/Volumes/SCOUT",
            "/private/var/folders/xy",
            "/Library/Desktop Pictures",
            "/Applications",
            "/usr/local",
            "/.Spotlight-V100",
            "/dev",
        ] {
            assert_eq!(classify_macos(&p(s)), MacClass::System, "{s}");
        }
        assert_eq!(classify_macos(&p("/private/tmp/x")), MacClass::Allow);
        assert_eq!(classify_macos(&p("/")), MacClass::Allow);
        assert_eq!(classify_macos(&p("/Users")), MacClass::Allow);
        assert_eq!(classify_macos(&p("/Users/Shared/stash")), MacClass::Allow);
    }

    #[test]
    fn classify_bundles_but_not_photos_library() {
        assert_eq!(classify_macos(&p("/Users/bob/Applications/Foo.app")), MacClass::Bundle);
        assert_eq!(
            classify_macos(&p("/Users/bob/Library/Frameworks/X.framework")),
            MacClass::Bundle
        );
        assert_eq!(
            classify_macos(&p("/Users/bob/Pictures/Photos Library.photoslibrary")),
            MacClass::Protected
        );
        assert_eq!(classify_macos(&p("/Users/bob/Pictures")), MacClass::Allow);
    }

    #[test]
    fn classify_tcc_home_paths_case_insensitively() {
        for s in [
            "/Users/bob/Desktop",
            "/Users/bob/documents/sub",
            "/Users/bob/Downloads",
            "/Users/bob/Library/Mail/V10",
            "/Users/bob/Library/Messages",
            "/Users/bob/Library/Safari",
            "/Users/bob/Library/Mobile Documents/com~apple~CloudDocs",
            "/Users/bob/Library/Application Support/com.apple.TCC",
        ] {
            assert_eq!(classify_macos(&p(s)), MacClass::Protected, "{s}");
        }
        for s in [
            "/Users/bob",
            "/Users/bob/Movies",
            "/Users/bob/Library",
            "/Users/bob/Library/Application Support/Telegram Desktop",
            "/Users/bob/DesktopBackup", // prefix match is per component
        ] {
            assert_eq!(classify_macos(&p(s)), MacClass::Allow, "{s}");
        }
    }

    #[test]
    fn passthrough_allows_everything() {
        let policy = leak(WalkPolicy::passthrough());
        let scope = policy.scope(&p("C:\\"));
        for s in ["/System", "/Users/bob/Desktop", "C:\\Windows", "/Volumes/X/Foo.app"] {
            assert!(scope.allows_dir(&p(s)), "{s}");
        }
        assert!(policy.take_skipped_protected().is_empty());
    }

    #[test]
    fn mac_scope_from_root_prunes_system_and_bundles() {
        let policy = leak(WalkPolicy::macos(false, vec![p("/Volumes/SCOUT")]));
        let scope = policy.scope(&p("/"));
        assert!(scope.allows_dir(&p("/")));
        assert!(scope.allows_dir(&p("/Users/bob/Pictures")));
        assert!(!scope.allows_dir(&p("/System")));
        assert!(!scope.allows_dir(&p("/Volumes")));
        assert!(!scope.allows_dir(&p("/Users/bob/Applications/Foo.app")));
    }

    #[test]
    fn mac_explicit_external_root_is_honoured_but_stick_never() {
        let policy = leak(WalkPolicy::macos(false, vec![p("/Volumes/SCOUT")]));
        let ext = policy.scope(&p("/Volumes/EXT"));
        assert!(ext.allows_dir(&p("/Volumes/EXT")));
        assert!(ext.allows_dir(&p("/Volumes/EXT/photos")));
        assert!(!ext.allows_dir(&p("/Volumes/OTHER")), "outside the explicit root");
        let stick = policy.scope(&p("/Volumes/SCOUT"));
        assert!(!stick.allows_dir(&p("/Volumes/SCOUT")));
        assert!(!stick.allows_dir(&p("/Volumes/SCOUT/ScoutData")));
        // An explicitly chosen bundle is walked, nested bundles are not.
        let app = policy.scope(&p("/Users/bob/Applications/Foo.app"));
        assert!(app.allows_dir(&p("/Users/bob/Applications/Foo.app")));
    }

    #[test]
    fn mac_tcc_skips_are_recorded_without_fda_and_allowed_with_it() {
        let no_fda = leak(WalkPolicy::macos(false, vec![]));
        let scope = no_fda.scope(&p("/"));
        assert!(!scope.allows_dir(&p("/Users/bob/Desktop")));
        assert!(!scope.allows_dir(&p("/Users/bob/Desktop"))); // recorded once
        assert!(!scope.allows_dir(&p("/Users/bob/Library/Safari")));
        assert_eq!(
            no_fda.take_skipped_protected(),
            vec![p("/Users/bob/Desktop"), p("/Users/bob/Library/Safari")]
        );
        assert!(no_fda.take_skipped_protected().is_empty(), "drained");

        let fda = leak(WalkPolicy::macos(true, vec![]));
        let scope = fda.scope(&p("/"));
        assert!(scope.allows_dir(&p("/Users/bob/Desktop")));
        assert!(scope.allows_dir(&p("/Users/bob/Library/Safari")));
        assert!(!scope.allows_dir(&p("/System")), "FDA does not unlock OS areas");
    }

    #[test]
    fn allows_entry_passes_files() {
        let policy = leak(WalkPolicy::macos(false, vec![]));
        let scope = policy.scope(&p("/"));
        assert!(scope.allows_entry(&p("/System/file.jpg"), false));
        assert!(!scope.allows_entry(&p("/System"), true));
    }

    #[test]
    fn host_policy_is_passthrough_off_mac() {
        #[cfg(not(target_os = "macos"))]
        assert!(host_scope(&p("/System")).allows_dir(&p("/System")));
    }
}
