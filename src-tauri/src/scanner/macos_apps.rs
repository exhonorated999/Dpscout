//! macOS installed-application inventory (portable edition, logged-in user).
//!
//! Sources, all read in-process (no `system_profiler`, `pkgutil`, `mdfind`):
//! - `.app` bundles in `/Applications` (plus one folder level, e.g. `Utilities`),
//!   `~/Applications` and `/System/Applications` (flagged as Apple)
//! - `Contents/Info.plist` → name, bundle id, version, category
//! - `Contents/_MASReceipt` → Mac App Store flag
//! - `/Library/Receipts/InstallHistory.plist` → install dates by display name
//! - Homebrew `Cellar` / `Caskroom` (Apple Silicon `/opt/homebrew`, Intel `/usr/local`)
//!
//! The parsers are plain functions that compile and are unit-tested on every
//! OS; only the filesystem walk is `cfg(target_os = "macos")`.
//!
//! Install dates use the Windows registry's `YYYYMMDD` shape so the existing
//! UI formatter (`AppDetails.tsx::formatInstallDate`) renders them unchanged.

use std::collections::HashMap;

/// Fields read from a bundle's `Contents/Info.plist`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BundleInfo {
    pub name: String,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub category_type: Option<String>,
}

/// Parse an `Info.plist` (XML or binary). `fallback_name` is the bundle's
/// file name without `.app`, used when the plist carries no name.
pub fn parse_info_plist(bytes: &[u8], fallback_name: &str) -> Option<BundleInfo> {
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let dict = value.as_dictionary()?;
    let s = |k: &str| {
        dict.get(k)
            .and_then(|v| v.as_string())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let name = s("CFBundleDisplayName")
        .or_else(|| s("CFBundleName"))
        .unwrap_or_else(|| fallback_name.to_string());
    if name.is_empty() {
        return None;
    }
    Some(BundleInfo {
        name,
        bundle_id: s("CFBundleIdentifier"),
        version: s("CFBundleShortVersionString").or_else(|| s("CFBundleVersion")),
        category_type: s("LSApplicationCategoryType"),
    })
}

/// Map `/Library/Receipts/InstallHistory.plist` to `lowercased displayName →
/// earliest install date (YYYYMMDD)`.
pub fn parse_install_history(bytes: &[u8]) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let Ok(value) = plist::Value::from_reader(std::io::Cursor::new(bytes)) else {
        return out;
    };
    let Some(items) = value.as_array() else {
        return out;
    };
    for item in items {
        let Some(d) = item.as_dictionary() else { continue };
        let Some(name) = d.get("displayName").and_then(|v| v.as_string()) else { continue };
        let Some(date) = d.get("date").and_then(|v| v.as_date()) else { continue };
        let st: std::time::SystemTime = date.into();
        let ymd = system_time_to_ymd(st);
        let key = name.trim().to_lowercase();
        if key.is_empty() {
            continue;
        }
        match out.get(&key) {
            Some(existing) if existing.as_str() <= ymd.as_str() => {}
            _ => {
                out.insert(key, ymd);
            }
        }
    }
    out
}

/// Homebrew `INSTALL_RECEIPT.json` → install date (YYYYMMDD) from its `time`
/// field (Unix seconds).
pub fn parse_brew_receipt_date(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let secs = v.get("time")?.as_i64()?;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)?;
    Some(dt.format("%Y%m%d").to_string())
}

pub fn system_time_to_ymd(t: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%Y%m%d").to_string()
}

/// Publisher guess from a reverse-DNS bundle id: `com.google.Chrome` → `google`.
/// Apple ids map to "Apple Inc.".
pub fn publisher_from_bundle_id(bundle_id: &str) -> Option<String> {
    let parts: Vec<&str> = bundle_id.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let org = parts[1];
    if org.eq_ignore_ascii_case("apple") {
        return Some("Apple Inc.".to_string());
    }
    if org.is_empty() {
        None
    } else {
        Some(org.to_string())
    }
}

// ─────────────────────────────── live scan ───────────────────────────────

#[cfg(target_os = "macos")]
pub use live::scan_installed_apps_macos;

#[cfg(target_os = "macos")]
mod live {
    use super::*;
    use crate::scanner::simple_categorizer::CategoryMappings;
    use crate::scanner::{AppCategory, QuestionableApp};
    use std::path::{Path, PathBuf};

    /// `classify(name, publisher)` returns the legacy category and artefact
    /// paths; it is passed in so `questionable_apps.rs` keeps ownership of them.
    pub fn scan_installed_apps_macos<F>(mappings: &CategoryMappings, classify: F) -> Vec<QuestionableApp>
    where
        F: Fn(&str, &Option<String>) -> (AppCategory, Vec<String>),
    {
        let history = std::fs::read("/Library/Receipts/InstallHistory.plist")
            .map(|b| parse_install_history(&b))
            .unwrap_or_default();

        let home = dirs::home_dir();
        let mut roots: Vec<(PathBuf, bool)> = vec![(PathBuf::from("/Applications"), false)];
        if let Some(h) = &home {
            roots.push((h.join("Applications"), false));
        }
        roots.push((PathBuf::from("/System/Applications"), true));

        let mut out = Vec::new();
        for (root, is_system) in roots {
            for bundle in find_app_bundles(&root) {
                if let Some(app) = app_from_bundle(&bundle, is_system, &history, mappings, &classify) {
                    out.push(app);
                }
            }
        }

        for prefix in ["/opt/homebrew", "/usr/local"] {
            out.extend(scan_homebrew(Path::new(prefix), mappings, &classify));
        }
        out
    }

    /// `.app` bundles directly in `root`, plus one level of plain folders
    /// (`/Applications/Utilities`, Setapp, vendor folders). Symlinks are not
    /// followed; bundles are not descended into.
    fn find_app_bundles(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(root) else { return out };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            if name.ends_with(".app") && ft.is_dir() {
                out.push(p);
            } else if ft.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&p) {
                    for s in sub.flatten() {
                        let sn = s.file_name().to_string_lossy().to_string();
                        if sn.ends_with(".app") && s.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            out.push(s.path());
                        }
                    }
                }
            }
        }
        out
    }

    fn app_from_bundle<F>(
        bundle: &Path,
        is_system: bool,
        history: &HashMap<String, String>,
        mappings: &CategoryMappings,
        classify: &F,
    ) -> Option<QuestionableApp>
    where
        F: Fn(&str, &Option<String>) -> (AppCategory, Vec<String>),
    {
        let fallback = bundle.file_stem()?.to_string_lossy().to_string();
        let plist_bytes = std::fs::read(bundle.join("Contents/Info.plist")).ok();
        let info = plist_bytes
            .as_deref()
            .and_then(|b| parse_info_plist(b, &fallback))
            .unwrap_or(BundleInfo { name: fallback.clone(), ..Default::default() });

        let mut publisher = info.bundle_id.as_deref().and_then(publisher_from_bundle_id);
        if is_system {
            publisher = Some("Apple Inc.".to_string());
        }
        let app_store = bundle.join("Contents/_MASReceipt").exists();

        let install_date = history
            .get(&info.name.to_lowercase())
            .cloned()
            .or_else(|| {
                std::fs::metadata(bundle)
                    .ok()
                    .and_then(|m| m.created().ok())
                    .map(system_time_to_ymd)
            });

        let install_path = bundle.to_string_lossy().to_string();
        let (investigative_category, confidence) =
            mappings.categorize(&info.name, &publisher, &install_path);
        let (category, artifact_paths) = classify(&info.name, &publisher);

        let mut version = info.version.unwrap_or_else(|| "Unknown".to_string());
        if app_store {
            version = format!("{} (App Store)", version);
        }

        Some(QuestionableApp {
            name: info.name,
            category,
            install_path,
            version,
            install_date,
            publisher,
            artifact_paths,
            investigative_category: investigative_category.clone(),
            function_category: investigative_category,
            confidence,
        })
    }

    /// Homebrew formulae (`Cellar/<name>/<version>`) and casks
    /// (`Caskroom/<name>/<version>`).
    fn scan_homebrew<F>(prefix: &Path, mappings: &CategoryMappings, classify: &F) -> Vec<QuestionableApp>
    where
        F: Fn(&str, &Option<String>) -> (AppCategory, Vec<String>),
    {
        let mut out = Vec::new();
        for (sub, kind) in [("Cellar", "Homebrew formula"), ("Caskroom", "Homebrew cask")] {
            let dir = prefix.join(sub);
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }
                let Ok(vers) = std::fs::read_dir(e.path()) else { continue };
                for v in vers.flatten() {
                    let vname = v.file_name().to_string_lossy().to_string();
                    if vname.starts_with('.') {
                        continue;
                    }
                    let vpath = v.path();
                    let install_date = std::fs::read_to_string(vpath.join("INSTALL_RECEIPT.json"))
                        .ok()
                        .and_then(|j| parse_brew_receipt_date(&j))
                        .or_else(|| {
                            std::fs::metadata(&vpath)
                                .ok()
                                .and_then(|m| m.created().ok())
                                .map(system_time_to_ymd)
                        });
                    let publisher = Some(kind.to_string());
                    let install_path = vpath.to_string_lossy().to_string();
                    let (investigative_category, confidence) =
                        mappings.categorize(&name, &publisher, &install_path);
                    let (category, artifact_paths) = classify(&name, &publisher);
                    out.push(QuestionableApp {
                        name: name.clone(),
                        category,
                        install_path,
                        version: vname,
                        install_date,
                        publisher,
                        artifact_paths,
                        investigative_category: investigative_category.clone(),
                        function_category: investigative_category,
                        confidence,
                    });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Tor Browser</string>
  <key>CFBundleIdentifier</key><string>org.torproject.torbrowser</string>
  <key>CFBundleShortVersionString</key><string>14.0.1</string>
  <key>CFBundleVersion</key><string>14001</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
</dict></plist>"#;

    #[test]
    fn info_plist_xml() {
        let i = parse_info_plist(INFO_XML.as_bytes(), "x").unwrap();
        assert_eq!(i.name, "Tor Browser");
        assert_eq!(i.bundle_id.as_deref(), Some("org.torproject.torbrowser"));
        assert_eq!(i.version.as_deref(), Some("14.0.1"));
        assert_eq!(i.category_type.as_deref(), Some("public.app-category.productivity"));
    }

    #[test]
    fn info_plist_display_name_wins_and_binary_format() {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), "chrome".into());
        d.insert("CFBundleDisplayName".into(), "Google Chrome".into());
        d.insert("CFBundleVersion".into(), "131.0".into());
        let mut buf = Vec::new();
        plist::Value::Dictionary(d).to_writer_binary(&mut buf).unwrap();
        let i = parse_info_plist(&buf, "x").unwrap();
        assert_eq!(i.name, "Google Chrome");
        assert_eq!(i.version.as_deref(), Some("131.0"), "falls back to CFBundleVersion");
        assert!(i.bundle_id.is_none());
    }

    #[test]
    fn info_plist_falls_back_to_bundle_name() {
        let xml = r#"<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>"#;
        let i = parse_info_plist(xml.as_bytes(), "Signal").unwrap();
        assert_eq!(i.name, "Signal");
        assert!(parse_info_plist(b"not a plist", "x").is_none());
    }

    #[test]
    fn install_history_keeps_earliest_date() {
        let xml = r#"<?xml version="1.0"?><plist version="1.0"><array>
  <dict><key>date</key><date>2025-03-04T10:00:00Z</date><key>displayName</key><string>VeraCrypt</string></dict>
  <dict><key>date</key><date>2024-01-02T23:30:00Z</date><key>displayName</key><string>VeraCrypt</string></dict>
  <dict><key>date</key><date>2024-06-07T00:00:00Z</date><key>displayName</key><string> macOS 15.1 </string></dict>
  <dict><key>displayName</key><string>no date</string></dict>
</array></plist>"#;
        let h = parse_install_history(xml.as_bytes());
        assert_eq!(h.get("veracrypt").map(String::as_str), Some("20240102"));
        assert_eq!(h.get("macos 15.1").map(String::as_str), Some("20240607"));
        assert!(!h.contains_key("no date"));
        assert!(parse_install_history(b"garbage").is_empty());
    }

    #[test]
    fn brew_receipt_time() {
        assert_eq!(
            parse_brew_receipt_date(r#"{"homebrew_version":"4.4.0","time":1700000000}"#).as_deref(),
            Some("20231114")
        );
        assert!(parse_brew_receipt_date(r#"{"time":null}"#).is_none());
        assert!(parse_brew_receipt_date("not json").is_none());
    }

    #[test]
    fn publisher_from_id() {
        assert_eq!(publisher_from_bundle_id("com.apple.Safari").as_deref(), Some("Apple Inc."));
        assert_eq!(publisher_from_bundle_id("com.google.Chrome").as_deref(), Some("google"));
        assert_eq!(publisher_from_bundle_id("single"), None);
    }
}
