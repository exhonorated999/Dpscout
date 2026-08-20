//! Centralised, portable-aware filesystem locations for everything Scout owns.
//!
//! # Why this module exists
//!
//! Scout ships as two builds from one codebase:
//!
//! * **Desktop** — installed normally.  User data lives under
//!   `%APPDATA%\Hindsight\` (plus a couple of legacy locations) so it
//!   survives installer upgrades.
//! * **Portable** — runs from a USB thumb drive.  *Everything* must live on
//!   the stick itself, under `<exe_dir>\ScoutData\`, so the officer's hash
//!   lists, keyword lists, settings and reports travel with the drive.
//!
//! Before this module existed only [`crate::licensing`] was portable-aware.
//! Every other subsystem hardcoded `%APPDATA%\Hindsight`, so a portable user
//! who imported a hash list on computer A found it missing on computer B —
//! the data had been written to computer A's profile, not the USB.
//!
//! # Invariant: the desktop build must not move
//!
//! Each accessor below returns the *exact* path the desktop build has always
//! used.  Only the `portable` branch is new.  Relocating desktop data would
//! orphan every existing installation, so the `#[cfg(not(feature =
//! "portable"))]` arms are deliberately identical to the code they replaced —
//! including the two subsystems that never lived in `Hindsight`
//! (`warrant_cases`/`investigations` under `%LOCALAPPDATA%`, and the
//! diagnostic log on the Desktop).
//!
//! # Read-only media
//!
//! A write-protected stick (the WinFE write-blocker workflow) is a hard
//! error, never a silent fallback to the host.  Portable Scout writing
//! evidence-adjacent data onto a subject machine would be a forensic
//! soundness problem, so [`data_root`] probes for writability once and
//! fails loudly with a message the officer can act on.
//!
//! # Deliberately not routed through here
//!
//! `security::auth::init_security_db` keeps `hindsight_secure.db` next to the
//! executable.  On the portable build that is already the USB drive, so the
//! encrypted-report store and trial state travel with the stick as intended —
//! moving it under `ScoutData` would orphan the data of everyone already
//! running a portable drive.  On desktop it sits in the install directory,
//! which is a separate pre-existing concern and is left alone here so this
//! change cannot disturb existing installations.

use std::path::PathBuf;

#[cfg(feature = "portable")]
use std::sync::OnceLock;

/// True when compiled as the portable USB build.
pub const IS_PORTABLE: bool = cfg!(feature = "portable");

/// Folder created on the USB stick to hold all Scout state.
#[cfg(feature = "portable")]
const PORTABLE_DATA_DIR: &str = "ScoutData";

// ---------------------------------------------------------------------------
// Root resolution
// ---------------------------------------------------------------------------

/// Portable: `<exe_dir>\ScoutData`, verified writable.
///
/// The writability probe runs once per process and is cached — it creates and
/// deletes a temporary marker file.  We probe rather than trusting metadata
/// because Windows reports a write-protected volume's directories as ordinary
/// writable directories right up until the first write fails.
#[cfg(feature = "portable")]
fn portable_root() -> Result<PathBuf, String> {
    static ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

    ROOT.get_or_init(|| {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Cannot determine Scout's location on the drive: {}", e))?;
        let exe_dir = exe_path
            .parent()
            .ok_or_else(|| "Cannot determine Scout's folder on the drive.".to_string())?;
        let root = exe_dir.join(PORTABLE_DATA_DIR);

        if !root.exists() {
            std::fs::create_dir_all(&root).map_err(|e| read_only_message(exe_dir, &e))?;
        }

        // Prove we can actually write, not just that the directory exists.
        let probe = root.join(".scout_write_test");
        std::fs::write(&probe, b"scout").map_err(|e| read_only_message(exe_dir, &e))?;
        let _ = std::fs::remove_file(&probe);

        Ok(root)
    })
    .clone()
}

/// Operator-facing explanation for a failed write to the USB drive.
#[cfg(feature = "portable")]
fn read_only_message(exe_dir: &std::path::Path, err: &std::io::Error) -> String {
    let drive = exe_dir
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .unwrap_or_else(|| "the USB drive".to_string());

    format!(
        "Scout Portable cannot write to {drive} ({err}).\n\n\
         Portable Scout stores hash lists, keyword lists, settings and reports \
         on the USB drive itself so they travel with it. It will not write them \
         to the host computer.\n\n\
         Check that:\n\
         \u{2022} the drive's write-protect switch is off\n\
         \u{2022} the drive is not mounted read-only by a write blocker\n\
         \u{2022} the drive is not full\n\
         \u{2022} you have permission to write to it"
    )
}

/// Desktop: `%APPDATA%\Hindsight` — unchanged from every prior release.
#[cfg(not(feature = "portable"))]
fn desktop_root() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "Could not find APPDATA directory".to_string())?;
    let root = PathBuf::from(app_data).join("Hindsight");
    if !root.exists() {
        std::fs::create_dir_all(&root)
            .map_err(|e| format!("Failed to create Hindsight directory: {}", e))?;
    }
    Ok(root)
}

/// Root directory for all Scout-owned data.
///
/// * portable → `<exe_dir>\ScoutData` (hard error if not writable)
/// * desktop  → `%APPDATA%\Hindsight`
pub fn data_root() -> Result<PathBuf, String> {
    #[cfg(feature = "portable")]
    {
        portable_root()
    }
    #[cfg(not(feature = "portable"))]
    {
        desktop_root()
    }
}

/// `data_root()/name`, created if absent.
fn subdir(name: &str) -> Result<PathBuf, String> {
    let dir = data_root()?.join(name);
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create {} directory: {}", name, e))?;
    }
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Individual data locations
// ---------------------------------------------------------------------------

/// Hash database (SQLite). Can reach multiple GB.
///
/// Single source of truth — [`crate::hash_db::HashDatabase::new`] and
/// `clear_hash_database` previously computed this independently, so a
/// portable fix applied to one would have left the other deleting a stale
/// file on the host.
pub fn hash_db_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join("hash_database.db"))
}

/// Imported keyword list `.txt` files.
pub fn keyword_lists_dir() -> Result<PathBuf, String> {
    subdir("keyword_lists")
}

/// Generated PDF reports.
pub fn reports_dir() -> Result<PathBuf, String> {
    subdir("reports")
}

/// `settings.json`.
pub fn settings_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join("settings.json"))
}

/// Cached license / registration database.
pub fn license_db_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join("scout_license.db"))
}

/// Aggregated telemetry counters.
pub fn telemetry_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join("telemetry.json"))
}

/// Presence of this file disables telemetry upload.
pub fn telemetry_opt_out_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join("telemetry_disabled"))
}

/// Portable data root computed by pure path math, with no writability probe.
///
/// Used by the infallible accessors below, which return a bare `PathBuf` and
/// so have no channel to report a read-only drive.  They must still never
/// resolve onto the host, so when the executable's own location cannot be
/// determined we hand back an unusable sentinel rather than something like
/// `std::env::temp_dir()` — a write there would silently land on the subject
/// machine, which is exactly the failure this module exists to prevent.
/// Callers surface the real, readable diagnosis the moment they touch
/// [`data_root`].
#[cfg(feature = "portable")]
fn portable_root_unchecked() -> PathBuf {
    match std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)) {
        Some(exe_dir) => exe_dir.join(PORTABLE_DATA_DIR),
        None => PathBuf::from(r"\\?\SCOUT-PORTABLE-DRIVE-UNAVAILABLE"),
    }
}

/// Warrant-return case working data (extracted media, per-case state).
///
/// Desktop keeps its historical `%LOCALAPPDATA%\DatapilotScout\warrant_cases`
/// location; portable moves it onto the stick.
pub fn cases_root() -> PathBuf {
    #[cfg(feature = "portable")]
    {
        portable_root_unchecked().join("warrant_cases")
    }
    #[cfg(not(feature = "portable"))]
    {
        let base = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
        base.join("DatapilotScout").join("warrant_cases")
    }
}

/// Warrant investigation manifests.
pub fn investigations_root() -> PathBuf {
    #[cfg(feature = "portable")]
    {
        portable_root_unchecked().join("investigations")
    }
    #[cfg(not(feature = "portable"))]
    {
        let base = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
        base.join("DatapilotScout").join("investigations")
    }
}

/// Diagnostic log.
///
/// Desktop drops it on the user's Desktop where support can talk them
/// through finding it.  Portable keeps it on the stick — writing to a
/// subject machine's Desktop or temp folder would contaminate it.
pub fn diag_log_path() -> Option<PathBuf> {
    #[cfg(feature = "portable")]
    {
        Some(portable_root_unchecked().join("Scout-Diagnostic-Log.txt"))
    }
    #[cfg(not(feature = "portable"))]
    {
        dirs::home_dir().map(|home| home.join("Desktop").join("Scout-Diagnostic-Log.txt"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every accessor must sit under the same root so a portable drive holds
    /// one self-contained `ScoutData` folder.
    #[test]
    fn data_locations_share_one_root() {
        let root = data_root().expect("data root resolves");
        for path in [
            hash_db_path().unwrap(),
            keyword_lists_dir().unwrap(),
            reports_dir().unwrap(),
            settings_path().unwrap(),
            license_db_path().unwrap(),
            telemetry_path().unwrap(),
        ] {
            assert!(
                path.starts_with(&root),
                "{:?} escaped the data root {:?}",
                path,
                root
            );
        }
    }

    /// The portable build must resolve next to the executable — on the stick —
    /// and never into the roaming/local profile of whatever host it's plugged
    /// into.  (`USERPROFILE` is deliberately not checked: a dev build tree
    /// legitimately lives under it.)
    #[cfg(feature = "portable")]
    #[test]
    fn portable_root_is_beside_the_executable() {
        let root = data_root().expect("portable root resolves");
        let expected = std::env::current_exe()
            .expect("exe path")
            .parent()
            .expect("exe dir")
            .join(PORTABLE_DATA_DIR);
        assert_eq!(root, expected, "portable data must sit beside the exe");

        let text = root.to_string_lossy().to_lowercase();
        for profile_var in ["APPDATA", "LOCALAPPDATA"] {
            if let Ok(profile) = std::env::var(profile_var) {
                if profile.is_empty() {
                    continue;
                }
                assert!(
                    !text.starts_with(&profile.to_lowercase()),
                    "portable data root {:?} is inside %{}% — it would stay on the host",
                    root,
                    profile_var
                );
            }
        }
    }

    /// A write-protected stick must fail loudly rather than quietly falling
    /// back to the host machine.
    #[cfg(feature = "portable")]
    #[test]
    fn read_only_message_names_the_drive_and_cause() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access is denied");
        let msg = read_only_message(std::path::Path::new(r"E:\Scout"), &err);
        assert!(msg.contains("E:"), "message should name the drive: {msg}");
        assert!(msg.contains("write-protect"), "message should mention write protection: {msg}");
        assert!(
            msg.contains("will not write them to the host computer"),
            "message should state we refuse to fall back to the host: {msg}"
        );
    }

    /// The infallible accessors return a bare `PathBuf`, so they cannot report
    /// a read-only drive. They must still never resolve into the host's temp
    /// folder — an earlier revision fell back to `std::env::temp_dir()`, which
    /// would have written case data onto the machine under examination.
    #[cfg(feature = "portable")]
    #[test]
    fn portable_infallible_paths_never_land_on_the_host() {
        let temp = std::env::temp_dir();
        for path in [cases_root(), investigations_root(), diag_log_path().unwrap()] {
            assert!(
                !path.starts_with(&temp),
                "{:?} resolves into the host temp folder {:?}",
                path,
                temp
            );
        }

        // On a healthy stick they must sit beside the exe, under ScoutData.
        let expected_root = std::env::current_exe()
            .expect("exe path")
            .parent()
            .expect("exe dir")
            .join(PORTABLE_DATA_DIR);
        assert!(cases_root().starts_with(&expected_root));
        assert!(investigations_root().starts_with(&expected_root));
        assert!(diag_log_path().unwrap().starts_with(&expected_root));
    }

    /// Desktop must keep using %APPDATA%\Hindsight — moving it would orphan
    /// every existing installation's hash lists and settings.
    #[cfg(not(feature = "portable"))]
    #[test]
    fn desktop_root_is_unchanged() {
        let root = data_root().expect("desktop root resolves");
        let expected = PathBuf::from(std::env::var("APPDATA").unwrap()).join("Hindsight");
        assert_eq!(root, expected);
    }
}
