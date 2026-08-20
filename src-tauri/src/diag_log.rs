//! Diagnostic logging — only compiled when the `diag` feature is on.
//!
//! Writes a plain-text log to `%USERPROFILE%\Desktop\Scout-Diagnostic-Log.txt`
//! (or `~/Desktop/...` on non-Windows). Designed for one purpose: customer
//! reproduces a hang, opens the file, copies the contents, and pastes them
//! into Teams.
//!
//! The macro `dlog!` is always defined (in non-diag builds it's a no-op),
//! so call sites don't need cfg blocks at every line.

#![allow(dead_code)]

use std::sync::{Mutex, OnceLock};
use std::path::PathBuf;
use std::io::Write;
use chrono::Local;

static LOG_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

/// Resolve the log file path. Always returns the same path for the
/// life of the process.
///
/// Desktop: `<Desktop>\Scout-Diagnostic-Log.txt` — easy for a customer to
/// find when support asks for it.
/// Portable: `<usb>\ScoutData\Scout-Diagnostic-Log.txt` — the log follows the
/// drive, and Scout never drops files on a subject machine's Desktop.
pub fn log_path() -> PathBuf {
    if let Some(path) = crate::app_paths::diag_log_path() {
        return path;
    }
    std::env::temp_dir().join("Scout-Diagnostic-Log.txt")
}

/// Truncate the existing log and write a fresh header. Call this when
/// a new SMS scan starts so the customer doesn't have to scroll past
/// stale runs.
pub fn start_session(label: &str) {
    let path = log_path();
    // Ensure Desktop folder exists (e.g. Windows redirected to OneDrive)
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let header = format!(
        "================================================================\n\
         Datapilot Scout — Diagnostic Log\n\
         Session: {}\n\
         Started: {}\n\
         Scout version: {}\n\
         OS: {}\n\
         Log path: {}\n\
         ================================================================\n\n",
        label,
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        path.display(),
    );
    // Truncate
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
    {
        let _ = f.write_all(header.as_bytes());
    }
}

/// Append one line. Always tagged with HH:MM:SS.mmm so we can spot
/// where the hang lives by looking at gaps between timestamps.
pub fn append(line: &str) {
    let path = log_path();
    let mutex = LOG_MUTEX.get_or_init(|| Mutex::new(()));
    let _guard = mutex.lock();
    let stamped = format!(
        "[{}] {}\n",
        Local::now().format("%H:%M:%S%.3f"),
        line,
    );
    // Always mirror to stderr too (release builds with console subsystem
    // will surface this; GUI builds discard but it costs nothing).
    eprint!("{}", stamped);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
    {
        let _ = f.write_all(stamped.as_bytes());
    }
}

/// Write a `=== SCAN ENDED ===` trailer so the customer knows where
/// to stop copying.
pub fn end_session(summary: &str) {
    append(&format!("=== SCAN ENDED === {}", summary));
    append("================================================================");
}

/// Read the log back as a string — used by the "Copy Log to Clipboard"
/// Tauri command on the frontend.
pub fn read_log() -> String {
    std::fs::read_to_string(log_path()).unwrap_or_else(|e| {
        format!("(could not read log file at {}: {})", log_path().display(), e)
    })
}

/// Public macro. In `diag` builds it appends to the log file; in
/// non-diag builds it expands to a no-op `eprintln!` so debug prints
/// don't disappear entirely.
#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {{
        #[cfg(feature = "diag")]
        { $crate::diag_log::append(&format!($($arg)*)); }
        #[cfg(not(feature = "diag"))]
        { eprintln!($($arg)*); }
    }};
}
