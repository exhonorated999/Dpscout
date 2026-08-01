//! Process elevation helpers.
//!
//! Raw volume reads (`\\.\X:`) required by the deleted-media unallocated
//! scan need Administrator rights. These helpers let the UI detect that the
//! current process is not elevated and offer a one-click UAC relaunch.

/// Returns true when the current process is running with an elevated token.
///
/// On non-Windows platforms this reports `true` when running as uid 0, since
/// raw block-device reads there are gated on root instead of UAC.
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::mem;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{
            TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY,
        };

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION {
                TokenIsElevated: 0,
            };
            let mut ret_len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);

            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Best-effort: on Unix-likes raw device reads need root.
        std::env::var("USER").map(|u| u == "root").unwrap_or(false)
    }
}

/// Relaunch the current executable with an elevation prompt (UAC), then ask
/// the current instance to exit.
///
/// Returns `Ok(())` once the elevated instance has been requested. The caller
/// is responsible for shutting the current process down (the Tauri command
/// wrapper does this after a short delay so the IPC response still lands).
pub fn relaunch_elevated() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let exe = std::env::current_exe()
            .map_err(|e| format!("Could not resolve current executable: {}", e))?;
        let exe_str = exe.to_string_lossy().to_string();

        // Single-quote escaping for PowerShell string literals.
        let ps_path = exe_str.replace('\'', "''");

        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &format!("Start-Process -FilePath '{}' -Verb RunAs", ps_path),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| format!("Failed to request elevation: {}", e))?;

        if !status.success() {
            // Most common cause: the user dismissed the UAC consent dialog.
            return Err(
                "Elevation was cancelled or denied. Administrator rights are required to read unallocated space."
                    .to_string(),
            );
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Elevation relaunch is only supported on Windows".to_string())
    }
}
