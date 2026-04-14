use super::usb_fingerprint::{verify_usb_fingerprint, UsbFingerprint};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

/// Monitor USB presence and emit lock event when USB is removed
pub fn start_usb_monitor(app_handle: AppHandle, fingerprint: UsbFingerprint) {
    let fingerprint = Arc::new(Mutex::new(fingerprint));
    
    std::thread::spawn(move || {
        eprintln!("USB monitor started");
        
        loop {
            std::thread::sleep(Duration::from_secs(2));
            
            // Check if USB is still present
            let fingerprint_guard = fingerprint.lock().unwrap();
            match verify_usb_fingerprint(&fingerprint_guard) {
                Ok(true) => {
                    // USB still present, continue monitoring
                }
                Ok(false) => {
                    eprintln!("⚠️  USB REMOVED - Auto-locking application");
                    let _ = app_handle.emit("usb-removed", ());
                    break;
                }
                Err(e) => {
                    eprintln!("⚠️  USB verification error: {} - Auto-locking", e);
                    let _ = app_handle.emit("usb-removed", ());
                    break;
                }
            }
            drop(fingerprint_guard);
        }
        
        eprintln!("USB monitor stopped");
    });
}
