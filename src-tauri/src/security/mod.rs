pub mod auth;
pub mod encryption;
pub mod usb_fingerprint;
pub mod trial;
pub mod elevation;

pub use auth::{is_registered, register_user, login, User, init_security_db};
pub use encryption::{
    save_encrypted_report, list_encrypted_reports, load_encrypted_report,
    delete_encrypted_report, EncryptedReport,
};
pub use usb_fingerprint::{get_usb_fingerprint, verify_usb_fingerprint, UsbFingerprint};
pub use trial::{get_trial_status, check_trial_access, is_trial_build, format_trial_message, TrialStatus};
