pub mod questionable_apps;
pub mod media;
pub mod browser;
pub mod keyword;
pub mod hash_scan;
pub mod android;
pub mod android_sms;
pub mod android_messages_multisilo;
pub mod ios;
pub mod ios_live;
pub mod ios_python;
pub mod ios_backup_parser;
pub mod ios_backup_scanner;
pub mod ios_apps;
pub mod ios_notes;
pub mod ios_media;     // Kept: scan_ios_backup_media used for backup media scanning
pub mod ios_mtp;       // Kept: still referenced from lib.rs commands (will be fully removed later)
pub mod ios_afc_sidecar; // New AFC live-triage engine (Phase 1: Python sidecar)
pub mod ios_afc_commands; // Tauri commands bridging the sidecar to the UI
// pub mod ios_browsers;  // Disabled: functionality covered by ios_backup_parser
pub mod intrusion;
pub mod app_classifier;
pub mod simple_categorizer;
pub mod usb_device;
pub mod deleted_media;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionableApp {
    pub name: String,
    pub category: AppCategory,
    pub install_path: String,
    pub version: String,
    pub install_date: Option<String>,
    pub publisher: Option<String>,
    pub artifact_paths: Vec<String>,
    pub investigative_category: String,
    pub function_category: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppCategory {
    SocialMedia,
    Messaging,
    Gaming,
    PeerToPeer,
    DarkWeb,
    VPN,
    VirtualMachine,
    WebBrowser,
    CloudStorage,
    CryptoPayment,
    Cleaner,
    Encryption,
    AntiForensics,
    RemoteAccess,
    Utilities,
    Productivity,
    Development,
    Multimedia,
    Unknown,
}

impl AppCategory {
    pub fn as_str(&self) -> &str {
        match self {
            AppCategory::SocialMedia => "Social Media",
            AppCategory::Messaging => "Messaging",
            AppCategory::Gaming => "Gaming",
            AppCategory::PeerToPeer => "P2P / File Sharing",
            AppCategory::DarkWeb => "Dark Web / Anonymity",
            AppCategory::VPN => "VPN",
            AppCategory::VirtualMachine => "Virtual Machine",
            AppCategory::WebBrowser => "Browser",
            AppCategory::CloudStorage => "Cloud Storage",
            AppCategory::CryptoPayment => "Crypto / Payment",
            AppCategory::Cleaner => "System Cleaner",
            AppCategory::Encryption => "Encryption",
            AppCategory::AntiForensics => "Anti-Forensic",
            AppCategory::RemoteAccess => "Remote Access",
            AppCategory::Utilities => "Utilities",
            AppCategory::Productivity => "Productivity",
            AppCategory::Development => "Development",
            AppCategory::Multimedia => "Multimedia",
            AppCategory::Unknown => "Unknown",
        }
    }
    
    pub fn risk_level(&self) -> &str {
        match self {
            AppCategory::SocialMedia => "MEDIUM",
            AppCategory::Messaging => "MEDIUM",
            AppCategory::Gaming => "LOW",
            AppCategory::PeerToPeer => "HIGH",
            AppCategory::DarkWeb => "CRITICAL",
            AppCategory::VPN => "HIGH",
            AppCategory::VirtualMachine => "HIGH",
            AppCategory::WebBrowser => "LOW",
            AppCategory::CloudStorage => "MEDIUM",
            AppCategory::CryptoPayment => "HIGH",
            AppCategory::Cleaner => "CRITICAL",
            AppCategory::Encryption => "HIGH",
            AppCategory::AntiForensics => "CRITICAL",
            AppCategory::RemoteAccess => "HIGH",
            AppCategory::Utilities => "LOW",
            AppCategory::Productivity => "LOW",
            AppCategory::Development => "LOW",
            AppCategory::Multimedia => "LOW",
            AppCategory::Unknown => "UNKNOWN",
        }
    }
}
