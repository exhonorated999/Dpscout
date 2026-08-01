/// Forensic report generation for bootable mode
/// 
/// Converts forensic scan results into report format

use super::forensic_scan::{ForensicScanResults, TargetSystemInfo};
use crate::reporter::{ReportPayload, ReportMetadata, ScanParameters, ReportScope, AllDataPayload};
use serde_json::json;

/// Convert forensic scan results to report payload
pub fn create_forensic_report_payload(
    results: ForensicScanResults,
    case_number: String,
    detective: String,
    officer: Option<String>,
    agency: Option<String>,
) -> ReportPayload {
    // Create metadata with forensic-specific fields
    let metadata = ReportMetadata {
        case_number,
        assigned_detective: detective,
        officer_name: officer,
        agency_name: agency,
        generated_date: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        device_name: Some(format!(
            "{} (Forensic Scan)",
            results.target_info.system_type
        )),
        operating_system: Some(format!(
            "{} - {}",
            results.system_info.os_name,
            results.system_info.os_version
        )),
        drive_scanned: Some(format!(
            "{} mounted at {}",
            results.target_info.partition,
            results.target_info.mount_point
        )),
        scan_parameters: Some(ScanParameters {
            applications_scanned: results.scan_statistics.total_apps > 0,
            browser_history_scanned: results.scan_statistics.browser_entries > 0,
            keyword_search_performed: results.scan_statistics.keyword_matches > 0,
            hash_matching_performed: true, // Always checked in forensic mode
            media_scan_performed: results.scan_statistics.media_files_found > 0,
            intrusion_detection_performed: false, // Not applicable in offline mode
            deleted_media_scan_performed: false,
        }),
        scan_duration: Some(format!(
            "{} seconds",
            results.scan_statistics.scan_duration_seconds
        )),
        triage_start_time: Some(results.scan_start_time.clone()),
        triage_end_time: Some(results.scan_end_time.clone()),
        total_flags: Some(results.scan_statistics.flagged_media as u32),
    };
    
    // Convert apps to JSON
    let apps_json = json!({
        "questionableApps": results.apps.iter().map(|app| {
            json!({
                "name": app.name,
                "publisher": app.publisher,
                "version": app.version,
                "installLocation": app.install_location,
                "installDate": app.install_date,
                "category": if app.name.contains("[HIGH RISK]") {
                    "High Risk"
                } else if app.name.contains("[MEDIUM RISK]") {
                    "Medium Risk"
                } else {
                    "Unknown"
                },
                "isForensic": true,
            })
        }).collect::<Vec<_>>(),
        "totalApps": results.apps.len(),
        "highRiskApps": results.scan_statistics.high_risk_apps,
    });
    
    // Convert browser history to JSON
    let browsers_json = json!({
        "history": results.browser_history.iter().map(|entry| {
            json!({
                "url": entry.url,
                "title": entry.title,
                "visitCount": entry.visit_count,
                "lastVisitTime": entry.last_visit_time,
                "browser": entry.browser,
            })
        }).collect::<Vec<_>>(),
        "totalEntries": results.browser_history.len(),
    });
    
    // Convert media to JSON
    let csam_json = json!({
        "mediaFiles": results.media_files,
        "totalFiles": results.scan_statistics.media_files_found,
        "flaggedFiles": results.scan_statistics.flagged_media,
    });
    
    // Convert keyword matches to JSON
    let keywords_json = json!({
        "matches": results.keyword_matches,
        "totalMatches": results.scan_statistics.keyword_matches,
    });
    
    // System info with forensic details
    let system_info_json = json!({
        "computerName": results.system_info.computer_name,
        "osName": results.system_info.os_name,
        "osVersion": results.system_info.os_version,
        "username": results.system_info.username,
        "installDate": results.system_info.install_date,
        "forensicMode": true,
        "scanMode": results.scan_mode,
        "targetType": results.target_info.system_type,
        "partition": results.target_info.partition,
        "mountPoint": results.target_info.mount_point,
    });
    
    // Intrusion detection not applicable for offline scans
    let intrusion_json = json!({
        "note": "Intrusion detection not available in forensic mode (offline scan)",
        "results": {}
    });
    
    ReportPayload {
        metadata,
        scope: ReportScope::All,
        formats: vec!["pdf".to_string()],
        flagged_item_ids: Vec::new(), // Will be populated if needed
        all_data: AllDataPayload {
            apps: apps_json,
            keywords: keywords_json,
            csam: csam_json,
            browsers: browsers_json,
            intrusion: intrusion_json,
            system_info: system_info_json,
            hash_matches: json!([]),
            deleted_media: json!([]),
        },
    }
}

/// Add forensic mode indicator to report metadata
pub fn add_forensic_indicators(payload: &mut ReportPayload, target_info: &TargetSystemInfo) {
    // Add forensic mode note to device name
    if let Some(ref device_name) = payload.metadata.device_name {
        payload.metadata.device_name = Some(format!(
            "{} [FORENSIC MODE: Offline Scan]",
            device_name
        ));
    }
    
    // Add target information to drive scanned
    payload.metadata.drive_scanned = Some(format!(
        "{} ({})\nMounted at: {}\nScan Mode: Read-Only Forensic",
        target_info.partition,
        target_info.system_type,
        target_info.mount_point
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::forensic_scan::*;
    use crate::platform::{AppInfo, SystemInfo};
    
    #[test]
    fn test_create_forensic_report() {
        let target_info = TargetSystemInfo {
            system_type: "Windows".to_string(),
            partition: "/dev/sda2".to_string(),
            mount_point: "/mnt/target_windows".to_string(),
            version: "Windows 11".to_string(),
        };
        
        let results = ForensicScanResults {
            target_info,
            system_info: SystemInfo {
                os_name: "Windows 11".to_string(),
                os_version: "22H2".to_string(),
                computer_name: "TEST-PC".to_string(),
                username: "testuser".to_string(),
                install_date: None,
            },
            apps: vec![],
            browser_history: vec![],
            media_files: vec![],
            keyword_matches: vec![],
            scan_statistics: ScanStatistics {
                total_apps: 0,
                high_risk_apps: 0,
                browser_entries: 0,
                media_files_found: 0,
                flagged_media: 0,
                keyword_matches: 0,
                scan_duration_seconds: 120,
                directories_scanned: 10,
                files_processed: 100,
            },
            scan_start_time: "2024-01-01 10:00:00".to_string(),
            scan_end_time: "2024-01-01 10:02:00".to_string(),
            scan_mode: "Forensic".to_string(),
        };
        
        let payload = create_forensic_report_payload(
            results,
            "CASE-001".to_string(),
            "Det. Smith".to_string(),
            None,
            None,
        );
        
        assert_eq!(payload.metadata.case_number, "CASE-001");
        assert!(payload.metadata.device_name.unwrap().contains("Forensic Scan"));
    }
}
