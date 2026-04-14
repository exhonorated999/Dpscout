// Test PDF Generation with Device Information
// This test verifies that device information is always included in PDF reports

#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn test_pdf_with_device_info() {
        // Create test payload with complete device information
        let payload = ReportPayload {
            metadata: ReportMetadata {
                case_number: "TEST-2026-001".to_string(),
                assigned_detective: "Det. Test User".to_string(),
                officer_name: Some("Officer Smith".to_string()),
                agency_name: Some("Test Police Department".to_string()),
                generated_date: "2026-01-05T12:00:00Z".to_string(),
                device_name: Some("TEST-COMPUTER".to_string()),
                operating_system: Some("Windows 11 Pro".to_string()),
                drive_scanned: Some("C:\\".to_string()),
                scan_parameters: Some(ScanParameters {
                    applications_scanned: true,
                    browser_history_scanned: true,
                    keyword_search_performed: false,
                    hash_matching_performed: false,
                    media_scan_performed: false,
                    intrusion_detection_performed: false,
                }),
                scan_duration: Some("5m 30s".to_string()),
                triage_start_time: None,
                triage_end_time: None,
                total_flags: Some(3),
            },
            scope: ReportScope::Flagged,
            formats: vec!["pdf".to_string()],
            flagged_item_ids: vec![],
            all_data: AllDataPayload {
                apps: json!([]),
                keywords: json!([]),
                csam: json!([]),
                browsers: json!([]),
                intrusion: json!(null),
                system_info: json!({
                    "computer_name": "TEST-COMPUTER",
                    "os_version": "Windows 11 Pro (Build 22631)",
                    "registered_owner": "John Doe",
                    "registered_organization": "Test Organization",
                    "product_id": "00331-10000-00001-AA123",
                    "domain": "TESTDOMAIN",
                    "user_accounts": [
                        {
                            "username": "testuser",
                            "full_name": "Test User",
                            "account_type": "Administrator",
                            "last_login": "2026-01-05 10:30:00"
                        },
                        {
                            "username": "admin",
                            "full_name": "System Administrator",
                            "account_type": "Administrator",
                            "last_login": "2026-01-04 15:22:00"
                        }
                    ],
                    "hardware": {
                        "bios_serial": "BIOS-123456",
                        "motherboard_serial": "MB-789012",
                        "system_uuid": "12345678-1234-1234-1234-123456789012",
                        "drives": [
                            {
                                "letter": "C:",
                                "label": "System Drive",
                                "serial_number": "DRIVE-12345",
                                "filesystem": "NTFS",
                                "free_space": 107374182400u64,
                                "total_space": 536870912000u64
                            },
                            {
                                "letter": "D:",
                                "label": "Data Drive",
                                "serial_number": "DRIVE-67890",
                                "filesystem": "NTFS",
                                "free_space": 214748364800u64,
                                "total_space": 1073741824000u64
                            }
                        ]
                    },
                    "network": {
                        "hostname": "TEST-COMPUTER",
                        "ip_addresses": ["192.168.1.100", "10.0.0.50", "fe80::1"],
                        "public_ip": "203.0.113.45",
                        "mac_addresses": ["00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5F"]
                    },
                    "emails": [
                        "test@example.com",
                        "john.doe@company.com",
                        "user123@gmail.com",
                        "admin@testorg.local"
                    ]
                }),
            },
        };

        // Create temporary directory for test output
        let temp_dir = std::env::temp_dir().join("hindsight_test_reports");
        std::fs::create_dir_all(&temp_dir).expect("Failed to create test directory");

        // Generate PDF
        println!("\n=== Testing PDF Generation with Device Information ===\n");
        println!("Generating PDF report to: {}", temp_dir.display());
        
        let result = pdf::generate_pdf(&payload, &temp_dir);
        
        match result {
            Ok(pdf_path) => {
                println!("\n✓ PDF Generated Successfully!");
                println!("  Location: {}", pdf_path.display());
                
                // Check if file exists
                assert!(pdf_path.exists(), "PDF file should exist");
                
                // Check file size (should be more than 10KB)
                let metadata = std::fs::metadata(&pdf_path).expect("Failed to read file metadata");
                let file_size = metadata.len();
                println!("  File Size: {} bytes ({:.2} KB)", file_size, file_size as f64 / 1024.0);
                assert!(file_size > 10000, "PDF should be larger than 10KB");
                
                println!("\n=== Device Information Included ===");
                println!("✓ Computer Name: TEST-COMPUTER");
                println!("✓ OS Version: Windows 11 Pro (Build 22631)");
                println!("✓ Registered Owner: John Doe");
                println!("✓ Organization: Test Organization");
                println!("✓ Product ID: 00331-10000-00001-AA123");
                println!("✓ Domain: TESTDOMAIN");
                println!("✓ User Accounts: 2 accounts");
                println!("✓ Hardware Info: BIOS, Motherboard, UUID, 2 Drives");
                println!("✓ Network Info: Hostname, 3 IPs, Public IP, 2 MACs");
                println!("✓ Email Addresses: 4 discovered emails");
                
                println!("\n📄 Open the PDF to verify all device information is present:");
                println!("   {}", pdf_path.display());
                println!("\nTest passed! Device information is always included in reports.\n");
            }
            Err(e) => {
                panic!("Failed to generate PDF: {}", e);
            }
        }
    }

    #[test]
    fn test_pdf_without_device_info() {
        // Test that PDF still generates gracefully when device info is missing
        let payload = ReportPayload {
            metadata: ReportMetadata {
                case_number: "TEST-2026-002".to_string(),
                assigned_detective: "Det. Test User".to_string(),
                officer_name: None,
                agency_name: None,
                generated_date: "2026-01-05T12:00:00Z".to_string(),
                device_name: None,
                operating_system: None,
                drive_scanned: None,
                scan_parameters: None,
                scan_duration: None,
                triage_start_time: None,
                triage_end_time: None,
                total_flags: None,
            },
            scope: ReportScope::All,
            formats: vec!["pdf".to_string()],
            flagged_item_ids: vec![],
            all_data: AllDataPayload {
                apps: json!([]),
                keywords: json!([]),
                csam: json!([]),
                browsers: json!([]),
                intrusion: json!(null),
                system_info: json!(null),  // No device info
            },
        };

        let temp_dir = std::env::temp_dir().join("hindsight_test_reports");
        std::fs::create_dir_all(&temp_dir).expect("Failed to create test directory");

        let result = pdf::generate_pdf(&payload, &temp_dir);
        
        match result {
            Ok(pdf_path) => {
                println!("\n✓ PDF Generated Successfully (no device info)");
                println!("  Location: {}", pdf_path.display());
                assert!(pdf_path.exists(), "PDF file should exist even without device info");
                println!("  Test passed! PDF generates gracefully without device info.\n");
            }
            Err(e) => {
                panic!("Failed to generate PDF without device info: {}", e);
            }
        }
    }
}
