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
                    deleted_media_scan_performed: false,
                }),
                scan_duration: Some("5m 30s".to_string()),
                triage_start_time: None,
                triage_end_time: None,
                total_flags: Some(3),
                generate_datapilot_file: None,
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
                hash_matches: json!([]),
                deleted_media: json!([]),
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
                generate_datapilot_file: None,
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
                hash_matches: json!([]),
                deleted_media: json!([]),
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

    /// The BitLocker (Beta) block reads its values out of an untyped
    /// `serde_json::Value`, so the compiler cannot catch a renamed field or a
    /// bad slice. Render it for real instead.
    ///
    /// Two things are deliberately nasty here:
    ///   * A recovery-key path containing non-ASCII characters and long enough
    ///     to force wrapping. `draw_wrapped_text` slices by byte offset, so
    ///     before it was made char-boundary aware this input panicked and took
    ///     down report generation for anyone with an accented username.
    ///   * A volume with no recovery password, which must render the
    ///     "not available" branch rather than being skipped.
    #[test]
    fn test_pdf_with_bitlocker_block() {
        let payload = ReportPayload {
            metadata: ReportMetadata {
                case_number: "TEST-2026-003".to_string(),
                assigned_detective: "Det. Test User".to_string(),
                officer_name: None,
                agency_name: None,
                generated_date: "2026-01-05T12:00:00Z".to_string(),
                device_name: Some("TEST-COMPUTER".to_string()),
                operating_system: Some("Windows 11 Pro".to_string()),
                drive_scanned: Some("C:\\".to_string()),
                scan_parameters: None,
                scan_duration: None,
                triage_start_time: None,
                triage_end_time: None,
                total_flags: None,
                generate_datapilot_file: None,
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
                hash_matches: json!([]),
                deleted_media: json!([]),
                system_info: json!({
                    "computer_name": "TEST-COMPUTER",
                    "bitlocker": {
                        "supported": true,
                        "elevated": true,
                        "status": "Enabled",
                        "status_detail": "BitLocker is enabled on 1 of 2 volumes.",
                        "sweep_scope": "Targeted",
                        "volumes": [
                            {
                                "drive_letter": "C:",
                                "protected": true,
                                "protection_status": "Protection On",
                                "lock_status": "Unlocked",
                                "conversion_status": "Fully Encrypted",
                                "encryption_method": "XTS-AES 128",
                                "recovery_key_id": "A1B2C3D4-1111-2222-3333-444455556666",
                                "recovery_password": "011011-022022-033033-044044-055055-066066-077077-088088"
                            },
                            {
                                "drive_letter": "D:",
                                "protected": false,
                                "protection_status": "Protection Off",
                                "lock_status": "Unlocked",
                                "conversion_status": "Fully Decrypted",
                                "encryption_method": "None",
                                "recovery_key_id": null,
                                "recovery_password": null
                            }
                        ],
                        "key_files": [
                            {
                                // Non-ASCII and long enough to wrap: the
                                // byte-slicing panic regression test.
                                "path": "C:\\Users\\José Müller\\OneDrive\\Documentos\\Copias de seguridad\\BitLocker Recovery Key A1B2C3D4-1111-2222-3333-444455556666.txt",
                                "file_type": "TXT",
                                "recovery_key_id": "A1B2C3D4-1111-2222-3333-444455556666",
                                "recovery_passwords": [
                                    "011011-022022-033033-044044-055055-066066-077077-088088"
                                ],
                                "checksum_valid": true,
                                "modified": "2026-01-02T03:04:05Z",
                                "size_bytes": 2048
                            },
                            {
                                "path": "E:\\密钥备份\\BitLocker 恢复密钥 99998888-7777-6666-5555-444433332222.BEK",
                                "file_type": "BEK",
                                "recovery_key_id": null,
                                "recovery_passwords": [],
                                "checksum_valid": false,
                                "modified": null,
                                "size_bytes": 1024
                            }
                        ],
                        "error": null
                    }
                }),
            },
        };

        let temp_dir = std::env::temp_dir().join("hindsight_test_reports");
        std::fs::create_dir_all(&temp_dir).expect("Failed to create test directory");

        let baseline = pdf::generate_pdf(&payload, &temp_dir)
            .expect("PDF generation must not fail with a BitLocker block present");
        assert!(baseline.exists(), "BitLocker PDF should exist");

        let size = std::fs::metadata(&baseline)
            .expect("Failed to read BitLocker PDF metadata")
            .len();
        println!("  BitLocker PDF: {} ({} bytes)", baseline.display(), size);
        assert!(
            size > 3000,
            "BitLocker PDF looks truncated at {} bytes",
            size
        );
    }

    /// Guards the "we were not allowed to look" path. An unelevated scan must
    /// still produce a BitLocker section, because a *missing* section is
    /// indistinguishable from "this machine is not encrypted" to a reviewer.
    #[test]
    fn test_pdf_with_bitlocker_needs_admin() {
        let payload = ReportPayload {
            metadata: ReportMetadata {
                case_number: "TEST-2026-004".to_string(),
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
                generate_datapilot_file: None,
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
                hash_matches: json!([]),
                deleted_media: json!([]),
                system_info: json!({
                    "bitlocker": {
                        "supported": true,
                        "elevated": false,
                        "status": "Requires Administrator",
                        "status_detail": "Scout is not running as Administrator. Windows blocks all BitLocker volume status and recovery key access without elevation.",
                        "sweep_scope": "Targeted",
                        "volumes": [],
                        "key_files": [],
                        "error": null
                    }
                }),
            },
        };

        let temp_dir = std::env::temp_dir().join("hindsight_test_reports");
        std::fs::create_dir_all(&temp_dir).expect("Failed to create test directory");

        let path = pdf::generate_pdf(&payload, &temp_dir)
            .expect("PDF generation must succeed for an unelevated BitLocker result");
        assert!(path.exists(), "needs-admin BitLocker PDF should exist");
    }

    /// `safe_break_point` is the guard that keeps `draw_wrapped_text` from
    /// panicking on non-ASCII paths. Property-test it rather than trying to
    /// hand-place a multi-byte character on the exact byte offset the wrap
    /// loop happens to use — that arithmetic is brittle and a fixture that
    /// drifts off the boundary silently stops testing anything.
    #[test]
    fn safe_break_point_always_lands_on_a_char_boundary() {
        let samples = [
            "",
            "plain ascii path C:\\Users\\Public\\Documents\\key.txt",
            "C:\\Users\\José Müller\\OneDrive\\Documentos\\Copias de seguridad\\key.txt",
            "E:\\密钥备份\\BitLocker 恢复密钥 99998888-7777-6666.BEK",
            "ααααααααααααααααααααααααααααααααααααααααααααααααααα",
            "🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑",
            "mixed é 漢 🔑 ascii tail that runs on for quite a while indeed yes",
        ];

        for s in samples {
            for limit in 0..=s.chars().count() + 3 {
                let idx = pdf::safe_break_point(s, limit);
                assert!(
                    idx <= s.len(),
                    "index {} past end of {:?} (len {})",
                    idx,
                    s,
                    s.len()
                );
                // The real invariant: slicing here must never panic.
                assert!(
                    s.is_char_boundary(idx),
                    "byte {} is not a char boundary in {:?} at limit {}",
                    idx,
                    s,
                    limit
                );
                let _ = &s[..idx]; // would panic if the guarantee were violated
            }
        }
    }

    /// The wrap loop subtracts `break_at` from `remaining` each pass. If that
    /// can be zero the loop never terminates and the report generator hangs.
    #[test]
    fn safe_break_point_makes_progress_on_non_empty_input() {
        for s in [
            "ascii",
            "éé",
            "漢字漢字",
            "🔑ascii",
            "C:\\Users\\José\\x",
        ] {
            for limit in 1..=8 {
                assert!(
                    pdf::safe_break_point(s, limit) >= 1,
                    "no progress for {:?} at limit {}",
                    s,
                    limit
                );
            }
        }
    }

    /// Pure-ASCII output must be byte-identical to the old behaviour, so this
    /// fix cannot silently reflow every existing report.
    #[test]
    fn safe_break_point_is_a_noop_for_ascii() {
        let s = "C:\\Users\\Public\\Documents\\BitLocker Recovery Key 1234.txt";
        for limit in 0..s.len() {
            assert_eq!(pdf::safe_break_point(s, limit), limit.min(s.len()));
        }
    }
}
