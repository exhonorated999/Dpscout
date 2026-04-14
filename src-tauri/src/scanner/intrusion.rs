use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use evtx::{EvtxParser, ParserSettings};
use chrono::Utc;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// Windows constant to hide console windows
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntrusionScanResults {
    pub event_log_anomalies: Vec<EventLogAnomaly>,
    pub persistence_items: Vec<PersistenceItem>,
    pub command_history: Vec<CommandHistoryItem>,
    pub user_account_changes: Vec<UserAccountChange>,
    pub remote_access_indicators: Vec<RemoteAccessIndicator>,
    pub security_tool_tampering: Vec<SecurityTamperingItem>,
    pub network_indicators: Vec<NetworkIndicator>,
    pub malware_indicators: Vec<MalwareIndicator>,
    pub browser_hijacking: Vec<BrowserHijackingItem>,
    pub summary: IntrusionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAccountChange {
    pub change_type: String, // "created", "modified", "enabled", "privileges_elevated"
    pub username: String,
    pub timestamp: String,
    pub details: String,
    pub is_admin: bool,
    pub suspicious: bool,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAccessIndicator {
    pub indicator_type: String, // "rdp_session", "remote_tool", "open_port", "vpn_connection"
    pub tool_name: String,
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
    pub username: Option<String>,
    pub details: String,
    pub risk_level: String, // "LOW", "MEDIUM", "HIGH", "CRITICAL"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityTamperingItem {
    pub tamper_type: String, // "antivirus_disabled", "firewall_disabled", "uac_disabled", "defender_disabled"
    pub component: String,
    pub timestamp: Option<String>,
    pub details: String,
    pub registry_key: Option<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkIndicator {
    pub indicator_type: String, // "suspicious_connection", "high_traffic", "dns_anomaly", "c2_communication"
    pub destination: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub timestamp: Option<String>,
    pub details: String,
    pub threat_intel: Option<String>, // Known malicious IP/domain info
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MalwareIndicator {
    pub indicator_type: String, // "hidden_process", "suspicious_binary", "modified_system_file", "dll_injection"
    pub file_path: String,
    pub process_name: Option<String>,
    pub hash: Option<String>,
    pub timestamp: Option<String>,
    pub details: String,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHijackingItem {
    pub hijack_type: String, // "homepage_changed", "search_engine_changed", "unwanted_extension", "credential_stealer"
    pub browser: String,
    pub item_name: String,
    pub value: String,
    pub timestamp: Option<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntrusionSummary {
    pub total_artifacts: usize,
    pub critical_findings: usize,
    pub high_risk_findings: usize,
    pub medium_risk_findings: usize,
    pub low_risk_findings: usize,
    pub overall_risk_score: u8, // 0-100
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogAnomaly {
    pub artifact_type: String,
    pub event_id: u32,
    pub timestamp: String,
    pub description: String,
    pub log_path: String,
    pub log_name: String,
    pub severity: String,
    pub user: Option<String>,
    pub process: Option<String>,
    pub event_data: Option<HashMap<String, String>>,
    pub computer: Option<String>,
    pub provider: Option<String>,
    pub level: Option<String>,
    pub suspicious_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistenceItem {
    pub persistence_type: String,
    pub name: String,
    pub target_path: String,
    pub location: String,
    pub timestamp: Option<String>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandHistoryItem {
    pub command_type: String,
    pub command: String,
    pub timestamp: String,
    pub source_path: String,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntrusionScanOptions {
    pub scan_event_logs: bool,
    pub scan_persistence: bool,
    pub scan_command_history: bool,
    pub scan_user_accounts: bool,
    pub scan_remote_access: bool,
    pub scan_security_tampering: bool,
    pub scan_network: bool,
    pub scan_malware: bool,
    pub scan_browser_hijacking: bool,
    pub target_drive: Option<String>,
}

impl Default for IntrusionScanOptions {
    fn default() -> Self {
        Self {
            scan_event_logs: true,
            scan_persistence: true,
            scan_command_history: true,
            scan_user_accounts: true,
            scan_remote_access: true,
            scan_security_tampering: true,
            scan_network: true,
            scan_malware: true,
            scan_browser_hijacking: true,
            target_drive: None,
        }
    }
}

/// Scan for Windows intrusion artifacts
pub fn scan_intrusion_artifacts(options: IntrusionScanOptions) -> Result<IntrusionScanResults, Box<dyn std::error::Error>> {
    let mut results = IntrusionScanResults {
        event_log_anomalies: Vec::new(),
        persistence_items: Vec::new(),
        command_history: Vec::new(),
        user_account_changes: Vec::new(),
        remote_access_indicators: Vec::new(),
        security_tool_tampering: Vec::new(),
        network_indicators: Vec::new(),
        malware_indicators: Vec::new(),
        browser_hijacking: Vec::new(),
        summary: IntrusionSummary {
            total_artifacts: 0,
            critical_findings: 0,
            high_risk_findings: 0,
            medium_risk_findings: 0,
            low_risk_findings: 0,
            overall_risk_score: 0,
            recommendations: Vec::new(),
        },
    };

    let base_path = if let Some(drive) = &options.target_drive {
        PathBuf::from(drive)
    } else {
        PathBuf::from("C:\\")
    };

    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  HINDSIGHT INTRUSION DETECTION SCAN                     ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!("Target: {:?}", base_path);
    eprintln!();

    if options.scan_event_logs {
        eprintln!("[1/9] Scanning Windows Event Logs...");
        match scan_event_logs(&base_path) {
            Ok(logs) => {
                results.event_log_anomalies = logs;
                eprintln!("✓ Found {} event log anomalies", results.event_log_anomalies.len());
            }
            Err(e) => eprintln!("⚠ Event log scan error: {}", e),
        }
    }

    if options.scan_persistence {
        eprintln!("[2/9] Scanning persistence mechanisms...");
        match scan_persistence_mechanisms(&base_path) {
            Ok(items) => {
                results.persistence_items = items;
                eprintln!("✓ Found {} persistence items", results.persistence_items.len());
            }
            Err(e) => eprintln!("⚠ Persistence scan error: {}", e),
        }
    }

    if options.scan_command_history {
        eprintln!("[3/9] Scanning command history...");
        match scan_command_history(&base_path) {
            Ok(history) => {
                results.command_history = history;
                eprintln!("✓ Found {} command history entries", results.command_history.len());
            }
            Err(e) => eprintln!("⚠ Command history scan error: {}", e),
        }
    }

    if options.scan_user_accounts {
        eprintln!("[4/9] Scanning user account changes...");
        match scan_user_account_changes(&base_path) {
            Ok(accounts) => {
                results.user_account_changes = accounts;
                eprintln!("✓ Found {} user account changes", results.user_account_changes.len());
            }
            Err(e) => eprintln!("⚠ User account scan error: {}", e),
        }
    }

    if options.scan_remote_access {
        eprintln!("[5/9] Scanning remote access indicators...");
        match scan_remote_access_indicators(&base_path) {
            Ok(indicators) => {
                results.remote_access_indicators = indicators;
                eprintln!("✓ Found {} remote access indicators", results.remote_access_indicators.len());
            }
            Err(e) => eprintln!("⚠ Remote access scan error: {}", e),
        }
    }

    if options.scan_security_tampering {
        eprintln!("[6/9] Scanning security tool tampering...");
        match scan_security_tampering(&base_path) {
            Ok(tampering) => {
                results.security_tool_tampering = tampering;
                eprintln!("✓ Found {} security tampering incidents", results.security_tool_tampering.len());
            }
            Err(e) => eprintln!("⚠ Security tampering scan error: {}", e),
        }
    }

    if options.scan_network {
        eprintln!("[7/9] Scanning network indicators...");
        match scan_network_indicators(&base_path) {
            Ok(network) => {
                results.network_indicators = network;
                eprintln!("✓ Found {} network indicators", results.network_indicators.len());
            }
            Err(e) => eprintln!("⚠ Network scan error: {}", e),
        }
    }

    if options.scan_malware {
        eprintln!("[8/9] Scanning malware indicators...");
        match scan_malware_indicators(&base_path) {
            Ok(malware) => {
                results.malware_indicators = malware;
                eprintln!("✓ Found {} malware indicators", results.malware_indicators.len());
            }
            Err(e) => eprintln!("⚠ Malware scan error: {}", e),
        }
    }

    if options.scan_browser_hijacking {
        eprintln!("[9/9] Scanning browser hijacking...");
        match scan_browser_hijacking(&base_path) {
            Ok(hijacking) => {
                results.browser_hijacking = hijacking;
                eprintln!("✓ Found {} browser hijacking items", results.browser_hijacking.len());
            }
            Err(e) => eprintln!("⚠ Browser hijacking scan error: {}", e),
        }
    }

    // Generate summary
    results.summary = generate_intrusion_summary(&results);

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  SCAN COMPLETE - SUMMARY                                ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!("Event Log Anomalies:      {}", results.event_log_anomalies.len());
    eprintln!("Persistence Items:        {} ({} suspicious)", 
        results.persistence_items.len(),
        results.persistence_items.iter().filter(|p| p.suspicious).count());
    eprintln!("Command History:          {} ({} suspicious)", 
        results.command_history.len(),
        results.command_history.iter().filter(|c| c.suspicious).count());
    eprintln!("User Account Changes:     {}", results.user_account_changes.len());
    eprintln!("Remote Access Indicators: {}", results.remote_access_indicators.len());
    eprintln!("Security Tampering:       {}", results.security_tool_tampering.len());
    eprintln!("Network Indicators:       {}", results.network_indicators.len());
    eprintln!("Malware Indicators:       {}", results.malware_indicators.len());
    eprintln!("Browser Hijacking:        {}", results.browser_hijacking.len());
    eprintln!();
    eprintln!("Total Artifacts:          {}", results.summary.total_artifacts);
    eprintln!("Critical Findings:        {}", results.summary.critical_findings);
    eprintln!("High Risk Findings:       {}", results.summary.high_risk_findings);
    eprintln!("Overall Risk Score:       {}/100", results.summary.overall_risk_score);
    eprintln!();

    Ok(results)
}

/// Scan Windows Event Logs for suspicious activity with full .evtx parsing
fn scan_event_logs(base_path: &Path) -> Result<Vec<EventLogAnomaly>, Box<dyn std::error::Error>> {
    let mut anomalies = Vec::new();
    
    // Define priority Event IDs to extract from each log
    let event_log_configs = vec![
        EventLogConfig {
            path: base_path.join("Windows\\System32\\winevt\\Logs\\Security.evtx"),
            name: "Security".to_string(),
            priority_events: vec![
                (1102, "Audit log cleared - CRITICAL indicator of anti-forensics", "CRITICAL"),
                (4624, "Successful logon", "MEDIUM"),
                (4625, "Failed logon attempt", "MEDIUM"),
                (4648, "Logon using explicit credentials", "HIGH"),
                (4672, "Special privileges assigned", "HIGH"),
                (4698, "Scheduled task created", "HIGH"),
                (4699, "Scheduled task deleted", "MEDIUM"),
                (4700, "Scheduled task enabled", "MEDIUM"),
                (4701, "Scheduled task disabled", "MEDIUM"),
                (4720, "User account created", "HIGH"),
                (4722, "User account enabled", "MEDIUM"),
                (4724, "Password reset attempt", "MEDIUM"),
                (4732, "Member added to security-enabled group", "HIGH"),
                (4733, "Member removed from security-enabled group", "MEDIUM"),
                (4756, "Member added to universal security group", "HIGH"),
            ],
            max_events: 5000,
        },
        EventLogConfig {
            path: base_path.join("Windows\\System32\\winevt\\Logs\\System.evtx"),
            name: "System".to_string(),
            priority_events: vec![
                (104, "Event log cleared", "CRITICAL"),
                (7045, "Service installed", "HIGH"),
                (7040, "Service startup type changed", "MEDIUM"),
                (7036, "Service started/stopped", "LOW"),
                (7030, "Service marked as interactive", "MEDIUM"),
                (7034, "Service crashed", "MEDIUM"),
            ],
            max_events: 3000,
        },
        EventLogConfig {
            path: base_path.join("Windows\\System32\\winevt\\Logs\\Application.evtx"),
            name: "Application".to_string(),
            priority_events: vec![
                (1000, "Application error", "MEDIUM"),
                (1001, "Windows Error Reporting", "LOW"),
                (1002, "Application hang", "MEDIUM"),
            ],
            max_events: 1000,
        },
        EventLogConfig {
            path: base_path.join("Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"),
            name: "PowerShell".to_string(),
            priority_events: vec![
                (4103, "Module logging", "MEDIUM"),
                (4104, "Script block logging", "HIGH"),
                (4105, "Script block invocation start", "MEDIUM"),
                (4106, "Script block invocation complete", "MEDIUM"),
            ],
            max_events: 2000,
        },
        EventLogConfig {
            path: base_path.join("Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"),
            name: "Sysmon".to_string(),
            priority_events: vec![
                (1, "Process creation", "MEDIUM"),
                (3, "Network connection", "MEDIUM"),
                (7, "Image loaded", "MEDIUM"),
                (8, "CreateRemoteThread", "HIGH"),
                (10, "Process access", "HIGH"),
                (11, "File creation", "MEDIUM"),
                (12, "Registry object create/delete", "MEDIUM"),
                (13, "Registry value set", "MEDIUM"),
                (22, "DNS query", "LOW"),
            ],
            max_events: 3000,
        },
    ];

    for config in event_log_configs {
        if config.path.exists() {
            eprintln!("Parsing .evtx file: {:?}", config.path);
            
            // Check file size first
            if let Ok(metadata) = fs::metadata(&config.path) {
                let size = metadata.len();
                
                // Check for suspiciously small logs (cleared)
                if size < 69632 {
                    anomalies.push(EventLogAnomaly {
                        artifact_type: "Log Tampered".to_string(),
                        event_id: 1102,
                        timestamp: Utc::now().to_rfc3339(),
                        description: format!("⚠️ {} log appears to have been recently cleared ({} bytes)", 
                            config.name, size),
                        log_path: config.path.to_string_lossy().to_string(),
                        log_name: config.name.clone(),
                        severity: "CRITICAL".to_string(),
                        user: None,
                        process: None,
                        event_data: None,
                        computer: None,
                        provider: None,
                        level: None,
                        suspicious_score: 100,
                    });
                }
            }
            
            // Try PowerShell first for live Windows systems, then fall back to .evtx parsing
            #[cfg(target_os = "windows")]
            {
                // Check if we're on a live system (C:\ exists and is the base path)
                let is_live_system = base_path == Path::new("C:\\");
                
                if is_live_system && (config.name == "Security" || config.name == "System" || config.name == "Application") {
                    // Try PowerShell Get-WinEvent for live systems
                    match query_event_log_powershell(&config) {
                        Ok(mut events) => {
                            eprintln!("Extracted {} events from {} (via PowerShell)", events.len(), config.name);
                            anomalies.append(&mut events);
                            continue; // Skip .evtx parsing
                        }
                        Err(e) => {
                            eprintln!("PowerShell query failed for {}: {}", config.name, e);
                            // Fall through to .evtx parsing attempt
                        }
                    }
                }
            }
            
            // Parse .evtx file (forensic mode or PowerShell fallback)
            match parse_evtx_file(&config) {
                Ok(mut events) => {
                    eprintln!("Extracted {} events from {}", events.len(), config.name);
                    anomalies.append(&mut events);
                }
                Err(e) => {
                    eprintln!("Error parsing {}: {}", config.name, e);
                    // Add informational message
                    #[cfg(target_os = "windows")]
                    {
                        let is_live_system = base_path == Path::new("C:\\");
                        if is_live_system {
                            anomalies.push(EventLogAnomaly {
                                artifact_type: "Access Limitation".to_string(),
                                event_id: 0,
                                timestamp: Utc::now().to_rfc3339(),
                                description: format!(
                                    "Cannot access {} log (requires Administrator privileges or forensic boot mode)", 
                                    config.name
                                ),
                                log_path: config.path.to_string_lossy().to_string(),
                                log_name: config.name.clone(),
                                severity: "INFO".to_string(),
                                user: None,
                                process: None,
                                event_data: None,
                                computer: None,
                                provider: None,
                                level: None,
                                suspicious_score: 0,
                            });
                        } else {
                            anomalies.push(EventLogAnomaly {
                                artifact_type: "Parse Error".to_string(),
                                event_id: 0,
                                timestamp: Utc::now().to_rfc3339(),
                                description: format!("Failed to parse {} log: {}", config.name, e),
                                log_path: config.path.to_string_lossy().to_string(),
                                log_name: config.name.clone(),
                                severity: "WARNING".to_string(),
                                user: None,
                                process: None,
                                event_data: None,
                                computer: None,
                                provider: None,
                                level: None,
                                suspicious_score: 0,
                            });
                        }
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        anomalies.push(EventLogAnomaly {
                            artifact_type: "Parse Error".to_string(),
                            event_id: 0,
                            timestamp: Utc::now().to_rfc3339(),
                            description: format!("Failed to parse {} log: {}", config.name, e),
                            log_path: config.path.to_string_lossy().to_string(),
                            log_name: config.name.clone(),
                            severity: "WARNING".to_string(),
                            user: None,
                            process: None,
                            event_data: None,
                            computer: None,
                            provider: None,
                            level: None,
                            suspicious_score: 0,
                        });
                    }
                }
            }
        } else {
            // Log is missing
            if config.name == "Security" || config.name == "System" {
                anomalies.push(EventLogAnomaly {
                    artifact_type: "Log Missing".to_string(),
                    event_id: 0,
                    timestamp: Utc::now().to_rfc3339(),
                    description: format!("⚠️ {} log file is MISSING - Possible anti-forensics", config.name),
                    log_path: config.path.to_string_lossy().to_string(),
                    log_name: config.name.clone(),
                    severity: "CRITICAL".to_string(),
                    user: None,
                    process: None,
                    event_data: None,
                    computer: None,
                    provider: None,
                    level: None,
                    suspicious_score: 100,
                });
            }
        }
    }

    // Perform cross-log correlation
    anomalies.extend(correlate_events(&anomalies)?);

    Ok(anomalies)
}

/// Configuration for parsing a specific event log
struct EventLogConfig {
    path: PathBuf,
    name: String,
    priority_events: Vec<(u32, &'static str, &'static str)>, // (event_id, description, severity)
    max_events: usize,
}

/// Query Windows Event Log using PowerShell (for live systems)
#[cfg(target_os = "windows")]
fn query_event_log_powershell(config: &EventLogConfig) -> Result<Vec<EventLogAnomaly>, Box<dyn std::error::Error>> {
    let mut anomalies = Vec::new();
    
    // Build filter for priority event IDs
    let event_ids: Vec<String> = config.priority_events.iter()
        .map(|(id, _, _)| id.to_string())
        .collect();
    let filter = event_ids.join(",");
    
    // Build PowerShell command to query recent events
    let ps_script = format!(
        "Get-WinEvent -LogName '{}' -MaxEvents {} -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -in @({}) }} | Select-Object -First {} | ForEach-Object {{ [PSCustomObject]@{{ EventId=$_.Id; TimeCreated=$_.TimeCreated.ToString('o'); Message=$_.Message; Level=$_.Level; Provider=$_.ProviderName }} }} | ConvertTo-Json",
        config.name,
        config.max_events * 2, // Query more, filter to max
        filter,
        config.max_events
    );
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    
    if !output.status.success() {
        return Err(format!("PowerShell command failed: {}", 
            String::from_utf8_lossy(&output.stderr)).into());
    }
    
    let json_output = String::from_utf8_lossy(&output.stdout);
    
    // Parse JSON output
    if json_output.trim().is_empty() || json_output.trim() == "null" {
        // No events found (not an error)
        return Ok(anomalies);
    }
    
    // Handle both single object and array
    let json_str = json_output.trim();
    let wrapped = if json_str.starts_with('[') {
        json_str.to_string()
    } else {
        format!("[{}]", json_str)
    };
    
    if let Ok(events) = serde_json::from_str::<Vec<serde_json::Value>>(&wrapped) {
        for event in events {
            if let Some(event_id) = event["EventId"].as_u64() {
                let event_id = event_id as u32;
                
                // Find the description and severity for this event ID
                if let Some((desc, severity)) = config.priority_events.iter()
                    .find(|(id, _, _)| *id == event_id)
                    .map(|(_, desc, sev)| (*desc, *sev))
                {
                    anomalies.push(EventLogAnomaly {
                        artifact_type: "Event Log Entry".to_string(),
                        event_id,
                        timestamp: event["TimeCreated"].as_str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| Utc::now().to_rfc3339()),
                        description: format!("{}\n{}", desc, 
                            event["Message"].as_str().unwrap_or("").chars().take(200).collect::<String>()),
                        log_path: config.path.to_string_lossy().to_string(),
                        log_name: config.name.clone(),
                        severity: severity.to_string(),
                        user: None,
                        process: None,
                        event_data: None,
                        computer: None,
                        provider: event["Provider"].as_str().map(|s| s.to_string()),
                        level: event["Level"].as_u64().map(|l| l.to_string()),
                        suspicious_score: match severity {
                            "CRITICAL" => 100,
                            "HIGH" => 75,
                            "MEDIUM" => 50,
                            "LOW" => 25,
                            _ => 0,
                        },
                    });
                }
            }
        }
    }
    
    Ok(anomalies)
}

/// Parse a single .evtx file and extract priority events
fn parse_evtx_file(config: &EventLogConfig) -> Result<Vec<EventLogAnomaly>, Box<dyn std::error::Error>> {
    let mut anomalies = Vec::new();
    let priority_ids: HashMap<u32, (&str, &str)> = config.priority_events.iter()
        .map(|(id, desc, sev)| (*id, (*desc, *sev)))
        .collect();
    
    // Create parser with settings
    let settings = ParserSettings::default()
        .num_threads(0); // Single-threaded for deterministic order
    
    let mut parser = EvtxParser::from_path(&config.path)?
        .with_configuration(settings);
    
    let mut count = 0;
    
    // Iterate through records
    for record in parser.records() {
        if count >= config.max_events {
            eprintln!("Reached max events limit ({}) for {}", config.max_events, config.name);
            break;
        }
        
        match record {
            Ok(r) => {
                // Parse the XML data
                let data = r.data;
                
                // Extract Event ID from the record
                if let Some(event_id) = extract_event_id(&data) {
                    // Only process priority events
                    if let Some((desc, severity)) = priority_ids.get(&event_id) {
                        let anomaly = parse_event_record(
                            &data,
                            event_id,
                            desc,
                            severity,
                            &config.name,
                            &config.path,
                        );
                        
                        anomalies.push(anomaly);
                        count += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading record from {}: {}", config.name, e);
                continue;
            }
        }
    }
    
    Ok(anomalies)
}

/// Extract Event ID from XML data
fn extract_event_id(xml: &str) -> Option<u32> {
    // Simple XML parsing to get EventID
    // Look for <EventID>XXX</EventID> or <EventID Qualifiers="...">XXX</EventID>
    if let Some(start) = xml.find("<EventID") {
        if let Some(close_tag) = xml[start..].find('>') {
            let content_start = start + close_tag + 1;
            if let Some(end) = xml[content_start..].find("</EventID>") {
                let id_str = &xml[content_start..content_start + end].trim();
                return id_str.parse::<u32>().ok();
            }
        }
    }
    None
}

/// Parse a single event record into EventLogAnomaly
fn parse_event_record(
    xml: &str,
    event_id: u32,
    description: &str,
    severity: &str,
    log_name: &str,
    log_path: &Path,
) -> EventLogAnomaly {
    let mut event_data = HashMap::new();
    
    // Extract timestamp
    let timestamp = extract_xml_field(xml, "TimeCreated", "SystemTime")
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    
    // Extract computer name
    let computer = extract_xml_field(xml, "Computer", "");
    
    // Extract provider
    let provider = extract_xml_field(xml, "Provider", "Name");
    
    // Extract level
    let level = extract_xml_field(xml, "Level", "");
    
    // Extract user SID/name
    let user = extract_xml_field(xml, "Security", "UserID");
    
    // Extract all EventData fields
    extract_event_data_fields(xml, &mut event_data);
    
    // Calculate suspicious score
    let suspicious_score = calculate_suspicious_score(event_id, &event_data, xml);
    
    // Build description with context
    let full_description = build_event_description(event_id, description, &event_data);
    
    EventLogAnomaly {
        artifact_type: "Event Log Entry".to_string(),
        event_id,
        timestamp,
        description: full_description,
        log_path: log_path.to_string_lossy().to_string(),
        log_name: log_name.to_string(),
        severity: severity.to_string(),
        user,
        process: event_data.get("ProcessName").or(event_data.get("Image")).cloned(),
        event_data: Some(event_data),
        computer,
        provider,
        level,
        suspicious_score,
    }
}

/// Extract a field from XML
fn extract_xml_field(xml: &str, tag: &str, attribute: &str) -> Option<String> {
    if attribute.is_empty() {
        // Extract tag content
        let start_tag = format!("<{}>", tag);
        let end_tag = format!("</{}>", tag);
        
        if let Some(start) = xml.find(&start_tag) {
            let content_start = start + start_tag.len();
            if let Some(end) = xml[content_start..].find(&end_tag) {
                return Some(xml[content_start..content_start + end].trim().to_string());
            }
        }
    } else {
        // Extract attribute value
        let attr_pattern = format!("{}=\"", attribute);
        if let Some(tag_start) = xml.find(&format!("<{}", tag)) {
            if let Some(attr_start) = xml[tag_start..].find(&attr_pattern) {
                let value_start = tag_start + attr_start + attr_pattern.len();
                if let Some(value_end) = xml[value_start..].find('"') {
                    return Some(xml[value_start..value_start + value_end].to_string());
                }
            }
        }
    }
    None
}

/// Extract all EventData fields from XML
fn extract_event_data_fields(xml: &str, data: &mut HashMap<String, String>) {
    // Look for <EventData> section
    if let Some(start) = xml.find("<EventData>") {
        if let Some(end) = xml[start..].find("</EventData>") {
            let event_data_section = &xml[start..start + end];
            
            // Extract <Data Name="...">value</Data> entries
            let mut search_pos = 0;
            while let Some(data_start) = event_data_section[search_pos..].find("<Data Name=\"") {
                let abs_start = search_pos + data_start;
                let name_start = abs_start + 12; // len of "<Data Name=\""
                
                if let Some(name_end) = event_data_section[name_start..].find('"') {
                    let name = &event_data_section[name_start..name_start + name_end];
                    
                    if let Some(content_start_rel) = event_data_section[name_start + name_end..].find('>') {
                        let content_start = name_start + name_end + content_start_rel + 1;
                        
                        if let Some(content_end) = event_data_section[content_start..].find("</Data>") {
                            let value = &event_data_section[content_start..content_start + content_end];
                            data.insert(name.to_string(), value.trim().to_string());
                        }
                    }
                }
                
                search_pos = abs_start + 1;
            }
        }
    }
}

/// Calculate suspicious score for an event
fn calculate_suspicious_score(event_id: u32, event_data: &HashMap<String, String>, xml: &str) -> u8 {
    let mut score = 0u8;
    
    // Critical events
    match event_id {
        1102 | 104 => score += 100, // Log cleared
        4720 | 4732 => score += 60, // User creation, group addition
        4698 => score += 50, // Scheduled task
        7045 => score += 60, // Service installed
        _ => score += 10,
    }
    
    // Check for suspicious patterns in data
    let xml_lower = xml.to_lowercase();
    
    // Check for suspicious processes
    if let Some(image) = event_data.get("Image").or(event_data.get("ProcessName")) {
        let image_lower = image.to_lowercase();
        if image_lower.contains("powershell") ||
           image_lower.contains("cmd.exe") ||
           image_lower.contains("wscript") ||
           image_lower.contains("cscript") ||
           image_lower.contains("mshta") ||
           image_lower.contains("regsvr32") ||
           image_lower.contains("rundll32") {
            score += 20;
        }
    }
    
    // Check for suspicious commands
    if let Some(command) = event_data.get("CommandLine").or(event_data.get("ScriptBlockText")) {
        if is_suspicious_command(command) {
            score += 40;
        }
    }
    
    // Check for unusual logon types
    if event_id == 4624 {
        if let Some(logon_type) = event_data.get("LogonType") {
            if logon_type == "10" { // RemoteInteractive
                score += 15;
            } else if logon_type == "3" { // Network
                score += 10;
            }
        }
    }
    
    // Check for failed logons
    if event_id == 4625 {
        score += 15;
    }
    
    // Cap at 100
    score.min(100)
}

/// Build a detailed description for an event
fn build_event_description(
    event_id: u32,
    base_description: &str,
    event_data: &HashMap<String, String>,
) -> String {
    let mut desc = base_description.to_string();
    
    // Add relevant context based on event type
    match event_id {
        4624 | 4625 => {
            // Logon events
            if let Some(user) = event_data.get("TargetUserName") {
                desc.push_str(&format!(" - User: {}", user));
            }
            if let Some(logon_type) = event_data.get("LogonType") {
                let logon_type_name = match logon_type.as_str() {
                    "2" => "Interactive",
                    "3" => "Network",
                    "4" => "Batch",
                    "5" => "Service",
                    "7" => "Unlock",
                    "8" => "NetworkCleartext",
                    "9" => "NewCredentials",
                    "10" => "RemoteInteractive",
                    "11" => "CachedInteractive",
                    _ => logon_type,
                };
                desc.push_str(&format!(", Type: {}", logon_type_name));
            }
            if let Some(ip) = event_data.get("IpAddress") {
                desc.push_str(&format!(", From: {}", ip));
            }
        }
        4698 | 4699 | 4700 | 4701 => {
            // Scheduled task events
            if let Some(task_name) = event_data.get("TaskName") {
                desc.push_str(&format!(" - Task: {}", task_name));
            }
        }
        4720 => {
            // User created
            if let Some(user) = event_data.get("TargetUserName") {
                desc.push_str(&format!(" - New User: {}", user));
            }
            if let Some(by) = event_data.get("SubjectUserName") {
                desc.push_str(&format!(", By: {}", by));
            }
        }
        7045 => {
            // Service installed
            if let Some(service) = event_data.get("ServiceName") {
                desc.push_str(&format!(" - Service: {}", service));
            }
            if let Some(path) = event_data.get("ImagePath") {
                desc.push_str(&format!(", Path: {}", path));
            }
        }
        4104 => {
            // PowerShell script block
            if let Some(script) = event_data.get("ScriptBlockText") {
                let preview = if script.len() > 200 {
                    format!("{}...", &script[..200])
                } else {
                    script.clone()
                };
                desc.push_str(&format!(" - Script: {}", preview));
            }
        }
        1 => {
            // Sysmon process creation
            if let Some(image) = event_data.get("Image") {
                desc.push_str(&format!(" - Process: {}", image));
            }
            if let Some(cmdline) = event_data.get("CommandLine") {
                let preview = if cmdline.len() > 150 {
                    format!("{}...", &cmdline[..150])
                } else {
                    cmdline.clone()
                };
                desc.push_str(&format!(", Command: {}", preview));
            }
        }
        _ => {}
    }
    
    desc
}

/// Correlate events across logs to detect attack patterns
fn correlate_events(events: &[EventLogAnomaly]) -> Result<Vec<EventLogAnomaly>, Box<dyn std::error::Error>> {
    let mut correlations = Vec::new();
    
    // Pattern 1: Multiple failed logins followed by success (brute force)
    let failed_logins: Vec<_> = events.iter()
        .filter(|e| e.event_id == 4625)
        .collect();
    
    let success_logins: Vec<_> = events.iter()
        .filter(|e| e.event_id == 4624)
        .collect();
    
    if failed_logins.len() >= 5 {
        for success in success_logins {
            if let Some(success_user) = &success.user {
                let related_failures = failed_logins.iter()
                    .filter(|f| {
                        if let Some(fail_user) = &f.user {
                            fail_user == success_user
                        } else {
                            false
                        }
                    })
                    .count();
                
                if related_failures >= 3 {
                    correlations.push(EventLogAnomaly {
                        artifact_type: "Attack Pattern".to_string(),
                        event_id: 0,
                        timestamp: success.timestamp.clone(),
                        description: format!(
                            "⚠️ BRUTE FORCE DETECTED: {} failed login attempts followed by successful login for user {}",
                            related_failures, success_user
                        ),
                        log_path: success.log_path.clone(),
                        log_name: "Correlation".to_string(),
                        severity: "CRITICAL".to_string(),
                        user: Some(success_user.clone()),
                        process: None,
                        event_data: None,
                        computer: success.computer.clone(),
                        provider: None,
                        level: None,
                        suspicious_score: 95,
                    });
                }
            }
        }
    }
    
    // Pattern 2: Service creation followed by suspicious process execution
    let services_created: Vec<_> = events.iter()
        .filter(|e| e.event_id == 7045)
        .collect();
    
    if services_created.len() > 0 {
        for service in services_created {
            if service.suspicious_score > 50 {
                correlations.push(EventLogAnomaly {
                    artifact_type: "Attack Pattern".to_string(),
                    event_id: 0,
                    timestamp: service.timestamp.clone(),
                    description: format!(
                        "⚠️ SUSPICIOUS SERVICE: New service created with suspicious characteristics - {}",
                        service.description
                    ),
                    log_path: service.log_path.clone(),
                    log_name: "Correlation".to_string(),
                    severity: "HIGH".to_string(),
                    user: service.user.clone(),
                    process: service.process.clone(),
                    event_data: service.event_data.clone(),
                    computer: service.computer.clone(),
                    provider: None,
                    level: None,
                    suspicious_score: 80,
                });
            }
        }
    }
    
    // Pattern 3: Log clearing events (always suspicious)
    let log_clears: Vec<_> = events.iter()
        .filter(|e| e.event_id == 1102 || e.event_id == 104)
        .collect();
    
    if log_clears.len() > 0 {
        for clear_event in log_clears {
            correlations.push(EventLogAnomaly {
                artifact_type: "Attack Pattern".to_string(),
                event_id: 0,
                timestamp: clear_event.timestamp.clone(),
                description: format!(
                    "⚠️ ANTI-FORENSICS DETECTED: {} log was cleared - Investigation required",
                    clear_event.log_name
                ),
                log_path: clear_event.log_path.clone(),
                log_name: "Correlation".to_string(),
                severity: "CRITICAL".to_string(),
                user: clear_event.user.clone(),
                process: None,
                event_data: None,
                computer: clear_event.computer.clone(),
                provider: None,
                level: None,
                suspicious_score: 100,
            });
        }
    }
    
    Ok(correlations)
}

/// Scan for persistence mechanisms
fn scan_persistence_mechanisms(base_path: &Path) -> Result<Vec<PersistenceItem>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();

    // Scan startup folders
    items.extend(scan_startup_folders(base_path)?);
    
    // Scan scheduled tasks
    items.extend(scan_scheduled_tasks(base_path)?);
    
    // Scan Registry run keys (Windows only)
    #[cfg(target_os = "windows")]
    {
        items.extend(scan_registry_run_keys()?);
    }

    Ok(items)
}

/// Scan Windows Registry for autorun locations
#[cfg(target_os = "windows")]
fn scan_registry_run_keys() -> Result<Vec<PersistenceItem>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();

    // Common autorun registry locations
    let registry_locations = vec![
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell Folders"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "User Shell Folders"),
    ];

    for (hkey, path, location_name) in registry_locations {
        if let Ok(key) = RegKey::predef(hkey).open_subkey(path) {
            for value_name in key.enum_values().filter_map(Result::ok) {
                let name = value_name.0;
                if let Ok(value) = key.get_value::<String, _>(&name) {
                    items.push(PersistenceItem {
                        persistence_type: "Registry Run Key".to_string(),
                        name: name.clone(),
                        target_path: value.clone(),
                        location: location_name.to_string(),
                        timestamp: None,
                        suspicious: is_suspicious_registry_value(&value),
                    });
                }
            }
        }
    }

    Ok(items)
}

#[cfg(not(target_os = "windows"))]
fn scan_registry_run_keys() -> Result<Vec<PersistenceItem>, Box<dyn std::error::Error>> {
    Ok(Vec::new())
}

/// Scan startup folders
fn scan_startup_folders(base_path: &Path) -> Result<Vec<PersistenceItem>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();

    let mut startup_paths = vec![
        base_path.join("ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        base_path.join("Users\\Public\\Start Menu\\Programs\\Startup"),
    ];

    // Also check user-specific startup folders
    if let Ok(users_dir) = fs::read_dir(base_path.join("Users")) {
        for user_entry in users_dir.filter_map(|e| e.ok()) {
            let user_startup = user_entry.path()
                .join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            if user_startup.exists() {
                startup_paths.push(user_startup);
            }
        }
    }

    for startup_path in startup_paths {
        if startup_path.exists() {
            if let Ok(entries) = fs::read_dir(&startup_path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() {
                        let metadata = fs::metadata(&path)?;
                        let modified = metadata.modified()?;
                        
                        items.push(PersistenceItem {
                            persistence_type: "Startup Folder".to_string(),
                            name: path.file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("Unknown")
                                .to_string(),
                            target_path: path.to_string_lossy().to_string(),
                            location: startup_path.to_string_lossy().to_string(),
                            timestamp: Some(format!("{:?}", modified)),
                            suspicious: is_suspicious_startup(&path),
                        });
                    }
                }
            }
        }
    }

    Ok(items)
}

/// Scan scheduled tasks
fn scan_scheduled_tasks(base_path: &Path) -> Result<Vec<PersistenceItem>, Box<dyn std::error::Error>> {
    let mut items = Vec::new();
    
    let tasks_path = base_path.join("Windows\\System32\\Tasks");
    
    if tasks_path.exists() {
        scan_tasks_recursive(&tasks_path, &tasks_path, &mut items)?;
    }

    Ok(items)
}

fn scan_tasks_recursive(
    base_path: &Path,
    current_path: &Path,
    items: &mut Vec<PersistenceItem>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(entries) = fs::read_dir(current_path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            
            if path.is_dir() {
                scan_tasks_recursive(base_path, &path, items)?;
            } else if path.is_file() {
                if let Ok(metadata) = fs::metadata(&path) {
                    let modified = metadata.modified()?;
                    
                    // Skip Microsoft default tasks
                    let is_microsoft = path.to_string_lossy().contains("Microsoft");
                    
                    items.push(PersistenceItem {
                        persistence_type: "Scheduled Task".to_string(),
                        name: path.file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        target_path: path.to_string_lossy().to_string(),
                        location: path.parent()
                            .unwrap_or(base_path)
                            .to_string_lossy()
                            .to_string(),
                        timestamp: Some(format!("{:?}", modified)),
                        suspicious: !is_microsoft,
                    });
                }
            }
        }
    }
    
    Ok(())
}

/// Scan command history
fn scan_command_history(base_path: &Path) -> Result<Vec<CommandHistoryItem>, Box<dyn std::error::Error>> {
    let mut commands = Vec::new();

    // Scan PowerShell history files
    commands.extend(scan_powershell_history(base_path)?);
    
    Ok(commands)
}

/// Scan PowerShell history
fn scan_powershell_history(base_path: &Path) -> Result<Vec<CommandHistoryItem>, Box<dyn std::error::Error>> {
    let mut commands = Vec::new();

    // PowerShell history locations
    if let Ok(users_dir) = fs::read_dir(base_path.join("Users")) {
        for user_entry in users_dir.filter_map(|e| e.ok()) {
            let ps_history_path = user_entry.path()
                .join("AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
            
            if ps_history_path.exists() {
                if let Ok(content) = fs::read_to_string(&ps_history_path) {
                    let metadata = fs::metadata(&ps_history_path)?;
                    let modified = metadata.modified()?;
                    
                    for (idx, line) in content.lines().enumerate() {
                        if !line.trim().is_empty() {
                            commands.push(CommandHistoryItem {
                                command_type: "PowerShell".to_string(),
                                command: line.to_string(),
                                timestamp: format!("{:?}", modified),
                                source_path: ps_history_path.to_string_lossy().to_string(),
                                suspicious: is_suspicious_command(line),
                            });
                            
                            // Limit to most recent 100 commands per user
                            if idx >= 100 {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(commands)
}

/// Check if a startup item is suspicious
fn is_suspicious_startup(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    
    // Check for common suspicious patterns
    path_str.contains("temp") ||
    path_str.contains("appdata\\local\\temp") ||
    path_str.ends_with(".bat") ||
    path_str.ends_with(".vbs") ||
    path_str.ends_with(".ps1")
}

/// Check if a registry value is suspicious
fn is_suspicious_registry_value(value: &str) -> bool {
    let value_lower = value.to_lowercase();
    
    // Suspicious patterns in registry values
    value_lower.contains("\\temp\\") ||
    value_lower.contains("\\appdata\\local\\temp\\") ||
    value_lower.contains("powershell") && (
        value_lower.contains("-encodedcommand") ||
        value_lower.contains("-enc") ||
        value_lower.contains("-w hidden") ||
        value_lower.contains("bypass")
    ) ||
    value_lower.contains("cmd.exe /c") ||
    value_lower.contains("wscript") ||
    value_lower.contains("cscript") ||
    value_lower.ends_with(".vbs") ||
    value_lower.ends_with(".bat") ||
    value_lower.ends_with(".ps1")
}

/// Check if a command is suspicious
fn is_suspicious_command(command: &str) -> bool {
    let cmd_lower = command.to_lowercase();
    
    // PowerShell obfuscation and evasion
    if cmd_lower.contains("invoke-expression") ||
       cmd_lower.contains("iex ") ||
       cmd_lower.contains("iex(") ||
       cmd_lower.contains("-encodedcommand") ||
       cmd_lower.contains("-enc ") ||
       cmd_lower.contains("-e ") && cmd_lower.contains("powershell") ||
       cmd_lower.contains("frombase64string") {
        return true;
    }
    
    // Download operations
    if cmd_lower.contains("downloadstring") ||
       cmd_lower.contains("downloadfile") ||
       cmd_lower.contains("webclient") ||
       cmd_lower.contains("invoke-webrequest") ||
       cmd_lower.contains("wget") ||
       cmd_lower.contains("curl") && cmd_lower.contains("http") {
        return true;
    }
    
    // Execution policy bypass
    if cmd_lower.contains("bypass") ||
       cmd_lower.contains("-ep bypass") ||
       cmd_lower.contains("-executionpolicy bypass") {
        return true;
    }
    
    // Hidden execution
    if cmd_lower.contains("-w hidden") ||
       cmd_lower.contains("-windowstyle hidden") ||
       cmd_lower.contains("-nop") {
        return true;
    }
    
    // Credential access tools
    if cmd_lower.contains("mimikatz") ||
       cmd_lower.contains("invoke-mimikatz") ||
       cmd_lower.contains("sekurlsa") ||
       cmd_lower.contains("lsadump") {
        return true;
    }
    
    // Lateral movement
    if cmd_lower.contains("invoke-wmimethod") ||
       cmd_lower.contains("psexec") ||
       cmd_lower.contains("wmic process call create") {
        return true;
    }
    
    // Persistence
    if cmd_lower.contains("new-service") ||
       cmd_lower.contains("schtasks /create") {
        return true;
    }
    
    // Reconnaissance
    if cmd_lower.contains("get-aduser") ||
       cmd_lower.contains("get-adcomputer") ||
       cmd_lower.contains("net user") ||
       cmd_lower.contains("net localgroup") ||
       cmd_lower.contains("whoami /all") {
        return true;
    }
    
    // Anti-forensics
    if cmd_lower.contains("clear-eventlog") ||
       cmd_lower.contains("wevtutil cl") ||
       cmd_lower.contains("del /f /s /q") {
        return true;
    }
    
    false
}

// ═══════════════════════════════════════════════════════════════════════════
// NEW ENHANCED INTRUSION DETECTION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Scan for user account changes (new accounts, privilege escalations, etc.)
fn scan_user_account_changes(_base_path: &Path) -> Result<Vec<UserAccountChange>, Box<dyn std::error::Error>> {
    let mut changes = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        // Get local user accounts
        eprintln!("  → Checking local user accounts...");
        let output = Command::new("net")
            .args(&["user"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("Administrator") || line.contains("Guest") {
                    // Check if suspicious accounts exist
                    if line.contains("$") || line.contains("_") {
                        changes.push(UserAccountChange {
                            change_type: "suspicious_account".to_string(),
                            username: line.trim().to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            details: "Account name contains suspicious characters".to_string(),
                            is_admin: false,
                            suspicious: true,
                            risk_score: 70,
                        });
                    }
                }
            }
        }

        // Check Administrators group
        eprintln!("  → Checking Administrators group members...");
        let output = Command::new("net")
            .args(&["localgroup", "Administrators"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut in_members_section = false;
            
            for line in stdout.lines() {
                if line.contains("Members") {
                    in_members_section = true;
                    continue;
                }
                
                if in_members_section && !line.trim().is_empty() && !line.starts_with("The command") {
                    let username = line.trim();
                    
                    // Flag unusual admin accounts
                    if !username.contains("Administrator") && !username.contains("Domain") {
                        changes.push(UserAccountChange {
                            change_type: "admin_privilege".to_string(),
                            username: username.to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            details: "User has administrative privileges".to_string(),
                            is_admin: true,
                            suspicious: true,
                            risk_score: 60,
                        });
                    }
                }
            }
        }

        // Check for recently created accounts via Registry
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(_sam) = hklm.open_subkey("SAM\\SAM\\Domains\\Account\\Users") {
            // Note: Requires admin privileges to access
            eprintln!("  → Checking SAM for recent account creation...");
        }
    }

    eprintln!("  ✓ Identified {} user account changes", changes.len());
    Ok(changes)
}

/// Scan for remote access indicators (RDP, TeamViewer, AnyDesk, etc.)
fn scan_remote_access_indicators(_base_path: &Path) -> Result<Vec<RemoteAccessIndicator>, Box<dyn std::error::Error>> {
    let mut indicators = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        // Check for remote access tools installed
        eprintln!("  → Checking for remote access tools...");
        
        let remote_tools = vec![
            ("TeamViewer", "C:\\Program Files\\TeamViewer", "HIGH"),
            ("TeamViewer", "C:\\Program Files (x86)\\TeamViewer", "HIGH"),
            ("AnyDesk", "C:\\Program Files\\AnyDesk", "HIGH"),
            ("AnyDesk", "C:\\Program Files (x86)\\AnyDesk", "HIGH"),
            ("VNC", "C:\\Program Files\\RealVNC", "MEDIUM"),
            ("VNC", "C:\\Program Files\\TightVNC", "MEDIUM"),
            ("Chrome Remote Desktop", "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\gbchcmhmhahfdphkhkmpfmihenigjmpp", "MEDIUM"),
        ];

        for (tool_name, path, risk) in remote_tools {
            let check_path = PathBuf::from(path);
            if check_path.exists() || path.contains("*") {
                indicators.push(RemoteAccessIndicator {
                    indicator_type: "remote_tool".to_string(),
                    tool_name: tool_name.to_string(),
                    timestamp: None,
                    source_ip: None,
                    username: None,
                    details: format!("Remote access tool detected: {}", path),
                    risk_level: risk.to_string(),
                });
            }
        }

        // Check RDP status
        eprintln!("  → Checking RDP configuration...");
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(rdp_key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server") {
            if let Ok(enabled) = rdp_key.get_value::<u32, &str>("fDenyTSConnections") {
                if enabled == 0 {
                    indicators.push(RemoteAccessIndicator {
                        indicator_type: "rdp_enabled".to_string(),
                        tool_name: "Remote Desktop Protocol".to_string(),
                        timestamp: None,
                        source_ip: None,
                        username: None,
                        details: "RDP is enabled on this system".to_string(),
                        risk_level: "HIGH".to_string(),
                    });
                }
            }
        }

        // Check for active RDP sessions
        eprintln!("  → Checking for active RDP sessions...");
        let output = Command::new("qwinsta")
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("rdp-tcp") || line.contains("Active") {
                    indicators.push(RemoteAccessIndicator {
                        indicator_type: "rdp_session".to_string(),
                        tool_name: "RDP".to_string(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        source_ip: None,
                        username: None,
                        details: format!("Active/recent RDP session: {}", line.trim()),
                        risk_level: "CRITICAL".to_string(),
                    });
                }
            }
        }

        // Check for SSH connections (OpenSSH on Windows)
        if PathBuf::from("C:\\Windows\\System32\\OpenSSH").exists() {
            indicators.push(RemoteAccessIndicator {
                indicator_type: "ssh_installed".to_string(),
                tool_name: "OpenSSH".to_string(),
                timestamp: None,
                source_ip: None,
                username: None,
                details: "OpenSSH is installed on this system".to_string(),
                risk_level: "MEDIUM".to_string(),
            });
        }

        // Check listening ports for remote access
        eprintln!("  → Checking for suspicious open ports...");
        let output = Command::new("netstat")
            .args(&["-ano"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let suspicious_ports = vec![
                (3389, "RDP", "HIGH"),
                (5900, "VNC", "HIGH"),
                (5800, "VNC", "HIGH"),
                (22, "SSH", "MEDIUM"),
                (23, "Telnet", "CRITICAL"),
                (445, "SMB", "HIGH"),
            ];

            for (port, service, risk) in suspicious_ports {
                for line in stdout.lines() {
                    if line.contains(&format!(":{}", port)) && line.contains("LISTENING") {
                        indicators.push(RemoteAccessIndicator {
                            indicator_type: "open_port".to_string(),
                            tool_name: service.to_string(),
                            timestamp: Some(chrono::Utc::now().to_rfc3339()),
                            source_ip: None,
                            username: None,
                            details: format!("Port {} ({}) is listening", port, service),
                            risk_level: risk.to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    eprintln!("  ✓ Identified {} remote access indicators", indicators.len());
    Ok(indicators)
}

/// Scan for security tool tampering (disabled AV, firewall, UAC, etc.)
fn scan_security_tampering(_base_path: &Path) -> Result<Vec<SecurityTamperingItem>, Box<dyn std::error::Error>> {
    let mut tampering = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        eprintln!("  → Checking Windows Defender status...");
        
        // Check Windows Defender via Registry
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        // Windows Defender
        if let Ok(defender) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender") {
            if let Ok(disabled) = defender.get_value::<u32, &str>("DisableAntiSpyware") {
                if disabled == 1 {
                    tampering.push(SecurityTamperingItem {
                        tamper_type: "defender_disabled".to_string(),
                        component: "Windows Defender".to_string(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        details: "Windows Defender is disabled via registry".to_string(),
                        registry_key: Some("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware".to_string()),
                        risk_level: "CRITICAL".to_string(),
                    });
                }
            }

            // Real-time protection
            if let Ok(rt_protection) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection") {
                if let Ok(disabled) = rt_protection.get_value::<u32, &str>("DisableRealtimeMonitoring") {
                    if disabled == 1 {
                        tampering.push(SecurityTamperingItem {
                            tamper_type: "realtime_protection_disabled".to_string(),
                            component: "Windows Defender Real-Time Protection".to_string(),
                            timestamp: Some(chrono::Utc::now().to_rfc3339()),
                            details: "Real-time protection is disabled".to_string(),
                            registry_key: Some("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring".to_string()),
                            risk_level: "CRITICAL".to_string(),
                        });
                    }
                }
            }
        }

        // Check UAC
        eprintln!("  → Checking UAC status...");
        if let Ok(uac) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") {
            if let Ok(uac_enabled) = uac.get_value::<u32, &str>("EnableLUA") {
                if uac_enabled == 0 {
                    tampering.push(SecurityTamperingItem {
                        tamper_type: "uac_disabled".to_string(),
                        component: "User Account Control".to_string(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        details: "UAC is completely disabled".to_string(),
                        registry_key: Some("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA".to_string()),
                        risk_level: "HIGH".to_string(),
                    });
                }
            }
        }

        // Check Firewall
        eprintln!("  → Checking Windows Firewall status...");
        if let Ok(firewall) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile") {
            if let Ok(enabled) = firewall.get_value::<u32, &str>("EnableFirewall") {
                if enabled == 0 {
                    tampering.push(SecurityTamperingItem {
                        tamper_type: "firewall_disabled".to_string(),
                        component: "Windows Firewall (Standard Profile)".to_string(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        details: "Windows Firewall is disabled for Standard profile".to_string(),
                        registry_key: Some("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall".to_string()),
                        risk_level: "HIGH".to_string(),
                    });
                }
            }
        }

        // Check via PowerShell for more detailed info
        let output = Command::new("powershell")
            .args(&["-Command", "Get-MpComputerStatus | ConvertTo-Json"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"RealTimeProtectionEnabled\":false") ||
               stdout.contains("\"RealTimeProtectionEnabled\": false") {
                if !tampering.iter().any(|t| t.tamper_type == "realtime_protection_disabled") {
                    tampering.push(SecurityTamperingItem {
                        tamper_type: "realtime_protection_disabled".to_string(),
                        component: "Windows Defender Real-Time Protection".to_string(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        details: "Real-time protection is disabled (verified via PowerShell)".to_string(),
                        registry_key: None,
                        risk_level: "CRITICAL".to_string(),
                    });
                }
            }
        }
    }

    eprintln!("  ✓ Identified {} security tampering incidents", tampering.len());
    Ok(tampering)
}

/// Scan for network indicators (suspicious connections, DNS queries, etc.)
fn scan_network_indicators(_base_path: &Path) -> Result<Vec<NetworkIndicator>, Box<dyn std::error::Error>> {
    let mut indicators = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        eprintln!("  → Checking active network connections...");
        
        let output = Command::new("netstat")
            .args(&["-ano"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Known malicious/suspicious ports
            let suspicious_ports: Vec<u16> = vec![
                4444, 4445, // Metasploit
                5555, // Android Debug Bridge (ADB)
                6666, 6667, 6668, 6669, // IRC (common C2)
                7777, 8888, 9999, // Generic backdoors
                31337, 12345, // Classic backdoor ports
            ];

            for line in stdout.lines() {
                // Parse netstat output
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let local_addr = parts[1];
                    let foreign_addr = parts[2];
                    
                    // Check for suspicious foreign addresses
                    if foreign_addr.contains(":") && !foreign_addr.starts_with("0.0.0.0") {
                        let addr_parts: Vec<&str> = foreign_addr.split(':').collect();
                        if addr_parts.len() == 2 {
                            if let Ok(port) = addr_parts[1].parse::<u16>() {
                                if suspicious_ports.contains(&port) {
                                    indicators.push(NetworkIndicator {
                                        indicator_type: "suspicious_connection".to_string(),
                                        destination: foreign_addr.to_string(),
                                        port: Some(port),
                                        protocol: Some("TCP".to_string()),
                                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                                        details: format!("Connection to suspicious port {} from {}", port, local_addr),
                                        threat_intel: Some(format!("Port {} is commonly used by malware/backdoors", port)),
                                        risk_score: 85,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check DNS cache for suspicious domains
        eprintln!("  → Checking DNS cache...");
        let output = Command::new("ipconfig")
            .args(&["/displaydns"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Suspicious TLDs and patterns
            let suspicious_patterns = vec![
                ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs popular with malware
                ".top", ".xyz", ".club",
                "dyndns", "no-ip", "ddns", // Dynamic DNS
            ];

            for line in stdout.lines() {
                let line_lower = line.to_lowercase();
                for pattern in &suspicious_patterns {
                    if line_lower.contains(pattern) {
                        indicators.push(NetworkIndicator {
                            indicator_type: "dns_anomaly".to_string(),
                            destination: line.trim().to_string(),
                            port: None,
                            protocol: Some("DNS".to_string()),
                            timestamp: Some(chrono::Utc::now().to_rfc3339()),
                            details: format!("DNS query to suspicious domain containing '{}'", pattern),
                            threat_intel: Some(format!("Domain contains suspicious pattern: {}", pattern)),
                            risk_score: 70,
                        });
                        break;
                    }
                }
            }
        }
    }

    eprintln!("  ✓ Identified {} network indicators", indicators.len());
    Ok(indicators)
}

/// Scan for malware indicators (hidden processes, suspicious binaries, etc.)
fn scan_malware_indicators(_base_path: &Path) -> Result<Vec<MalwareIndicator>, Box<dyn std::error::Error>> {
    let mut indicators = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        eprintln!("  → Checking for suspicious processes...");
        
        // Get process list
        let output = Command::new("tasklist")
            .args(&["/V", "/FO", "CSV"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Known suspicious process names
            let suspicious_names = vec![
                "keylogger", "rat", "trojan", "backdoor", "hack",
                "mimikatz", "psexec", "procdump", "pwdump",
                "crack", "bypass", "payload",
            ];

            for line in stdout.lines().skip(1) { // Skip header
                let line_lower = line.to_lowercase();
                for name in &suspicious_names {
                    if line_lower.contains(name) {
                        indicators.push(MalwareIndicator {
                            indicator_type: "suspicious_process".to_string(),
                            file_path: "Unknown".to_string(),
                            process_name: Some(line.split(',').next().unwrap_or("Unknown").replace("\"", "")),
                            hash: None,
                            timestamp: Some(chrono::Utc::now().to_rfc3339()),
                            details: format!("Process name contains suspicious keyword: {}", name),
                            risk_score: 90,
                        });
                        break;
                    }
                }
            }
        }

        // Check common malware locations
        eprintln!("  → Checking common malware locations...");
        let suspicious_locations = vec![
            "C:\\Windows\\Temp",
            "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp",
            "C:\\Users\\Public",
            "C:\\ProgramData",
        ];

        for location in suspicious_locations {
            let path = PathBuf::from(location);
            if path.exists() {
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries.flatten().take(50) { // Limit to 50 per directory
                        let file_path = entry.path();
                        if let Some(ext) = file_path.extension() {
                            let ext_str = ext.to_string_lossy().to_lowercase();
                            // Check for executable files in temp directories
                            if ext_str == "exe" || ext_str == "dll" || ext_str == "scr" || ext_str == "bat" {
                                indicators.push(MalwareIndicator {
                                    indicator_type: "suspicious_binary".to_string(),
                                    file_path: file_path.to_string_lossy().to_string(),
                                    process_name: None,
                                    hash: None,
                                    timestamp: entry.metadata().ok()
                                        .and_then(|m| m.modified().ok())
                                        .map(|t| format!("{:?}", t)),
                                    details: format!("Executable found in temporary directory: {}", location),
                                    risk_score: 75,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for system file modifications
        eprintln!("  → Checking system file integrity...");
        let critical_files = vec![
            ("C:\\Windows\\System32\\svchost.exe", "svchost.exe"),
            ("C:\\Windows\\System32\\explorer.exe", "explorer.exe"),
            ("C:\\Windows\\System32\\lsass.exe", "lsass.exe"),
            ("C:\\Windows\\System32\\csrss.exe", "csrss.exe"),
        ];

        for (path_str, name) in critical_files {
            let path = PathBuf::from(path_str);
            if let Ok(metadata) = fs::metadata(&path) {
                // Check if file size is suspicious (very small or very large)
                let size = metadata.len();
                if size < 10000 || size > 10_000_000 {
                    indicators.push(MalwareIndicator {
                        indicator_type: "modified_system_file".to_string(),
                        file_path: path_str.to_string(),
                        process_name: Some(name.to_string()),
                        hash: None,
                        timestamp: metadata.modified().ok()
                            .map(|t| format!("{:?}", t)),
                        details: format!("System file has suspicious size: {} bytes", size),
                        risk_score: 95,
                    });
                }
            }
        }
    }

    eprintln!("  ✓ Identified {} malware indicators", indicators.len());
    Ok(indicators)
}

/// Scan for browser hijacking (modified homepage, extensions, etc.)
fn scan_browser_hijacking(_base_path: &Path) -> Result<Vec<BrowserHijackingItem>, Box<dyn std::error::Error>> {
    let mut hijacking = Vec::new();

    #[cfg(target_os = "windows")]
    {
        eprintln!("  → Checking browser settings...");
        
        // Check Internet Explorer/Edge settings via Registry
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(ie_main) = hkcu.open_subkey("Software\\Microsoft\\Internet Explorer\\Main") {
            if let Ok(homepage) = ie_main.get_value::<String, &str>("Start Page") {
                let homepage_lower = homepage.to_lowercase();
                let is_suspicious = !homepage_lower.contains("microsoft") &&
                                    !homepage_lower.contains("google") &&
                                    !homepage_lower.contains("bing") &&
                                    !homepage.is_empty() &&
                                    homepage != "about:blank";

                if is_suspicious {
                    hijacking.push(BrowserHijackingItem {
                        hijack_type: "homepage_changed".to_string(),
                        browser: "Internet Explorer / Edge".to_string(),
                        item_name: "Start Page".to_string(),
                        value: homepage.clone(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        risk_level: "MEDIUM".to_string(),
                    });
                }
            }
        }

        // Check for unwanted browser extensions via Registry
        if let Ok(_extensions) = hkcu.open_subkey("Software\\Google\\Chrome\\PreferenceMACs\\Default\\extensions.settings") {
            eprintln!("  → Found Chrome extensions in registry");
            // Note: Full extension analysis would require parsing JSON from Preferences file
        }

        // Check for browser hijacking via hosts file
        eprintln!("  → Checking hosts file...");
        let hosts_path = PathBuf::from("C:\\Windows\\System32\\drivers\\etc\\hosts");
        if let Ok(contents) = fs::read_to_string(&hosts_path) {
            for line in contents.lines() {
                let line_trimmed = line.trim();
                if !line_trimmed.is_empty() && !line_trimmed.starts_with('#') {
                    // Check for redirects to popular sites
                    if line_trimmed.contains("google.com") ||
                       line_trimmed.contains("facebook.com") ||
                       line_trimmed.contains("youtube.com") ||
                       line_trimmed.contains("microsoft.com") {
                        hijacking.push(BrowserHijackingItem {
                            hijack_type: "hosts_file_redirect".to_string(),
                            browser: "All Browsers".to_string(),
                            item_name: "Hosts File Entry".to_string(),
                            value: line_trimmed.to_string(),
                            timestamp: None,
                            risk_level: "HIGH".to_string(),
                        });
                    }
                }
            }
        }
    }

    eprintln!("  ✓ Identified {} browser hijacking items", hijacking.len());
    Ok(hijacking)
}

/// Generate comprehensive summary of intrusion scan results
fn generate_intrusion_summary(results: &IntrusionScanResults) -> IntrusionSummary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    // Count by severity from event logs
    for anomaly in &results.event_log_anomalies {
        match anomaly.severity.as_str() {
            "CRITICAL" => critical += 1,
            "HIGH" => high += 1,
            "MEDIUM" => medium += 1,
            _ => low += 1,
        }
    }

    // Count from other categories
    critical += results.security_tool_tampering.iter()
        .filter(|t| t.risk_level == "CRITICAL").count();
    high += results.remote_access_indicators.iter()
        .filter(|r| r.risk_level == "HIGH" || r.risk_level == "CRITICAL").count();
    medium += results.user_account_changes.iter()
        .filter(|u| u.suspicious).count();

    let total = results.event_log_anomalies.len() +
                results.persistence_items.len() +
                results.command_history.len() +
                results.user_account_changes.len() +
                results.remote_access_indicators.len() +
                results.security_tool_tampering.len() +
                results.network_indicators.len() +
                results.malware_indicators.len() +
                results.browser_hijacking.len();

    // Calculate overall risk score (0-100)
    let risk_score = ((critical * 25 + high * 15 + medium * 5 + low * 1) as f32 / (total.max(1) as f32 * 25.0) * 100.0).min(100.0) as u8;

    // Generate recommendations
    let mut recommendations = Vec::new();

    if critical > 0 {
        recommendations.push("⚠ CRITICAL: Immediate investigation required - potential active compromise detected".to_string());
    }

    if !results.security_tool_tampering.is_empty() {
        recommendations.push("Re-enable disabled security tools (Windows Defender, Firewall, UAC)".to_string());
    }

    if !results.remote_access_indicators.is_empty() {
        recommendations.push("Review and disable unnecessary remote access tools and services".to_string());
    }

    if results.persistence_items.iter().any(|p| p.suspicious) {
        recommendations.push("Remove suspicious persistence mechanisms from startup and registry".to_string());
    }

    if !results.malware_indicators.is_empty() {
        recommendations.push("Quarantine and analyze suspicious binaries with antivirus/sandbox".to_string());
    }

    if results.user_account_changes.iter().any(|u| u.is_admin && u.suspicious) {
        recommendations.push("Review and remove unauthorized administrator accounts".to_string());
    }

    if !results.network_indicators.is_empty() {
        recommendations.push("Block suspicious IP addresses and domains in firewall".to_string());
    }

    if risk_score > 70 {
        recommendations.push("Consider full system reimaging or professional forensic analysis".to_string());
    }

    recommendations.push("Save this report and all logs for forensic documentation".to_string());
    recommendations.push("Change all passwords after remediation".to_string());

    IntrusionSummary {
        total_artifacts: total,
        critical_findings: critical,
        high_risk_findings: high,
        medium_risk_findings: medium,
        low_risk_findings: low,
        overall_risk_score: risk_score,
        recommendations,
    }
}
