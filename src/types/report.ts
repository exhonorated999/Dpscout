export interface ScanReport {
  id: string;
  timestamp: string;
  systemInfo: SystemInfo;
  scanModules: ScanModule[];
  findings: ReportFindings;
  taggedEvidence: TaggedItem[];
  duration: number; // seconds
}

export interface SystemInfo {
  hostname: string;
  osVersion: string;
  osName: string;
  currentUser: string;
  ipAddress: string;
  macAddress: string;
  userAccounts: string[];
  installedDrives: string[];
  totalRAM: string;
  cpuInfo: string;
}

export interface ScanModule {
  name: string;
  enabled: boolean;
  itemsScanned: number;
  itemsFlagged: number;
  duration: number;
  status: 'completed' | 'failed' | 'skipped';
}

export interface ReportFindings {
  questionableApps: number;
  criticalApps: number;
  mediaFiles: number;
  flaggedMedia: number;
  criticalMedia: number;
  hashMatches: number;
  keywordMatches: number;
  totalFlags: number;
}

export interface TaggedItem {
  type: 'app' | 'media' | 'browser' | 'file';
  name: string;
  path: string;
  flags: string[];
  hash?: string;
  notes?: string;
  taggedAt: string;
}

export interface ScanProgress {
  moduleId: string;
  moduleName: string;
  status: 'pending' | 'scanning' | 'complete' | 'error';
  currentItem: string;
  itemsProcessed: number;
  totalItems: number;
  percentage: number;
  estimatedTimeRemaining: number; // seconds
  startTime: number;
  itemsPerSecond: number;
}

export type ReportFormat = 'pdf';
export type ReportScope = 'all' | 'flagged';

export interface ReportExportOptions {
  format: ReportFormat;
  includeSystemInfo: boolean;
  includeScanDetails: boolean;
  includeAllFindings: boolean;
  includeTaggedOnly: boolean;
  includeThumbnails: boolean;
  includeHashes: boolean;
  outputPath: string;
}

// New report generation types for REPORTER module
export interface ReportMetadata {
  case_number: string;
  assigned_detective: string;
  generated_date: string;
  device_name?: string;
  operating_system?: string;
  officer_name?: string;
  agency_name?: string;
  drive_scanned?: string;
  scan_parameters?: ScanParameters;
  scan_duration?: string;
  triage_start_time?: string;
  triage_end_time?: string;
  total_flags?: number;
  generate_datapilot_file?: boolean;
}

export interface ScanParameters {
  applications_scanned: boolean;
  browser_history_scanned: boolean;
  keyword_search_performed: boolean;
  hash_matching_performed: boolean;
  media_scan_performed: boolean;
  intrusion_detection_performed: boolean;
  deleted_media_scan_performed?: boolean;
}

export interface ReportConfiguration {
  metadata: ReportMetadata;
  scope: ReportScope;
  formats: ReportFormat[];
  flaggedItemIds: string[];
}

export interface ReportGenerationResult {
  success: boolean;
  pdf_path?: string;
  error?: string;
}

export interface FlaggedItemData {
  itemId: string;
  type: 'app' | 'keyword' | 'csam' | 'browser-history' | 'browser-download' | 'browser-credential' | 'intrusion-event' | 'intrusion-persistence' | 'intrusion-command';
  data: any;
}

export interface ReportPayload {
  metadata: ReportMetadata;
  scope: ReportScope;
  formats: string[];
  flagged_item_ids: string[];
  all_data: {
    apps: any[];
    keywords: any[];
    csam: any[];
    browsers: any[];
    intrusion: any;
    system_info: any;
    hash_matches?: any[];
    deleted_media?: any[];
  };
}
