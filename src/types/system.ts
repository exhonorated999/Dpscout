// System identification types

export interface UsbDeviceHistory {
  device_name: string;
  vendor_id: string | null;
  product_id: string | null;
  serial_number: string | null;
  last_connected: string | null;
  drive_letter: string | null;
}

// ---------------------------------------------------------------------------
// BitLocker (Beta)
// Mirrors system_info::bitlocker in the Rust backend.
// ---------------------------------------------------------------------------

/** Headline states emitted by the backend. */
export type BitLockerStatus =
  | 'Enabled'
  | 'Not Enabled'
  | 'Requires Administrator'
  | 'Not Supported';

export interface BitLockerVolume {
  drive_letter: string | null;
  device_id: string | null;
  persistent_volume_id: string | null;
  protected: boolean;
  protection_status: string;
  lock_status: string;
  conversion_status: string;
  encryption_method: string;
  encryption_percentage: number | null;
  recovery_key_id: string | null;
  recovery_password: string | null;
  note: string | null;
}

export interface BitLockerKeyFile {
  path: string;
  file_type: string;
  recovery_key_id: string | null;
  recovery_passwords: string[];
  /** False when a recovered key fails BitLocker's divisible-by-11 group check. */
  checksum_valid: boolean;
  modified: string | null;
  size_bytes: number | null;
}

export interface BitLockerFindings {
  supported: boolean;
  /** When false, Windows blocked all live-volume access and `volumes` is empty. */
  elevated: boolean;
  status: BitLockerStatus | string;
  status_detail: string;
  volumes: BitLockerVolume[];
  key_files: BitLockerKeyFile[];
  sweep_scope: 'none' | 'targeted' | 'full' | string;
  error: string | null;
}

export interface SystemInfo {
  scan_id?: string;
  scan_timestamp?: string;
  scan_duration_secs?: number;
  computer_name: string;
  os_version: string;
  registered_owner: string | null;
  registered_organization: string | null;
  product_id: string | null;
  domain: string | null;
  user_accounts?: UserAccount[];
  emails?: string[];
  hardware?: HardwareInfo;
  network?: NetworkInfo;
  usb_history?: UsbDeviceHistory[];
  bitlocker?: BitLockerFindings;
  usb_device_info?: UsbDeviceInfo;  // NEW: For USB device scans
  android_device_info?: any;  // NEW: For Android device scans
  // iOS-specific fields (optional)
  udid?: string;
  imei?: string;
  serial_number?: string;
  phone_number?: string;
  wifi_address?: string;
  bluetooth_address?: string;
  build_version?: string;
  device_color?: string;
  total_capacity?: string;
  available_capacity?: string;
  install_date?: string;
  last_boot_time?: string;
  system_manufacturer?: string;
  system_model?: string;
  processor?: string;
  installed_ram?: string;
}

export interface UserAccount {
  username: string;
  full_name: string | null;
  profile_path: string;
  last_login: string | null;
  account_type: string;
}

export interface HardwareInfo {
  drives: DriveInfo[];
  motherboard_serial: string | null;
  bios_serial: string | null;
  system_uuid: string | null;
}

export interface DriveInfo {
  letter: string;
  label: string;
  serial_number: string;
  filesystem: string;
  total_space: number;
  free_space: number;
}

export interface NetworkInfo {
  mac_addresses: string[];
  hostname: string;
  ip_addresses: string[];
  public_ip: string | null;
}

export interface UsbDeviceInfo {
  drive_letter: string;
  drive_name: string;
  make: string | null;
  model: string | null;
  capacity_gb: number;
  used_space_gb: number;
  free_space_gb: number;
  file_count: number;
  serial_number: string;
  volume_id: string;
}

// ---------------------------------------------------------------------------
// Deleted-media unallocated-space triage
// Mirrors scanner::deleted_media in the Rust backend (serde camelCase).
// ---------------------------------------------------------------------------

export interface DeletedFile {
  fileName: string;
  extension: string;
  sizeBytes: number;
  mediaType: 'image' | 'video';
  source: 'dir_entry' | 'mft';
  startCluster: number;
  likelyRecoverable: boolean;
}

export interface HeaderHitCount {
  signature: string;
  mediaType: 'image' | 'video';
  count: number;
}

export interface DeletedMediaSummary {
  driveLetter: string;
  fsType: string;
  scanCompleted: boolean;
  cancelled: boolean;
  deletedMediaFound: boolean;
  namedFiles: DeletedFile[];
  namedImageCount: number;
  namedVideoCount: number;
  headerHits: HeaderHitCount[];
  unallocatedImageHeaders: number;
  unallocatedVideoHeaders: number;
  estimatedTotal: number;
  freeBytes: number;
  scannedBytes: number;
  clusterSize: number;
  durationMs: number;
  notes: string[];
}

export interface DeletedMediaScanOptions {
  scanMetadataResidue: boolean;
  scanUnallocated: boolean;
  maxBytesToScan: number;
  maxNamedFiles: number;
}

export interface DeletedMediaProgress {
  percent: number;
  scannedBytes: number;
  freeBytes: number;
  phase: string;
}

/**
 * Per-drive outcome of a pipeline deleted-media scan. Exactly one of
 * `summary` / `error` is populated.
 */
export interface DeletedMediaDriveResult {
  driveLetter: string;
  summary: DeletedMediaSummary | null;
  error: string | null;
}

// Helper function to format bytes
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Helper function to format timestamp
export function formatTimestamp(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    return date.toLocaleString();
  } catch {
    return timestamp;
  }
}
