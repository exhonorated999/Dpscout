// System identification types

export interface UsbDeviceHistory {
  device_name: string;
  vendor_id: string | null;
  product_id: string | null;
  serial_number: string | null;
  last_connected: string | null;
  drive_letter: string | null;
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
