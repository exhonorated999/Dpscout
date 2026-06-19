export interface MediaFile {
  id: string;
  filePath: string;
  fileName: string;
  fileSize: number;
  extension: string;
  mediaType: MediaType;
  thumbnailPath: string;
  width?: number;
  height?: number;
  dateCreated?: string;
  dateModified?: string;
  dateAccessed?: string;
  md5Hash?: string;
  sha256Hash?: string;
  flags: MediaFlag[];
  metadata?: MediaMetadata;
  // Android-specific fields
  isAndroidFile?: boolean;
  androidSerial?: string;
  localCachePath?: string; // Path to locally cached file if pulled
  // iOS AFC live-triage fields
  isIosAfcFile?: boolean;
  iosUdid?: string;
}

export type MediaType = 'image' | 'video' | 'unknown';

export interface MediaFlag {
  type: FlagType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  source: string; // e.g., "Keyword: child", "Hash: Project VIC"
}

export type FlagType = 
  | 'hash_match'
  | 'keyword_match'
  | 'suspicious_filename'
  | 'metadata_flag';

export interface MediaMetadata {
  camera?: string;
  dateTaken?: string;
  gpsLatitude?: number;
  gpsLongitude?: number;
  gpsAltitude?: number;
  orientation?: number;
  software?: string;
}

export interface MediaScanProgress {
  totalFiles: number;
  scannedFiles: number;
  flaggedFiles: number;
  currentPath: string;
  status: 'scanning' | 'hashing' | 'complete' | 'error';
}

export interface MediaScanOptions {
  scanPaths: string[];
  includeImages: boolean;
  includeVideos: boolean;
  generateThumbnails: boolean;
  computeHashes: boolean;
  checkHashLists: boolean;
  checkKeywords: boolean;
  maxFileSize: number; // in MB, 0 = no limit
  thumbnailSize: number; // pixels
}

export const defaultMediaScanOptions: MediaScanOptions = {
  scanPaths: ['C:\\Users'],
  includeImages: true,
  includeVideos: true,
  generateThumbnails: true,
  computeHashes: true,
  checkHashLists: true,
  checkKeywords: false,
  maxFileSize: 0,
  thumbnailSize: 200,
};
