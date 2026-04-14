export type BrowserType = 
  | 'Chrome' 
  | 'Edge' 
  | 'Firefox' 
  | 'Brave' 
  | 'Opera' 
  | 'Vivaldi';

export interface BrowserData {
  browserType: BrowserType;
  browserName: string;
  profileName: string;
  history: HistoryEntry[];
  bookmarks: BookmarkEntry[];
  credentials: CredentialEntry[];
  downloads: DownloadEntry[];
  installPath: string;
  profilePath: string;
}

export interface HistoryEntry {
  url: string;
  title: string;
  visitCount: number;
  lastVisit: string;
  typedCount: number;
}

export interface BookmarkEntry {
  url: string;
  title: string;
  dateAdded: string;
  folder: string;
}

export interface CredentialEntry {
  originUrl: string;
  username: string;
  passwordEncrypted: boolean;
  dateCreated: string;
  dateLastUsed: string;
}

export interface DownloadEntry {
  targetPath: string;
  url: string;
  startTime: string;
  endTime: string;
  totalBytes: number;
  dangerType: string;
  state: string;
  mimeType: string;
  referrerUrl: string;
}

export interface BrowserScanOptions {
  includeHistory: boolean;
  includeBookmarks: boolean;
  includeCredentials: boolean;
  maxHistoryEntries: number;
}

export const defaultBrowserScanOptions: BrowserScanOptions = {
  includeHistory: true,
  includeBookmarks: true,
  includeCredentials: true,
  maxHistoryEntries: 5000,
};
