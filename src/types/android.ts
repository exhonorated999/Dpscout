export interface AndroidDevice {
  serial: string;
  model: string;
  manufacturer: string;
  androidVersion: string;
  deviceName: string;
  state: string;
}

export interface AndroidApp {
  packageName: string;
  appName: string;
  version: string;
  installTime: string;
  isSystemApp: boolean;
}

export interface AndroidBrowserData {
  browserName: string;
  packageName: string;
  history: AndroidHistoryEntry[];
  bookmarks: AndroidBookmarkEntry[];
}

export interface AndroidHistoryEntry {
  url: string;
  title: string;
  visitCount: number;
  lastVisit: string;
}

export interface AndroidBookmarkEntry {
  url: string;
  title: string;
  folder: string;
}

export interface AndroidHashMatch {
  filePath: string;
  fileName: string;
  fileSize: number;
  md5Hash: string;
  sha256Hash: string;
  matchedHash: string;
  hashType: string;
  listName: string;
  listSource: string;
  description?: string;
  severity: string;
}
