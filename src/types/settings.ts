export interface AppSettings {
  officer_name?: string;
  agency_name?: string;
  keywordLists: KeywordList[];
  hashLists: HashList[];
  customApps: CustomAppDefinition[];
  scanOptions: ScanOptions;
}

export interface KeywordList {
  id: string;
  name: string;
  description: string;
  keywords: string[];
  enabled: boolean;
  caseSensitive: boolean;
  useRegex: boolean;
  createdAt: string;
  modifiedAt: string;
}

export interface HashList {
  id: string;
  name: string;
  description: string;
  hashType: 'MD5' | 'SHA1' | 'SHA256';
  hashes: HashEntry[];
  enabled: boolean;
  source: string; // e.g., "Project VIC", "NCMEC", "Custom"
  createdAt: string;
  modifiedAt: string;
}

export interface HashEntry {
  hash: string;
  description?: string;
  category?: string;
}

export interface CustomAppDefinition {
  id: string;
  name: string;
  category: string;
  patterns: string[];
  description: string;
  enabled: boolean;
  createdAt: string;
  modifiedAt: string;
}

export interface ScanOptions {
  enableQuestionableApps: boolean;
  enableBrowserHistory: boolean;
  enableKeywordSearch: boolean;
  enableMediaScan: boolean;
  enableHashMatching: boolean;
  scanDepth: 'quick' | 'standard' | 'deep';
  includeSystemDirs: boolean;
}

export const defaultSettings: AppSettings = {
  officer_name: undefined,
  agency_name: undefined,
  keywordLists: [],
  hashLists: [],
  customApps: [],
  scanOptions: {
    enableQuestionableApps: true,
    enableBrowserHistory: false,
    enableKeywordSearch: false,
    enableMediaScan: false,
    enableHashMatching: false,
    scanDepth: 'standard',
    includeSystemDirs: false,
  }
};
