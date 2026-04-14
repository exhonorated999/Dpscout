export interface KeywordMatch {
  filePath: string;
  fileName: string;
  fileSize: number;
  matchedKeywords: string[];
  matchLocations: MatchLocation[];
  dateModified?: string;
  dateCreated?: string;
  fileExtension: string;
}

export interface MatchLocation {
  keyword: string;
  location: MatchType;
  context: string;
}

export type MatchType = 'FileName' | 'FilePath' | 'FileContent';

export interface KeywordScanOptions {
  scanPaths: string[];
  keywordLists: KeywordList[];
  scanFileNames: boolean;
  scanFilePaths: boolean;
  scanFileContents: boolean;
  caseSensitive: boolean;
  maxFileSizeMb: number;
  fileExtensions: string[];
}

export interface KeywordList {
  name: string;
  keywords: string[];
  enabled: boolean;
}

export const defaultKeywordScanOptions: KeywordScanOptions = {
  scanPaths: [],
  keywordLists: [],
  scanFileNames: true,
  scanFilePaths: true,
  scanFileContents: false, // Disabled by default for performance
  caseSensitive: false,
  maxFileSizeMb: 10, // Only scan files smaller than 10MB
  fileExtensions: [], // Empty = scan all
};
