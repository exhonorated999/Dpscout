export const defaultKeywordScanOptions = {
    scanPaths: [],
    keywordLists: [],
    scanFileNames: true,
    scanFilePaths: true,
    scanFileContents: false, // Disabled by default for performance
    caseSensitive: false,
    maxFileSizeMb: 10, // Only scan files smaller than 10MB
    fileExtensions: [], // Empty = scan all
};
