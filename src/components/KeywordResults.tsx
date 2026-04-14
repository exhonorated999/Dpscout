import React, { useState } from 'react';
import { Button } from './Button';
import { KeywordMatch, MatchLocation } from '../types/keyword';
import { invoke } from '@tauri-apps/api/core';
import './KeywordResults.css';

interface KeywordResultsProps {
  matches: KeywordMatch[];
  isScanning: boolean;
  onStartScan: () => void;
  onBack: () => void;
}

interface FileMetadata {
  created: string;
  modified: string;
  accessed: string;
  size: number;
  readonly: boolean;
  hidden: boolean;
}

interface KeywordHitSummary {
  keyword: string;
  hitCount: number;
}

export const KeywordResults: React.FC<KeywordResultsProps> = ({
  matches,
  isScanning,
  onStartScan,
  onBack,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedKeyword, setSelectedKeyword] = useState<string>('');
  const [expandedFile, setExpandedFile] = useState<string | null>(null);
  const [fileMetadata, setFileMetadata] = useState<FileMetadata | null>(null);
  const [loadingMetadata, setLoadingMetadata] = useState(false);

  // Calculate keyword hit summary
  const keywordHitSummary: KeywordHitSummary[] = (() => {
    const keywordMap = new Map<string, number>();
    
    matches.forEach(match => {
      match.matchedKeywords.forEach(keyword => {
        keywordMap.set(keyword, (keywordMap.get(keyword) || 0) + 1);
      });
    });
    
    return Array.from(keywordMap.entries())
      .map(([keyword, hitCount]) => ({ keyword, hitCount }))
      .sort((a, b) => b.hitCount - a.hitCount);
  })();

  // Filter matches based on selected keyword
  const filteredMatches = (): KeywordMatch[] => {
    if (!selectedKeyword) return [];
    
    let filtered = matches.filter(m => m.matchedKeywords.includes(selectedKeyword));

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        m =>
          m.fileName.toLowerCase().includes(query) ||
          m.filePath.toLowerCase().includes(query)
      );
    }

    return filtered;
  };

  const currentMatches = filteredMatches();

  // Truncate long file paths for display
  const truncatePath = (path: string, maxLength: number = 80): string => {
    if (path.length <= maxLength) return path;
    
    // Try to keep the filename and some parent directories
    const parts = path.split(/[\\\/]/);
    const filename = parts[parts.length - 1];
    const filenameLength = filename.length;
    
    if (filenameLength >= maxLength - 10) {
      // If filename itself is too long, truncate it
      return '...' + filename.slice(-(maxLength - 3));
    }
    
    // Keep first part (drive/root) and last part (filename)
    const firstPart = parts[0];
    const remainingLength = maxLength - firstPart.length - filenameLength - 6; // 6 for "...\" separators
    
    // Try to include some middle directories
    let middleParts = parts.slice(1, -1);
    let middleStr = middleParts.join('\\');
    
    if (middleStr.length > remainingLength) {
      // Truncate middle
      middleStr = '...' + middleStr.slice(-(remainingLength - 3));
    }
    
    return `${firstPart}\\${middleStr}\\${filename}`;
  };

  // Handle opening file in Explorer
  const handleOpenInExplorer = async (filePath: string) => {
    try {
      await invoke('open_in_explorer', { path: filePath });
    } catch (error) {
      console.error('Failed to open in Explorer:', error);
      alert(`Failed to open file in Explorer: ${error}`);
    }
  };

  // Handle loading detailed file metadata
  const handleLoadMetadata = async (filePath: string) => {
    setLoadingMetadata(true);
    try {
      const metadata = await invoke<FileMetadata>('get_file_metadata', { path: filePath });
      setFileMetadata(metadata);
    } catch (error) {
      console.error('Failed to load metadata:', error);
      alert(`Failed to load file metadata: ${error}`);
    } finally {
      setLoadingMetadata(false);
    }
  };

  // Toggle expanded file details
  const toggleFileExpansion = (filePath: string) => {
    if (expandedFile === filePath) {
      setExpandedFile(null);
      setFileMetadata(null);
    } else {
      setExpandedFile(filePath);
      handleLoadMetadata(filePath);
    }
  };

  const getMatchIcon = (location: MatchLocation): string => {
    switch (location.location) {
      case 'FileName':
        return '📄';
      case 'FilePath':
        return '📁';
      case 'FileContent':
        return '📝';
      default:
        return '🔍';
    }
  };

  const highlightKeyword = (text: string, keyword: string): React.ReactElement => {
    const lowerText = text.toLowerCase();
    const lowerKeyword = keyword.toLowerCase();
    const index = lowerText.indexOf(lowerKeyword);

    if (index === -1) {
      return <span>{text}</span>;
    }

    const before = text.substring(0, index);
    const match = text.substring(index, index + keyword.length);
    const after = text.substring(index + keyword.length);

    return (
      <span>
        {before}
        <span className="keyword-highlight">{match}</span>
        {after}
      </span>
    );
  };

  if (isScanning) {
    return (
      <div className="keyword-results">
        <div className="scanning-overlay">
          <div className="spinner-large"></div>
          <h2>Scanning for Keywords...</h2>
          <p>Searching file names, paths, and contents for flagged terms</p>
        </div>
      </div>
    );
  }

  if (matches.length === 0 && !isScanning) {
    return (
      <div className="keyword-results">
        <div className="keyword-header">
          <div className="header-content">
            <h1>🔍 KEYWORD SEARCH RESULTS</h1>
            <p>No matches found</p>
          </div>
          <Button variant="secondary" onClick={onBack}>
            ← Back
          </Button>
        </div>

        <div className="empty-state-large">
          <div className="empty-icon">🔍</div>
          <h2>No Keyword Matches</h2>
          <p>No files matched the configured keyword lists</p>
          <div style={{ display: 'flex', gap: '1rem', marginTop: '2rem' }}>
            <Button variant="primary" onClick={onStartScan}>
              🔄 Scan Again
            </Button>
            <Button variant="secondary" onClick={onBack}>
              ← Back
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="keyword-results">
      <div className="keyword-header">
        <div className="header-content">
          <h1>🔍 KEYWORD SEARCH RESULTS</h1>
          <p>
            {matches.length} total files with keyword matches
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button variant="secondary" onClick={onStartScan}>
            🔄 Rescan
          </Button>
          <Button variant="secondary" onClick={onBack}>
            ← Back
          </Button>
        </div>
      </div>

      <div className="keyword-content">
        {/* Left Sidebar - Keyword List */}
        <div className="keyword-sidebar">
          <div className="sidebar-header">
            <h3>🔑 Keywords Found</h3>
            <span className="keyword-count">{keywordHitSummary.length} keywords</span>
          </div>
          
          <div className="keyword-list">
            {keywordHitSummary.map((item, idx) => (
              <button
                key={idx}
                className={`keyword-item ${selectedKeyword === item.keyword ? 'active' : ''}`}
                onClick={() => {
                  setSelectedKeyword(item.keyword);
                  setExpandedFile(null);
                  setFileMetadata(null);
                }}
              >
                <div className="keyword-name">{item.keyword}</div>
                <div className="keyword-hits">
                  <span className="hits-badge">{item.hitCount}</span>
                  <span className="hits-label">hit{item.hitCount !== 1 ? 's' : ''}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Main Content - Files with Selected Keyword */}
        <div className="keyword-main">
          {!selectedKeyword ? (
            <div className="empty-state">
              <div className="empty-icon">🔍</div>
              <h2>Select a Keyword</h2>
              <p>Choose a keyword from the left to view matching files</p>
            </div>
          ) : (
            <div className="files-view">
              <div className="files-header">
                <h2>📂 Files Containing: <span className="keyword-highlight">{selectedKeyword}</span></h2>
                <p>{currentMatches.length} file{currentMatches.length !== 1 ? 's' : ''} found</p>
              </div>

              <div className="search-section">
                <input
                  type="text"
                  placeholder="Filter files..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="search-input"
                />
              </div>

              <div className="files-list">
                {currentMatches.map((match, idx) => (
                  <div key={idx} className="file-card">
                    {/* File Header - Grid Layout */}
                    <div className="file-header">
                      <div className="file-name">📄 {match.fileName}</div>
                      <div className="file-size">{(match.fileSize / 1024).toFixed(2)} KB</div>
                      <span className="match-count-badge">
                        {match.matchLocations.length} match{match.matchLocations.length !== 1 ? 'es' : ''}
                      </span>
                      <button
                        className="expand-btn"
                        onClick={() => toggleFileExpansion(match.filePath)}
                      >
                        {expandedFile === match.filePath ? '▼ Less' : '▶ More'}
                      </button>
                    </div>

                    {/* File Path (Clickable with truncation) */}
                    <div className="file-path-row">
                      <span className="path-label">Path:</span>
                      <button
                        className="file-path-link"
                        onClick={() => handleOpenInExplorer(match.filePath)}
                        title={`${match.filePath}\n\nClick to open in Windows Explorer`}
                      >
                        📁 {truncatePath(match.filePath)}
                      </button>
                    </div>

                    {/* Match Info */}
                    <div className="file-matches">
                      <span className="match-count">
                        {match.matchLocations.length} match location{match.matchLocations.length !== 1 ? 's' : ''}
                      </span>
                      {match.matchedKeywords.length > 1 && (
                        <span className="other-keywords">
                          + {match.matchedKeywords.length - 1} other keyword{match.matchedKeywords.length - 1 !== 1 ? 's' : ''}
                        </span>
                      )}
                    </div>

                    {/* Expanded Details */}
                    {expandedFile === match.filePath && (
                      <div className="file-details-expanded">
                        {loadingMetadata ? (
                          <div className="loading-metadata">
                            <div className="spinner-small"></div>
                            <span>Loading metadata...</span>
                          </div>
                        ) : fileMetadata ? (
                          <div className="metadata-section">
                            <h4>📊 File Metadata</h4>
                            <div className="metadata-grid">
                              <div className="metadata-item">
                                <span className="meta-label">Created:</span>
                                <span className="meta-value">{fileMetadata.created}</span>
                              </div>
                              <div className="metadata-item">
                                <span className="meta-label">Modified:</span>
                                <span className="meta-value">{fileMetadata.modified}</span>
                              </div>
                              <div className="metadata-item">
                                <span className="meta-label">Last Accessed:</span>
                                <span className="meta-value">{fileMetadata.accessed}</span>
                              </div>
                              <div className="metadata-item">
                                <span className="meta-label">Size:</span>
                                <span className="meta-value">{(fileMetadata.size / 1024).toFixed(2)} KB</span>
                              </div>
                              <div className="metadata-item">
                                <span className="meta-label">Attributes:</span>
                                <span className="meta-value">
                                  {fileMetadata.readonly && '🔒 Read-only '}
                                  {fileMetadata.hidden && '👁️ Hidden'}
                                  {!fileMetadata.readonly && !fileMetadata.hidden && 'Normal'}
                                </span>
                              </div>
                            </div>
                          </div>
                        ) : null}

                        {/* All Matched Keywords */}
                        <div className="keywords-section">
                          <h4>🔑 All Matched Keywords</h4>
                          <div className="keyword-badges">
                            {match.matchedKeywords.map((kw, kidx) => (
                              <span key={kidx} className={`keyword-badge ${kw === selectedKeyword ? 'primary' : 'secondary'}`}>
                                {kw}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* Match Locations */}
                        <div className="locations-section">
                          <h4>📍 Match Locations</h4>
                          {match.matchLocations
                            .filter(loc => loc.keyword === selectedKeyword)
                            .map((loc, lidx) => (
                              <div key={lidx} className="location-item">
                                <div className="location-type">
                                  <span className="location-icon">{getMatchIcon(loc)}</span>
                                  <span>{loc.location}</span>
                                </div>
                                <div className="location-context">
                                  {highlightKeyword(loc.context, loc.keyword)}
                                </div>
                              </div>
                            ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
