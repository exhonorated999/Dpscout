import React, { useState } from 'react';
import { Button } from './Button';
import { MediaFile } from '../types/media';
import { invoke } from '@tauri-apps/api/core';
import './HashResults.css';

interface HashResultsProps {
  matches: MediaFile[];
  isScanning: boolean;
  onStartScan: () => void;
  onBack: () => void;
  /** Hash list names in user-chosen priority order (highest first). Used to group hits in the order the investigator selected. */
  listPriority?: string[];
}

interface FileMetadata {
  created: string;
  modified: string;
  accessed: string;
  size: number;
  readonly: boolean;
  hidden: boolean;
}

interface FileAccessEvent {
  timestamp: string;
  eventId: number;
  eventType: string;
  processName: string;
  userName: string;
  description: string;
}

export const HashResults: React.FC<HashResultsProps> = ({
  matches,
  isScanning,
  onStartScan,
  onBack,
  listPriority = [],
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFile, setExpandedFile] = useState<string | null>(null);
  const [fileMetadata, setFileMetadata] = useState<FileMetadata | null>(null);
  const [accessEvents, setAccessEvents] = useState<FileAccessEvent[]>([]);
  const [loadingMetadata, setLoadingMetadata] = useState(false);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [excludedPaths, setExcludedPaths] = useState<Set<string>>(new Set());
  const [excludingFile, setExcludingFile] = useState<string | null>(null);
  const [excludeReason, setExcludeReason] = useState('');
  const [removingFalsePositives, setRemovingFalsePositives] = useState(false);

  // Filter matches based on search query, then hide excluded paths.
  // Final ordering respects the list priority chosen on the configure screen.
  const filteredMatches = (): MediaFile[] => {
    let result = matches;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        m =>
          m.fileName.toLowerCase().includes(query) ||
          m.filePath.toLowerCase().includes(query) ||
          m.md5Hash?.toLowerCase().includes(query) ||
          m.sha256Hash?.toLowerCase().includes(query) ||
          (m as any).matchedHash?.toLowerCase().includes(query)
      );
    }
    result = result.filter(m => !excludedPaths.has(m.filePath));

    // Sort by list priority: files whose match belongs to priority-1 list come first.
    if (listPriority.length > 0) {
      const priorityIndex = (name: string) => {
        const idx = listPriority.indexOf(name);
        return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
      };
      result = [...result].sort((a, b) => {
        const aName = (a as any).listName || 'Unknown';
        const bName = (b as any).listName || 'Unknown';
        return priorityIndex(aName) - priorityIndex(bName);
      });
    }
    return result;
  };

  const currentMatches = filteredMatches();

  // Extract the matched hash and its type from a match object.
  // HashResults receives HashMatch[] (which have matchedHash/hashType directly)
  // OR MediaFile[] with flags. Handle both.
  const getHashFromFlag = (file: MediaFile): { hash: string; hashType: string } => {
    // Direct HashMatch fields (from scan_for_hash_matches result)
    const anyFile = file as any;
    if (anyFile.matchedHash && anyFile.hashType) {
      return { hash: anyFile.matchedHash, hashType: anyFile.hashType };
    }
    // MediaFile with flags (from merged media+hash flow)
    if (file.flags) {
      const hashFlag = file.flags.find(f => f.type === 'hash_match');
      if (hashFlag) {
        const reason = hashFlag.reason;
        const typeMatch = reason.match(/\((MD5|SHA1|SHA256)\)/i);
        const hashType = typeMatch ? typeMatch[1].toUpperCase() : 'MD5';
        if (hashType === 'SHA1' && anyFile.matchedHash) {
          return { hash: anyFile.matchedHash, hashType: 'SHA1' };
        }
        if (hashType === 'SHA256' && file.sha256Hash) {
          return { hash: file.sha256Hash, hashType: 'SHA256' };
        }
        if (file.md5Hash) {
          return { hash: file.md5Hash, hashType: 'MD5' };
        }
      }
    }
    // Fallback
    if (file.sha256Hash) return { hash: file.sha256Hash, hashType: 'SHA256' };
    if (file.md5Hash) return { hash: file.md5Hash, hashType: 'MD5' };
    return { hash: '', hashType: 'MD5' };
  };

  const handleExcludeHash = async (file: MediaFile) => {
    const { hash, hashType } = getHashFromFlag(file);
    if (!hash) return;
    try {
      await invoke('exclude_hash', {
        hash,
        hashType,
        fileName: file.fileName || null,
        reason: excludeReason || null,
      });
      setExcludedPaths(prev => new Set(prev).add(file.filePath));
      setExcludingFile(null);
      setExcludeReason('');
    } catch (error) {
      console.error('Failed to exclude hash:', error);
      alert(`Failed to exclude hash: ${error}`);
    }
  };

  // Group matches by list name for summary
  const getMatchesByList = () => {
    const groups: Record<string, { count: number; hashes: string[] }> = {};
    for (const m of matches) {
      const anyM = m as any;
      const listName = anyM.listName || 'Unknown';
      if (!groups[listName]) {
        groups[listName] = { count: 0, hashes: [] };
      }
      groups[listName].count++;
      if (anyM.matchedHash) {
        groups[listName].hashes.push(anyM.matchedHash);
      }
    }
    return groups;
  };

  // Remove false positive hashes from a .txt hash file
  const handleRemoveFalsePositives = async (listName: string) => {
    const groups = getMatchesByList();
    const group = groups[listName];
    if (!group || group.hashes.length === 0) {
      alert('No hashes to remove.');
      return;
    }

    const { open } = await import('@tauri-apps/plugin-dialog');
    const selected = await open({
      title: `Select the .txt hash file to remove ${group.hashes.length} false positives from`,
      filters: [{ name: 'Text Hash Files', extensions: ['txt'] }],
      multiple: false,
    });

    if (!selected) return;

    const confirm = window.confirm(
      `Remove ${group.hashes.length} false positive hashes from:\n${selected}\n\nA backup (.bak) will be created.`
    );
    if (!confirm) return;

    setRemovingFalsePositives(true);
    try {
      const removed = await invoke<number>('remove_hashes_from_file', {
        filePath: selected,
        hashesToRemove: group.hashes,
      });
      alert(`✓ Removed ${removed} false positive hashes from file.\nBackup saved as .bak`);
    } catch (error) {
      console.error('Failed to remove hashes:', error);
      alert(`Failed to remove hashes: ${error}`);
    } finally {
      setRemovingFalsePositives(false);
    }
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
      setFileMetadata(null);
    } finally {
      setLoadingMetadata(false);
    }
  };

  // Handle loading file access events from Windows Event Logs
  const handleLoadAccessEvents = async (filePath: string) => {
    setLoadingEvents(true);
    try {
      const events = await invoke<FileAccessEvent[]>('get_file_access_events', { path: filePath });
      setAccessEvents(events);
    } catch (error) {
      console.error('Failed to load access events:', error);
      setAccessEvents([]);
    } finally {
      setLoadingEvents(false);
    }
  };

  // Toggle expanded file details
  const toggleFileExpansion = (filePath: string) => {
    if (expandedFile === filePath) {
      setExpandedFile(null);
      setFileMetadata(null);
      setAccessEvents([]);
    } else {
      setExpandedFile(filePath);
      handleLoadMetadata(filePath);
      handleLoadAccessEvents(filePath);
    }
  };

  // Get hash match flags
  const getHashMatchFlags = (file: MediaFile) => {
    if (!file.flags) return [];
    return file.flags.filter(f => f.type === 'hash_match');
  };

  // Get hash display value
  const getHashDisplay = (file: MediaFile) => {
    const anyFile = file as any;
    // Direct HashMatch: show the matched hash prominently
    if (anyFile.matchedHash && anyFile.hashType) {
      return { type: anyFile.hashType, value: anyFile.matchedHash };
    }
    if (file.md5Hash && file.sha256Hash) {
      return { type: 'MD5 & SHA256', value: `${file.md5Hash.substring(0, 16)}... / ${file.sha256Hash.substring(0, 16)}...` };
    } else if (file.md5Hash) {
      return { type: 'MD5', value: file.md5Hash };
    } else if (file.sha256Hash) {
      return { type: 'SHA256', value: file.sha256Hash };
    }
    return { type: 'Unknown', value: 'No hash available' };
  };

  if (isScanning) {
    return (
      <div className="hash-results">
        <div className="scanning-overlay">
          <div className="spinner-large"></div>
          <h2>Scanning for Hash Matches...</h2>
          <p>Computing file hashes and checking against known databases</p>
        </div>
      </div>
    );
  }

  if (matches.length === 0 && !isScanning) {
    return (
      <div className="hash-results">
        <div className="hash-header">
          <div className="header-content">
            <h1>🔐 HASH SEARCH RESULTS</h1>
            <p>No matches found</p>
          </div>
          <Button variant="secondary" onClick={onBack}>
            ← Back
          </Button>
        </div>

        <div className="empty-state-large">
          <div className="empty-icon">🔐</div>
          <h2>No Hash Matches</h2>
          <p>No files matched the configured hash databases</p>
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
    <div className="hash-results">
      <div className="hash-header">
        <div className="header-content">
          <h1>🔐 HASH SEARCH RESULTS</h1>
          <p>
            {matches.length} file{matches.length !== 1 ? 's' : ''} matched known hash databases
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

      <div className="hash-content">
        <div className="hash-main">
          <div className="files-view">
            <div className="search-section">
              <input
                type="text"
                placeholder="Filter by filename, path, or hash..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="search-input"
              />
            </div>

            <div className="info-banner critical">
              <span className="banner-icon">⚠️</span>
              <div className="banner-content">
                <strong>CRITICAL HASH MATCHES DETECTED</strong>
                <p>These files match known illegal content databases. Handle with care and follow proper chain of custody procedures.</p>
              </div>
            </div>

            {/* Match summary by hash list — shows which lists produced hits, ordered by user-chosen priority */}
            {(() => {
              const groups = getMatchesByList();
              let listNames = Object.keys(groups);
              if (listNames.length <= 1) return null;
              // Sort list names by user-chosen priority (unknown lists go to the bottom)
              if (listPriority.length > 0) {
                const idxOf = (name: string) => {
                  const i = listPriority.indexOf(name);
                  return i === -1 ? Number.MAX_SAFE_INTEGER : i;
                };
                listNames = [...listNames].sort((a, b) => idxOf(a) - idxOf(b));
              }
              return (
                <div style={{
                  marginBottom: '1rem',
                  padding: '0.75rem 1rem',
                  background: 'rgba(30, 35, 50, 0.8)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.5rem' }}>
                    📋 Matches by Hash List
                  </div>
                  {listNames.map(name => (
                    <div key={name} style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '0.4rem 0',
                      borderBottom: '1px solid rgba(255,255,255,0.05)',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          background: 'rgba(88, 166, 255, 0.15)',
                          color: '#58a6ff',
                          padding: '1px 8px',
                          borderRadius: '10px',
                        }}>
                          {groups[name].count}
                        </span>
                        <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>{name}</span>
                      </div>
                      {groups[name].hashes.length > 0 && (
                        <button
                          onClick={() => handleRemoveFalsePositives(name)}
                          disabled={removingFalsePositives}
                          style={{
                            fontSize: '0.7rem',
                            padding: '3px 10px',
                            background: 'rgba(248, 81, 73, 0.15)',
                            color: '#f85149',
                            border: '1px solid rgba(248, 81, 73, 0.4)',
                            borderRadius: '4px',
                            cursor: removingFalsePositives ? 'wait' : 'pointer',
                            opacity: removingFalsePositives ? 0.5 : 1,
                          }}
                          title={`Remove these ${groups[name].hashes.length} hashes from a .txt hash file`}
                        >
                          {removingFalsePositives ? '⏳ Removing...' : `🗑️ Remove from .txt file`}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              );
            })()}

            <div className="files-list">
              {currentMatches.map((file, idx) => {
                const hashMatchFlags = getHashMatchFlags(file);
                const hashInfo = getHashDisplay(file);
                
                return (
                  <div key={idx} className="file-card critical">
                    {/* File Header */}
                    <div className="file-header">
                      <div className="file-info">
                        <div className="file-type-icon">
                          {file.mediaType === 'image' ? '🖼️' : file.mediaType === 'video' ? '🎥' : '📄'}
                        </div>
                        <div className="file-details">
                          <div className="file-name">{file.fileName}</div>
                          <div className="file-meta">
                            <span className="file-size">{(file.fileSize / 1024 / 1024).toFixed(2)} MB</span>
                            <span className="file-separator">•</span>
                            <span className="file-type">{file.extension.toUpperCase()}</span>
                            <span className="file-separator">•</span>
                            <span className="file-dimensions">
                              {file.width && file.height ? `${file.width}x${file.height}` : 'Unknown dimensions'}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
                        <button
                          className="exclude-btn"
                          onClick={() => {
                            setExcludingFile(excludingFile === file.filePath ? null : file.filePath);
                            setExcludeReason('');
                          }}
                          title="Exclude this hash match (mark as false positive)"
                        >
                          ✕ Exclude
                        </button>
                        <button
                          className="expand-btn"
                          onClick={() => toggleFileExpansion(file.filePath)}
                        >
                          {expandedFile === file.filePath ? '▼ Less' : '▶ More'}
                        </button>
                      </div>
                    </div>

                    {/* Inline Exclude Confirmation */}
                    {excludingFile === file.filePath && (
                      <div className="exclude-confirm-bar">
                        <div className="exclude-confirm-info">
                          <span className="exclude-confirm-label">Mark as false positive:</span>
                          <span className="exclude-confirm-hash" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: '#f85149' }}>
                            {getHashFromFlag(file).hash.substring(0, 16)}...
                          </span>
                          <span className="exclude-confirm-type" style={{ fontSize: '0.7rem', color: '#8b949e', marginLeft: '0.25rem' }}>
                            ({getHashFromFlag(file).hashType})
                          </span>
                        </div>
                        <div className="exclude-confirm-actions">
                          <input
                            type="text"
                            placeholder="Reason (optional)..."
                            value={excludeReason}
                            onChange={e => setExcludeReason(e.target.value)}
                            className="exclude-reason-input"
                            onKeyDown={e => {
                              if (e.key === 'Enter') handleExcludeHash(file);
                              if (e.key === 'Escape') { setExcludingFile(null); setExcludeReason(''); }
                            }}
                          />
                          <button className="exclude-confirm-yes" onClick={() => handleExcludeHash(file)}>
                            ✓ Exclude
                          </button>
                          <button className="exclude-confirm-no" onClick={() => { setExcludingFile(null); setExcludeReason(''); }}>
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Thumbnail Preview */}
                    {file.thumbnailPath && (
                      <div className="thumbnail-preview">
                        <div className="thumbnail-container blur-heavy">
                          <img src={file.thumbnailPath} alt="Preview (blurred)" />
                          <div className="blur-overlay">CSAM - PREVIEW BLURRED</div>
                        </div>
                      </div>
                    )}

                    {/* Hash Information */}
                    <div className="hash-info-section">
                      <div className="hash-type-label">{hashInfo.type}</div>
                      <div className="hash-value">{hashInfo.value}</div>
                    </div>

                    {/* Flags */}
                    {hashMatchFlags.length > 0 && (
                      <div className="flags-section">
                        {hashMatchFlags.map((flag, fidx) => (
                          <div key={fidx} className={`flag-badge severity-${flag.severity}`}>
                            <span className="flag-source">{flag.source}</span>
                            <span className="flag-reason">{flag.reason}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* File Path (Clickable) */}
                    <div className="file-path-row">
                      <span className="path-label">Location:</span>
                      <button
                        className="file-path-link"
                        onClick={() => handleOpenInExplorer(file.filePath)}
                        title="Click to open in Windows Explorer"
                      >
                        📁 {file.filePath}
                      </button>
                    </div>

                    {/* Expanded Details */}
                    {expandedFile === file.filePath && (
                      <div className="file-details-expanded">
                        {/* Metadata Section */}
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
                                <span className="meta-value">{(fileMetadata.size / 1024 / 1024).toFixed(2)} MB</span>
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

                        {/* EXIF/Media Metadata */}
                        {file.metadata && (
                          <div className="media-metadata-section">
                            <h4>📷 Media Metadata</h4>
                            <div className="metadata-grid">
                              {file.metadata.camera && (
                                <div className="metadata-item">
                                  <span className="meta-label">Camera:</span>
                                  <span className="meta-value">{file.metadata.camera}</span>
                                </div>
                              )}
                              {file.metadata.dateTaken && (
                                <div className="metadata-item">
                                  <span className="meta-label">Date Taken:</span>
                                  <span className="meta-value">{file.metadata.dateTaken}</span>
                                </div>
                              )}
                              {file.metadata.software && (
                                <div className="metadata-item">
                                  <span className="meta-label">Software:</span>
                                  <span className="meta-value">{file.metadata.software}</span>
                                </div>
                              )}
                              {(file.metadata.gpsLatitude !== undefined && file.metadata.gpsLongitude !== undefined) && (
                                <div className="metadata-item">
                                  <span className="meta-label">GPS Location:</span>
                                  <span className="meta-value">
                                    {file.metadata.gpsLatitude.toFixed(6)}, {file.metadata.gpsLongitude.toFixed(6)}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* File Access Events */}
                        <div className="access-events-section">
                          <h4>📋 File Access History</h4>
                          {loadingEvents ? (
                            <div className="loading-metadata">
                              <div className="spinner-small"></div>
                              <span>Loading access events from Windows Event Logs...</span>
                            </div>
                          ) : accessEvents.length > 0 ? (
                            <div className="events-list">
                              {accessEvents.map((event, eidx) => (
                                <div key={eidx} className="event-item">
                                  <div className="event-header">
                                    <span className="event-timestamp">{event.timestamp}</span>
                                    <span className="event-id">Event ID: {event.eventId}</span>
                                  </div>
                                  <div className="event-details">
                                    <div className="event-row">
                                      <span className="event-label">Type:</span>
                                      <span className="event-value">{event.eventType}</span>
                                    </div>
                                    <div className="event-row">
                                      <span className="event-label">Process:</span>
                                      <span className="event-value">{event.processName}</span>
                                    </div>
                                    <div className="event-row">
                                      <span className="event-label">User:</span>
                                      <span className="event-value">{event.userName}</span>
                                    </div>
                                    {event.description && (
                                      <div className="event-description">{event.description}</div>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="no-events">
                              <p>No file access events found in Windows Event Logs.</p>
                              <p className="note">Note: File access auditing must be enabled in Windows for detailed access logs.</p>
                            </div>
                          )}
                        </div>

                        {/* Full Hash Values */}
                        <div className="full-hashes-section">
                          <h4>🔑 Complete Hash Values</h4>
                          {file.md5Hash && (
                            <div className="hash-display">
                              <span className="hash-label">MD5:</span>
                              <span className="hash-full">{file.md5Hash}</span>
                            </div>
                          )}
                          {file.sha256Hash && (
                            <div className="hash-display">
                              <span className="hash-label">SHA256:</span>
                              <span className="hash-full">{file.sha256Hash}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
