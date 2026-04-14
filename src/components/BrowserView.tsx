import React, { useState } from 'react';
import { Button } from './Button';
import { BrowserData } from '../types/browser';
import './BrowserView.css';

interface BrowserViewProps {
  browsers: BrowserData[];
  isScanning: boolean;
  onStartScan: () => void;
  onBack: () => void;
  onExportBrowser: (browser: BrowserData) => void;
}

type ViewMode = 'overview' | 'history' | 'bookmarks' | 'credentials' | 'downloads';

export const BrowserView: React.FC<BrowserViewProps> = ({
  browsers,
  isScanning,
  onStartScan,
  onBack,
  onExportBrowser,
}) => {
  const [selectedBrowser, setSelectedBrowser] = useState<BrowserData | null>(
    browsers.length > 0 ? browsers[0] : null
  );
  const [viewMode, setViewMode] = useState<ViewMode>('overview');
  const [searchQuery, setSearchQuery] = useState('');

  const getBrowserIcon = (browserName: string): string => {
    if (browserName.includes('Chrome')) return '🌐';
    if (browserName.includes('Edge')) return '🔷';
    if (browserName.includes('Firefox')) return '🦊';
    if (browserName.includes('Brave')) return '🦁';
    if (browserName.includes('Opera')) return '🎭';
    if (browserName.includes('Vivaldi')) return '🎨';
    return '🌐';
  };

  const filterItems = <T extends { url?: string; title?: string; username?: string }>(
    items: T[]
  ): T[] => {
    if (!searchQuery) return items;
    const query = searchQuery.toLowerCase();
    return items.filter(
      (item) =>
        item.url?.toLowerCase().includes(query) ||
        item.title?.toLowerCase().includes(query) ||
        (item as any).username?.toLowerCase().includes(query)
    );
  };

  const renderOverview = () => {
    if (!selectedBrowser) return null;

    return (
      <div className="browser-overview">
        <div className="overview-header">
          <h2>
            {getBrowserIcon(selectedBrowser.browserName)} {selectedBrowser.browserName}
          </h2>
          <p className="profile-name">Profile: {selectedBrowser.profileName}</p>
        </div>

        <div className="stats-grid">
          <div className="stat-card" onClick={() => setViewMode('history')}>
            <div className="stat-icon">🕒</div>
            <div className="stat-content">
              <h3>History Entries</h3>
              <p className="stat-value">{selectedBrowser.history.length.toLocaleString()}</p>
              <p className="stat-hint">Click to view details</p>
            </div>
          </div>

          <div className="stat-card" onClick={() => setViewMode('bookmarks')}>
            <div className="stat-icon">⭐</div>
            <div className="stat-content">
              <h3>Bookmarks</h3>
              <p className="stat-value">{selectedBrowser.bookmarks.length.toLocaleString()}</p>
              <p className="stat-hint">Click to view details</p>
            </div>
          </div>

          <div className="stat-card" onClick={() => setViewMode('credentials')}>
            <div className="stat-icon">🔑</div>
            <div className="stat-content">
              <h3>Saved Credentials</h3>
              <p className="stat-value">{selectedBrowser.credentials.length.toLocaleString()}</p>
              <p className="stat-hint">Click to view details</p>
            </div>
          </div>

          <div className="stat-card" onClick={() => setViewMode('downloads')}>
            <div className="stat-icon">📥</div>
            <div className="stat-content">
              <h3>Download History</h3>
              <p className="stat-value">{selectedBrowser.downloads.length.toLocaleString()}</p>
              <p className="stat-hint">Click to view details</p>
            </div>
          </div>
        </div>

        <div className="overview-details">
          <div className="detail-row">
            <span className="detail-label">Install Path:</span>
            <span className="detail-value">{selectedBrowser.installPath}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Profile Path:</span>
            <span className="detail-value">{selectedBrowser.profilePath}</span>
          </div>
        </div>

        <div className="overview-actions">
          <Button variant="primary" onClick={() => onExportBrowser(selectedBrowser)}>
            📄 Export Browser Data
          </Button>
        </div>
      </div>
    );
  };

  const renderHistory = () => {
    if (!selectedBrowser) return null;
    const filteredHistory = filterItems(selectedBrowser.history);

    return (
      <div className="browser-data-view">
        <div className="data-header">
          <h3>🕒 Browsing History ({filteredHistory.length.toLocaleString()} entries)</h3>
          <Button variant="secondary" size="sm" onClick={() => setViewMode('overview')}>
            ← Back to Overview
          </Button>
        </div>

        <div className="search-bar">
          <input
            type="text"
            placeholder="Search history by URL or title..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>URL</th>
                <th>Title</th>
                <th>Visit Count</th>
                <th>Typed Count</th>
                <th>Last Visit</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((entry, idx) => (
                <tr key={idx}>
                  <td className="url-cell">
                    <a href={entry.url} target="_blank" rel="noopener noreferrer">
                      {entry.url}
                    </a>
                  </td>
                  <td>{entry.title || '(No title)'}</td>
                  <td className="numeric-cell">{entry.visitCount}</td>
                  <td className="numeric-cell">{entry.typedCount}</td>
                  <td className="date-cell">{entry.lastVisit}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderBookmarks = () => {
    if (!selectedBrowser) return null;
    const filteredBookmarks = filterItems(selectedBrowser.bookmarks);

    return (
      <div className="browser-data-view">
        <div className="data-header">
          <h3>⭐ Bookmarks ({filteredBookmarks.length.toLocaleString()} entries)</h3>
          <Button variant="secondary" size="sm" onClick={() => setViewMode('overview')}>
            ← Back to Overview
          </Button>
        </div>

        <div className="search-bar">
          <input
            type="text"
            placeholder="Search bookmarks by URL or title..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Folder</th>
                <th>Title</th>
                <th>URL</th>
                <th>Date Added</th>
              </tr>
            </thead>
            <tbody>
              {filteredBookmarks.map((entry, idx) => (
                <tr key={idx}>
                  <td className="folder-cell">{entry.folder || 'Root'}</td>
                  <td>{entry.title}</td>
                  <td className="url-cell">
                    <a href={entry.url} target="_blank" rel="noopener noreferrer">
                      {entry.url}
                    </a>
                  </td>
                  <td className="date-cell">{entry.dateAdded}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderCredentials = () => {
    if (!selectedBrowser) return null;
    const filteredCredentials = filterItems(selectedBrowser.credentials);

    return (
      <div className="browser-data-view">
        <div className="data-header">
          <h3>🔑 Saved Credentials ({filteredCredentials.length.toLocaleString()} entries)</h3>
          <Button variant="secondary" size="sm" onClick={() => setViewMode('overview')}>
            ← Back to Overview
          </Button>
        </div>

        <div className="warning-banner">
          <strong>⚠️ Security Notice:</strong> Passwords are encrypted and not displayed for security reasons. 
          This shows only the sites and usernames for which credentials were saved.
        </div>

        <div className="search-bar">
          <input
            type="text"
            placeholder="Search credentials by URL or username..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Origin URL</th>
                <th>Username</th>
                <th>Date Created</th>
                <th>Last Used</th>
              </tr>
            </thead>
            <tbody>
              {filteredCredentials.map((entry, idx) => (
                <tr key={idx}>
                  <td className="url-cell">
                    <a href={entry.originUrl} target="_blank" rel="noopener noreferrer">
                      {entry.originUrl}
                    </a>
                  </td>
                  <td>{entry.username || '(No username)'}</td>
                  <td className="date-cell">{entry.dateCreated}</td>
                  <td className="date-cell">{entry.dateLastUsed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderDownloads = () => {
    if (!selectedBrowser) return null;
    
    const filteredDownloads = selectedBrowser.downloads.filter(entry => {
      if (!searchQuery) return true;
      const query = searchQuery.toLowerCase();
      return entry.targetPath?.toLowerCase().includes(query) ||
             entry.url?.toLowerCase().includes(query);
    });

    const formatBytes = (bytes: number): string => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    };

    return (
      <div className="browser-data-view">
        <div className="data-header">
          <h3>📥 Download History ({filteredDownloads.length.toLocaleString()} entries)</h3>
          <Button variant="secondary" size="sm" onClick={() => setViewMode('overview')}>
            ← Back to Overview
          </Button>
        </div>

        <div className="search-bar">
          <input
            type="text"
            placeholder="Search downloads by filename or URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>File Path</th>
                <th>Source URL</th>
                <th>Size</th>
                <th>Status</th>
                <th>Danger Type</th>
                <th>Start Time</th>
                <th>End Time</th>
              </tr>
            </thead>
            <tbody>
              {filteredDownloads.map((entry, idx) => (
                <tr key={idx}>
                  <td className="file-path-cell" title={entry.targetPath}>
                    {entry.targetPath.split('\\').pop() || entry.targetPath}
                  </td>
                  <td className="url-cell">
                    <a href={entry.url} target="_blank" rel="noopener noreferrer" title={entry.url}>
                      {entry.url.length > 50 ? entry.url.substring(0, 50) + '...' : entry.url}
                    </a>
                  </td>
                  <td className="size-cell">{formatBytes(entry.totalBytes)}</td>
                  <td className="status-cell">
                    <span className={`status-badge status-${entry.state.toLowerCase().replace(' ', '-')}`}>
                      {entry.state}
                    </span>
                  </td>
                  <td className="danger-cell">
                    <span className={`danger-badge danger-${entry.dangerType.toLowerCase().replace(' ', '-')}`}>
                      {entry.dangerType}
                    </span>
                  </td>
                  <td className="date-cell">{entry.startTime}</td>
                  <td className="date-cell">{entry.endTime}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  if (isScanning) {
    return (
      <div className="browser-view">
        <div className="scanning-overlay">
          <div className="spinner-large"></div>
          <h2>Scanning Browsers...</h2>
          <p>Extracting history, bookmarks, and credentials from installed browsers</p>
        </div>
      </div>
    );
  }

  if (browsers.length === 0) {
    return (
      <div className="browser-view">
        <div className="browser-header">
          <div className="header-content">
            <h1>🌐 BROWSER HISTORY SCANNER</h1>
            <p>Extract and analyze browser history, bookmarks, and saved credentials</p>
          </div>
          <Button variant="secondary" onClick={onBack}>
            ← Back
          </Button>
        </div>

        <div className="empty-state-large">
          <div className="empty-icon">🌐</div>
          <h2>No Browser Data Scanned</h2>
          <p>Click the button below to scan all installed browsers on this system</p>
          <Button variant="primary" size="lg" onClick={onStartScan} glow>
            🔍 Start Browser Scan
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="browser-view">
      <div className="browser-header">
        <div className="header-content">
          <h1>🌐 BROWSER HISTORY SCANNER</h1>
          <p>{browsers.length} browser profile(s) found</p>
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

      <div className="browser-content">
        <div className="browser-sidebar">
          <h3>Detected Browsers</h3>
          <div className="browser-list">
            {browsers.map((browser, idx) => (
              <div
                key={idx}
                className={`browser-item ${selectedBrowser === browser ? 'selected' : ''}`}
                onClick={() => {
                  setSelectedBrowser(browser);
                  setViewMode('overview');
                  setSearchQuery('');
                }}
              >
                <div className="browser-icon">
                  {getBrowserIcon(browser.browserName)}
                </div>
                <div className="browser-info">
                  <div className="browser-name">{browser.browserName}</div>
                  <div className="browser-profile">{browser.profileName}</div>
                  <div className="browser-stats">
                    {browser.history.length}H · {browser.bookmarks.length}B · {browser.credentials.length}C
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="browser-main">
          <div className="view-tabs">
            <button
              className={`view-tab ${viewMode === 'overview' ? 'active' : ''}`}
              onClick={() => setViewMode('overview')}
            >
              📊 Overview
            </button>
            <button
              className={`view-tab ${viewMode === 'history' ? 'active' : ''}`}
              onClick={() => setViewMode('history')}
            >
              🕒 History
            </button>
            <button
              className={`view-tab ${viewMode === 'bookmarks' ? 'active' : ''}`}
              onClick={() => setViewMode('bookmarks')}
            >
              ⭐ Bookmarks
            </button>
            <button
              className={`view-tab ${viewMode === 'credentials' ? 'active' : ''}`}
              onClick={() => setViewMode('credentials')}
            >
              🔑 Credentials
            </button>
            <button
              className={`view-tab ${viewMode === 'downloads' ? 'active' : ''}`}
              onClick={() => setViewMode('downloads')}
            >
              📥 Downloads
            </button>
          </div>

          <div className="view-content">
            {viewMode === 'overview' && renderOverview()}
            {viewMode === 'history' && renderHistory()}
            {viewMode === 'bookmarks' && renderBookmarks()}
            {viewMode === 'credentials' && renderCredentials()}
            {viewMode === 'downloads' && renderDownloads()}
          </div>
        </div>
      </div>
    </div>
  );
};
