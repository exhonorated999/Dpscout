import React, { useState } from 'react';
import { Button } from './Button';
import { ScanReport, ReportFormat, SystemInfo } from '../types/report';
import { QuestionableApp } from '../types/scanner';
import { MediaFile } from '../types/media';
import './ReportView.css';

interface ReportViewProps {
  apps: QuestionableApp[];
  media: MediaFile[];
  onExport: (format: ReportFormat) => void;
  onClose: () => void;
}

export const ReportView: React.FC<ReportViewProps> = ({ apps, media, onExport, onClose }) => {
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>('pdf');
  const [activeTab, setActiveTab] = useState<'overview' | 'apps' | 'media' | 'system'>('overview');

  // Calculate statistics
  const stats = {
    totalApps: apps.length,
    criticalApps: apps.filter(a => a.flags.some(f => f.severity === 'critical')).length,
    totalMedia: media.length,
    flaggedMedia: media.filter(m => m.flags.length > 0).length,
    criticalMedia: media.filter(m => m.flags.some(f => f.severity === 'critical')).length,
    hashMatches: media.filter(m => m.flags.some(f => f.flagType === 'HashMatch')).length,
    keywordMatches: media.filter(m => m.flags.some(f => f.flagType === 'KeywordMatch')).length,
  };

  const hasFindings = stats.totalApps > 0 || stats.totalMedia > 0;

  return (
    <div className="report-view">
      <div className="report-header">
        <div className="header-content">
          <h1>📊 SCAN REPORT</h1>
          <p className="report-timestamp">{new Date().toLocaleString()}</p>
        </div>
        <Button variant="ghost" onClick={onClose}>✕ Close</Button>
      </div>

      <div className="report-content">
        <div className="report-sidebar">
          <div className="sidebar-section">
            <h3>Report Sections</h3>
            <button
              className={`sidebar-btn ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              <span className="btn-icon">📋</span>
              <span>Overview</span>
            </button>
            <button
              className={`sidebar-btn ${activeTab === 'apps' ? 'active' : ''}`}
              onClick={() => setActiveTab('apps')}
            >
              <span className="btn-icon">📱</span>
              <span>Applications ({stats.totalApps})</span>
            </button>
            <button
              className={`sidebar-btn ${activeTab === 'media' ? 'active' : ''}`}
              onClick={() => setActiveTab('media')}
            >
              <span className="btn-icon">🖼️</span>
              <span>Media Files ({stats.totalMedia})</span>
            </button>
            <button
              className={`sidebar-btn ${activeTab === 'system' ? 'active' : ''}`}
              onClick={() => setActiveTab('system')}
            >
              <span className="btn-icon">💻</span>
              <span>System Info</span>
            </button>
          </div>

          <div className="sidebar-section export-section">
            <h3>Export Report</h3>
            <div className="format-selector">
              <label className={`format-option ${selectedFormat === 'pdf' ? 'selected' : ''}`}>
                <input
                  type="radio"
                  name="format"
                  value="pdf"
                  checked={selectedFormat === 'pdf'}
                  onChange={() => setSelectedFormat('pdf')}
                />
                <span className="format-icon">📄</span>
                <span className="format-label">PDF</span>
              </label>
              <label className={`format-option ${selectedFormat === 'rtf' ? 'selected' : ''}`}>
                <input
                  type="radio"
                  name="format"
                  value="rtf"
                  checked={selectedFormat === 'rtf'}
                  onChange={() => setSelectedFormat('rtf')}
                />
                <span className="format-icon">📝</span>
                <span className="format-label">RTF</span>
              </label>
              <label className={`format-option ${selectedFormat === 'html' ? 'selected' : ''}`}>
                <input
                  type="radio"
                  name="format"
                  value="html"
                  checked={selectedFormat === 'html'}
                  onChange={() => setSelectedFormat('html')}
                />
                <span className="format-icon">🌐</span>
                <span className="format-label">HTML</span>
              </label>
              <label className={`format-option ${selectedFormat === 'json' ? 'selected' : ''}`}>
                <input
                  type="radio"
                  name="format"
                  value="json"
                  checked={selectedFormat === 'json'}
                  onChange={() => setSelectedFormat('json')}
                />
                <span className="format-icon">📦</span>
                <span className="format-label">JSON</span>
              </label>
            </div>
            <Button
              variant="primary"
              size="md"
              glow
              onClick={() => onExport(selectedFormat)}
              disabled={!hasFindings}
            >
              💾 Export Report
            </Button>
          </div>
        </div>

        <div className="report-main">
          {activeTab === 'overview' && (
            <OverviewTab stats={stats} apps={apps} media={media} />
          )}
          {activeTab === 'apps' && (
            <ApplicationsTab apps={apps} />
          )}
          {activeTab === 'media' && (
            <MediaTab media={media} />
          )}
          {activeTab === 'system' && (
            <SystemTab />
          )}
        </div>
      </div>
    </div>
  );
};

// Overview Tab
const OverviewTab: React.FC<{
  stats: any;
  apps: QuestionableApp[];
  media: MediaFile[];
}> = ({ stats, apps, media }) => {
  const hasCriticalFindings = stats.criticalApps > 0 || stats.criticalMedia > 0;

  return (
    <div className="tab-content">
      <div className="tab-header">
        <h2>Scan Overview</h2>
        <p>Summary of all findings from the system triage</p>
      </div>

      {hasCriticalFindings && (
        <div className="critical-alert">
          <div className="alert-icon">🚨</div>
          <div className="alert-content">
            <h3>CRITICAL FINDINGS DETECTED</h3>
            <p>
              This scan has identified {stats.criticalApps + stats.criticalMedia} critical items
              requiring immediate attention. Review flagged applications and hash-matched media files.
            </p>
          </div>
        </div>
      )}

      <div className="stats-grid">
        <div className={`stat-card ${stats.totalApps > 0 ? 'has-data' : ''}`}>
          <div className="stat-icon">📱</div>
          <div className="stat-value">{stats.totalApps}</div>
          <div className="stat-label">Questionable Apps</div>
          {stats.criticalApps > 0 && (
            <div className="stat-badge critical">{stats.criticalApps} Critical</div>
          )}
        </div>

        <div className={`stat-card ${stats.totalMedia > 0 ? 'has-data' : ''}`}>
          <div className="stat-icon">🖼️</div>
          <div className="stat-value">{stats.totalMedia}</div>
          <div className="stat-label">Media Files</div>
          {stats.flaggedMedia > 0 && (
            <div className="stat-badge warning">{stats.flaggedMedia} Flagged</div>
          )}
        </div>

        <div className={`stat-card ${stats.hashMatches > 0 ? 'has-data critical' : ''}`}>
          <div className="stat-icon">🔐</div>
          <div className="stat-value">{stats.hashMatches}</div>
          <div className="stat-label">Hash Matches</div>
          {stats.hashMatches > 0 && (
            <div className="stat-badge critical">Project VIC</div>
          )}
        </div>

        <div className={`stat-card ${stats.keywordMatches > 0 ? 'has-data' : ''}`}>
          <div className="stat-icon">🔍</div>
          <div className="stat-value">{stats.keywordMatches}</div>
          <div className="stat-label">Keyword Matches</div>
        </div>
      </div>

      <div className="findings-summary">
        <h3>Scan Modules</h3>
        <div className="module-summary-list">
          <div className="module-summary-item completed">
            <span className="module-status">✓</span>
            <span className="module-name">Questionable Applications</span>
            <span className="module-result">{stats.totalApps} found</span>
          </div>
          <div className="module-summary-item completed">
            <span className="module-status">✓</span>
            <span className="module-name">Media Scanner</span>
            <span className="module-result">{stats.totalMedia} files</span>
          </div>
          <div className="module-summary-item disabled">
            <span className="module-status">○</span>
            <span className="module-name">Browser History</span>
            <span className="module-result">Not run</span>
          </div>
          <div className="module-summary-item disabled">
            <span className="module-status">○</span>
            <span className="module-name">Keyword Search</span>
            <span className="module-result">Not run</span>
          </div>
        </div>
      </div>

      {stats.criticalMedia > 0 && (
        <div className="priority-section">
          <h3>High Priority Items</h3>
          <p className="section-note">Files with hash matches or critical flags</p>
          <div className="priority-items">
            {media
              .filter(m => m.flags.some(f => f.severity === 'critical'))
              .slice(0, 10)
              .map(item => (
                <div key={item.id} className="priority-item">
                  <span className="priority-icon">🚨</span>
                  <div className="priority-info">
                    <div className="priority-name">{item.fileName}</div>
                    <div className="priority-path">{item.filePath}</div>
                    <div className="priority-flags">
                      {item.flags.map((flag, i) => (
                        <span key={i} className="priority-flag">
                          {flag.source}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Applications Tab
const ApplicationsTab: React.FC<{ apps: QuestionableApp[] }> = ({ apps }) => {
  const groupedApps = apps.reduce((acc, app) => {
    const category = app.category;
    if (!acc[category]) acc[category] = [];
    acc[category].push(app);
    return acc;
  }, {} as Record<string, QuestionableApp[]>);

  return (
    <div className="tab-content">
      <div className="tab-header">
        <h2>Detected Applications</h2>
        <p>{apps.length} questionable applications found</p>
      </div>

      {Object.entries(groupedApps).map(([category, categoryApps]) => (
        <div key={category} className="category-section">
          <h3 className="category-title">
            {category} ({categoryApps.length})
          </h3>
          <div className="apps-table">
            {categoryApps.map((app, index) => (
              <div key={index} className="app-row">
                <div className="app-info-col">
                  <div className="app-name">{app.name}</div>
                  <div className="app-version">v{app.version}</div>
                </div>
                <div className="app-path-col">{app.install_path}</div>
                {app.install_date && (
                  <div className="app-date-col">
                    {new Date(app.install_date).toLocaleDateString()}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

// Media Tab
const MediaTab: React.FC<{ media: MediaFile[] }> = ({ media }) => {
  const flaggedMedia = media.filter(m => m.flags.length > 0);

  return (
    <div className="tab-content">
      <div className="tab-header">
        <h2>Media Files</h2>
        <p>{media.length} files scanned, {flaggedMedia.length} flagged</p>
      </div>

      {flaggedMedia.length > 0 && (
        <div className="media-section">
          <h3>Flagged Media</h3>
          <div className="media-list">
            {flaggedMedia.map(item => (
              <div key={item.id} className="media-row">
                <div className="media-info-col">
                  <div className="media-name">{item.fileName}</div>
                  <div className="media-size">{formatFileSize(item.fileSize)}</div>
                </div>
                <div className="media-flags-col">
                  {item.flags.map((flag, i) => (
                    <span key={i} className={`flag-badge severity-${flag.severity}`}>
                      {flag.source}
                    </span>
                  ))}
                </div>
                {item.sha256Hash && (
                  <div className="media-hash-col">{item.sha256Hash.substring(0, 16)}...</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// System Tab
const SystemTab: React.FC = () => {
  return (
    <div className="tab-content">
      <div className="tab-header">
        <h2>System Information</h2>
        <p>Target device details</p>
      </div>

      <div className="system-info-grid">
        <div className="info-card">
          <label>Hostname</label>
          <div className="info-value">{getHostname()}</div>
        </div>
        <div className="info-card">
          <label>Operating System</label>
          <div className="info-value">{getOS()}</div>
        </div>
        <div className="info-card">
          <label>Current User</label>
          <div className="info-value">{getCurrentUser()}</div>
        </div>
        <div className="info-card">
          <label>Scan Date/Time</label>
          <div className="info-value">{new Date().toLocaleString()}</div>
        </div>
      </div>

      <div className="info-note">
        <strong>Note:</strong> Additional system information will be automatically included in exported reports.
      </div>
    </div>
  );
};

// Helper functions
function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function getHostname(): string {
  return window.location.hostname || 'Unknown';
}

function getOS(): string {
  return navigator.platform || 'Unknown';
}

function getCurrentUser(): string {
  return 'User'; // Will be replaced with actual system user from Rust
}
