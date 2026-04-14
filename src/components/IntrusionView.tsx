import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './IntrusionView.css';

interface IntrusionSummary {
  totalArtifacts: number;
  criticalFindings: number;
  highRiskFindings: number;
  mediumRiskFindings: number;
  lowRiskFindings: number;
  overallRiskScore: number;
  recommendations: string[];
}

interface UserAccountChange {
  changeType: string;
  username: string;
  timestamp: string;
  details: string;
  isAdmin: boolean;
  suspicious: boolean;
  riskScore: number;
}

interface RemoteAccessIndicator {
  indicatorType: string;
  toolName: string;
  timestamp: string | null;
  sourceIp: string | null;
  username: string | null;
  details: string;
  riskLevel: string;
}

interface SecurityTamperingItem {
  tamperType: string;
  component: string;
  timestamp: string | null;
  details: string;
  registryKey: string | null;
  riskLevel: string;
}

interface NetworkIndicator {
  indicatorType: string;
  destination: string;
  port: number | null;
  protocol: string | null;
  timestamp: string | null;
  details: string;
  threatIntel: string | null;
  riskScore: number;
}

interface MalwareIndicator {
  indicatorType: string;
  filePath: string;
  processName: string | null;
  hash: string | null;
  timestamp: string | null;
  details: string;
  riskScore: number;
}

interface BrowserHijackingItem {
  hijackType: string;
  browser: string;
  itemName: string;
  value: string;
  timestamp: string | null;
  riskLevel: string;
}

interface EventLogAnomaly {
  artifactType: string;
  eventId: number;
  timestamp: string;
  description: string;
  logPath: string;
  logName: string;
  severity: string;
  user: string | null;
  process: string | null;
  suspiciousScore: number;
}

interface PersistenceItem {
  persistenceType: string;
  name: string;
  targetPath: string;
  location: string;
  timestamp: string | null;
  suspicious: boolean;
}

interface CommandHistoryItem {
  commandType: string;
  command: string;
  timestamp: string;
  sourcePath: string;
  suspicious: boolean;
}

interface IntrusionScanResults {
  eventLogAnomalies: EventLogAnomaly[];
  persistenceItems: PersistenceItem[];
  commandHistory: CommandHistoryItem[];
  userAccountChanges: UserAccountChange[];
  remoteAccessIndicators: RemoteAccessIndicator[];
  securityToolTampering: SecurityTamperingItem[];
  networkIndicators: NetworkIndicator[];
  malwareIndicators: MalwareIndicator[];
  browserHijacking: BrowserHijackingItem[];
  summary: IntrusionSummary;
}

export const IntrusionView: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<IntrusionScanResults | null>(null);
  const [error, setError] = useState<string>('');
  const [activeTab, setActiveTab] = useState<string>('summary');

  const startScan = async () => {
    setLoading(true);
    setError('');

    try {
      const scanResults = await invoke<IntrusionScanResults>('scan_intrusion_artifacts', {
        options: {
          scanEventLogs: true,
          scanPersistence: true,
          scanCommandHistory: true,
          scanUserAccounts: true,
          scanRemoteAccess: true,
          scanSecurityTampering: true,
          scanNetwork: true,
          scanMalware: true,
          scanBrowserHijacking: true,
          targetDrive: null,
        },
      });
      setResults(scanResults);
      setActiveTab('summary');
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return '#ff3b30';
    if (score >= 50) return '#ff9500';
    if (score >= 25) return '#ffcc00';
    return '#34c759';
  };

  const getRiskLabel = (score: number) => {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return '#ff3b30';
      case 'HIGH':
        return '#ff9500';
      case 'MEDIUM':
        return '#ffcc00';
      case 'LOW':
        return '#34c759';
      default:
        return '#8b9dc3';
    }
  };

  return (
    <div className="intrusion-view">
      <div className="intrusion-header">
        <div className="header-left">
          <h1>🛡️ Intrusion Detection</h1>
          <p>Detect evidence of hacking, unauthorized access, and system compromise</p>
        </div>
        <button
          className="scan-button"
          onClick={startScan}
          disabled={loading}
        >
          {loading ? '⏳ Scanning...' : '🔍 Start Intrusion Scan'}
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <span>⚠️ {error}</span>
        </div>
      )}

      {loading && (
        <div className="scanning-overlay">
          <div className="scanning-content">
            <div className="spinner"></div>
            <h2>Scanning for Intrusion Artifacts...</h2>
            <p>Analyzing system for signs of compromise</p>
            <div className="scan-phases">
              <div className="phase">✓ Event Logs</div>
              <div className="phase">✓ Persistence Mechanisms</div>
              <div className="phase">✓ Command History</div>
              <div className="phase active">⏳ User Accounts</div>
              <div className="phase">Remote Access</div>
              <div className="phase">Security Tampering</div>
              <div className="phase">Network Indicators</div>
              <div className="phase">Malware Indicators</div>
              <div className="phase">Browser Hijacking</div>
            </div>
          </div>
        </div>
      )}

      {results && (
        <div className="intrusion-results">
          {/* Risk Score Dashboard */}
          <div className="risk-dashboard">
            <div className="risk-score-card">
              <div className="risk-gauge">
                <svg viewBox="0 0 200 120">
                  <path
                    d="M 20 100 A 80 80 0 0 1 180 100"
                    fill="none"
                    stroke="rgba(255,255,255,0.1)"
                    strokeWidth="20"
                  />
                  <path
                    d="M 20 100 A 80 80 0 0 1 180 100"
                    fill="none"
                    stroke={getRiskColor(results.summary.overallRiskScore)}
                    strokeWidth="20"
                    strokeDasharray={`${results.summary.overallRiskScore * 2.51}, 251`}
                    style={{ transition: 'stroke-dasharray 1s ease' }}
                  />
                </svg>
                <div className="risk-score-value">
                  <span className="score">{results.summary.overallRiskScore}</span>
                  <span className="label">{getRiskLabel(results.summary.overallRiskScore)}</span>
                </div>
              </div>
              <h3>Overall Risk Score</h3>
            </div>

            <div className="findings-grid">
              <div className="finding-card critical">
                <div className="finding-number">{results.summary.criticalFindings}</div>
                <div className="finding-label">Critical</div>
              </div>
              <div className="finding-card high">
                <div className="finding-number">{results.summary.highRiskFindings}</div>
                <div className="finding-label">High Risk</div>
              </div>
              <div className="finding-card medium">
                <div className="finding-number">{results.summary.mediumRiskFindings}</div>
                <div className="finding-label">Medium Risk</div>
              </div>
              <div className="finding-card low">
                <div className="finding-number">{results.summary.lowRiskFindings}</div>
                <div className="finding-label">Low Risk</div>
              </div>
            </div>
          </div>

          {/* Recommendations */}
          {results.summary.recommendations.length > 0 && (
            <div className="recommendations-section">
              <h3>🎯 Recommended Actions</h3>
              <div className="recommendations-list">
                {results.summary.recommendations.map((rec, idx) => (
                  <div key={idx} className="recommendation-item">
                    <span className="rec-icon">→</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="intrusion-tabs">
            <button
              className={activeTab === 'summary' ? 'active' : ''}
              onClick={() => setActiveTab('summary')}
            >
              Summary ({results.summary.totalArtifacts})
            </button>
            <button
              className={activeTab === 'security' ? 'active' : ''}
              onClick={() => setActiveTab('security')}
            >
              Security Tampering ({results.securityToolTampering.length})
            </button>
            <button
              className={activeTab === 'remote' ? 'active' : ''}
              onClick={() => setActiveTab('remote')}
            >
              Remote Access ({results.remoteAccessIndicators.length})
            </button>
            <button
              className={activeTab === 'accounts' ? 'active' : ''}
              onClick={() => setActiveTab('accounts')}
            >
              User Accounts ({results.userAccountChanges.length})
            </button>
            <button
              className={activeTab === 'malware' ? 'active' : ''}
              onClick={() => setActiveTab('malware')}
            >
              Malware ({results.malwareIndicators.length})
            </button>
            <button
              className={activeTab === 'network' ? 'active' : ''}
              onClick={() => setActiveTab('network')}
            >
              Network ({results.networkIndicators.length})
            </button>
            <button
              className={activeTab === 'persistence' ? 'active' : ''}
              onClick={() => setActiveTab('persistence')}
            >
              Persistence ({results.persistenceItems.length})
            </button>
            <button
              className={activeTab === 'events' ? 'active' : ''}
              onClick={() => setActiveTab('events')}
            >
              Event Logs ({results.eventLogAnomalies.length})
            </button>
          </div>

          {/* Tab Content */}
          <div className="tab-content">
            {activeTab === 'summary' && (
              <div className="summary-tab">
                <div className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-icon">📋</div>
                    <div className="stat-value">{results.eventLogAnomalies.length}</div>
                    <div className="stat-label">Event Log Anomalies</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-icon">🔄</div>
                    <div className="stat-value">{results.persistenceItems.length}</div>
                    <div className="stat-label">Persistence Items</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-icon">💻</div>
                    <div className="stat-value">{results.commandHistory.length}</div>
                    <div className="stat-label">Command History</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-icon">👤</div>
                    <div className="stat-value">{results.userAccountChanges.length}</div>
                    <div className="stat-label">Account Changes</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-icon">🌐</div>
                    <div className="stat-value">{results.networkIndicators.length}</div>
                    <div className="stat-label">Network Indicators</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-icon">🌐</div>
                    <div className="stat-value">{results.browserHijacking.length}</div>
                    <div className="stat-label">Browser Hijacking</div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'security' && (
              <div className="security-tab">
                <h3>Security Tool Tampering</h3>
                {results.securityToolTampering.length === 0 ? (
                  <div className="empty-state">✓ No security tampering detected</div>
                ) : (
                  <div className="items-list">
                    {results.securityToolTampering.map((item, idx) => (
                      <div key={idx} className="item-card severity-critical">
                        <div className="item-header">
                          <span
                            className="severity-badge"
                            style={{ background: getSeverityColor(item.riskLevel) }}
                          >
                            {item.riskLevel}
                          </span>
                          <span className="item-type">{item.tamperType}</span>
                        </div>
                        <div className="item-title">{item.component}</div>
                        <div className="item-details">{item.details}</div>
                        {item.registryKey && (
                          <div className="item-meta">
                            <code>{item.registryKey}</code>
                          </div>
                        )}
                        {item.timestamp && (
                          <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'remote' && (
              <div className="remote-tab">
                <h3>Remote Access Indicators</h3>
                {results.remoteAccessIndicators.length === 0 ? (
                  <div className="empty-state">✓ No remote access tools detected</div>
                ) : (
                  <div className="items-list">
                    {results.remoteAccessIndicators.map((item, idx) => (
                      <div key={idx} className="item-card">
                        <div className="item-header">
                          <span
                            className="severity-badge"
                            style={{ background: getSeverityColor(item.riskLevel) }}
                          >
                            {item.riskLevel}
                          </span>
                          <span className="item-type">{item.indicatorType}</span>
                        </div>
                        <div className="item-title">{item.toolName}</div>
                        <div className="item-details">{item.details}</div>
                        {item.sourceIp && (
                          <div className="item-meta">IP: {item.sourceIp}</div>
                        )}
                        {item.username && (
                          <div className="item-meta">User: {item.username}</div>
                        )}
                        {item.timestamp && (
                          <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'accounts' && (
              <div className="accounts-tab">
                <h3>User Account Changes</h3>
                {results.userAccountChanges.length === 0 ? (
                  <div className="empty-state">✓ No suspicious account changes detected</div>
                ) : (
                  <div className="items-list">
                    {results.userAccountChanges.map((item, idx) => (
                      <div key={idx} className={`item-card ${item.suspicious ? 'suspicious' : ''}`}>
                        <div className="item-header">
                          <span className="severity-badge" style={{ background: getRiskColor(item.riskScore) }}>
                            Risk: {item.riskScore}
                          </span>
                          <span className="item-type">{item.changeType}</span>
                          {item.isAdmin && <span className="admin-badge">👑 ADMIN</span>}
                        </div>
                        <div className="item-title">{item.username}</div>
                        <div className="item-details">{item.details}</div>
                        <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'malware' && (
              <div className="malware-tab">
                <h3>Malware Indicators</h3>
                {results.malwareIndicators.length === 0 ? (
                  <div className="empty-state">✓ No malware indicators detected</div>
                ) : (
                  <div className="items-list">
                    {results.malwareIndicators.map((item, idx) => (
                      <div key={idx} className="item-card severity-high">
                        <div className="item-header">
                          <span className="severity-badge" style={{ background: getRiskColor(item.riskScore) }}>
                            Risk: {item.riskScore}
                          </span>
                          <span className="item-type">{item.indicatorType}</span>
                        </div>
                        {item.processName && <div className="item-title">{item.processName}</div>}
                        <div className="item-details">{item.details}</div>
                        <div className="item-meta">
                          <code>{item.filePath}</code>
                        </div>
                        {item.hash && (
                          <div className="item-meta">Hash: <code>{item.hash}</code></div>
                        )}
                        {item.timestamp && (
                          <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'network' && (
              <div className="network-tab">
                <h3>Network Indicators</h3>
                {results.networkIndicators.length === 0 ? (
                  <div className="empty-state">✓ No suspicious network activity detected</div>
                ) : (
                  <div className="items-list">
                    {results.networkIndicators.map((item, idx) => (
                      <div key={idx} className="item-card">
                        <div className="item-header">
                          <span className="severity-badge" style={{ background: getRiskColor(item.riskScore) }}>
                            Risk: {item.riskScore}
                          </span>
                          <span className="item-type">{item.indicatorType}</span>
                        </div>
                        <div className="item-title">{item.destination}</div>
                        <div className="item-details">{item.details}</div>
                        <div className="item-meta">
                          {item.protocol && <span>Protocol: {item.protocol}</span>}
                          {item.port && <span> | Port: {item.port}</span>}
                        </div>
                        {item.threatIntel && (
                          <div className="threat-intel">🔍 {item.threatIntel}</div>
                        )}
                        {item.timestamp && (
                          <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'persistence' && (
              <div className="persistence-tab">
                <h3>Persistence Mechanisms</h3>
                {results.persistenceItems.length === 0 ? (
                  <div className="empty-state">✓ No persistence items found</div>
                ) : (
                  <div className="items-list">
                    {results.persistenceItems.map((item, idx) => (
                      <div key={idx} className={`item-card ${item.suspicious ? 'suspicious' : ''}`}>
                        <div className="item-header">
                          <span className="item-type">{item.persistenceType}</span>
                          {item.suspicious && <span className="suspicious-badge">⚠️ SUSPICIOUS</span>}
                        </div>
                        <div className="item-title">{item.name}</div>
                        <div className="item-meta">
                          <code>{item.targetPath}</code>
                        </div>
                        <div className="item-details">Location: {item.location}</div>
                        {item.timestamp && (
                          <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'events' && (
              <div className="events-tab">
                <h3>Event Log Anomalies</h3>
                {results.eventLogAnomalies.length === 0 ? (
                  <div className="empty-state">✓ No event log anomalies detected</div>
                ) : (
                  <div className="items-list">
                    {results.eventLogAnomalies.map((item, idx) => (
                      <div key={idx} className="item-card">
                        <div className="item-header">
                          <span
                            className="severity-badge"
                            style={{ background: getSeverityColor(item.severity) }}
                          >
                            {item.severity}
                          </span>
                          <span className="item-type">Event ID: {item.eventId}</span>
                          <span className="item-type">{item.logName}</span>
                        </div>
                        <div className="item-title">{item.artifactType}</div>
                        <div className="item-details">{item.description}</div>
                        {item.user && <div className="item-meta">User: {item.user}</div>}
                        {item.process && <div className="item-meta">Process: {item.process}</div>}
                        <div className="item-timestamp">{new Date(item.timestamp).toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {!results && !loading && (
        <div className="empty-view">
          <div className="empty-icon">🛡️</div>
          <h2>No Scan Results</h2>
          <p>Click "Start Intrusion Scan" to detect evidence of hacking or unauthorized access</p>
        </div>
      )}
    </div>
  );
};
