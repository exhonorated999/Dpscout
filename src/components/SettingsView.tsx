import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button } from './Button';
import { AppSettings, KeywordList, HashList, CustomAppDefinition, ScanOptions } from '../types/settings';
import { ReportsManager } from './ReportsManager';
import { ScanDocumentationPanel } from './ScanDocumentation';
import './SettingsView.css';

interface SettingsViewProps {
  settings: AppSettings;
  onSave: (settings: AppSettings) => void;
  onClose: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ settings, onSave, onClose }) => {
  // Ensure settings have default values with ALL required fields
  const initialSettings: AppSettings = {
    officer_name: settings?.officer_name || undefined,
    agency_name: settings?.agency_name || undefined,
    keywordLists: settings?.keywordLists || [],
    hashLists: settings?.hashLists || [],
    customApps: settings?.customApps || [],
    scanOptions: settings?.scanOptions || {
      enableQuestionableApps: true,
      enableBrowserHistory: false,
      enableKeywordSearch: false,
      enableMediaScan: false,
      enableHashMatching: false,
      scanDepth: 'standard',
      includeSystemDirs: false,
    }
  };

  const [currentSettings, setCurrentSettings] = useState<AppSettings>(initialSettings);
  const [activeTab, setActiveTab] = useState<'profile' | 'keywords' | 'hashes' | 'apps' | 'options' | 'reports' | 'documentation' | 'license'>('keywords');

  const handleSave = () => {
    onSave(currentSettings);
  };

  console.log('SettingsView rendering', { settings, currentSettings, activeTab });

  return (
    <div className="settings-view">
      <div className="settings-header">
        <div className="header-content">
          <h1>⚙️ SETTINGS</h1>
          <p>Configure detection lists and scan options (Active Tab: {activeTab})</p>
        </div>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <Button variant="secondary" size="lg" onClick={onClose} style={{ fontSize: '1.1rem', padding: '0.75rem 1.5rem' }}>
            ← Back
          </Button>
        </div>
      </div>

      <div className="settings-content">
        <div className="settings-tabs">
          <button
            className={`settings-tab ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            👤 Profile
          </button>
          <button
            className={`settings-tab ${activeTab === 'keywords' ? 'active' : ''}`}
            onClick={() => setActiveTab('keywords')}
          >
            🔍 Keyword Lists
          </button>
          <button
            className={`settings-tab ${activeTab === 'hashes' ? 'active' : ''}`}
            onClick={() => setActiveTab('hashes')}
          >
            🔐 Hash Lists
          </button>
          <button
            className={`settings-tab ${activeTab === 'apps' ? 'active' : ''}`}
            onClick={() => setActiveTab('apps')}
          >
            📱 Custom Apps
          </button>
          <button
            className={`settings-tab ${activeTab === 'options' ? 'active' : ''}`}
            onClick={() => setActiveTab('options')}
          >
            ⚙️ Scan Options
          </button>
          <button
            className={`settings-tab ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => setActiveTab('reports')}
          >
            📄 Encrypted Reports
          </button>
          <button
            className={`settings-tab ${activeTab === 'license' ? 'active' : ''}`}
            onClick={() => setActiveTab('license')}
          >
            🔑 License
          </button>
          <button
            className={`settings-tab ${activeTab === 'documentation' ? 'active' : ''}`}
            onClick={() => setActiveTab('documentation')}
          >
            📚 Scan Documentation
          </button>
        </div>

        <div className="settings-panel">
          {activeTab === 'profile' && (
            <ProfilePanel
              officerName={currentSettings.officer_name}
              agencyName={currentSettings.agency_name}
              onChange={(officerName, agencyName) => {
                setCurrentSettings({ 
                  ...currentSettings, 
                  officer_name: officerName,
                  agency_name: agencyName
                });
              }}
            />
          )}
          {activeTab === 'keywords' && (
            <KeywordListsPanel
              lists={currentSettings.keywordLists}
              onChange={(lists) => setCurrentSettings({ ...currentSettings, keywordLists: lists })}
              onAutoSave={(lists) => {
                const newSettings = { ...currentSettings, keywordLists: lists };
                setCurrentSettings(newSettings);
                onSave(newSettings);
              }}
            />
          )}
          {activeTab === 'hashes' && (
            <HashListsPanel
              lists={currentSettings.hashLists}
              onChange={(lists) => setCurrentSettings({ ...currentSettings, hashLists: lists })}
              onAutoSave={(lists) => {
                const newSettings = { ...currentSettings, hashLists: lists };
                setCurrentSettings(newSettings);
                onSave(newSettings);
              }}
            />
          )}
          {activeTab === 'apps' && (
            <CustomAppsPanel
              apps={currentSettings.customApps}
              onChange={(apps) => setCurrentSettings({ ...currentSettings, customApps: apps })}
            />
          )}
          {activeTab === 'options' && (
            <ScanOptionsPanel
              options={currentSettings.scanOptions}
              onChange={(options) => setCurrentSettings({ ...currentSettings, scanOptions: options })}
            />
          )}
          {activeTab === 'reports' && (
            <ReportsManager />
          )}

          {activeTab === 'license' && (
            <LicensePanel />
          )}

          {activeTab === 'documentation' && (
            <ScanDocumentationPanel />
          )}
        </div>
      </div>

      <div className="settings-footer">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={handleSave} glow>💾 Save Settings</Button>
      </div>
    </div>
  );
};

// License Panel
interface LicenseInfo {
  registered: boolean;
  agency_name?: string;
  plan?: string;
  status?: string;
  expires_at?: string;
  days_remaining: number;
  is_expired: boolean;
}

interface UpdateInfo {
  update_available: boolean;
  latest_version?: string;
  download_url?: string;
  current_version?: string;
}

type UpdateProgress = {
  phase: 'idle' | 'checking' | 'downloading' | 'installing' | 'done' | 'error';
  percent: number;
  message: string;
};

interface ActivateResponse {
  success: boolean;
  plan?: string;
  expires_at?: string;
  days_remaining?: number;
  message?: string;
}

const LicensePanel: React.FC = () => {
  const [licenseInfo, setLicenseInfo] = React.useState<LicenseInfo | null>(null);
  const [updateInfo, setUpdateInfo] = React.useState<UpdateInfo | null>(null);
  const [licenseKey, setLicenseKey] = React.useState('');
  const [activating, setActivating] = React.useState(false);
  const [checking, setChecking] = React.useState(false);
  const [updateProgress, setUpdateProgress] = React.useState<UpdateProgress>({ phase: 'idle', percent: 0, message: '' });
  const [message, setMessage] = React.useState('');
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    loadLicenseStatus();
  }, []);

  const loadLicenseStatus = async () => {
    setChecking(true);
    try {
      const info = await invoke<LicenseInfo>('get_license_status');
      setLicenseInfo(info);
    } catch (err) {
      console.error('Failed to load license status:', err);
    } finally {
      setChecking(false);
    }
  };

  const handleActivate = async () => {
    if (!licenseKey.trim()) {
      setError('Please enter a license key');
      return;
    }
    setActivating(true);
    setError('');
    setMessage('');
    try {
      const response = await invoke<ActivateResponse>('activate_license_key', { licenseKey: licenseKey.trim() });
      if (response.success) {
        setMessage(`License activated! Plan: ${response.plan}, Expires: ${response.expires_at}`);
        setLicenseKey('');
        await loadLicenseStatus();
      } else {
        setError(response.message || 'Activation failed');
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setActivating(false);
    }
  };

  const handleCheckAndInstallUpdate = async () => {
    setUpdateProgress({ phase: 'checking', percent: 0, message: 'Checking for updates...' });
    setUpdateInfo(null);
    setError('');
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check();
      if (update) {
        setUpdateInfo({
          update_available: true,
          latest_version: update.version,
          current_version: update.currentVersion,
        });
        setUpdateProgress({ phase: 'downloading', percent: 0, message: `Downloading v${update.version}...` });

        let downloaded = 0;
        let contentLength = 0;

        await update.downloadAndInstall((event) => {
          switch (event.event) {
            case 'Started':
              contentLength = event.data.contentLength ?? 0;
              break;
            case 'Progress':
              downloaded += event.data.chunkLength;
              const pct = contentLength > 0 ? Math.round((downloaded / contentLength) * 100) : 0;
              setUpdateProgress({ phase: 'downloading', percent: pct, message: `Downloading... ${pct}%` });
              break;
            case 'Finished':
              setUpdateProgress({ phase: 'installing', percent: 100, message: 'Installing update...' });
              break;
          }
        });

        setUpdateProgress({ phase: 'done', percent: 100, message: 'Update installed! Restarting...' });

        // Relaunch the app after a brief delay
        setTimeout(async () => {
          try {
            const { relaunch } = await import('@tauri-apps/plugin-process');
            await relaunch();
          } catch { /* OS will close the app via installer */ }
        }, 1500);
      } else {
        // No update — get current version from the old API for display
        try {
          const info = await invoke<UpdateInfo>('check_for_updates');
          setUpdateInfo(info);
        } catch {
          setUpdateInfo({ update_available: false, current_version: undefined });
        }
        setUpdateProgress({ phase: 'idle', percent: 0, message: '' });
      }
    } catch (err) {
      console.error('Update error:', err);
      setUpdateProgress({ phase: 'error', percent: 0, message: String(err) });
    }
  };

  const getPlanBadge = (plan?: string) => {
    switch (plan) {
      case 'trial': return { label: 'TRIAL', color: '#f59e0b' };
      case 'annual': return { label: 'ANNUAL', color: '#10b981' };
      case 'perpetual': return { label: 'PERPETUAL', color: '#6366f1' };
      default: return { label: 'UNKNOWN', color: '#6b7280' };
    }
  };

  const getStatusColor = (status?: string, isExpired?: boolean) => {
    if (isExpired) return '#ef4444';
    if (status === 'active') return '#10b981';
    return '#f59e0b';
  };

  return (
    <div style={{ padding: '20px' }}>
      <h3 style={{ color: 'var(--accent-blue)', marginBottom: '24px', textTransform: 'uppercase', letterSpacing: '1px' }}>
        License & Updates
      </h3>

      {/* License Status Card */}
      <div style={{
        background: 'var(--color-bg-tertiary)',
        border: '1px solid var(--color-border)',
        borderRadius: '8px',
        padding: '24px',
        marginBottom: '24px'
      }}>
        <h4 style={{ color: 'var(--color-text-primary)', marginTop: 0, marginBottom: '16px' }}>
          📋 License Status
        </h4>

        {checking ? (
          <p style={{ color: 'var(--color-text-secondary)' }}>Checking license status...</p>
        ) : licenseInfo ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>Agency</span>
              <p style={{ color: 'var(--color-text-primary)', margin: '4px 0 0', fontWeight: 600 }}>
                {licenseInfo.agency_name || 'Not registered'}
              </p>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>Plan</span>
              <p style={{ margin: '4px 0 0' }}>
                {licenseInfo.plan ? (
                  <span style={{
                    background: getPlanBadge(licenseInfo.plan).color,
                    color: '#fff',
                    padding: '2px 10px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 700,
                    textTransform: 'uppercase'
                  }}>
                    {getPlanBadge(licenseInfo.plan).label}
                  </span>
                ) : '—'}
              </p>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>Status</span>
              <p style={{
                color: getStatusColor(licenseInfo.status, licenseInfo.is_expired),
                margin: '4px 0 0',
                fontWeight: 600
              }}>
                {licenseInfo.is_expired ? '🔴 Expired' : '🟢 Active'}
              </p>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>Days Remaining</span>
              <p style={{
                color: licenseInfo.days_remaining <= 7 ? '#ef4444' : 'var(--color-text-primary)',
                margin: '4px 0 0',
                fontWeight: 600,
                fontSize: '18px'
              }}>
                {licenseInfo.days_remaining > 0 ? licenseInfo.days_remaining : 0}
              </p>
            </div>
            {licenseInfo.expires_at && (
              <div style={{ gridColumn: '1 / -1' }}>
                <span style={{ color: 'var(--color-text-secondary)', fontSize: '12px', textTransform: 'uppercase' }}>Expires</span>
                <p style={{ color: 'var(--color-text-primary)', margin: '4px 0 0' }}>
                  {new Date(licenseInfo.expires_at).toLocaleDateString('en-US', {
                    year: 'numeric', month: 'long', day: 'numeric'
                  })}
                </p>
              </div>
            )}
          </div>
        ) : (
          <p style={{ color: 'var(--color-text-secondary)' }}>Unable to retrieve license info</p>
        )}

        <button
          onClick={loadLicenseStatus}
          disabled={checking}
          style={{
            marginTop: '16px',
            padding: '8px 16px',
            background: 'transparent',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            color: 'var(--color-text-secondary)',
            cursor: 'pointer',
            fontSize: '13px'
          }}
        >
          {checking ? 'Refreshing...' : '🔄 Refresh Status'}
        </button>
      </div>

      {/* Activate License Key */}
      <div style={{
        background: 'var(--color-bg-tertiary)',
        border: '1px solid var(--color-border)',
        borderRadius: '8px',
        padding: '24px',
        marginBottom: '24px'
      }}>
        <h4 style={{ color: 'var(--color-text-primary)', marginTop: 0, marginBottom: '16px' }}>
          🔑 Activate License Key
        </h4>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', color: 'var(--color-text-secondary)', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>
              License Key
            </label>
            <input
              type="text"
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
              placeholder="SCT-2026-XXXX-XXXX-XXXX"
              disabled={activating}
              style={{
                width: '100%',
                padding: '10px 14px',
                background: 'var(--color-bg-primary)',
                border: '1px solid var(--color-border)',
                borderRadius: '6px',
                color: 'var(--color-text-primary)',
                fontSize: '14px',
                fontFamily: 'monospace',
                letterSpacing: '1px',
                boxSizing: 'border-box'
              }}
              onKeyDown={(e) => { if (e.key === 'Enter') handleActivate(); }}
            />
          </div>
          <button
            onClick={handleActivate}
            disabled={activating || !licenseKey.trim()}
            style={{
              padding: '10px 24px',
              background: 'linear-gradient(135deg, var(--primary-blue), var(--accent-blue))',
              border: 'none',
              borderRadius: '6px',
              color: '#fff',
              fontWeight: 600,
              cursor: 'pointer',
              fontSize: '14px',
              whiteSpace: 'nowrap',
              opacity: activating || !licenseKey.trim() ? 0.5 : 1
            }}
          >
            {activating ? 'Activating...' : 'Activate'}
          </button>
        </div>

        {error && (
          <div style={{
            marginTop: '12px',
            padding: '10px 14px',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '6px',
            color: '#ef4444',
            fontSize: '13px'
          }}>
            ⚠️ {error}
          </div>
        )}
        {message && (
          <div style={{
            marginTop: '12px',
            padding: '10px 14px',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: '6px',
            color: '#10b981',
            fontSize: '13px'
          }}>
            ✅ {message}
          </div>
        )}
      </div>

      {/* Check for Updates */}
      <div style={{
        background: 'var(--color-bg-tertiary)',
        border: '1px solid var(--color-border)',
        borderRadius: '8px',
        padding: '24px'
      }}>
        <h4 style={{ color: 'var(--color-text-primary)', marginTop: 0, marginBottom: '16px' }}>
          🔄 Software Updates
        </h4>

        <button
          onClick={handleCheckAndInstallUpdate}
          disabled={updateProgress.phase !== 'idle' && updateProgress.phase !== 'error'}
          style={{
            padding: '10px 24px',
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            border: 'none',
            borderRadius: '6px',
            color: '#fff',
            fontWeight: 600,
            cursor: 'pointer',
            fontSize: '14px',
            opacity: (updateProgress.phase !== 'idle' && updateProgress.phase !== 'error') ? 0.5 : 1
          }}
        >
          {updateProgress.phase === 'checking' ? 'Checking...' : '🔍 Check for Updates'}
        </button>

        {/* Download / install progress bar */}
        {(updateProgress.phase === 'downloading' || updateProgress.phase === 'installing' || updateProgress.phase === 'done') && (
          <div style={{ marginTop: '16px', padding: '16px', background: 'var(--color-bg-primary)', border: '1px solid var(--color-border)', borderRadius: '6px' }}>
            {updateInfo?.latest_version && (
              <p style={{ color: '#f59e0b', fontWeight: 600, margin: '0 0 8px' }}>
                🆕 Updating to v{updateInfo.latest_version}
              </p>
            )}
            <div style={{ background: '#1a2a3a', borderRadius: '4px', overflow: 'hidden', height: '22px', marginBottom: '8px' }}>
              <div style={{
                width: `${updateProgress.percent}%`,
                height: '100%',
                background: updateProgress.phase === 'done' ? '#10b981' : 'linear-gradient(90deg, #6366f1, #8b5cf6)',
                transition: 'width 0.3s ease',
                borderRadius: '4px',
              }} />
            </div>
            <p style={{ color: 'var(--color-text-secondary)', margin: 0, fontSize: '13px' }}>
              {updateProgress.message}
            </p>
          </div>
        )}

        {/* Error state */}
        {updateProgress.phase === 'error' && (
          <div style={{ marginTop: '16px', padding: '16px', background: 'var(--color-bg-primary)', border: '1px solid #dc2626', borderRadius: '6px' }}>
            <p style={{ color: '#ef4444', fontWeight: 600, margin: 0, fontSize: '13px' }}>
              ❌ Update failed: {updateProgress.message}
            </p>
          </div>
        )}

        {/* Up-to-date state (shown after check finds no update) */}
        {updateInfo && !updateInfo.update_available && updateProgress.phase === 'idle' && (
          <div style={{ marginTop: '16px', padding: '16px', background: 'var(--color-bg-primary)', border: '1px solid var(--color-border)', borderRadius: '6px' }}>
            <p style={{ color: '#10b981', fontWeight: 600, margin: 0 }}>
              ✅ You are running the latest version{updateInfo.current_version ? ` (v${updateInfo.current_version})` : ''}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

// Profile Panel
const ProfilePanel: React.FC<{
  officerName?: string;
  agencyName?: string;
  onChange: (officerName?: string, agencyName?: string) => void;
}> = ({ officerName, agencyName, onChange }) => {
  const [localOfficerName, setLocalOfficerName] = useState(officerName || '');
  const [localAgencyName, setLocalAgencyName] = useState(agencyName || '');

  const handleOfficerChange = (value: string) => {
    setLocalOfficerName(value);
    onChange(value || undefined, localAgencyName || undefined);
  };

  const handleAgencyChange = (value: string) => {
    setLocalAgencyName(value);
    onChange(localOfficerName || undefined, value || undefined);
  };

  return (
    <div className="panel-content">
      <div className="panel-header">
        <h2>👤 User Profile</h2>
        <p style={{ color: '#a0a0a0', marginTop: '0.5rem', fontSize: '0.9rem' }}>
          This information will be included in all generated PDF reports
        </p>
      </div>

      <div style={{ maxWidth: '600px', marginTop: '2rem' }}>
        <div className="profile-field">
          <label htmlFor="officer-name" style={{ 
            display: 'block', 
            marginBottom: '0.5rem',
            color: '#e0e0e0',
            fontWeight: '600'
          }}>
            Officer Name
          </label>
          <input
            id="officer-name"
            type="text"
            value={localOfficerName}
            onChange={(e) => handleOfficerChange(e.target.value)}
            placeholder="e.g., Detective John Smith"
            style={{
              width: '100%',
              padding: '0.75rem',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              color: '#e0e0e0',
              fontSize: '1rem',
            }}
          />
          <p style={{ 
            color: '#a0a0a0', 
            fontSize: '0.85rem', 
            marginTop: '0.5rem' 
          }}>
            Your name as it should appear on official reports
          </p>
        </div>

        <div className="profile-field" style={{ marginTop: '1.5rem' }}>
          <label htmlFor="agency-name" style={{ 
            display: 'block', 
            marginBottom: '0.5rem',
            color: '#e0e0e0',
            fontWeight: '600'
          }}>
            Agency Name
          </label>
          <input
            id="agency-name"
            type="text"
            value={localAgencyName}
            onChange={(e) => handleAgencyChange(e.target.value)}
            placeholder="e.g., Metro Police Department"
            style={{
              width: '100%',
              padding: '0.75rem',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              color: '#e0e0e0',
              fontSize: '1rem',
            }}
          />
          <p style={{ 
            color: '#a0a0a0', 
            fontSize: '0.85rem', 
            marginTop: '0.5rem' 
          }}>
            Your law enforcement agency or organization name
          </p>
        </div>

        <div style={{
          marginTop: '2rem',
          padding: '1rem',
          background: 'rgba(79, 195, 247, 0.1)',
          border: '1px solid rgba(79, 195, 247, 0.3)',
          borderRadius: '6px',
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
            <span style={{ fontSize: '1.25rem' }}>ℹ️</span>
            <div>
              <strong style={{ color: '#4fc3f7' }}>Report Integration</strong>
              <p style={{ color: '#c0c0c0', marginTop: '0.5rem', fontSize: '0.9rem', lineHeight: '1.5' }}>
                This information will automatically appear in the header of all PDF reports you generate.
                You can update these values at any time, but changes will only affect newly generated reports.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Keyword Lists Panel
const KeywordListsPanel: React.FC<{
  lists: KeywordList[];
  onChange: (lists: KeywordList[]) => void;
  onAutoSave?: (lists: KeywordList[]) => void;
}> = ({ lists = [], onChange, onAutoSave }) => {
  const [selectedList, setSelectedList] = useState<KeywordList | null>(null);
  const [isImporting, setIsImporting] = useState(false);
  const [loadedLists, setLoadedLists] = useState<Array<{ name: string; keywords: string[]; enabled: boolean }>>([]);

  // Load keyword lists from backend on mount
  React.useEffect(() => {
    loadKeywordLists();
  }, []);

  const loadKeywordLists = async () => {
    try {
      const lists = await invoke<Array<{ name: string; keywords: string[]; enabled: boolean }>>('load_keyword_lists');
      setLoadedLists(lists);
      console.log('Loaded keyword lists:', lists);
    } catch (error) {
      console.error('Failed to load keyword lists:', error);
    }
  };

  const handleImportList = async () => {
    setIsImporting(true);
    try {
      // Use Tauri's file dialog
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        multiple: false,
        filters: [{
          name: 'Text Files',
          extensions: ['txt']
        }]
      });

      if (selected) {
        const filePath = typeof selected === 'string' ? selected : selected.path;
        const fileName = filePath.split(/[/\\]/).pop() || 'keyword_list.txt';
        
        const result = await invoke<string>('import_keyword_list', {
          filePath,
          fileName
        });

        alert(result);
        await loadKeywordLists(); // Reload lists
      }
    } catch (error) {
      console.error('Failed to import keyword list:', error);
      alert(`Failed to import keyword list: ${error}`);
    } finally {
      setIsImporting(false);
    }
  };

  const handleDeleteList = async (listName: string) => {
    if (!confirm(`Are you sure you want to delete the keyword list "${listName}"?`)) {
      return;
    }

    try {
      const result = await invoke<string>('delete_keyword_list', {
        listName
      });
      
      alert(result);
      setSelectedList(null);
      await loadKeywordLists(); // Reload lists
    } catch (error) {
      console.error('Failed to delete keyword list:', error);
      alert(`Failed to delete keyword list: ${error}`);
    }
  };

  return (
    <div className="panel-content">
      <div className="panel-header">
        <h2>Keyword Search Lists</h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button 
            variant="primary" 
            size="sm" 
            onClick={handleImportList}
            disabled={isImporting}
          >
            {isImporting ? '⏳ Importing...' : '📁 Import .txt File'}
          </Button>
        </div>
      </div>

      <div className="info-banner" style={{ marginBottom: '1rem', padding: '1rem', background: 'rgba(255,200,100,0.1)', borderRadius: '8px' }}>
        <p style={{ margin: 0, fontSize: '0.9rem', color: '#ffc864' }}>
          💡 <strong>Import keyword lists as .txt files.</strong> Each line in the file should contain one keyword. 
          Lines starting with # are treated as comments. Once imported, lists will be available for selection during scan setup.
        </p>
      </div>

      <div className="list-grid">
        <div className="list-sidebar">
          <div className="list-items">
            {loadedLists.length === 0 && (
              <div className="empty-state-small">
                <p>No keyword lists found</p>
                <p className="hint">Import a .txt file to get started</p>
              </div>
            )}
            {loadedLists.map(list => (
              <div
                key={list.name}
                className={`list-item ${selectedList?.name === list.name ? 'selected' : ''}`}
                onClick={() => setSelectedList(list)}
              >
                <div className="list-item-header">
                  <span className="list-name">{list.name}</span>
                  <span className="list-count">{list.keywords.length}</span>
                </div>
                <div className="list-item-meta">{list.keywords.length} keywords loaded</div>
              </div>
            ))}
          </div>
        </div>

        <div className="list-details">
          {selectedList ? (
            <>
              <div className="details-header-panel">
                <div>
                  <h3>{selectedList.name}</h3>
                  <p className="details-meta">{selectedList.keywords.length} keywords</p>
                </div>
                <div className="details-actions">
                  <Button variant="danger" size="sm" onClick={() => handleDeleteList(selectedList.name)}>
                    🗑️ Delete
                  </Button>
                </div>
              </div>

              <div className="details-body">
                <div className="detail-section">
                  <label>File Name</label>
                  <p>{selectedList.name}.txt</p>
                </div>

                <div className="detail-section">
                  <label>Keywords ({selectedList.keywords.length})</label>
                  <div className="keyword-tags" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                    {selectedList.keywords.map((keyword, index) => (
                      <span key={index} className="keyword-tag">{keyword}</span>
                    ))}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">🔍</div>
              <p>Select a keyword list to view details</p>
              <p className="hint">Import keyword lists from the button above</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Keyword List Editor
const KeywordListEditor: React.FC<{
  list: KeywordList;
  onSave: (list: KeywordList) => void;
  onCancel: () => void;
}> = ({ list, onSave, onCancel }) => {
  const [editedList, setEditedList] = useState<KeywordList>(list);
  const [newKeyword, setNewKeyword] = useState('');

  const addKeyword = () => {
    if (newKeyword.trim()) {
      setEditedList({
        ...editedList,
        keywords: [...editedList.keywords, newKeyword.trim()]
      });
      setNewKeyword('');
    }
  };

  const removeKeyword = (index: number) => {
    setEditedList({
      ...editedList,
      keywords: editedList.keywords.filter((_, i) => i !== index)
    });
  };

  const importKeywords = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt,.csv';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
          const text = event.target?.result as string;
          const keywords = text.split(/[\r\n,]+/).map(k => k.trim()).filter(k => k);
          setEditedList({
            ...editedList,
            keywords: [...new Set([...editedList.keywords, ...keywords])]
          });
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };

  return (
    <div className="editor-panel">
      <div className="editor-header">
        <h2>✏️ Edit Keyword List</h2>
      </div>

      <div className="editor-body">
        <div className="form-group">
          <label>List Name *</label>
          <input
            type="text"
            value={editedList.name}
            onChange={(e) => setEditedList({ ...editedList, name: e.target.value })}
            placeholder="e.g., CSAM Terms, Drug-Related Keywords"
          />
        </div>

        <div className="form-group">
          <label>Description</label>
          <textarea
            value={editedList.description}
            onChange={(e) => setEditedList({ ...editedList, description: e.target.value })}
            placeholder="Brief description of this keyword list and its purpose"
            rows={3}
          />
        </div>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={editedList.caseSensitive}
              onChange={(e) => setEditedList({ ...editedList, caseSensitive: e.target.checked })}
            />
            <span>Case Sensitive Search</span>
          </label>
        </div>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={editedList.useRegex}
              onChange={(e) => setEditedList({ ...editedList, useRegex: e.target.checked })}
            />
            <span>Use Regular Expressions</span>
          </label>
        </div>

        <div className="form-group">
          <label>Keywords</label>
          <div className="keyword-input-group">
            <input
              type="text"
              value={newKeyword}
              onChange={(e) => setNewKeyword(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && addKeyword()}
              placeholder="Type keyword and press Enter"
            />
            <Button variant="secondary" size="sm" onClick={addKeyword}>Add</Button>
            <Button variant="secondary" size="sm" onClick={importKeywords}>📂 Import</Button>
          </div>

          <div className="keyword-tags-editor">
            {editedList.keywords.map((keyword, index) => (
              <span key={index} className="keyword-tag">
                {keyword}
                <button onClick={() => removeKeyword(index)}>×</button>
              </span>
            ))}
          </div>
          <p className="hint">{editedList.keywords.length} keywords in list</p>
        </div>
      </div>

      <div className="editor-footer">
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
        <Button variant="primary" onClick={() => onSave(editedList)} disabled={!editedList.name.trim()}>
          💾 Save List
        </Button>
      </div>
    </div>
  );
};

// Hash Lists Panel - Full Implementation
const HashListsPanel: React.FC<{
  lists: HashList[];
  onChange: (lists: HashList[]) => void;
  onAutoSave?: (lists: HashList[]) => void;
}> = ({ lists = [], onChange, onAutoSave }) => {
  const [localLists, setLocalLists] = useState<HashList[]>(lists);
  const [selectedList, setSelectedList] = useState<HashList | null>(null);
  const [isImporting, setIsImporting] = useState(false);
  const [importProgress, setImportProgress] = useState<{
    current: number;
    total: number;
    percentage: number;
    message: string;
    stage?: string;
  } | null>(null);
  const [dbStats, setDbStats] = useState<any>(null);
  const [isLoadingStats, setIsLoadingStats] = useState(false);

  // Update local state when props change
  React.useEffect(() => {
    console.log('HashListsPanel: lists prop changed', lists);
    setLocalLists(lists);
  }, [lists]);

  // Load database statistics and sync DB lists on mount
  React.useEffect(() => {
    loadDatabaseStats();
    syncDbLists();
  }, []);

  const syncDbLists = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const dbLists = await invoke<Array<{id: number, name: string, source: string, hash_count: number, imported_at: string}>>('get_db_hash_lists');
      
      // Find DB lists not in settings.json (e.g. VIC import that wasn't saved)
      setLocalLists(prev => {
        const existingNames = new Set(prev.map(l => l.name));
        const newLists: HashList[] = [];
        
        for (const dbList of dbLists) {
          if (!existingNames.has(dbList.name)) {
            // Create a HashList entry for this DB-only list
            newLists.push({
              id: `db-${dbList.id}`,
              name: dbList.name,
              description: `${dbList.source} — ${dbList.hash_count.toLocaleString()} hashes`,
              hashType: 'MD5' as any,
              hashes: [],
              hashCount: dbList.hash_count,
              enabled: true,
              source: dbList.source,
              createdAt: dbList.imported_at,
              modifiedAt: dbList.imported_at,
            });
          }
        }
        
        if (newLists.length > 0) {
          const merged = [...prev, ...newLists];
          onChange(merged); // Notify parent so it can save
          return merged;
        }
        return prev;
      });
    } catch (error) {
      console.error('Failed to sync DB hash lists:', error);
    }
  };

  const loadDatabaseStats = async () => {
    setIsLoadingStats(true);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const stats = await invoke('get_hash_database_stats');
      setDbStats(stats);
    } catch (error) {
      console.error('Failed to load hash database stats:', error);
    } finally {
      setIsLoadingStats(false);
    }
  };

  const importHashList = async () => {
    try {
      setIsImporting(true);
      setImportProgress(null);
      const { open } = await import('@tauri-apps/plugin-dialog');
      const { invoke } = await import('@tauri-apps/api/core');
      const { listen } = await import('@tauri-apps/api/event');
      
      const selected = await open({
        title: 'Select Hash List JSON File',
        filters: [{
          name: 'JSON Files',
          extensions: ['json']
        }],
        multiple: false,
        directory: false
      });

      if (selected && typeof selected === 'string') {
        // Listen for progress updates
        const unlisten = await listen('hash-import-progress', (event: any) => {
          const data = event.payload;
          console.log('Import progress:', data);
          
          // Backend sends: { stage, message, total?, progress? }
          const current = data.progress || 0;
          const total = data.total || current;  // streaming: total unknown, use current
          const pct = total > 0 ? Math.min((current / total) * 100, 100) : (data.stage === 'importing' ? 50 : 0);
          
          setImportProgress({
            current,
            total,
            percentage: data.stage === 'complete' ? 100 : pct,
            message: data.message || 'Processing...',
            stage: data.stage || 'importing'
          });
        });
        
        try {
          // Import and load in one async call with progress
          const hashList = await invoke<HashList>('import_and_load_hash_list', { 
            jsonPath: selected 
          });
          
          // Add to both local and parent state
          const updatedLists = [...localLists, hashList];
          setLocalLists(updatedLists);
          onChange(updatedLists);
          setSelectedList(hashList);
          
          // Refresh stats
          await loadDatabaseStats();
          
          alert(`✓ Imported "${hashList.name}"\n\nHashes: ${hashList.hashCount || hashList.hashes.length}\nTotal lists: ${updatedLists.length}\n\nLook for it in the left sidebar!`);
        } finally {
          unlisten();
        }
      }
    } catch (error) {
      console.error('Failed to import hash list:', error);
      alert(`Failed to import hash list: ${error}`);
    } finally {
      setIsImporting(false);
      setImportProgress(null);
    }
  };

  const importTxtHashList = async () => {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{
          name: 'Text Files',
          extensions: ['txt']
        }]
      });
      
      if (selected) {
        // Prompt for list name
        const listName = prompt('Enter a name for this hash list:', 'Custom Hash List');
        if (!listName) return;
        
        // Prompt for hash type
        const hashType = prompt('Enter hash type (MD5, SHA1, or SHA256):', 'SHA256')?.toUpperCase();
        if (!hashType || !['MD5', 'SHA1', 'SHA256'].includes(hashType)) {
          alert('Invalid hash type. Please enter MD5, SHA1, or SHA256.');
          return;
        }
        
        setIsImporting(true);
        setImportProgress({ stage: 'parsing', current: 0, total: 0, percentage: 0, message: 'Reading file...' });
        
        const { listen } = await import('@tauri-apps/api/event');
        const unlisten = await listen<any>('hash-import-progress', (event) => {
          const data = event.payload;
          const current = data.progress || 0;
          const total = data.total || current;
          setImportProgress({
            stage: data.stage || 'importing',
            current,
            total,
            percentage: total > 0 ? Math.min((current / total) * 100, 100) : 0,
            message: data.message || 'Processing...'
          });
        });
        
        try {
          const hashList = await invoke<HashList>('import_txt_hash_list', { 
            txtPath: selected,
            listName: listName,
            hashType: hashType
          });
          
          const updatedLists = [...localLists, hashList];
          setLocalLists(updatedLists);
          onChange(updatedLists);
          setSelectedList(hashList);
          
          await loadDatabaseStats();
          
          alert(`✓ Imported "${hashList.name}"\n\nHashes: ${hashList.hashes.length}\nType: ${hashType}\n\nLook for it in the left sidebar!`);
        } finally {
          unlisten();
        }
      }
    } catch (error) {
      console.error('Failed to import text hash list:', error);
      alert(`Failed to import hash list: ${error}`);
    } finally {
      setIsImporting(false);
      setImportProgress(null);
    }
  };

  const deleteList = async (id: string) => {
    const listToDelete = localLists.find(l => l.id === id);
    if (!listToDelete) return;
    
    if (confirm(`Are you sure you want to delete "${listToDelete.name}"?\n\nThis will remove it from settings AND delete all its hashes from the database.`)) {
      try {
        // Delete from backend hash database
        const { invoke } = await import('@tauri-apps/api/core');
        await invoke('delete_hash_list', { listName: listToDelete.name });
      } catch (error) {
        console.error('Failed to delete from hash database:', error);
        // Continue removing from settings even if DB delete fails
      }
      
      const updatedLists = localLists.filter(l => l.id !== id);
      setLocalLists(updatedLists);
      onChange(updatedLists);
      if (selectedList?.id === id) {
        setSelectedList(null);
      }
      
      // Refresh database stats
      await loadDatabaseStats();
    }
  };

  const toggleEnabled = (id: string) => {
    const updatedLists = localLists.map(l => l.id === id ? { ...l, enabled: !l.enabled } : l);
    setLocalLists(updatedLists);
    onChange(updatedLists);
  };

  const clearDatabase = async () => {
    if (confirm('⚠️ WARNING: This will clear ALL hash lists from the database.\n\nYou will need to re-import them. This cannot be undone.\n\nAre you sure?')) {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        await invoke('clear_hash_database');
        await loadDatabaseStats();
        alert('✓ Hash database cleared successfully');
      } catch (error) {
        alert(`Failed to clear database: ${error}`);
      }
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="panel-content">
      <div className="panel-header">
        <h2>Hash Lists (CSAM Detection)</h2>
        <div className="button-group">
          <Button variant="secondary" size="sm" onClick={importHashList} disabled={isImporting}>
            {isImporting ? '⏳ Importing...' : '📥 Import JSON Hash List'}
          </Button>
          <Button variant="secondary" size="sm" onClick={importTxtHashList} disabled={isImporting}>
            {isImporting ? '⏳ Importing...' : '📄 Import TXT Hash List'}
          </Button>
        </div>
      </div>

      <div className="info-banner">
        <strong>🔐 Hash Database:</strong> Import hash databases like Project VIC or NCMEC to automatically detect known CSAM content.
        Supports JSON format (Project VIC) or plain text files (one hash per line). Supports MD5, SHA1, and SHA256 hashes.
      </div>

      {/* Import Progress Indicator */}
      {isImporting && importProgress && (
        <div className="import-progress-overlay">
          <div className="import-progress-modal">
            <h3>📥 Importing Hash List</h3>
            <div className="progress-info">
              <p className="progress-message">{importProgress.message}</p>
              <p className="progress-stats">
                {importProgress.current.toLocaleString()} hashes imported
              </p>
            </div>
            <div className="progress-bar-container">
              <div 
                className="progress-bar-fill" 
                style={{ width: `${Math.max(importProgress.percentage, importProgress.current > 0 ? 5 : 0)}%` }}
              >
              </div>
            </div>
            {importProgress.stage === 'importing' && (
              <p className="progress-note">
                ⏱️ Large files (Project VIC) may take a few minutes. Please wait...
              </p>
            )}
            {importProgress.stage === 'loading' && (
              <p className="progress-note">
                🧠 Loading hashes into memory for fast scanning...
              </p>
            )}
          </div>
        </div>
      )}

      {/* Simple loading indicator when import starts but progress not yet available */}
      {isImporting && !importProgress && (
        <div className="import-progress-overlay">
          <div className="import-progress-modal">
            <h3>📥 Starting Import...</h3>
            <div className="loading-spinner"></div>
            <p className="progress-note">Reading hash file...</p>
          </div>
        </div>
      )}

      {/* Database Statistics */}
      {dbStats && (
        <div className="hash-stats-panel">
          <h3>📊 Database Statistics</h3>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{(dbStats.total_hashes || 0).toLocaleString()}</div>
              <div className="stat-label">Total Hashes</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{dbStats.total_lists || 0}</div>
              <div className="stat-label">Hash Lists</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{formatBytes(dbStats.database_size_bytes || 0)}</div>
              <div className="stat-label">Database Size</div>
            </div>
            <div className="stat-card-action">
              <Button variant="danger" size="sm" onClick={clearDatabase}>
                🗑️ Clear Database
              </Button>
            </div>
          </div>
        </div>
      )}

      <div className="list-grid">
        <div className="list-sidebar">
          <div className="list-items">
            {localLists.length === 0 && (
              <div className="empty-state-small">
                <p>No hash lists configured</p>
                <p className="hint">Click "Import Hash List" to add Project VIC or NCMEC hashes</p>
              </div>
            )}
            {localLists.map(list => (
              <div
                key={list.id}
                className={`list-item ${selectedList?.id === list.id ? 'selected' : ''} ${!list.enabled ? 'disabled' : ''}`}
                onClick={() => setSelectedList(list)}
              >
                <div className="list-item-header">
                  <input
                    type="checkbox"
                    checked={list.enabled}
                    onChange={(e) => {
                      e.stopPropagation();
                      toggleEnabled(list.id);
                    }}
                    className="list-checkbox"
                  />
                  <span className="list-name">{list.name}</span>
                  <span className="list-count">{(list.hashCount || list.hashes.length).toLocaleString()}</span>
                </div>
                <div className="list-item-meta">
                  <span className="badge">{list.hashType}</span>
                  <span className="badge">{list.source}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="list-details">
          {selectedList ? (
            <>
              <div className="details-header-panel">
                <div>
                  <h3>{selectedList.name}</h3>
                  <p className="details-meta">{(selectedList.hashCount || selectedList.hashes.length).toLocaleString()} hashes • {selectedList.hashType}</p>
                </div>
                <div className="details-actions">
                  <Button variant="danger" size="sm" onClick={() => deleteList(selectedList.id)}>
                    🗑️ Remove
                  </Button>
                </div>
              </div>
              <div className="details-body">
                <div className="detail-section">
                  <label>Source</label>
                  <p>{selectedList.source}</p>
                </div>
                <div className="detail-section">
                  <label>Description</label>
                  <p>{selectedList.description || 'No description provided'}</p>
                </div>
                <div className="detail-section">
                  <label>Hash Type</label>
                  <p>{selectedList.hashType}</p>
                </div>
                <div className="detail-section">
                  <label>Status</label>
                  <p className={selectedList.enabled ? 'status-enabled' : 'status-disabled'}>
                    {selectedList.enabled ? '✓ Enabled - Will be used during scans' : '✗ Disabled - Will not be used'}
                  </p>
                </div>
                <div className="detail-section">
                  <label>Imported</label>
                  <p>{new Date(selectedList.createdAt).toLocaleString()}</p>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">🔐</div>
              <p>Select a hash list to view details</p>
              <p className="hint">Or import a new hash list to get started</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Custom Apps Panel
const CustomAppsPanel: React.FC<{
  apps: CustomAppDefinition[];
  onChange: (apps: CustomAppDefinition[]) => void;
}> = ({ apps = [], onChange }) => {
  const [localApps, setLocalApps] = useState<CustomAppDefinition[]>(apps);
  const [editingApp, setEditingApp] = useState<CustomAppDefinition | null>(null);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [selectedApp, setSelectedApp] = useState<CustomAppDefinition | null>(null);

  // Update local state when props change
  React.useEffect(() => {
    console.log('CustomAppsPanel: apps prop changed', apps);
    setLocalApps(apps);
  }, [apps]);

  const createNewApp = () => {
    const newApp: CustomAppDefinition = {
      id: Date.now().toString(),
      name: '',
      category: 'privacy',
      patterns: [],
      description: '',
      enabled: true,
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
    };
    setEditingApp(newApp);
    setShowAddDialog(true);
  };

  const saveApp = () => {
    console.log('saveApp called', editingApp);
    
    if (!editingApp || !editingApp.name.trim()) {
      alert('❌ Error: Please enter an app name');
      return;
    }
    if (editingApp.patterns.length === 0) {
      alert('❌ Error: Please add at least one file pattern');
      return;
    }

    const existingIndex = localApps.findIndex(a => a.id === editingApp.id);
    let updatedApps;
    
    if (existingIndex >= 0) {
      // Update existing
      updatedApps = [...localApps];
      updatedApps[existingIndex] = { ...editingApp, modifiedAt: new Date().toISOString() };
      console.log('Updated existing app', updatedApps);
      alert(`✓ Updated "${editingApp.name}"\nTotal apps: ${updatedApps.length}`);
    } else {
      // Add new
      updatedApps = [...localApps, editingApp];
      console.log('Added new app', updatedApps);
      alert(`✓ Added "${editingApp.name}"\nTotal apps: ${updatedApps.length}\n\nLook for it in the left sidebar!`);
    }
    
    // Update both local and parent state
    setLocalApps(updatedApps);
    onChange(updatedApps);
    console.log('State updated, closing modal');
    
    // Select the newly added app
    setSelectedApp(editingApp);
    setEditingApp(null);
    setShowAddDialog(false);
  };

  const deleteApp = (id: string) => {
    const appToDelete = localApps.find(a => a.id === id);
    if (!appToDelete) return;
    
    if (confirm(`Are you sure you want to delete "${appToDelete.name}"?`)) {
      const updatedApps = localApps.filter(a => a.id !== id);
      setLocalApps(updatedApps);
      onChange(updatedApps);
      setSelectedApp(null);
    }
  };

  return (
    <div className="panel-content">
      <div className="panel-header">
        <h2>Custom Application Definitions</h2>
        <Button variant="primary" size="sm" onClick={createNewApp}>+ Add Custom App</Button>
      </div>

      <div className="info-banner" style={{ marginBottom: '1rem', padding: '1rem', background: 'rgba(255,200,100,0.1)', borderRadius: '8px' }}>
        <p style={{ margin: 0, fontSize: '0.9rem', color: '#ffc864' }}>
          💡 <strong>Define custom applications</strong> to extend the detection database. 
          Add agency-specific or investigation-specific tools that aren't in the default database.
        </p>
      </div>

      <div className="list-grid">
        <div className="list-sidebar">
          <div className="list-items">
            {localApps.length === 0 && (
              <div className="empty-state-small">
                <p>No custom apps defined</p>
                <p className="hint">Click "Add Custom App" to create one</p>
              </div>
            )}
            {localApps.map(app => (
              <div
                key={app.id}
                className={`list-item ${selectedApp?.id === app.id ? 'selected' : ''}`}
                onClick={() => setSelectedApp(app)}
              >
                <div className="list-item-header">
                  <span className="list-name">{app.name}</span>
                  <span className="list-count">{app.patterns.length}</span>
                </div>
                <div className="list-item-meta">{app.category.replace('_', ' ')}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="list-details">
          {selectedApp ? (
            <>
              <div className="details-header-panel">
                <div>
                  <h3>{selectedApp.name}</h3>
                  <p className="details-meta">{selectedApp.patterns.length} pattern(s)</p>
                </div>
                <div className="details-actions">
                  <Button 
                    variant="secondary" 
                    size="sm" 
                    onClick={() => { setEditingApp(selectedApp); setShowAddDialog(true); }}
                  >
                    ✏️ Edit
                  </Button>
                  <Button 
                    variant="danger" 
                    size="sm" 
                    onClick={() => deleteApp(selectedApp.id)}
                  >
                    🗑️ Delete
                  </Button>
                </div>
              </div>

              <div className="details-body">
                <div className="detail-section">
                  <label>Category</label>
                  <p style={{
                    background: 'var(--color-accent)',
                    display: 'inline-block',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '4px',
                    color: '#000',
                    fontWeight: 'bold'
                  }}>
                    {selectedApp.category.replace('_', ' ').toUpperCase()}
                  </p>
                </div>

                <div className="detail-section">
                  <label>Description</label>
                  <p>{selectedApp.description || 'No description provided'}</p>
                </div>

                <div className="detail-section">
                  <label>File Patterns ({selectedApp.patterns.length})</label>
                  <div className="keyword-tags" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                    {selectedApp.patterns.map((pattern, index) => (
                      <span key={index} className="keyword-tag">{pattern}</span>
                    ))}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">📱</div>
              <p>Select a custom app to view details</p>
              <p className="hint">Add custom applications from the button above</p>
            </div>
          )}
        </div>
      </div>

      {showAddDialog && editingApp && (
        <div className="modal-overlay" onClick={() => setShowAddDialog(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0 }}>{editingApp.id && localApps.some(a => a.id === editingApp.id) ? 'Edit' : 'Add'} Custom App</h3>
              <button onClick={() => setShowAddDialog(false)} style={{ background: 'none', border: 'none', fontSize: '1.5rem', cursor: 'pointer', color: 'var(--color-text)' }}>×</button>
            </div>
            
            <div className="form-group">
              <label>App Name *</label>
              <input
                type="text"
                value={editingApp.name}
                onChange={(e) => setEditingApp({ ...editingApp, name: e.target.value })}
                placeholder="e.g., Tor Browser, Signal Desktop"
              />
            </div>

            <div className="form-group">
              <label>Category *</label>
              <select
                value={editingApp.category}
                onChange={(e) => setEditingApp({ ...editingApp, category: e.target.value })}
              >
                <option value="privacy">Privacy/Encryption</option>
                <option value="communication">Communication</option>
                <option value="file_sharing">File Sharing</option>
                <option value="remote_access">Remote Access</option>
                <option value="antiforensics">Anti-Forensics</option>
                <option value="other">Other</option>
              </select>
            </div>

            <div className="form-group">
              <label>Description</label>
              <textarea
                value={editingApp.description}
                onChange={(e) => setEditingApp({ ...editingApp, description: e.target.value })}
                placeholder="Brief description of the application"
                rows={2}
              />
            </div>

            <div className="form-group">
              <label>File Patterns * (one per line)</label>
              <textarea
                value={editingApp.patterns.join('\n')}
                onChange={(e) => setEditingApp({ 
                  ...editingApp, 
                  patterns: e.target.value.split('\n').filter(p => p.trim()) 
                })}
                placeholder="e.g., tor.exe, signal.exe, *.onion"
                rows={4}
              />
              <small>Use wildcards: *.exe, tor*, *vpn*</small>
            </div>

            <div className="modal-actions" style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end', marginTop: '2rem' }}>
              <Button variant="secondary" size="md" onClick={() => {
                console.log('Cancel clicked');
                setShowAddDialog(false);
              }}>
                Cancel
              </Button>
              <Button variant="primary" size="md" onClick={(e) => {
                console.log('Save App button clicked');
                e.preventDefault();
                e.stopPropagation();
                saveApp();
              }}>
                Save App
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Scan Options Panel
const ScanOptionsPanel: React.FC<{
  options: ScanOptions;
  onChange: (options: ScanOptions) => void;
}> = ({ options, onChange }) => {
  return (
    <div className="panel-content">
      <div className="panel-header">
        <h2>Scan Options</h2>
      </div>

      <div className="options-grid">
        <div className="option-card">
          <h3>📱 Questionable Applications</h3>
          <p>Scan for VPNs, encryption tools, file shredders, and other forensically relevant applications</p>
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={options?.enableQuestionableApps || false}
              onChange={(e) => onChange({ ...options, enableQuestionableApps: e.target.checked })}
            />
            <span>Enable Application Scanner</span>
          </label>
        </div>

        <div className="option-card">
          <h3>🌐 Browser History</h3>
          <p>Extract browsing history, downloads, and cache from all major browsers</p>
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={options?.enableBrowserHistory || false}
              onChange={(e) => onChange({ ...options, enableBrowserHistory: e.target.checked })}
            />
            <span>Enable Browser Scanner</span>
          </label>
        </div>

        <div className="option-card">
          <h3>🔍 Keyword Search</h3>
          <p>Search files and free space for configured keyword lists</p>
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={options?.enableKeywordSearch || false}
              onChange={(e) => onChange({ ...options, enableKeywordSearch: e.target.checked })}
            />
            <span>Enable Keyword Search</span>
          </label>
          <div style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: 'var(--color-accent-amber)' }}>
            ⚠️ Requires keyword lists to be configured in Keyword Lists tab
          </div>
        </div>

        <div className="option-card">
          <h3>🖼️ Media Scan</h3>
          <p>Locate and catalog images and videos with metadata extraction</p>
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={options?.enableMediaScan || false}
              onChange={(e) => onChange({ ...options, enableMediaScan: e.target.checked })}
            />
            <span>Enable Media Scanner</span>
          </label>
        </div>

        <div className="option-card">
          <h3>🔐 Hash Matching</h3>
          <p>Compare media files against imported hash databases (Project VIC, NCMEC) to detect known CSAM content</p>
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={options?.enableHashMatching || false}
              onChange={(e) => onChange({ ...options, enableHashMatching: e.target.checked })}
            />
            <span>Enable Hash Matching</span>
          </label>
          <div style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: 'var(--color-accent-amber)' }}>
            ⚠️ Requires hash lists to be imported in Hash Lists tab
          </div>
        </div>
      </div>
    </div>
  );
};

// Encrypted Reports Panel
const EncryptedReportsPanel: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<any | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  // Load reports on mount
  React.useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    setLoading(true);
    try {
      const reportsList = await invoke<any[]>('list_saved_reports');
      setReports(reportsList);
    } catch (err) {
      console.error('Failed to load reports:', err);
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const openReport = async (reportId: number) => {
    if (!password) {
      setError('Please enter your password');
      return;
    }

    try {
      console.log('Opening report:', reportId);
      
      // Call backend command to decrypt and save PDF, then open it
      await invoke('open_encrypted_report', {
        reportId,
        password
      });
      
      setPassword('');
      setSelectedReport(null);
      setError('');
    } catch (err) {
      console.error('Error opening report:', err);
      setError(String(err));
    }
  };

  const deleteReport = async (reportId: number) => {
    if (!confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
      return;
    }

    try {
      await invoke('delete_saved_report', { reportId });
      await loadReports();
      setSelectedReport(null);
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div className="encrypted-reports-panel">
      <div className="panel-header">
        <h2>📄 Encrypted Reports</h2>
        <p>Your generated reports are encrypted and stored securely. Enter your password to view them.</p>
      </div>

      {loading && (
        <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--color-gray)' }}>
          Loading reports...
        </div>
      )}

      {!loading && reports.length === 0 && (
        <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--color-gray)' }}>
          No encrypted reports found. Generate a report from the dashboard to save it here.
        </div>
      )}

      {!loading && reports.length > 0 && (
        <div className="reports-list">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--color-gray-700)' }}>
                <th style={{ padding: '1rem', textAlign: 'left' }}>Report Name</th>
                <th style={{ padding: '1rem', textAlign: 'left' }}>Created</th>
                <th style={{ padding: '1rem', textAlign: 'center' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id} style={{ borderBottom: '1px solid var(--color-gray-800)' }}>
                  <td style={{ padding: '1rem' }}>{report.report_name}</td>
                  <td style={{ padding: '1rem', color: 'var(--color-gray)' }}>
                    {new Date(report.created_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '1rem', textAlign: 'center' }}>
                    <button
                      onClick={() => setSelectedReport(report)}
                      style={{
                        padding: '0.5rem 1rem',
                        marginRight: '0.5rem',
                        background: 'var(--color-accent-purple)',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'white',
                        cursor: 'pointer'
                      }}
                    >
                      📖 Open
                    </button>
                    <button
                      onClick={() => deleteReport(report.id)}
                      style={{
                        padding: '0.5rem 1rem',
                        background: 'var(--color-accent-red)',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'white',
                        cursor: 'pointer'
                      }}
                    >
                      🗑️ Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedReport && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}
          onClick={() => setSelectedReport(null)}
        >
          <div
            style={{
              background: 'var(--color-gray-900)',
              padding: '2rem',
              borderRadius: '8px',
              maxWidth: '500px',
              width: '90%'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ marginBottom: '1rem' }}>Enter Password</h3>
            <p style={{ color: 'var(--color-gray)', marginBottom: '1rem' }}>
              Enter your password to decrypt and view: {selectedReport.report_name}
            </p>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              style={{
                width: '100%',
                padding: '0.75rem',
                marginBottom: '1rem',
                background: 'var(--color-gray-800)',
                border: '1px solid var(--color-gray-700)',
                borderRadius: '4px',
                color: 'white'
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  openReport(selectedReport.id);
                }
              }}
            />
            {error && (
              <div style={{ color: 'var(--color-accent-red)', marginBottom: '1rem' }}>
                {error}
              </div>
            )}
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => {
                  setSelectedReport(null);
                  setPassword('');
                  setError('');
                }}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'var(--color-gray-700)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'white',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => openReport(selectedReport.id)}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'var(--color-accent-purple)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'white',
                  cursor: 'pointer'
                }}
              >
                Open Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
