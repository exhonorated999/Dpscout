import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button } from './Button';
import { DriveInfo, formatBytes } from '../types/drive';
import { DeviceType } from './StartScreen';
// ItunesBackupScanner removed — iOS now uses MTP live scan instead of backup
import './ScanConfig.css';

export interface ScanModules {
  questionableApps: boolean;
  browserHistory: boolean;
  mediaScan: boolean;
  keywordSearch: boolean;
  hashMatching: boolean;
  intrusionDetection: boolean;
  smsMessages?: boolean; // Android and iOS only
}

export interface KeywordScanConfig {
  scanPaths: string[];
  scanFileNames: boolean;
  scanFilePaths: boolean;
  scanFileContents: boolean;
  selectedLists?: Array<{name: string, keywords: string[], enabled: boolean}>;
  selectedDrives?: string[];
  selectedBackup?: string;
  selectedDevice?: string;
  deviceType?: string;
}

export interface HashMatchingConfig {
  selectedHashLists?: Array<{id: string, name: string, enabled: boolean}>;
}

interface ScanConfigProps {
  onStartScan: (modules: ScanModules, keywordConfig?: KeywordScanConfig, hashConfig?: HashMatchingConfig) => void;
  onBack: () => void;
  deviceType?: DeviceType;
}

export const ScanConfig: React.FC<ScanConfigProps> = ({ onStartScan, onBack, deviceType = 'windows' }) => {
  // Define which modules are supported per device type
  const supportedModules = {
    windows: {
      questionableApps: true,
      browserHistory: true,
      mediaScan: true,
      keywordSearch: true,
      hashMatching: true,
      intrusionDetection: true,
    },
    usb: {
      questionableApps: false,
      browserHistory: false,
      mediaScan: true,
      keywordSearch: true,
      hashMatching: true,
      intrusionDetection: false,
    },
    android: {
      questionableApps: true,  // Apps supported
      browserHistory: false,   // Not accessible on non-rooted Android 10+
      mediaScan: true,         // Media supported
      keywordSearch: false,    // Not yet implemented
      hashMatching: true,      // Hash matching implemented
      intrusionDetection: false, // N/A for Android
      smsMessages: true,       // SMS extraction implemented
    },
    ios: {
      questionableApps: false,  // Not available via MTP live scan
      browserHistory: false,    // Not available via MTP live scan
      mediaScan: true,          // Media files via MTP (DCIM)
      keywordSearch: false,     // Not available via MTP live scan
      hashMatching: true,       // Hash matching on media files
      intrusionDetection: false,
    },
  };

  const isModuleSupported = (module: keyof ScanModules) => {
    return supportedModules[deviceType]?.[module] || false;
  };

  const [modules, setModules] = useState<ScanModules>({
    questionableApps: deviceType === 'windows' || deviceType === 'android',
    browserHistory: false,
    mediaScan: deviceType === 'ios',         // iOS MTP: media scan on by default
    keywordSearch: false,
    hashMatching: deviceType === 'ios',      // iOS MTP: hash matching on by default
    intrusionDetection: false,
    smsMessages: false,
  });

  const [keywordConfig, setKeywordConfig] = useState<KeywordScanConfig>({
    scanPaths: [],
    scanFileNames: true,
    scanFilePaths: true,
    scanFileContents: false,
  });

  const [availableKeywordLists, setAvailableKeywordLists] = useState<Array<{name: string, keywords: string[], enabled: boolean}>>([]);
  const [keywordListsLoaded, setKeywordListsLoaded] = useState(false);
  const [availableHashLists, setAvailableHashLists] = useState<Array<{id: string, name: string, enabled: boolean}>>([]);
  const [hashListsLoaded, setHashListsLoaded] = useState(false);
  const [availableDrives, setAvailableDrives] = useState<DriveInfo[]>([]);
  const [selectedDrives, setSelectedDrives] = useState<string[]>([]);
  const [iosBackups, setIosBackups] = useState<any[]>([]);
  const [selectedBackup, setSelectedBackup] = useState<string | null>(null);
  const [androidDevices, setAndroidDevices] = useState<string[]>([]);

  useEffect(() => {
    if (deviceType === 'windows' || deviceType === 'usb') {
      loadDrives();
    } else if (deviceType === 'ios') {
      detectIosBackups();
    } else if (deviceType === 'android') {
      detectAndroidDevices();
    }
  }, [deviceType]);

  const loadDrives = async () => {
    try {
      const drives = await invoke<DriveInfo[]>('get_available_drives');
      setAvailableDrives(drives);
      
      // For Windows mode: auto-select C: drive
      // For USB mode: don't auto-select any drives
      if (deviceType === 'windows') {
        setSelectedDrives(drives.filter(d => d.letter === 'C:').map(d => d.letter));
      } else {
        setSelectedDrives([]);
      }
    } catch (error) {
      console.error('Failed to load drives:', error);
    }
  };

  const detectIosBackups = async () => {
    try {
      // Step 1: Try live device detection via pymobiledevice3
      console.log('[iOS] Detecting live devices via pymobiledevice3...');
      const liveDevices = await invoke<any[]>('detect_live_ios_devices');
      console.log('[iOS] Live devices found:', liveDevices.length);
      
      if (liveDevices.length > 0) {
        setIosBackups(liveDevices);
        // Prefer first trusted device, otherwise first device
        const trusted = liveDevices.find((d: any) => d.isTrusted);
        setSelectedBackup((trusted || liveDevices[0]).udid);
        return;
      }
    } catch (error) {
      console.warn('[iOS] Live device detection failed:', error);
    }
    
    // Step 2: Fall back to existing iTunes backup detection
    try {
      console.log('[iOS] Checking for existing iTunes backups...');
      const backups = await invoke<any[]>('get_ios_backups');
      console.log('[iOS] Found existing backups:', backups.length);
      if (backups.length > 0) {
        setIosBackups(backups);
        setSelectedBackup(backups[0].udid);
        return;
      }
    } catch (backupError) {
      console.warn('[iOS] Backup detection failed:', backupError);
    }
    
    // Nothing found
    setIosBackups([]);
    setSelectedBackup(null);
  };

  const detectAndroidDevices = async () => {
    try {
      const devices = await invoke<any[]>('get_android_devices');
      console.log('Found Android devices:', devices);
      setAndroidDevices(devices);
    } catch (error) {
      console.error('Failed to detect Android devices:', error);
      setAndroidDevices([]);
    }
  };

  const toggleModule = (key: keyof ScanModules) => {
    setModules(prev => ({ ...prev, [key]: !prev[key] }));
    
    // Load keyword lists when keyword search is enabled
    if (key === 'keywordSearch' && !modules.keywordSearch && !keywordListsLoaded) {
      loadKeywordLists();
    }
    
    // Load hash lists when hash matching is enabled
    if (key === 'hashMatching' && !modules.hashMatching && !hashListsLoaded) {
      loadHashLists();
    }
  };

  const toggleDrive = (driveLetter: string) => {
    setSelectedDrives(prev => 
      prev.includes(driveLetter)
        ? prev.filter(d => d !== driveLetter)
        : [...prev, driveLetter]
    );
  };

  const loadKeywordLists = async () => {
    try {
      const lists = await invoke<Array<{name: string, keywords: string[], enabled: boolean}>>('load_keyword_lists');
      setAvailableKeywordLists(lists);
      setKeywordListsLoaded(true);
    } catch (error) {
      console.error('Failed to load keyword lists:', error);
      alert(`Failed to load keyword lists: ${error}`);
    }
  };

  const toggleKeywordList = (index: number) => {
    setAvailableKeywordLists(prev => 
      prev.map((list, i) => 
        i === index ? { ...list, enabled: !list.enabled } : list
      )
    );
  };

  // ── Drag-to-reorder helpers (priority of selected lists) ──────────────
  // Use refs for active-drag tracking so onDragOver handlers see fresh values
  // (React state updates lag behind drag events and cause not-allowed cursor).
  const draggedKeyRef = useRef<string | null>(null);
  const [dragOverKey, setDragOverKey] = useState<string | null>(null);

  const moveItem = <T,>(arr: T[], from: number, to: number): T[] => {
    if (from === to || from < 0 || to < 0 || from >= arr.length || to >= arr.length) return arr;
    const next = [...arr];
    const [picked] = next.splice(from, 1);
    next.splice(to, 0, picked);
    return next;
  };

  const reorderKeywordLists = (fromIdx: number, toIdx: number) => {
    setAvailableKeywordLists(prev => moveItem(prev, fromIdx, toIdx));
  };

  const reorderHashLists = (fromIdx: number, toIdx: number) => {
    setAvailableHashLists(prev => moveItem(prev, fromIdx, toIdx));
  };

  const loadHashLists = async () => {
    try {
      const settings = await invoke<any>('get_settings');
      const lists = settings.hashLists || [];
      
      // Also fetch lists from DB (covers VIC imports not saved to settings.json)
      let dbLists: Array<{id: number, name: string, source: string, hash_count: number}> = [];
      try {
        dbLists = await invoke<any>('get_db_hash_lists');
      } catch (_) {}
      
      const settingsNames = new Set(lists.map((l: any) => l.name));
      const merged = [
        ...lists.map((list: any) => ({
          id: list.id,
          name: list.name,
          enabled: list.enabled !== false,
        })),
        ...dbLists
          .filter(dl => !settingsNames.has(dl.name))
          .map(dl => ({
            id: `db-${dl.id}`,
            name: dl.name,
            enabled: true,
          }))
      ];
      
      setAvailableHashLists(merged);
      setHashListsLoaded(true);
    } catch (error) {
      console.error('Failed to load hash lists:', error);
      alert(`Failed to load hash lists: ${error}`);
    }
  };

  const toggleHashList = (index: number) => {
    setAvailableHashLists(prev => 
      prev.map((list, i) => 
        i === index ? { ...list, enabled: !list.enabled } : list
      )
    );
  };

  const selectAll = () => {
    setModules({
      questionableApps: true,
      browserHistory: true,
      mediaScan: true,
      keywordSearch: true,
      hashMatching: true,
    });
  };

  const selectNone = () => {
    setModules({
      questionableApps: false,
      browserHistory: false,
      mediaScan: false,
      keywordSearch: false,
      hashMatching: false,
    });
  };

  const hasSelection = Object.values(modules).some(v => v);
  const selectedCount = Object.values(modules).filter(v => v).length;

  return (
    <div className="scan-config">
      <div className="scan-config-header">
        <div className="header-content">
          <h1>🔍 CONFIGURE SCAN</h1>
          <p>Select which modules to include in the scan</p>
        </div>
        <Button variant="secondary" onClick={onBack}>
          ← Back
        </Button>
      </div>

      <div className="scan-config-content">
        <div className="config-info">
          <div className="selection-summary">
            <span className="summary-count">{selectedCount}</span>
            <span className="summary-text">module{selectedCount !== 1 ? 's' : ''} selected</span>
          </div>
          <div className="quick-actions">
            <button className="text-button" onClick={selectAll}>Select All</button>
            <span className="separator">|</span>
            <button className="text-button" onClick={selectNone}>Clear All</button>
          </div>
        </div>

        {/* Device-specific selection UI */}
        {(deviceType === 'windows' || deviceType === 'usb') && (
          <div className="drive-selector-panel">
            <h3>💾 Select Drives to Scan</h3>
            <p className="options-description">Choose which drives to include in the scan (showing {deviceType === 'windows' ? 'all drives' : 'all drives except C:'})</p>
            
            <div className="drives-grid">
              {availableDrives
                .filter(drive => deviceType === 'usb' ? drive.letter !== 'C:' : true)
                .map((drive) => (
                <label key={drive.letter} className={`drive-item ${selectedDrives.includes(drive.letter) ? 'selected' : ''}`}>
                  <input
                    type="checkbox"
                    checked={selectedDrives.includes(drive.letter)}
                    onChange={() => toggleDrive(drive.letter)}
                  />
                  <div className="drive-info">
                    <div className="drive-header">
                      <span className="drive-letter">{drive.letter}</span>
                      <span className="drive-type-badge">{drive.driveType}</span>
                    </div>
                    <div className="drive-label">{drive.label || 'Local Disk'}</div>
                    <div className="drive-space">
                      {formatBytes(drive.freeSpace)} free of {formatBytes(drive.totalSpace)}
                    </div>
                  </div>
                </label>
              ))}
            </div>

            {availableDrives.filter(drive => deviceType === 'usb' ? drive.letter !== 'C:' : true).length === 0 && (
              <div className="warning-box">
                <strong>⚠️ No drives available</strong>
                <p>{deviceType === 'usb' ? 'Only C: drive detected. Connect additional drives to scan.' : 'Unable to detect any drives on this system.'}</p>
              </div>
            )}

            {selectedDrives.length === 0 && availableDrives.length > 0 && (
              <div className="warning-box">
                <strong>⚠️ Warning:</strong> No drives selected. Please select at least one drive to scan.
              </div>
            )}
          </div>
        )}

        {/* First iOS panel removed — consolidated into the main iOS panel below */}

        {deviceType === 'android' && (
          <div className="android-device-selector-panel">
            <h3>🤖 Select Android Device</h3>
            <p className="options-description">
              Android devices must have USB Debugging enabled.
              <br />
              Enable it in: Settings → About Phone → Tap "Build Number" 7 times → Developer Options → USB Debugging
            </p>
            
            {androidDevices.length === 0 ? (
              <div className="warning-box">
                <strong>⚠️ No Android Devices Detected</strong>
                <p>Make sure:</p>
                <ul style={{ textAlign: 'left', margin: '10px 0', paddingLeft: '20px' }}>
                  <li>USB Debugging is enabled on your Android device</li>
                  <li>Device is connected via USB cable</li>
                  <li>You've authorized this computer when prompted on the device</li>
                  <li>ADB drivers are installed</li>
                </ul>
                <Button variant="secondary" onClick={detectAndroidDevices} style={{ marginTop: '10px' }}>
                  🔄 Refresh
                </Button>
              </div>
            ) : (
              <div className="devices-list">
                {androidDevices.map((device: any, idx) => (
                  <div key={idx} className="device-item selected">
                    <div className="device-info">
                      <span className="device-icon">📱</span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span className="device-name">{device.deviceName || device.model || 'Unknown Device'}</span>
                        <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                          {device.manufacturer} • Android {device.androidVersion} • {device.serial}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
                <Button variant="secondary" onClick={detectAndroidDevices} style={{ marginTop: '10px', width: '100%' }}>
                  🔄 Refresh Devices
                </Button>
              </div>
            )}
          </div>
        )}

        {deviceType === 'ios' && (
          <div className="android-device-selector-panel">
            <h3>📱 iOS Device — Live Media Scan</h3>
            <p className="options-description">
              Connect an unlocked iPhone or iPad via USB and tap <strong>"Trust"</strong> when prompted.
              <br />
              SCOUT will scan media files (photos &amp; videos) directly from the device and run hash matching.
            </p>

            {iosBackups.length === 0 ? (
              <div className="warning-box">
                <strong>⚠️ No iOS Devices Detected</strong>
                <p><strong>To scan an iOS device:</strong></p>
                <ol style={{ textAlign: 'left', margin: '10px 0', paddingLeft: '20px' }}>
                  <li>Connect iPhone/iPad via <strong>USB cable</strong></li>
                  <li><strong>Unlock</strong> the device (enter passcode)</li>
                  <li>Tap <strong>"Trust"</strong> when prompted on the device</li>
                  <li>Verify it appears in <strong>File Explorer</strong> under This PC</li>
                  <li>Click <strong>Refresh</strong> below</li>
                </ol>
                <Button variant="secondary" onClick={detectIosBackups} style={{ marginTop: '10px' }}>
                  🔄 Detect Devices
                </Button>
              </div>
            ) : (
              <div className="devices-list">
                {iosBackups.map((device: any, idx: number) => (
                  <label key={device.udid || idx} className={`device-item ${selectedBackup === device.udid ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="ios-device"
                      checked={selectedBackup === device.udid}
                      onChange={() => setSelectedBackup(device.udid)}
                      style={{ display: 'none' }}
                    />
                    <div className="device-info">
                      <span className="device-icon">📱</span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <span className="device-name">
                          {device.isTrusted === false ? '⚠️ ' : '✅ '}
                          {device.deviceName || 'iPhone'}
                        </span>
                        <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                          {device.deviceModel || device.productType || ''} • iOS {device.iosVersion || 'Unknown'} • {device.udid?.slice(0, 8)}...
                        </span>
                        {device.isTrusted === false && (
                          <span style={{ fontSize: '0.8rem', color: 'var(--accent-orange)' }}>
                            <strong>Not trusted</strong> — unlock device and tap "Trust"
                          </span>
                        )}
                      </div>
                    </div>
                  </label>
                ))}
                <Button variant="secondary" onClick={detectIosBackups} style={{ marginTop: '10px', width: '100%' }}>
                  🔄 Refresh Devices
                </Button>
              </div>
            )}
          </div>
        )}

        {modules.keywordSearch && (
          <div className="keyword-options-panel">
            <h3>🔍 Keyword Search Options</h3>
            <p className="options-description">Configure what to scan for keyword matches</p>
            
            {availableKeywordLists.length > 0 && (
              <div className="keyword-lists-selector">
                <h4>Select Keyword Lists to Use:</h4>
                <p className="reorder-hint">Drag <span className="drag-icon-inline">⋮⋮</span> to set scan priority — higher-ranked lists are evaluated and grouped first in results.</p>
                <div className="keyword-lists-grid">
                  {(() => {
                    // Show enabled (ordered, priority-numbered) first, then unselected
                    const enabledLists = availableKeywordLists
                      .map((list, idx) => ({ list, idx }))
                      .filter(({ list }) => list.enabled);
                    const disabledLists = availableKeywordLists
                      .map((list, idx) => ({ list, idx }))
                      .filter(({ list }) => !list.enabled);
                    return [...enabledLists, ...disabledLists].map(({ list, idx }, displayPos) => {
                      const priority = list.enabled
                        ? enabledLists.findIndex(e => e.idx === idx) + 1
                        : 0;
                      const dragKey = `kw-${idx}`;
                      const isDragOver = dragOverKey === dragKey && draggedKeyRef.current && draggedKeyRef.current !== dragKey && draggedKeyRef.current.startsWith('kw-');
                      return (
                        <div
                          key={list.name + idx}
                          className={`keyword-list-item ${list.enabled ? 'is-prioritized' : ''} ${isDragOver ? 'drag-over' : ''}`}
                          draggable={list.enabled}
                          onDragStart={(e) => {
                            if (!list.enabled) { e.preventDefault(); return; }
                            draggedKeyRef.current = dragKey;
                            e.dataTransfer.effectAllowed = 'move';
                            try { e.dataTransfer.setData('text/plain', dragKey); } catch {}
                          }}
                          onDragEnd={() => { draggedKeyRef.current = null; setDragOverKey(null); }}
                          onDragOver={(e) => {
                            const dk = draggedKeyRef.current;
                            if (!dk || !dk.startsWith('kw-')) return;
                            e.preventDefault();
                            e.dataTransfer.dropEffect = 'move';
                            if (list.enabled && dragOverKey !== dragKey) setDragOverKey(dragKey);
                          }}
                          onDragLeave={() => { if (dragOverKey === dragKey) setDragOverKey(null); }}
                          onDrop={(e) => {
                            const dk = draggedKeyRef.current;
                            if (!dk || !dk.startsWith('kw-')) return;
                            e.preventDefault();
                            const fromIdx = parseInt(dk.replace('kw-', ''), 10);
                            // Only reorder when dropping on an enabled tile (priority slots)
                            if (list.enabled && !Number.isNaN(fromIdx) && fromIdx !== idx) {
                              reorderKeywordLists(fromIdx, idx);
                            }
                            draggedKeyRef.current = null;
                            setDragOverKey(null);
                          }}
                        >
                          {list.enabled && (
                            <span
                              className="drag-handle"
                              title="Drag to reorder priority"
                              onMouseDown={(e) => e.stopPropagation()}
                            >⋮⋮</span>
                          )}
                          {list.enabled && (
                            <span className="priority-badge" title={`Priority ${priority}`}>{priority}</span>
                          )}
                          <input
                            type="checkbox"
                            checked={list.enabled}
                            onChange={() => toggleKeywordList(idx)}
                            onClick={(e) => e.stopPropagation()}
                          />
                          <div
                            className="keyword-list-info"
                            onClick={() => toggleKeywordList(idx)}
                            style={{ cursor: 'pointer' }}
                          >
                            <span className="keyword-list-name">{list.name}</span>
                            <span className="keyword-list-count">{list.keywords.length} keywords</span>
                          </div>
                        </div>
                      );
                    });
                  })()}
                </div>
                <div className="selected-keywords-summary">
                  Total: {availableKeywordLists.filter(l => l.enabled).reduce((sum, l) => sum + l.keywords.length, 0)} keywords selected 
                  from {availableKeywordLists.filter(l => l.enabled).length} list(s)
                </div>
              </div>
            )}

            <div className="options-checkboxes">
              <label className="option-checkbox">
                <input
                  type="checkbox"
                  checked={keywordConfig.scanFileNames}
                  onChange={(e) => setKeywordConfig({...keywordConfig, scanFileNames: e.target.checked})}
                />
                <div className="option-info">
                  <span className="option-label">Scan File Names</span>
                  <span className="option-hint">Search for keywords in file names (fast)</span>
                </div>
              </label>

              <label className="option-checkbox">
                <input
                  type="checkbox"
                  checked={keywordConfig.scanFilePaths}
                  onChange={(e) => setKeywordConfig({...keywordConfig, scanFilePaths: e.target.checked})}
                />
                <div className="option-info">
                  <span className="option-label">Scan File Paths</span>
                  <span className="option-hint">Search for keywords in full file paths including folder names (fast)</span>
                </div>
              </label>

              <label className="option-checkbox">
                <input
                  type="checkbox"
                  checked={keywordConfig.scanFileContents}
                  onChange={(e) => setKeywordConfig({...keywordConfig, scanFileContents: e.target.checked})}
                />
                <div className="option-info">
                  <span className="option-label">Scan File Contents</span>
                  <span className="option-hint">⚠️ Search inside text files for keywords (MUCH SLOWER - only scans files &lt;10MB)</span>
                </div>
              </label>
            </div>

            <div className="warning-box">
              <strong>⚠️ Performance Warning:</strong> Scanning file contents is significantly slower and may take several minutes depending on the number of files. 
              It only searches text-based files (documents, logs, etc.) under 10MB in size.
            </div>
          </div>
        )}

        <div className="modules-grid">
          {/* Questionable Applications - Supported on Windows, Android, iOS */}
          {isModuleSupported('questionableApps') && (
            <div 
              className={`module-card ${modules.questionableApps ? 'selected' : ''}`}
              onClick={() => toggleModule('questionableApps')}
            >
              <input
                type="checkbox"
                checked={modules.questionableApps}
                onChange={() => toggleModule('questionableApps')}
                onClick={(e) => e.stopPropagation()}
              />
              <div className="module-icon">📱</div>
              <div className="module-content">
                <h3>
                  {deviceType === 'android' ? 'Android Applications' : 
                   deviceType === 'ios' ? 'iOS Applications' : 
                   'Questionable Applications'}
                </h3>
                <p>
                  {deviceType === 'android' ? 'List all installed Android apps including package names and system apps' :
                   deviceType === 'ios' ? 'List all installed iOS apps from device backup' :
                   'Scan for VPNs, encryption tools, file shredders, P2P apps, and other forensically relevant applications'}
                </p>
                <div className="module-meta">
                  <span className="meta-badge">⚡ Fast</span>
                  <span className="meta-badge">🎯 High Value</span>
                </div>
              </div>
            </div>
          )}

          {/* Browser History - Supported on Windows only for now */}
          {isModuleSupported('browserHistory') && (
            <div 
              className={`module-card ${modules.browserHistory ? 'selected' : ''}`}
              onClick={() => toggleModule('browserHistory')}
            >
              <input
                type="checkbox"
                checked={modules.browserHistory}
                onChange={() => toggleModule('browserHistory')}
                onClick={(e) => e.stopPropagation()}
              />
              <div className="module-icon">🌐</div>
              <div className="module-content">
                <h3>Browser History Scanner</h3>
                <p>Extract browsing history, bookmarks, and saved credentials from Chrome, Edge, Firefox, Brave, Opera, and Vivaldi</p>
                <div className="module-meta">
                  <span className="meta-badge">⚡ Fast</span>
                  <span className="meta-badge">🎯 High Value</span>
                </div>
              </div>
            </div>
          )}

          {/* SMS Messages - Android and iOS only */}
          {isModuleSupported('smsMessages') && (
            <div 
              className={`module-card ${modules.smsMessages ? 'selected' : ''}`}
              onClick={() => toggleModule('smsMessages')}
            >
              <input
                type="checkbox"
                checked={modules.smsMessages || false}
                onChange={() => toggleModule('smsMessages')}
                onClick={(e) => e.stopPropagation()}
              />
              <div className="module-icon">💬</div>
              <div className="module-content">
                <h3>SMS/MMS Messages</h3>
                <p>
                  {deviceType === 'android' 
                    ? 'Extract SMS and MMS messages using ADB backup (requires user approval and password "1" if prompted)' 
                    : 'Extract SMS and iMessage conversations from device backup'}
                </p>
                <div className="module-meta">
                  <span className="meta-badge">⏱️ Moderate</span>
                  <span className="meta-badge">👤 User Approval Required</span>
                </div>
              </div>
            </div>
          )}

          {/* Media File Scanner - Supported on all device types */}
          {isModuleSupported('mediaScan') && (
            <div 
              className={`module-card ${modules.mediaScan ? 'selected' : ''}`}
              onClick={() => toggleModule('mediaScan')}
            >
              <input
                type="checkbox"
                checked={modules.mediaScan}
                onChange={() => toggleModule('mediaScan')}
                onClick={(e) => e.stopPropagation()}
              />
              <div className="module-icon">🖼️</div>
              <div className="module-content">
                <h3>Media File Scanner</h3>
                <p>
                  {deviceType === 'android' ? 'Scan DCIM, Downloads, and Pictures folders for images and videos' :
                   deviceType === 'ios' ? 'Extract media files from iOS device backup' :
                   'Locate and analyze images and videos with metadata extraction, thumbnail generation, and keyword matching in file paths'}
                </p>
                <div className="module-meta">
                  <span className="meta-badge">⏱️ Moderate</span>
                  <span className="meta-badge">💾 Storage Required</span>
                </div>
              </div>
            </div>
          )}

          {/* Keyword Search - Not yet supported on Android/iOS */}
          {isModuleSupported('keywordSearch') ? (
            <div 
              className={`module-card ${modules.keywordSearch ? 'selected' : ''}`}
              onClick={() => toggleModule('keywordSearch')}
            >
              <input
                type="checkbox"
                checked={modules.keywordSearch}
                onChange={() => toggleModule('keywordSearch')}
                onClick={(e) => e.stopPropagation()}
              />
              <div className="module-icon">🔍</div>
              <div className="module-content">
                <h3>Keyword Search</h3>
                <p>Search file names and paths for configured keyword lists (CSAM terms, drug-related keywords, etc.)</p>
                <div className="module-meta">
                  <span className="meta-badge">⚡ Fast</span>
                  <span className="meta-badge">🎯 High Value</span>
                </div>
              </div>
            </div>
          ) : (deviceType === 'android' || deviceType === 'ios') && (
            <div className="module-card disabled">
              <div className="module-icon">🔍</div>
              <div className="module-content">
                <h3>Keyword Search</h3>
                <p>Coming soon for {deviceType === 'android' ? 'Android' : 'iOS'} devices</p>
                <div className="module-meta">
                  <span className="meta-badge">🚧 In Development</span>
                </div>
              </div>
            </div>
          )}

          {/* Hash Matching - Not yet supported on Android/iOS */}
          {isModuleSupported('hashMatching') ? (
            <>
              {/* Hash List Selection - Show BEFORE the module card */}
              {availableHashLists.length > 0 && (
                <div className="hash-lists-selector keyword-lists-selector">
                  <h4>Select Hash Lists to Use:</h4>
                  <p className="reorder-hint">Drag <span className="drag-icon-inline">⋮⋮</span> to set scan priority — hits attribute to the highest-priority list first.</p>
                  <div className="keyword-lists-grid">
                    {(() => {
                      const enabledLists = availableHashLists
                        .map((list, idx) => ({ list, idx }))
                        .filter(({ list }) => list.enabled);
                      const disabledLists = availableHashLists
                        .map((list, idx) => ({ list, idx }))
                        .filter(({ list }) => !list.enabled);
                      return [...enabledLists, ...disabledLists].map(({ list, idx }) => {
                        const priority = list.enabled
                          ? enabledLists.findIndex(e => e.idx === idx) + 1
                          : 0;
                        const dragKey = `hash-${idx}`;
                        const isDragOver = dragOverKey === dragKey && draggedKeyRef.current && draggedKeyRef.current !== dragKey && draggedKeyRef.current.startsWith('hash-');
                        return (
                          <div
                            key={list.id}
                            className={`keyword-list-item ${list.enabled ? 'is-prioritized' : ''} ${isDragOver ? 'drag-over' : ''}`}
                            draggable={list.enabled}
                            onDragStart={(e) => {
                              if (!list.enabled) { e.preventDefault(); return; }
                              draggedKeyRef.current = dragKey;
                              e.dataTransfer.effectAllowed = 'move';
                              try { e.dataTransfer.setData('text/plain', dragKey); } catch {}
                            }}
                            onDragEnd={() => { draggedKeyRef.current = null; setDragOverKey(null); }}
                            onDragOver={(e) => {
                              const dk = draggedKeyRef.current;
                              if (!dk || !dk.startsWith('hash-')) return;
                              e.preventDefault();
                              e.dataTransfer.dropEffect = 'move';
                              if (list.enabled && dragOverKey !== dragKey) setDragOverKey(dragKey);
                            }}
                            onDragLeave={() => { if (dragOverKey === dragKey) setDragOverKey(null); }}
                            onDrop={(e) => {
                              const dk = draggedKeyRef.current;
                              if (!dk || !dk.startsWith('hash-')) return;
                              e.preventDefault();
                              const fromIdx = parseInt(dk.replace('hash-', ''), 10);
                              if (list.enabled && !Number.isNaN(fromIdx) && fromIdx !== idx) {
                                reorderHashLists(fromIdx, idx);
                              }
                              draggedKeyRef.current = null;
                              setDragOverKey(null);
                            }}
                          >
                            {list.enabled && (
                              <span
                                className="drag-handle"
                                title="Drag to reorder priority"
                                onMouseDown={(e) => e.stopPropagation()}
                              >⋮⋮</span>
                            )}
                            {list.enabled && (
                              <span className="priority-badge" title={`Priority ${priority}`}>{priority}</span>
                            )}
                            <input
                              type="checkbox"
                              checked={list.enabled}
                              onChange={() => toggleHashList(idx)}
                              onClick={(e) => e.stopPropagation()}
                            />
                            <div
                              className="keyword-list-info"
                              onClick={() => toggleHashList(idx)}
                              style={{ cursor: 'pointer' }}
                            >
                              <span className="keyword-list-name">{list.name}</span>
                            </div>
                          </div>
                        );
                      });
                    })()}
                  </div>
                  <div className="selected-keywords-summary">
                    {availableHashLists.filter(l => l.enabled).length} of {availableHashLists.length} hash list(s) selected
                  </div>
                </div>
              )}

              {availableHashLists.length === 0 && (
                <div className="hash-lists-empty info-banner warning">
                  <strong>⚠️ No hash lists configured</strong>
                  <p>Go to Settings → Hash Lists to import Project VIC or custom hash databases</p>
                </div>
              )}

              <div 
                className={`module-card ${modules.hashMatching ? 'selected' : ''}`}
                onClick={() => toggleModule('hashMatching')}
              >
                <input
                  type="checkbox"
                  checked={modules.hashMatching}
                  onChange={() => {}}
                />
                <div className="module-icon">🔐</div>
                <div className="module-content">
                  <h3>Hash Matching (Project VIC)</h3>
                  <p>Compare file hashes against Project VIC and other known contraband databases to identify flagged content</p>
                  <div className="module-meta">
                    <span className="meta-badge">⏱️ Moderate</span>
                    <span className="meta-badge">🎯 Available</span>
                  </div>
                </div>
              </div>
            </>
          ) : (deviceType === 'android' || deviceType === 'ios') && (
            <div className="module-card disabled">
              <div className="module-icon">🔐</div>
              <div className="module-content">
                <h3>Hash Matching (Project VIC)</h3>
                <p>Coming soon for {deviceType === 'android' ? 'Android' : 'iOS'} devices</p>
                <div className="module-meta">
                  <span className="meta-badge">🚧 In Development</span>
                </div>
              </div>
            </div>
          )}

          {/* Intrusion Detection - Windows only */}
          {deviceType === 'windows' && (
            <div 
              className={`module-card ${modules.intrusionDetection ? 'selected' : ''}`}
              onClick={() => setModules({...modules, intrusionDetection: !modules.intrusionDetection})}
            >
              <input
                type="checkbox"
                checked={modules.intrusionDetection}
                onChange={() => {}}
              />
              <div className="module-icon">⚠️</div>
              <div className="module-content">
                <h3>Intrusion Detection</h3>
                <p>Analyze Windows event logs, persistence mechanisms, and command history for signs of unauthorized access or malicious activity</p>
                <div className="module-meta">
                  <span className="meta-badge">⏱️ Moderate</span>
                  <span className="meta-badge">🎯 Windows Only</span>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="config-footer">
          <div className="footer-info">
            <div className="info-item">
              <span className="info-icon">💡</span>
              <span>Tip: Select only the modules you need for faster scan times</span>
            </div>
            <div className="info-item">
              <span className="info-icon">⚠️</span>
              <span>Ensure sufficient storage space on your target device</span>
            </div>
          </div>
          <div className="footer-actions">
            <Button 
              variant="primary" 
              size="lg" 
              onClick={() => {
                // iOS mode
                if (deviceType === 'ios') {
                  if (!selectedBackup && iosBackups.length === 0) {
                    alert('Please connect an iOS device.\nEnsure it is unlocked, trusted, and visible in File Explorer.');
                    return;
                  }
                  
                  const iosConfig = {
                    ...keywordConfig,
                    selectedDevice: selectedBackup || iosBackups[0]?.udid || undefined,
                    deviceType: 'ios'
                  };
                  const hashConfig: HashMatchingConfig = {
                    selectedHashLists: availableHashLists
                  };
                  onStartScan(modules, iosConfig, hashConfig);
                  return;
                }

                // Android mode
                if (deviceType === 'android') {
                  if (androidDevices.length === 0) {
                    alert('Please connect an Android device with USB debugging enabled.');
                    return;
                  }
                  const androidConfig = {
                    ...keywordConfig,
                    selectedDevice: androidDevices[0]?.serial,
                    deviceType: 'android'
                  };
                  const hashConfig: HashMatchingConfig = {
                    selectedHashLists: availableHashLists
                  };
                  onStartScan(modules, androidConfig, hashConfig);
                  return;
                }

                // Windows/USB mode
                if (selectedDrives.length === 0) {
                  alert('Please select at least one drive to scan.');
                  return;
                }
                
                // For USB mode, ensure apps and browser history are disabled
                const scanModules = deviceType === 'usb' 
                  ? { ...modules, questionableApps: false, browserHistory: false }
                  : modules;
                
                const configWithLists = {
                  ...keywordConfig,
                  selectedLists: availableKeywordLists,
                  selectedDrives,
                  deviceType
                };
                
                const hashConfig: HashMatchingConfig = {
                  selectedHashLists: availableHashLists
                };
                
                onStartScan(scanModules, configWithLists, hashConfig);
              }}
              disabled={
                (deviceType === 'ios' && !selectedBackup && iosBackups.length === 0) ||
                (deviceType === 'android' && androidDevices.length === 0) ||
                ((deviceType === 'windows' || deviceType === 'usb') && selectedDrives.length === 0)
              }
              glow={
                (deviceType === 'ios' && (selectedBackup || iosBackups.length > 0)) ||
                (deviceType === 'android' && androidDevices.length > 0) ||
                ((deviceType === 'windows' || deviceType === 'usb') && selectedDrives.length > 0)
              }
            >
              {deviceType === 'ios' && selectedBackup && `▶ Scan iOS Device`}
              {deviceType === 'ios' && !selectedBackup && iosBackups.length > 0 && `▶ Scan iOS Device`}
              {deviceType === 'ios' && !selectedBackup && iosBackups.length === 0 && `▶ Scan iOS`}
              {deviceType === 'android' && `▶ Scan Android Device (${androidDevices.length} connected)`}
              {(deviceType === 'windows' || deviceType === 'usb') && `▶ Start Scan (${selectedCount} module${selectedCount !== 1 ? 's' : ''}) on ${selectedDrives.length} drive${selectedDrives.length !== 1 ? 's' : ''}`}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
