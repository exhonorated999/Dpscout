import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './IosView.css';

interface LiveIosDevice {
  udid: string;
  deviceName: string;
  deviceModel: string;
  productType: string;
  iosVersion: string;
  isTrusted: boolean;
  connectionType: string;
  serialNumber: string;
  imei: string;
  phoneNumber: string;
  wifiAddress: string;
  bluetoothAddress: string;
  buildVersion: string;
  hardwareModel: string;
  deviceColor: string;
  batteryLevel: string;
  totalCapacity: string;
  availableCapacity: string;
}

interface IosDeviceInfo {
  udid: string;
  deviceName: string;
  deviceModel: string;
  productType: string;
  iosVersion: string;
  serialNumber: string;
  imei: string;
  phoneNumber: string;
  wifiAddress: string;
  bluetoothAddress: string;
  buildVersion: string;
  hardwareModel: string;
  deviceColor: string;
  batteryLevel: string;
  totalCapacity: string;
  availableCapacity: string;
  modelNumber: string;
  activationState: string;
  timezone: string;
  language: string;
  region: string;
}

interface IosInstalledApp {
  bundleId: string;
  appName: string;
  version: string;
  isSystemApp: boolean;
  installDate?: string;
  appSize?: number;
  dataSize?: number;
}

interface IosNote {
  title: string;
  content: string;
  createdDate: string;
  modifiedDate: string;
  folder: string;
  noteId: string;
}

interface IosAppInfo {
  bundleId: string;
  appName: string;
  version: string;
  isSystemApp: boolean;
  category: string;
}

interface IosHashMatch {
  fileHash: string;
  hashType: string;
  fileName: string;
  filePath: string;
  fileSize: number;
  matchCategory: string;
  timestamp: string;
}

interface IosViewProps {
  onBack: () => void;
  onScanComplete?: (results: any) => void;
}

interface IosScanConfig {
  scanApps: boolean;
  scanBrowser: boolean;
  scanMedia: boolean;
  scanNotes: boolean;
  scanHash: boolean;
  scanKeywords: boolean;
}

type ViewMode = 'devices' | 'selection' | 'config' | 'scanning' | 'deviceInfo' | 'apps' | 'notes' | 'media' | 'results';

export const IosView: React.FC<IosViewProps> = ({ onBack, onScanComplete }) => {
  const [devices, setDevices] = useState<LiveIosDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<LiveIosDevice | null>(null);
  const [deviceInfo, setDeviceInfo] = useState<IosDeviceInfo | null>(null);
  const [installedApps, setInstalledApps] = useState<IosInstalledApp[]>([]);
  const [notes, setNotes] = useState<IosNote[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('devices');
  const [activeSection, setActiveSection] = useState<string>('device-info');
  const [showResultsView, setShowResultsView] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState<string>('');
  // Guards against overlapping detect runs: each click of Refresh (and the
  // mount-time auto-detect) otherwise spawns a concurrent pymobiledevice3
  // process whose results race and clobber the device list.
  const detectingRef = useRef(false);
  const [libimobileAvailable, setLibimobileAvailable] = useState<boolean | null>(null);
  const [apps, setApps] = useState<IosAppInfo[]>([]);
  const [hashMatches, setHashMatches] = useState<IosHashMatch[]>([]);
  const [error, setError] = useState<string>('');
  const [appFilter, setAppFilter] = useState<'all' | 'user' | 'system'>('all');
  const [selectedNote, setSelectedNote] = useState<IosNote | null>(null);
  
  // Scan configuration state
  const [scanConfig, setScanConfig] = useState<IosScanConfig>({
    scanApps: true,
    scanBrowser: true,
    scanMedia: true,
    scanNotes: true,
    scanHash: true,
    scanKeywords: false,
  });

  useEffect(() => {
    checkLibimobileDevice();
    detectDevices();
  }, []);

  async function checkLibimobileDevice() {
    try {
      const available = await invoke<boolean>('check_libimobiledevice_available');
      setLibimobileAvailable(available);
      if (!available) {
        setError('libimobiledevice tools not found. Please install libimobiledevice to scan iOS devices.');
      }
    } catch (err) {
      console.error('Failed to check libimobiledevice:', err);
      setLibimobileAvailable(false);
      setError('Failed to check libimobiledevice availability');
    }
  }

  async function detectDevices() {
    // Ignore re-entrant calls (rapid Refresh clicks / mount + trust refresh)
    // so we never run two detections at once.
    if (detectingRef.current) {
      console.log('[iOS] detectDevices already in progress — ignoring duplicate call');
      return;
    }
    detectingRef.current = true;
    try {
      setIsLoading(true);
      setError('');
      setScanProgress('Detecting iOS devices...');

      // Try libimobiledevice detection
      const detectedDevices = await invoke<LiveIosDevice[]>('detect_live_ios_devices');
      console.log('libimobiledevice detected devices:', detectedDevices);

      setDevices(detectedDevices);
      setScanProgress('');

      if (detectedDevices.length === 0) {
        // Check if MTP detection works as fallback info
        try {
          const mtpDevices = await invoke<any[]>('detect_ios_mtp_devices');
          if (mtpDevices && mtpDevices.length > 0) {
            // Show warning that device is detected via MTP but not via libimobiledevice
            setError(
              '⚠️ iPhone detected via Windows but not accessible via libimobiledevice.\n\n' +
              'This means you can scan media files but not device info or apps.\n\n' +
              'Options:\n' +
              '1. Use "USB Drive" mode to scan media (photos/videos)\n' +
              '2. Ensure iTunes is installed and Apple Mobile Device Service is running\n' +
              '3. Create an iTunes backup to extract all data'
            );
          } else {
            setError('No iOS devices detected. Please connect an iOS device via USB and trust this computer.');
          }
        } catch (mtpErr) {
          setError('No iOS devices detected. Please connect an iOS device via USB and trust this computer.');
        }
      } else if (detectedDevices.length === 1) {
        setSelectedDevice(detectedDevices[0]);
      }
    } catch (err) {
      console.error('Failed to detect iOS devices:', err);
      setError(`Failed to detect iOS devices: ${err}`);
    } finally {
      setScanProgress('');
      setIsLoading(false);
      detectingRef.current = false;
    }
  }

  async function requestTrust() {
    if (!selectedDevice) return;

    try {
      setError('');
      setScanProgress('Requesting device trust — check your iPhone…');
      const result = await invoke<{ paired: boolean; state: string; message: string }>(
        'request_ios_device_trust',
        { udid: selectedDevice.udid }
      );

      if (result.paired) {
        // already_paired | paired
        setScanProgress(result.message || 'Device trusted! You can now scan.');
        // Refresh device info now that we're paired.
        await detectDevices();
      } else {
        // prompt_shown | locked | denied | stale_record | no_device | error.
        // These are actionable states, not hard failures — surface the guidance
        // the backend produced verbatim so the examiner knows what to do next.
        setError(result.message || 'Could not establish trust. Unlock the iPhone and tap "Trust".');
      }
    } catch (err) {
      console.error('Failed to request trust:', err);
      setError(`Failed to request trust: ${err}`);
    } finally {
      setScanProgress('');
    }
  }

  async function scanApps() {
    if (!selectedDevice) return;

    try {
      setIsLoading(true);
      setError('');
      setScanProgress('Scanning installed applications...');
      
      const appList = await invoke<string[]>('list_ios_device_apps', {
        udid: selectedDevice.udid
      });

      // Convert to IosAppInfo format
      const iosApps: IosAppInfo[] = appList.map(bundleId => ({
        bundleId,
        appName: bundleId.split('.').pop() || bundleId,
        version: 'Unknown',
        isSystemApp: bundleId.startsWith('com.apple.'),
        category: 'Unknown'
      }));

      setApps(iosApps);
      setScanProgress(`Found ${iosApps.length} applications`);
    } catch (err) {
      console.error('Failed to scan apps:', err);
      setError(`Failed to scan apps: ${err}`);
    } finally {
      setIsLoading(false);
    }
  }

  async function performFullTriage() {
    if (!selectedDevice) return;

    try {
      setIsLoading(true);
      setError('');
      setScanProgress('Performing full device triage...');

      const results = await invoke('perform_ios_live_triage', {
        udid: selectedDevice.udid,
        keywordLists: [],
        hashLists: []
      });

      console.log('iOS triage results:', results);
      setScanProgress('Triage complete!');
      
      if (onScanComplete) {
        onScanComplete(results);
      }
    } catch (err) {
      console.error('Failed to perform triage:', err);
      setError(`Failed to perform triage: ${err}`);
    } finally {
      setIsLoading(false);
    }
  }

  async function loadDeviceInfo() {
    if (!selectedDevice) return;

    setIsLoading(true);
    setError('');
    try {
      const info = await invoke<IosDeviceInfo>('get_ios_device_info', {
        udid: selectedDevice.udid
      });
      setDeviceInfo(info);
      setShowResultsView(true);
      setActiveSection('device-info');
      setViewMode('deviceInfo');
    } catch (err) {
      setError(`Failed to load device info: ${err}`);
    } finally {
      setIsLoading(false);
    }
  }

  async function loadInstalledApps() {
    if (!selectedDevice) return;

    setIsLoading(true);
    setError('');
    try {
      const apps = await invoke<IosInstalledApp[]>('get_ios_installed_apps', {
        udid: selectedDevice.udid
      });
      setInstalledApps(apps);
      setShowResultsView(true);
      setActiveSection('apps');
      setViewMode('apps');
    } catch (err) {
      console.error('Failed to load apps from live device:', err);
      setError(
        'Unable to load apps from live device.\n\n' +
        'Apps can be extracted from iTunes backup instead.\n' +
        'Please create an iTunes backup and use the iOS Backup scanner.'
      );
    } finally {
      setIsLoading(false);
    }
  }

  async function loadNotes() {
    setError(
      'Notes extraction requires iTunes backup.\n\n' +
      'To extract notes:\n' +
      '1. Create an iTunes backup of your device\n' +
      '2. Go back and select "iOS Backup" scanner\n' +
      '3. Select your backup from the list\n' +
      '4. Notes will be available for extraction'
    );
  }

  const filteredApps = installedApps.filter(app => {
    if (appFilter === 'user') return !app.isSystemApp;
    if (appFilter === 'system') return app.isSystemApp;
    return true;
  });

  async function scanHashMatches() {
    if (!selectedDevice) return;

    try {
      setIsLoading(true);
      setError('');
      setScanProgress('Scanning for hash matches (CSAM)...');

      // This would need to be implemented in the backend
      // For now, show a placeholder
      setError('Hash matching for iOS is not yet implemented. This feature requires jailbreak or backup extraction.');
      
    } catch (err) {
      console.error('Failed to scan hashes:', err);
      setError(`Failed to scan hashes: ${err}`);
    } finally {
      setIsLoading(false);
    }
  }

  if (libimobileAvailable === null) {
    return (
      <div className="ios-view">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Checking for libimobiledevice tools...</p>
        </div>
      </div>
    );
  }

  if (libimobileAvailable === false) {
    return (
      <div className="ios-view">
        <div className="ios-header">
          <button onClick={onBack} className="back-button">
            ← Back
          </button>
          <h1>🍎 iOS Device Scanner</h1>
        </div>

        <div className="error-container">
          <div className="error-icon">⚠️</div>
          <h2>libimobiledevice Not Found</h2>
          <p>
            The libimobiledevice tools are required to scan iOS devices.
            These tools allow communication with iOS devices over USB.
          </p>
          <div className="installation-instructions">
            <h3>Installation Instructions:</h3>
            <div className="instruction-section">
              <h4>Windows:</h4>
              <ol>
                <li>Download libimobiledevice from the official repository</li>
                <li>Extract to the "external/libimobiledevice" folder next to the application</li>
                <li>Restart the application</li>
              </ol>
            </div>
            <div className="instruction-section">
              <h4>Alternative:</h4>
              <p>Install iTunes for Windows, which includes the necessary drivers and libraries.</p>
            </div>
          </div>
          <button onClick={checkLibimobileDevice} className="retry-button">
            🔄 Retry Detection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="ios-view">
      <div className="ios-header">
        <button onClick={onBack} className="back-button">
          ← Back
        </button>
        <h1>🍎 iOS Device Scanner</h1>
        <button onClick={detectDevices} className="refresh-button" disabled={isLoading}>
          {isLoading ? '⏳ Detecting…' : '🔄 Refresh Devices'}
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
          <button onClick={() => setError('')} className="dismiss-button">×</button>
        </div>
      )}

      {scanProgress && (
        <div className="progress-banner">
          <div className="progress-spinner"></div>
          <span>{scanProgress}</span>
        </div>
      )}

      <div className="ios-content">
        {devices.length === 0 ? (
          <div className="no-devices">
            <div className="no-devices-icon">📱</div>
            <h2>No iOS Devices Detected</h2>
            <p>Please connect an iOS device via USB cable</p>
            <div className="connection-tips">
              <h3>Connection Tips:</h3>
              <ul>
                <li>Ensure the device is unlocked</li>
                <li>Tap "Trust This Computer" when prompted on the device</li>
                <li>Make sure iTunes or libimobiledevice is properly installed</li>
                <li>Try a different USB cable or port</li>
              </ul>
            </div>
            <button onClick={detectDevices} className="refresh-button" disabled={isLoading}>
              {isLoading ? '⏳ Detecting…' : '🔄 Refresh Devices'}
            </button>
          </div>
        ) : (
          <>
            {/* Device Selection */}
            <div className="device-selection-section">
              <h2>Connected Devices ({devices.length})</h2>
              <div className="device-grid">
                {devices.map((device) => (
                  <div
                    key={device.udid}
                    className={`device-card ${selectedDevice?.udid === device.udid ? 'selected' : ''}`}
                    onClick={() => setSelectedDevice(device)}
                  >
                    <div className="device-icon">📱</div>
                    <div className="device-info">
                      <h3>{device.deviceName}</h3>
                      <p className="device-model">{device.deviceModel}</p>
                      <p className="device-version">iOS {device.iosVersion}</p>
                      <div className="device-status">
                        {device.isTrusted ? (
                          <span className="status-badge trusted">✓ Trusted</span>
                        ) : (
                          <span className="status-badge untrusted">⚠ Not Trusted</span>
                        )}
                        <span className="connection-badge">{device.connectionType}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Device Details and Actions */}
            {selectedDevice && (
              <>
                <div className="device-details-section">
                  <h2>Device Identification</h2>
                  <div className="device-details-grid">
                    <div className="detail-item">
                      <span className="detail-label">DEVICE NAME</span>
                      <span className="detail-value">{selectedDevice.deviceName}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">MODEL</span>
                      <span className="detail-value">{selectedDevice.deviceModel}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">SERIAL NUMBER</span>
                      <span className="detail-value">{selectedDevice.serialNumber}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">IMEI</span>
                      <span className="detail-value">{selectedDevice.imei || 'N/A'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">PHONE NUMBER</span>
                      <span className="detail-value">{selectedDevice.phoneNumber || 'N/A'}</span>
                    </div>
                  </div>
                </div>

                <div className="device-details-section">
                  <h2>System Information</h2>
                  <div className="device-details-grid">
                    <div className="detail-item">
                      <span className="detail-label">iOS VERSION</span>
                      <span className="detail-value">{selectedDevice.iosVersion}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">BUILD VERSION</span>
                      <span className="detail-value">{selectedDevice.buildVersion || 'N/A'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">BATTERY LEVEL</span>
                      <span className="detail-value">{selectedDevice.batteryLevel || 'N/A'}</span>
                    </div>
                  </div>
                </div>

                <div className="device-details-section">
                  <h2>Storage & Connectivity</h2>
                  <div className="device-details-grid">
                    <div className="detail-item">
                      <span className="detail-label">STORAGE</span>
                      <span className="detail-value">
                        {selectedDevice.availableCapacity && selectedDevice.totalCapacity
                          ? `${selectedDevice.availableCapacity} / ${selectedDevice.totalCapacity}`
                          : 'N/A'}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">WiFi ADDRESS</span>
                      <span className="detail-value">{selectedDevice.wifiAddress || 'N/A'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">BLUETOOTH ADDRESS</span>
                      <span className="detail-value">{selectedDevice.bluetoothAddress || 'N/A'}</span>
                    </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="device-details-section">
                  <h2>Device Actions</h2>
                  
                  {!selectedDevice.isTrusted && (
                    <div className="trust-warning">
                      <p>⚠️ Device must be trusted before scanning. Please unlock your device and approve the trust dialog.</p>
                      <button 
                        onClick={requestTrust} 
                        className="action-button trust-button"
                        disabled={isLoading}
                      >
                        🔑 Request Trust
                      </button>
                    </div>
                  )}

                  <div className="action-buttons">
                    <button
                      onClick={loadDeviceInfo}
                      className="action-button"
                      disabled={isLoading || !selectedDevice.isTrusted}
                    >
                      📱 Device Info
                    </button>

                    <button
                      onClick={loadInstalledApps}
                      className="action-button"
                      disabled={isLoading || !selectedDevice.isTrusted}
                    >
                      📦 Installed Apps
                    </button>

                    <button
                      onClick={loadNotes}
                      className="action-button"
                      disabled={isLoading}
                    >
                      📝 Notes
                    </button>

                    <button
                      onClick={() => alert('Media scanning coming soon!')}
                      className="action-button"
                      disabled={isLoading || !selectedDevice.isTrusted}
                    >
                      📷 Media
                    </button>

                    <button
                      onClick={() => setViewMode('config')}
                      className="action-button primary-button"
                      disabled={isLoading || !selectedDevice.isTrusted}
                    >
                      🔍 Start Scan
                    </button>
                  </div>
                </div>
              </>
            )}

            {/* Scan Configuration */}
            {viewMode === 'config' && selectedDevice && (
              <div className="scan-config-view">
                <div className="config-header">
                  <h2>📋 Configure Scan</h2>
                  <p>Select which modules to scan on {selectedDevice.deviceName}</p>
                </div>
                
                <div className="config-options">
                  <div className="config-option">
                    <input
                      type="checkbox"
                      id="scanApps"
                      checked={scanConfig.scanApps}
                      onChange={(e) => setScanConfig({...scanConfig, scanApps: e.target.checked})}
                    />
                    <label htmlFor="scanApps">
                      <span className="option-icon">📱</span>
                      <div className="option-info">
                        <div className="option-title">Installed Applications</div>
                        <div className="option-desc">Scan all installed apps (system and user)</div>
                      </div>
                    </label>
                  </div>

                  <div className="config-option">
                    <input
                      type="checkbox"
                      id="scanBrowser"
                      checked={scanConfig.scanBrowser}
                      onChange={(e) => setScanConfig({...scanConfig, scanBrowser: e.target.checked})}
                    />
                    <label htmlFor="scanBrowser">
                      <span className="option-icon">🌐</span>
                      <div className="option-info">
                        <div className="option-title">Browser History</div>
                        <div className="option-desc">Extract Safari, Chrome, and Firefox browsing history</div>
                      </div>
                    </label>
                  </div>

                  <div className="config-option">
                    <input
                      type="checkbox"
                      id="scanMedia"
                      checked={scanConfig.scanMedia}
                      onChange={(e) => setScanConfig({...scanConfig, scanMedia: e.target.checked})}
                    />
                    <label htmlFor="scanMedia">
                      <span className="option-icon">📸</span>
                      <div className="option-info">
                        <div className="option-title">Media Files</div>
                        <div className="option-desc">Scan photos and videos metadata</div>
                      </div>
                    </label>
                  </div>

                  <div className="config-option">
                    <input
                      type="checkbox"
                      id="scanNotes"
                      checked={scanConfig.scanNotes}
                      onChange={(e) => setScanConfig({...scanConfig, scanNotes: e.target.checked})}
                    />
                    <label htmlFor="scanNotes">
                      <span className="option-icon">📝</span>
                      <div className="option-info">
                        <div className="option-title">Notes</div>
                        <div className="option-desc">Extract notes and memos</div>
                      </div>
                    </label>
                  </div>

                  <div className="config-option">
                    <input
                      type="checkbox"
                      id="scanHash"
                      checked={scanConfig.scanHash}
                      onChange={(e) => setScanConfig({...scanConfig, scanHash: e.target.checked})}
                    />
                    <label htmlFor="scanHash">
                      <span className="option-icon">🔒</span>
                      <div className="option-info">
                        <div className="option-title">Hash Matching (CSAM)</div>
                        <div className="option-desc">Check media files against known CSAM hashes</div>
                      </div>
                    </label>
                  </div>

                  <div className="config-option">
                    <input
                      type="checkbox"
                      id="scanKeywords"
                      checked={scanConfig.scanKeywords}
                      onChange={(e) => setScanConfig({...scanConfig, scanKeywords: e.target.checked})}
                    />
                    <label htmlFor="scanKeywords">
                      <span className="option-icon">🔍</span>
                      <div className="option-info">
                        <div className="option-title">Keyword Search</div>
                        <div className="option-desc">Search files for specified keywords</div>
                      </div>
                    </label>
                  </div>
                </div>

                <div className="config-actions">
                  <button 
                    onClick={() => setViewMode('devices')} 
                    className="btn-secondary"
                  >
                    ← Back
                  </button>
                  <button 
                    onClick={performFullTriage}
                    className="btn-primary"
                    disabled={isLoading || !Object.values(scanConfig).some(v => v)}
                  >
                    {isLoading ? 'Scanning...' : '🚀 Start Scan'}
                  </button>
                </div>
              </div>
            )}

            {/* View Mode Content */}
            {viewMode === 'deviceInfo' && deviceInfo && (
              <div className="view-section">
                <div className="view-header">
                  <h2>📱 Device Information</h2>
                  <button onClick={() => setViewMode('devices')} className="back-to-device-btn">
                    ← Back to Device
                  </button>
                </div>
                <div className="device-info-grid">
                  <div className="info-card">
                        <h3>Identity</h3>
                        <div className="info-row">
                          <span className="info-label">Device Name:</span>
                          <span className="info-value">{deviceInfo.deviceName}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Model:</span>
                          <span className="info-value">{deviceInfo.deviceModel}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Product Type:</span>
                          <span className="info-value">{deviceInfo.productType}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Serial Number:</span>
                          <span className="info-value selectable">{deviceInfo.serialNumber}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">UDID:</span>
                          <span className="info-value selectable">{deviceInfo.udid}</span>
                        </div>
                      </div>

                      <div className="info-card">
                        <h3>Software</h3>
                        <div className="info-row">
                          <span className="info-label">iOS Version:</span>
                          <span className="info-value">{deviceInfo.iosVersion}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Build Version:</span>
                          <span className="info-value">{deviceInfo.buildVersion}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Activation State:</span>
                          <span className="info-value">{deviceInfo.activationState}</span>
                        </div>
                      </div>

                      <div className="info-card">
                        <h3>Connectivity</h3>
                        <div className="info-row">
                          <span className="info-label">Phone Number:</span>
                          <span className="info-value">{deviceInfo.phoneNumber || 'N/A'}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">IMEI:</span>
                          <span className="info-value selectable">{deviceInfo.imei || 'N/A'}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">WiFi Address:</span>
                          <span className="info-value">{deviceInfo.wifiAddress || 'N/A'}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Bluetooth Address:</span>
                          <span className="info-value">{deviceInfo.bluetoothAddress || 'N/A'}</span>
                        </div>
                      </div>

                      <div className="info-card">
                        <h3>Storage & Battery</h3>
                        <div className="info-row">
                          <span className="info-label">Battery Level:</span>
                          <span className="info-value">{deviceInfo.batteryLevel}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Total Capacity:</span>
                          <span className="info-value">{deviceInfo.totalCapacity}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Available:</span>
                          <span className="info-value">{deviceInfo.availableCapacity}</span>
                        </div>
                      </div>

                      <div className="info-card">
                        <h3>Localization</h3>
                        <div className="info-row">
                          <span className="info-label">Timezone:</span>
                          <span className="info-value">{deviceInfo.timezone}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Language:</span>
                          <span className="info-value">{deviceInfo.language}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Region:</span>
                          <span className="info-value">{deviceInfo.region}</span>
                        </div>
                      </div>
                    </div>
              </div>
            )}

            {viewMode === 'apps' && installedApps.length > 0 && (
              <div className="view-section">
                <div className="view-header">
                  <h2>📦 Installed Applications ({installedApps.length})</h2>
                  <button onClick={() => setViewMode('devices')} className="back-to-device-btn">
                    ← Back to Device
                  </button>
                </div>
                
                <div className="app-filters">
                  <button 
                    className={`filter-btn ${appFilter === 'all' ? 'active' : ''}`}
                    onClick={() => setAppFilter('all')}
                  >
                    All Apps ({installedApps.length})
                  </button>
                      <button 
                        className={`filter-btn ${appFilter === 'user' ? 'active' : ''}`}
                        onClick={() => setAppFilter('user')}
                      >
                        User Apps ({installedApps.filter(a => !a.isSystemApp).length})
                      </button>
                      <button 
                        className={`filter-btn ${appFilter === 'system' ? 'active' : ''}`}
                        onClick={() => setAppFilter('system')}
                      >
                        System Apps ({installedApps.filter(a => a.isSystemApp).length})
                      </button>
                    </div>

                    <div className="apps-table-container">
                      <table className="apps-table">
                        <thead>
                          <tr>
                            <th>App Name</th>
                            <th>Bundle ID</th>
                            <th>Version</th>
                            <th>Type</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredApps.map((app, index) => (
                            <tr key={index}>
                              <td>
                                <div className="app-name-cell">
                                  <span className="app-icon">📦</span>
                                  <span>{app.appName}</span>
                                </div>
                              </td>
                              <td className="bundle-id-cell">{app.bundleId}</td>
                              <td>{app.version}</td>
                              <td>
                                <span className={`app-type-badge ${app.isSystemApp ? 'system' : 'user'}`}>
                                  {app.isSystemApp ? 'System' : 'User'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

            {hashMatches.length > 0 && (
              <div className="results-section critical">
                <h2>⚠️ Hash Matches Found ({hashMatches.length})</h2>
                <div className="hash-matches-list">
                  {hashMatches.map((match, index) => (
                    <div key={index} className="hash-match-item">
                      <div className="match-icon">🚨</div>
                      <div className="match-info">
                        <div className="match-filename">{match.fileName}</div>
                        <div className="match-category">{match.matchCategory}</div>
                        <div className="match-hash">{match.hashType}: {match.fileHash}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
