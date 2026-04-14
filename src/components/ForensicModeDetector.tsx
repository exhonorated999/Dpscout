/**
 * Forensic Mode Detector Component
 * 
 * Detects target systems for forensic scanning when running in bootable Linux mode.
 * Shows detected Windows/Chrome OS partitions and allows user to select target.
 */

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './ForensicModeDetector.css';

interface TargetSystem {
  Windows?: {
    partition: string;
    version: string;
    mount_point: string;
  };
  ChromeOS?: {
    partition: string;
    mount_point: string;
  };
  Unknown?: null;
}

interface SystemInfo {
  os_name: string;
  os_version: string;
  computer_name: string;
  username: string;
  install_date?: string;
}

interface AppInfo {
  name: string;
  publisher: string;
  version: string;
  install_location: string;
  install_date?: string;
}

export const ForensicModeDetector: React.FC = () => {
  const [isForensicMode, setIsForensicMode] = useState(false);
  const [isDetecting, setIsDetecting] = useState(false);
  const [targets, setTargets] = useState<TargetSystem[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<TargetSystem | null>(null);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [apps, setApps] = useState<AppInfo[]>([]);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    checkForensicMode();
  }, []);

  const checkForensicMode = async () => {
    try {
      const forensicMode = await invoke<boolean>('is_forensic_mode');
      setIsForensicMode(forensicMode);
      
      if (forensicMode) {
        detectTargets();
      }
    } catch (err) {
      console.error('Failed to check forensic mode:', err);
    }
  };

  const detectTargets = async () => {
    setIsDetecting(true);
    setError('');
    
    try {
      const detected = await invoke<TargetSystem[]>('detect_forensic_targets');
      setTargets(detected);
      
      if (detected.length === 0) {
        setError('No target systems detected. Please ensure a Windows or Chrome OS drive is connected.');
      } else if (detected.length === 1) {
        // Auto-select if only one target
        selectTarget(detected[0]);
      }
    } catch (err) {
      setError(`Failed to detect targets: ${err}`);
    } finally {
      setIsDetecting(false);
    }
  };

  const selectTarget = async (target: TargetSystem) => {
    setSelectedTarget(target);
    setError('');
    
    try {
      // Get system info
      const info = await invoke<SystemInfo>('get_forensic_system_info', { target });
      setSystemInfo(info);
      
      // Get installed apps
      const appList = await invoke<AppInfo[]>('get_forensic_apps', { target });
      setApps(appList);
    } catch (err) {
      setError(`Failed to scan target: ${err}`);
    }
  };

  const unmountTarget = async () => {
    if (!selectedTarget) return;
    
    try {
      await invoke('unmount_forensic_target', { target: selectedTarget });
      setSelectedTarget(null);
      setSystemInfo(null);
      setApps([]);
    } catch (err) {
      setError(`Failed to unmount: ${err}`);
    }
  };

  const startForensicScan = async () => {
    if (!selectedTarget) return;
    
    setError('');
    
    try {
      // Get data paths for keyword lists
      const dataPaths = await invoke<any>('get_data_paths');
      
      // Prepare keyword list paths
      const keywordLists: string[] = [];
      // Note: In production, read keyword list files from dataPaths.keyword_lists
      
      // Start forensic scan
      const resultsJson = await invoke<string>('perform_forensic_scan', {
        target: selectedTarget,
        scanApps: true,
        scanBrowser: true,
        scanMedia: true,
        scanKeywords: keywordLists.length > 0,
        checkHashes: true,
        generateThumbnails: true,
        keywordLists,
        useHashDb: true,
      });
      
      // Parse results
      const results = JSON.parse(resultsJson);
      
      // Navigate to results view or show results
      console.log('Forensic scan results:', results);
      alert(`Scan complete!\n\nApps: ${results.scanStatistics.totalApps}\nBrowser entries: ${results.scanStatistics.browserEntries}\nMedia files: ${results.scanStatistics.mediaFilesFound}\nFlagged media: ${results.scanStatistics.flaggedMedia}\nDuration: ${results.scanStatistics.scanDurationSeconds}s`);
      
      // TODO: Navigate to results dashboard or save results
      
    } catch (err) {
      setError(`Forensic scan failed: ${err}`);
    }
  };

  const getTargetName = (target: TargetSystem): string => {
    if ('Windows' in target && target.Windows) {
      return `Windows (${target.Windows.partition})`;
    } else if ('ChromeOS' in target && target.ChromeOS) {
      return `Chrome OS (${target.ChromeOS.partition})`;
    }
    return 'Unknown System';
  };

  // Not in forensic mode - don't render
  if (!isForensicMode) {
    return null;
  }

  return (
    <div className="forensic-detector">
      <div className="forensic-header">
        <h2>🔍 Forensic Mode - Target Detection</h2>
        <p className="forensic-subtitle">
          Scanning for Windows and Chrome OS partitions...
        </p>
      </div>

      {isDetecting && (
        <div className="detecting-spinner">
          <div className="spinner"></div>
          <p>Detecting target systems...</p>
        </div>
      )}

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      {!selectedTarget && targets.length > 0 && (
        <div className="target-selection">
          <h3>Select Target System</h3>
          <div className="target-list">
            {targets.map((target, index) => (
              <button
                key={index}
                className="target-card"
                onClick={() => selectTarget(target)}
              >
                <div className="target-icon">
                  {'Windows' in target ? '🪟' : '🌐'}
                </div>
                <div className="target-info">
                  <h4>{getTargetName(target)}</h4>
                  {'Windows' in target && target.Windows && (
                    <p className="target-detail">{target.Windows.version}</p>
                  )}
                </div>
              </button>
            ))}
          </div>
          <button 
            className="btn-secondary" 
            onClick={detectTargets}
            disabled={isDetecting}
          >
            🔄 Refresh Detection
          </button>
        </div>
      )}

      {selectedTarget && systemInfo && (
        <div className="target-details">
          <div className="details-header">
            <h3>📊 Target System Information</h3>
            <button className="btn-danger" onClick={unmountTarget}>
              Unmount & Exit
            </button>
          </div>

          <div className="system-info-grid">
            <div className="info-item">
              <label>Operating System:</label>
              <span>{systemInfo.os_name}</span>
            </div>
            <div className="info-item">
              <label>Version:</label>
              <span>{systemInfo.os_version}</span>
            </div>
            <div className="info-item">
              <label>Computer Name:</label>
              <span>{systemInfo.computer_name}</span>
            </div>
            <div className="info-item">
              <label>Username:</label>
              <span>{systemInfo.username}</span>
            </div>
          </div>

          <div className="apps-section">
            <h4>Installed Applications ({apps.length})</h4>
            <div className="apps-list">
              {apps.slice(0, 10).map((app, index) => (
                <div key={index} className="app-item">
                  <div className="app-name">{app.name}</div>
                  <div className="app-publisher">{app.publisher}</div>
                </div>
              ))}
              {apps.length > 10 && (
                <div className="apps-more">
                  + {apps.length - 10} more applications
                </div>
              )}
            </div>
          </div>

          <div className="forensic-actions">
            <button 
              className="btn-primary" 
              onClick={() => startForensicScan()}
            >
              Start Full Forensic Scan
            </button>
          </div>
        </div>
      )}

      {targets.length === 0 && !isDetecting && !error && (
        <div className="no-targets">
          <p>No target systems detected.</p>
          <button className="btn-primary" onClick={detectTargets}>
            Try Detection Again
          </button>
        </div>
      )}
    </div>
  );
};
