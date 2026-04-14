import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AndroidDevice, AndroidApp, AndroidBrowserData, AndroidHashMatch } from "../types/android";
import { SmsViewer } from "./SmsViewer";
import "./AndroidView.css";

interface AndroidViewProps {
  onBack: () => void;
}

type ViewMode = "devices" | "apps" | "browser" | "files" | "sms" | "hashScan";

export function AndroidView({ onBack }: AndroidViewProps) {
  const [adbAvailable, setAdbAvailable] = useState<boolean | null>(null);
  const [devices, setDevices] = useState<AndroidDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<AndroidDevice | null>(null);
  const [apps, setApps] = useState<AndroidApp[]>([]);
  const [browserData, setBrowserData] = useState<AndroidBrowserData | null>(null);
  const [hashMatches, setHashMatches] = useState<AndroidHashMatch[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>("devices");
  const [isLoading, setIsLoading] = useState(false);
  const [isHashScanning, setIsHashScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isPullingFiles, setIsPullingFiles] = useState(false);

  useEffect(() => {
    checkAdb();
  }, []);

  async function checkAdb() {
    try {
      const available = await invoke<boolean>("check_adb_available");
      setAdbAvailable(available);
      if (available) {
        await refreshDevices();
      }
    } catch (err) {
      setError("Failed to check ADB availability");
      console.error(err);
    }
  }

  async function refreshDevices() {
    setIsLoading(true);
    setError(null);
    try {
      const deviceList = await invoke<AndroidDevice[]>("get_android_devices");
      setDevices(deviceList);
      if (deviceList.length === 1) {
        setSelectedDevice(deviceList[0]);
      }
    } catch (err) {
      setError(err as string);
    } finally {
      setIsLoading(false);
    }
  }

  async function scanApps() {
    if (!selectedDevice) return;
    
    setIsLoading(true);
    setError(null);
    try {
      const appList = await invoke<AndroidApp[]>("get_android_apps", {
        serial: selectedDevice.serial,
      });
      setApps(appList);
      setViewMode("apps");
    } catch (err) {
      setError(err as string);
    } finally {
      setIsLoading(false);
    }
  }

  async function scanBrowser() {
    if (!selectedDevice) return;
    
    setIsLoading(true);
    setError(null);
    try {
      const data = await invoke<AndroidBrowserData>("get_android_chrome_history", {
        serial: selectedDevice.serial,
      });
      setBrowserData(data);
      setViewMode("browser");
    } catch (err) {
      setError(err as string);
    } finally {
      setIsLoading(false);
    }
  }

  async function scanForHashes() {
    if (!selectedDevice) return;
    
    setIsHashScanning(true);
    setError(null);
    try {
      const matches = await invoke<AndroidHashMatch[]>("scan_android_media_hashes", {
        serial: selectedDevice.serial,
      });
      setHashMatches(matches);
      setViewMode("hashScan");
    } catch (err) {
      setError(err as string);
    } finally {
      setIsHashScanning(false);
    }
  }

  async function pullFiles() {
    if (!selectedDevice) return;
    
    setIsPullingFiles(true);
    setError(null);
    try {
      const paths = [
        "/sdcard/Download",
        "/sdcard/DCIM",
        "/sdcard/Pictures",
        "/sdcard/Documents",
      ];
      
      const tempDir = await invoke<string>("pull_android_files", {
        serial: selectedDevice.serial,
        paths,
      });
      
      alert(`Files pulled to: ${tempDir}\nYou can now scan this directory using the regular file scanner.`);
      setViewMode("files");
    } catch (err) {
      setError(err as string);
    } finally {
      setIsPullingFiles(false);
    }
  }

  function renderAdbWarning() {
    return (
      <div className="android-warning">
        <div className="warning-icon">⚠️</div>
        <h2>ADB Not Available</h2>
        <p>Android Debug Bridge (ADB) is required to scan Android devices.</p>
        <div className="warning-instructions">
          <h3>Installation Instructions:</h3>
          <ol>
            <li>Download Android Platform Tools from Google</li>
            <li>Extract the archive</li>
            <li>Add the platform-tools directory to your PATH</li>
            <li>Restart this application</li>
          </ol>
          <a 
            href="https://developer.android.com/tools/releases/platform-tools"
            target="_blank"
            rel="noopener noreferrer"
            className="download-link"
          >
            Download Platform Tools
          </a>
        </div>
        <button className="btn-secondary" onClick={onBack}>
          Back
        </button>
      </div>
    );
  }

  function renderDeviceList() {
    if (devices.length === 0) {
      return (
        <div className="android-empty">
          <div className="empty-icon">📱</div>
          <h2>No Devices Found</h2>
          <p>Make sure your Android device is:</p>
          <ul>
            <li>Connected via USB</li>
            <li>USB Debugging is enabled</li>
            <li>You've authorized this computer on the device</li>
          </ul>
          <button className="btn-primary" onClick={refreshDevices} disabled={isLoading}>
            {isLoading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      );
    }

    return (
      <div className="device-list">
        <h2>Connected Devices</h2>
        {devices.map((device) => (
          <div
            key={device.serial}
            className={`device-card ${selectedDevice?.serial === device.serial ? "selected" : ""}`}
            onClick={() => setSelectedDevice(device)}
          >
            <div className="device-icon">📱</div>
            <div className="device-info">
              <h3>{device.deviceName || device.model}</h3>
              <p className="device-detail">{device.manufacturer} {device.model}</p>
              <p className="device-detail">Android {device.androidVersion}</p>
              <p className="device-serial">Serial: {device.serial}</p>
              <span className={`device-status ${device.state === "device" ? "online" : "offline"}`}>
                {device.state}
              </span>
            </div>
          </div>
        ))}
        
        {selectedDevice && (
          <div className="device-actions">
            <h3>Scan Options</h3>
            <div className="action-buttons">
              <button className="btn-primary" onClick={scanApps} disabled={isLoading}>
                📦 Scan Installed Apps
              </button>
              <button className="btn-primary" onClick={scanBrowser} disabled={isLoading}>
                🌐 Scan Browser History
              </button>
              <button className="btn-primary" onClick={() => setViewMode("sms")} disabled={isLoading}>
                💬 View SMS Messages
              </button>
              <button 
                className="btn-primary hash-scan-button" 
                onClick={scanForHashes} 
                disabled={isHashScanning}
                title="Scan media files for known CSAM hashes"
              >
                🔍 {isHashScanning ? "Scanning Hashes..." : "Hash Scan (CSAM)"}
              </button>
              <button className="btn-primary" onClick={pullFiles} disabled={isPullingFiles}>
                📁 {isPullingFiles ? "Pulling Files..." : "Pull Files for Scanning"}
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  function renderApps() {
    const userApps = apps.filter(app => !app.isSystemApp);
    const systemApps = apps.filter(app => app.isSystemApp);

    return (
      <div className="apps-view">
        <div className="view-header">
          <button className="btn-back" onClick={() => setViewMode("devices")}>
            ← Back to Devices
          </button>
          <h2>Installed Apps ({apps.length})</h2>
        </div>

        {userApps.length > 0 && (
          <div className="app-section">
            <h3>User Apps ({userApps.length})</h3>
            <div className="app-list">
              {userApps.map((app) => (
                <div key={app.packageName} className="app-card">
                  <div className="app-icon">📱</div>
                  <div className="app-info">
                    <h4>{app.appName}</h4>
                    <p className="app-package">{app.packageName}</p>
                    <p className="app-meta">Version {app.version}</p>
                    <p className="app-meta">Installed: {app.installTime}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {systemApps.length > 0 && (
          <div className="app-section">
            <h3>System Apps ({systemApps.length})</h3>
            <div className="app-list">
              {systemApps.map((app) => (
                <div key={app.packageName} className="app-card system">
                  <div className="app-icon">⚙️</div>
                  <div className="app-info">
                    <h4>{app.appName}</h4>
                    <p className="app-package">{app.packageName}</p>
                    <p className="app-meta">Version {app.version}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  function renderBrowser() {
    if (!browserData) return null;

    return (
      <div className="browser-view">
        <div className="view-header">
          <button className="btn-back" onClick={() => setViewMode("devices")}>
            ← Back to Devices
          </button>
          <h2>{browserData.browserName} History</h2>
        </div>

        {browserData.history.length > 0 && (
          <div className="history-section">
            <h3>Browsing History ({browserData.history.length})</h3>
            <div className="history-list">
              {browserData.history.map((entry, index) => (
                <div key={index} className="history-entry">
                  <div className="history-icon">🌐</div>
                  <div className="history-info">
                    <h4>{entry.title || "Untitled"}</h4>
                    <a href={entry.url} target="_blank" rel="noopener noreferrer" className="history-url">
                      {entry.url}
                    </a>
                    <p className="history-meta">
                      Visits: {entry.visitCount} | Last visit: {entry.lastVisit}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {browserData.bookmarks.length > 0 && (
          <div className="bookmark-section">
            <h3>Bookmarks ({browserData.bookmarks.length})</h3>
            <div className="bookmark-list">
              {browserData.bookmarks.map((bookmark, index) => (
                <div key={index} className="bookmark-entry">
                  <div className="bookmark-icon">⭐</div>
                  <div className="bookmark-info">
                    <h4>{bookmark.title}</h4>
                    <a href={bookmark.url} target="_blank" rel="noopener noreferrer" className="bookmark-url">
                      {bookmark.url}
                    </a>
                    <p className="bookmark-folder">Folder: {bookmark.folder}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  function renderHashScanResults() {
    return (
      <div className="hash-scan-view">
        <div className="view-header">
          <button className="btn-back" onClick={() => setViewMode("devices")}>
            ← Back to Devices
          </button>
          <h2>Hash Scan Results</h2>
        </div>

        {hashMatches.length === 0 ? (
          <div className="no-matches">
            <div className="success-icon">✅</div>
            <h3>No Hash Matches Found</h3>
            <p>No files on the device matched known CSAM hashes.</p>
          </div>
        ) : (
          <div className="hash-matches-section">
            <div className="critical-warning">
              <div className="warning-icon">⚠️</div>
              <h3>CRITICAL: {hashMatches.length} Hash Match{hashMatches.length > 1 ? 'es' : ''} Found</h3>
              <p>The following files matched known CSAM hash databases:</p>
            </div>
            
            <div className="hash-match-list">
              {hashMatches.map((match, index) => (
                <div key={index} className="hash-match-entry critical">
                  <div className="match-header">
                    <span className="severity-badge critical">{match.severity}</span>
                    <h4>{match.fileName}</h4>
                  </div>
                  
                  <div className="match-details">
                    <div className="detail-row">
                      <span className="detail-label">File Path:</span>
                      <span className="detail-value">{match.filePath}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">File Size:</span>
                      <span className="detail-value">{(match.fileSize / 1024 / 1024).toFixed(2)} MB</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Matched Hash ({match.hashType}):</span>
                      <span className="detail-value hash-value">{match.matchedHash}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Hash List:</span>
                      <span className="detail-value">{match.listName}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Source:</span>
                      <span className="detail-value">{match.listSource}</span>
                    </div>
                    {match.description && (
                      <div className="detail-row">
                        <span className="detail-label">Description:</span>
                        <span className="detail-value">{match.description}</span>
                      </div>
                    )}
                  </div>
                  
                  <div className="match-hashes">
                    <details>
                      <summary>View Full Hashes</summary>
                      <div className="hash-info">
                        <div><strong>MD5:</strong> {match.md5Hash}</div>
                        <div><strong>SHA256:</strong> {match.sha256Hash}</div>
                      </div>
                    </details>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  function renderFilesView() {
    return (
      <div className="files-view">
        <div className="view-header">
          <button className="btn-back" onClick={() => setViewMode("devices")}>
            ← Back to Devices
          </button>
          <h2>Files Pulled Successfully</h2>
        </div>
        <div className="files-info">
          <p>Files have been copied to a temporary directory on your computer.</p>
          <p>You can now use the regular file scanner to scan these files for media content.</p>
          <button className="btn-primary" onClick={onBack}>
            Go to Main Menu
          </button>
        </div>
      </div>
    );
  }

  if (adbAvailable === null) {
    return (
      <div className="android-container">
        <div className="android-loading">
          <div className="spinner"></div>
          <p>Checking ADB availability...</p>
        </div>
      </div>
    );
  }

  if (adbAvailable === false) {
    return <div className="android-container">{renderAdbWarning()}</div>;
  }

  return (
    <div className="android-container">
      <div className="android-view">
        <div className="android-header">
          <h1>🤖 Android Device Scanner</h1>
          <div className="header-actions">
            <button className="btn-refresh" onClick={refreshDevices} disabled={isLoading}>
              🔄 Refresh Devices
            </button>
            <button className="btn-secondary" onClick={onBack}>
              ← Back
            </button>
          </div>
        </div>

        {error && (
          <div className="error-banner">
            <span className="error-icon">⚠️</span>
            <span>{error}</span>
            <button onClick={() => setError(null)}>×</button>
          </div>
        )}

        {isLoading && (
          <div className="loading-overlay">
            <div className="spinner"></div>
            <p>Loading...</p>
          </div>
        )}

        <div className="android-content">
          {viewMode === "devices" && renderDeviceList()}
          {viewMode === "apps" && renderApps()}
          {viewMode === "browser" && renderBrowser()}
          {viewMode === "hashScan" && renderHashScanResults()}
          {viewMode === "files" && renderFilesView()}
          {viewMode === "sms" && (
            <SmsViewer
              deviceId={selectedDevice?.serial || null}
              onClose={() => setViewMode("devices")}
            />
          )}
        </div>
      </div>
    </div>
  );
}
