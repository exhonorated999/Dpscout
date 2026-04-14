import React, { useState, useEffect } from 'react';
import './ScanningIndicator.css';

interface ScanningIndicatorProps {
  currentModule?: string;
  isScanning?: boolean;
  startTime?: Date;
  scanComplete?: boolean;
  scanDuration?: string;
  totalFilesScanned?: number;
  onDismiss?: () => void;
  onStopScan?: () => void;
  backupProgress?: number; // iOS backup progress (0-100)
}

export const ScanningIndicator: React.FC<ScanningIndicatorProps> = ({ 
  currentModule = "System", 
  isScanning = true,
  startTime,
  scanComplete = false,
  scanDuration,
  totalFilesScanned,
  onDismiss,
  onStopScan,
  backupProgress = 0
}) => {
  const [elapsedTime, setElapsedTime] = useState('00:00');

  useEffect(() => {
    if (!isScanning || !startTime) return;

    const updateElapsed = () => {
      const now = new Date();
      const diff = now.getTime() - startTime.getTime();
      const seconds = Math.floor(diff / 1000);
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = seconds % 60;
      setElapsedTime(
        `${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`
      );
    };

    updateElapsed();
    const interval = setInterval(updateElapsed, 1000);
    return () => clearInterval(interval);
  }, [isScanning, startTime]);

  // Show completion summary
  if (scanComplete && !isScanning) {
    return (
      <div className="scan-complete-indicator">
        <div className="complete-content">
          <div className="complete-icon">✓</div>
          <div className="complete-info">
            <span className="complete-label">SCAN COMPLETE</span>
            <div className="complete-stats">
              {scanDuration && <span className="stat">Duration: {scanDuration}</span>}
              {totalFilesScanned !== undefined && (
                <span className="stat">Files Scanned: {totalFilesScanned.toLocaleString()}</span>
              )}
            </div>
          </div>
        </div>
        {onDismiss && (
          <button className="dismiss-button" onClick={onDismiss}>✕</button>
        )}
      </div>
    );
  }

  if (!isScanning) return null;

  return (
    <div className="scanning-indicator">
      <div className="scanning-particles">
        {[...Array(12)].map((_, i) => (
          <div 
            key={i} 
            className="particle" 
            style={{
              '--angle': `${i * 30}deg`,
              '--delay': `${i * 0.1}s`
            } as React.CSSProperties}
          />
        ))}
      </div>
      
      <div className="scanning-content">
        <div className="scanning-text">
          SCANNING
          <span className="dots">
            <span className="dot">.</span>
            <span className="dot">.</span>
            <span className="dot">.</span>
          </span>
        </div>
        <div className="scanning-sonar">
          <div className="sonar-ring ring-1"></div>
          <div className="sonar-ring ring-2"></div>
          <div className="sonar-ring ring-3"></div>
          <div className="sonar-center"></div>
        </div>
      </div>
      
      <div className="scanning-footer">
        {currentModule && (
          <div className="scanning-module">
            <span className="module-label">ANALYZING:</span>
            <span className="module-name">{currentModule}</span>
          </div>
        )}
        {startTime && (
          <div className="scanning-timer">
            <span className="timer-label">ELAPSED:</span>
            <span className="timer-value">{elapsedTime}</span>
          </div>
        )}
        {backupProgress > 0 && backupProgress < 100 && (
          <div className="backup-progress-container">
            <div className="backup-progress-bar">
              <div 
                className="backup-progress-fill" 
                style={{ width: `${backupProgress}%` }}
              />
            </div>
            <div className="backup-progress-text">{backupProgress}%</div>
          </div>
        )}
        {onStopScan && (
          <button className="stop-scan-button" onClick={onStopScan}>
            <span className="stop-icon">■</span>
            STOP SCAN
          </button>
        )}
      </div>
    </div>
  );
};
