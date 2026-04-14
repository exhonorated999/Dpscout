import React, { useEffect, useState } from 'react';
import { ScanProgress as ScanProgressType } from '../types/report';
import './ScanProgress.css';

interface ScanProgressProps {
  progress: ScanProgressType[];
  onCancel?: () => void;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ progress, onCancel }) => {
  const [particles, setParticles] = useState<Array<{ id: number; x: number; y: number; size: number }>>([]);

  useEffect(() => {
    // Generate background particles
    const newParticles = Array.from({ length: 30 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 3 + 1,
    }));
    setParticles(newParticles);
  }, []);

  const activeModule = progress.find(p => p.status === 'scanning');
  const completedCount = progress.filter(p => p.status === 'complete').length;
  const totalModules = progress.length;
  const overallProgress = (completedCount / totalModules) * 100;

  return (
    <div className="scan-progress-overlay">
      <div className="scan-progress-background">
        {particles.map(particle => (
          <div
            key={particle.id}
            className="particle"
            style={{
              left: `${particle.x}%`,
              top: `${particle.y}%`,
              width: `${particle.size}px`,
              height: `${particle.size}px`,
              animationDelay: `${Math.random() * 5}s`,
            }}
          />
        ))}
      </div>

      <div className="scan-progress-content">
        <div className="scan-progress-header">
          <div className="scanner-icon">
            <div className="scanner-beam"></div>
            <div className="scanner-grid">
              {Array.from({ length: 9 }).map((_, i) => (
                <div key={i} className="grid-cell"></div>
              ))}
            </div>
          </div>
          <h1 className="scan-title">SCANNING SYSTEM</h1>
          <p className="scan-subtitle">Analyzing target device for evidence</p>
        </div>

        {activeModule && (
          <div className="active-module-display">
            <div className="module-name">{activeModule.moduleName}</div>
            <div className="module-status">
              {activeModule.currentItem && (
                <div className="current-item">
                  <span className="item-label">Processing:</span>
                  <span className="item-path">{truncatePath(activeModule.currentItem, 60)}</span>
                </div>
              )}
              <div className="module-stats">
                <span className="stat">
                  {activeModule.itemsProcessed.toLocaleString()} / {activeModule.totalItems.toLocaleString()} items
                </span>
                {activeModule.itemsPerSecond > 0 && (
                  <span className="stat speed">
                    {activeModule.itemsPerSecond.toFixed(1)} items/sec
                  </span>
                )}
              </div>
            </div>

            <div className="progress-bar-container">
              <div className="progress-bar-background">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${activeModule.percentage}%` }}
                >
                  <div className="progress-shine"></div>
                </div>
              </div>
              <div className="progress-info">
                <span className="percentage">{activeModule.percentage.toFixed(1)}%</span>
                {activeModule.estimatedTimeRemaining > 0 && (
                  <span className="eta">
                    ETA: {formatTime(activeModule.estimatedTimeRemaining)}
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="modules-list">
          {progress.map((module, index) => (
            <ModuleItem key={module.moduleId} module={module} index={index} />
          ))}
        </div>

        <div className="overall-progress">
          <div className="overall-label">Overall Progress</div>
          <div className="overall-bar-container">
            <div
              className="overall-bar-fill"
              style={{ width: `${overallProgress}%` }}
            ></div>
          </div>
          <div className="overall-stats">
            {completedCount} of {totalModules} modules completed
          </div>
        </div>

        {onCancel && (
          <button className="cancel-button" onClick={onCancel}>
            Cancel Scan
          </button>
        )}
      </div>
    </div>
  );
};

const ModuleItem: React.FC<{ module: ScanProgressType; index: number }> = ({ module, index }) => {
  return (
    <div className={`module-item status-${module.status}`}>
      <div className="module-indicator">
        {module.status === 'complete' && <span className="indicator-icon">✓</span>}
        {module.status === 'scanning' && <span className="indicator-icon spinning">⟳</span>}
        {module.status === 'pending' && <span className="indicator-icon">○</span>}
        {module.status === 'error' && <span className="indicator-icon">✕</span>}
      </div>
      <div className="module-info">
        <div className="module-title">{module.moduleName}</div>
        {module.status === 'scanning' && (
          <div className="module-progress-mini">
            <div
              className="module-progress-mini-fill"
              style={{ width: `${module.percentage}%` }}
            ></div>
          </div>
        )}
        {module.status === 'complete' && module.itemsProcessed > 0 && (
          <div className="module-summary">
            {module.itemsProcessed.toLocaleString()} items scanned
          </div>
        )}
      </div>
    </div>
  );
};

function truncatePath(path: string, maxLength: number): string {
  if (path.length <= maxLength) return path;
  const parts = path.split('\\');
  if (parts.length <= 2) return path;
  
  const filename = parts[parts.length - 1];
  const drive = parts[0];
  const available = maxLength - drive.length - filename.length - 6;
  
  if (available < 0) {
    return `${drive}\\...\\${filename.substring(0, maxLength - drive.length - 6)}...`;
  }
  
  return `${drive}\\...\\${filename}`;
}

function formatTime(seconds: number): string {
  if (seconds < 60) {
    return `${Math.ceil(seconds)}s`;
  }
  
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.ceil(seconds % 60);
  
  if (minutes < 60) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
}
