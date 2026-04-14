import React from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { Button } from './Button';
import './ScanConfig.css';

interface ItunesBackup {
  udid: string;
  deviceName: string;
  backupPath: string;
  lastBackupDate: string;
  iosVersion: string;
  deviceModel: string;
  backupSizeMb: number;
}

interface ItunesBackupScannerProps {
  onBackupSelected: (backupPath: string, udid: string) => void;
}

export const ItunesBackupScanner: React.FC<ItunesBackupScannerProps> = ({ onBackupSelected }) => {
  const [backups, setBackups] = React.useState<ItunesBackup[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [selectedBackup, setSelectedBackup] = React.useState<string | null>(null);

  const loadBackups = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const foundBackups = await invoke<ItunesBackup[]>('list_itunes_backups');
      console.log('Found iTunes backups:', foundBackups);
      setBackups(foundBackups);
      
      if (foundBackups.length === 0) {
        setError('No iTunes backups found. Create a backup in iTunes or using SCOUT first.');
      }
    } catch (err) {
      console.error('Failed to list iTunes backups:', err);
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const selectBackupManually = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: 'Select iTunes Backup Folder'
      });

      if (selected && typeof selected === 'string') {
        console.log('Manually selected backup:', selected);
        
        // Extract UDID from path (last folder name)
        const pathParts = selected.split(/[\\/]/);
        const udid = pathParts[pathParts.length - 1];
        
        // Create a manual backup entry
        const manualBackup: ItunesBackup = {
          udid: udid,
          deviceName: 'Manually Selected Device',
          backupPath: selected,
          lastBackupDate: 'Unknown',
          iosVersion: 'Unknown',
          deviceModel: 'Unknown',
          backupSizeMb: 0
        };
        
        // Add to backups list
        setBackups(prev => [manualBackup, ...prev]);
        setError(null);
      }
    } catch (err) {
      console.error('Failed to select backup:', err);
      setError('Failed to select backup folder: ' + String(err));
    }
  };

  React.useEffect(() => {
    loadBackups();
  }, []);

  const handleScanBackup = (backup: ItunesBackup) => {
    setSelectedBackup(backup.udid);
    onBackupSelected(backup.backupPath, backup.udid);
  };

  const formatDate = (dateStr: string) => {
    if (dateStr === 'Unknown') return dateStr;
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const formatSize = (sizeMb: number) => {
    if (sizeMb < 1024) {
      return `${sizeMb.toFixed(1)} MB`;
    }
    return `${(sizeMb / 1024).toFixed(1)} GB`;
  };

  return (
    <div className="itunes-backup-scanner">
      <div className="section-header">
        <div>
          <h3>📱 Scan Existing iTunes Backup</h3>
          <p>Select a previously created iTunes backup to analyze</p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <Button variant="secondary" onClick={loadBackups}>
            🔄 Refresh
          </Button>
          <Button variant="primary" onClick={selectBackupManually}>
            📁 Select Backup
          </Button>
        </div>
      </div>

      {loading && (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Searching for iTunes backups...</p>
        </div>
      )}

      {error && (
        <div className="error-message">
          <p>⚠️ {error}</p>
          <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
            <Button variant="secondary" onClick={loadBackups}>
              Retry
            </Button>
            <Button variant="primary" onClick={selectBackupManually}>
              Select Backup Manually
            </Button>
          </div>
        </div>
      )}

      {!loading && !error && backups.length > 0 && (
        <div className="backups-list">
          {backups.map((backup) => (
            <div 
              key={backup.udid} 
              className={`backup-card ${selectedBackup === backup.udid ? 'selected' : ''}`}
            >
              <div className="backup-info">
                <div className="backup-header">
                  <h4>{backup.deviceName}</h4>
                  <span className="backup-model">{backup.deviceModel}</span>
                </div>
                
                <div className="backup-details">
                  <div className="detail-row">
                    <span className="label">iOS Version:</span>
                    <span className="value">{backup.iosVersion}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Last Backup:</span>
                    <span className="value">{formatDate(backup.lastBackupDate)}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Backup Size:</span>
                    <span className="value">{formatSize(backup.backupSizeMb)}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">UDID:</span>
                    <span className="value udid">{backup.udid}</span>
                  </div>
                </div>
              </div>

              <button 
                onClick={() => handleScanBackup(backup)}
                className="button-primary"
                disabled={selectedBackup === backup.udid}
              >
                {selectedBackup === backup.udid ? 'Selected ✓' : 'Scan This Backup'}
              </button>
            </div>
          ))}
        </div>
      )}

      {!loading && !error && backups.length === 0 && (
        <div className="no-backups">
          <p>No iTunes backups found on this computer.</p>
          <div className="help-text">
            <h4>To create a backup:</h4>
            <ol>
              <li>Connect your iPhone via USB</li>
              <li>Use the "Create iOS Backup" option above, or</li>
              <li>Open iTunes and click "Back Up Now"</li>
            </ol>
          </div>
        </div>
      )}
    </div>
  );
};

export default ItunesBackupScanner;
