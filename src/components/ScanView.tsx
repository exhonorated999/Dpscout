import React, { useState } from 'react';
import { Layout } from './Layout';
import { Button } from './Button';
// import { StatusBar } from './StatusBar';  // Temporarily disabled
import { AppResultCard } from './AppResultCard';
import { AppDetails } from './AppDetails';
import { QuestionableApp } from '../types/scanner';
import './ScanView.css';

interface ScanViewProps {
  apps: QuestionableApp[];
  isScanning: boolean;
  onNewScan: () => void;
  onOpenSettings: () => void;
  onOpenReport: () => void;
}

export const ScanView: React.FC<ScanViewProps> = ({ apps, isScanning, onNewScan, onOpenSettings, onOpenReport }) => {
  const [selectedApp, setSelectedApp] = useState<QuestionableApp | null>(null);
  const [taggedApps, setTaggedApps] = useState<Set<string>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  const handleTagApp = (app: QuestionableApp) => {
    const key = `${app.name}-${app.install_path}`;
    setTaggedApps(prev => {
      const newSet = new Set(prev);
      if (newSet.has(key)) {
        newSet.delete(key);
      } else {
        newSet.add(key);
      }
      return newSet;
    });
  };

  const isAppTagged = (app: QuestionableApp): boolean => {
    const key = `${app.name}-${app.install_path}`;
    return taggedApps.has(key);
  };

  // Filter apps by category
  const filteredApps = categoryFilter 
    ? apps.filter(app => app.category === categoryFilter)
    : apps;

  // Count apps by category
  const categoryCounts = apps.reduce((acc, app) => {
    acc[app.category] = (acc[app.category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const navigation = (
    <div className="scan-navigation">
      <div className="nav-header">
        <h2>HINDSIGHT</h2>
        <div className="nav-status">
          {apps.length > 0 && (
            <span className="status-badge">
              {apps.length} App{apps.length !== 1 ? 's' : ''} Detected
            </span>
          )}
        </div>
      </div>

      <div className="nav-actions">
        <Button 
          variant="secondary" 
          size="sm" 
          onClick={onOpenSettings}
        >
          ⚙️ Settings
        </Button>
        <Button 
          variant="primary" 
          size="sm" 
          onClick={onNewScan}
          disabled={isScanning}
        >
          New Scan
        </Button>
        {apps.length > 0 && (
          <Button 
            variant="danger" 
            size="sm"
            onClick={onOpenReport}
          >
            📊 Generate Report
          </Button>
        )}
      </div>

      <div className="nav-filters">
        <h3>Filter by Category</h3>
        <div className="module-list">
          <div 
            className={`module-item ${categoryFilter === null ? 'active' : ''}`}
            onClick={() => setCategoryFilter(null)}
          >
            <span className="module-icon">📋</span>
            <span className="module-name">All Categories</span>
            {apps.length > 0 && <span className="module-count">{apps.length}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'SocialMedia' ? 'active' : ''} ${!categoryCounts['SocialMedia'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['SocialMedia'] && setCategoryFilter('SocialMedia')}
          >
            <span className="module-icon">💬</span>
            <span className="module-name">Social Media</span>
            {categoryCounts['SocialMedia'] && <span className="module-count">{categoryCounts['SocialMedia']}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'PeerToPeer' ? 'active' : ''} ${!categoryCounts['PeerToPeer'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['PeerToPeer'] && setCategoryFilter('PeerToPeer')}
          >
            <span className="module-icon">🔗</span>
            <span className="module-name">Peer-to-Peer</span>
            {categoryCounts['PeerToPeer'] && <span className="module-count">{categoryCounts['PeerToPeer']}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'VPN' ? 'active' : ''} ${!categoryCounts['VPN'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['VPN'] && setCategoryFilter('VPN')}
          >
            <span className="module-icon">🔒</span>
            <span className="module-name">VPN Clients</span>
            {categoryCounts['VPN'] && <span className="module-count">{categoryCounts['VPN']}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'VirtualMachine' ? 'active' : ''} ${!categoryCounts['VirtualMachine'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['VirtualMachine'] && setCategoryFilter('VirtualMachine')}
          >
            <span className="module-icon">💻</span>
            <span className="module-name">Virtual Machines</span>
            {categoryCounts['VirtualMachine'] && <span className="module-count">{categoryCounts['VirtualMachine']}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'WebBrowser' ? 'active' : ''} ${!categoryCounts['WebBrowser'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['WebBrowser'] && setCategoryFilter('WebBrowser')}
          >
            <span className="module-icon">🌐</span>
            <span className="module-name">Web Browsers</span>
            {categoryCounts['WebBrowser'] && <span className="module-count">{categoryCounts['WebBrowser']}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'Cleaner' ? 'active' : ''} ${!categoryCounts['Cleaner'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['Cleaner'] && setCategoryFilter('Cleaner')}
          >
            <span className="module-icon">🧹</span>
            <span className="module-name">Cleaners/Shredders</span>
            {categoryCounts['Cleaner'] && <span className="module-count">{categoryCounts['Cleaner']}</span>}
          </div>
          <div 
            className={`module-item ${categoryFilter === 'Encryption' ? 'active' : ''} ${!categoryCounts['Encryption'] ? 'disabled' : ''}`}
            onClick={() => categoryCounts['Encryption'] && setCategoryFilter('Encryption')}
          >
            <span className="module-icon">🔐</span>
            <span className="module-name">Encryption Tools</span>
            {categoryCounts['Encryption'] && <span className="module-count">{categoryCounts['Encryption']}</span>}
          </div>
        </div>
      </div>
      
      <div className="nav-filters" style={{ marginTop: 'var(--spacing-lg)' }}>
        <h3>Other Modules</h3>
        <div className="module-list">
          <div className="module-item disabled">
            <span className="module-icon">🌐</span>
            <span className="module-name">Browser History</span>
          </div>
          <div className="module-item disabled">
            <span className="module-icon">🔍</span>
            <span className="module-name">Keyword Search</span>
          </div>
          <div className="module-item disabled">
            <span className="module-icon">🖼️</span>
            <span className="module-name">Media Gallery</span>
          </div>
        </div>
      </div>
    </div>
  );

  const results = (
    <div className="scan-results">
      <div className="results-header">
        <h2>Detected Applications</h2>
        {filteredApps.length > 0 && (
          <span className="results-count">
            {filteredApps.length} result{filteredApps.length !== 1 ? 's' : ''}
            {categoryFilter && ` (filtered)`}
          </span>
        )}
      </div>

      {isScanning && (
        <div className="scanning-indicator">
          <div className="spinner"></div>
          <p>Scanning system for questionable applications...</p>
        </div>
      )}

      {!isScanning && apps.length === 0 && (
        <div className="no-results">
          <div className="no-results-icon">✓</div>
          <h3>No Questionable Applications Detected</h3>
          <p>The scan did not find any VPN clients, encryption tools, or file shredders.</p>
        </div>
      )}

      {!isScanning && apps.length > 0 && filteredApps.length === 0 && (
        <div className="no-results">
          <div className="no-results-icon">🔍</div>
          <h3>No Results in This Category</h3>
          <p>No applications found matching the selected filter.</p>
        </div>
      )}

      {!isScanning && filteredApps.length > 0 && (
        <div className="results-list">
          {filteredApps.map((app, index) => (
            <AppResultCard
              key={`${app.name}-${index}`}
              app={app}
              isSelected={selectedApp === app}
              onClick={() => setSelectedApp(app)}
              onTag={() => handleTagApp(app)}
              isTagged={isAppTagged(app)}
            />
          ))}
        </div>
      )}
    </div>
  );

  const details = <AppDetails app={selectedApp} />;

  return (
    <>
      <Layout navigation={navigation} results={results} details={details} />
      {/* StatusBar temporarily disabled */}
    </>
  );
};
