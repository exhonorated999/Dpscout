import React, { useState } from 'react';
import { NavigationSidebar, NavItem } from './NavigationSidebar';
import { QuestionableApp } from '../types/scanner';
import { MediaFile } from '../types/media';
import { KeywordMatch } from '../types/keyword';
import { BrowserData } from '../types/browser';
import './ResultsDashboard.css';

interface ResultsDashboardProps {
  apps: QuestionableApp[];
  media: MediaFile[];
  keywords: KeywordMatch[];
  browsers: BrowserData[];
  onNavigate: (view: string) => void;
}

export const ResultsDashboard: React.FC<ResultsDashboardProps> = ({
  apps,
  media,
  keywords,
  browsers,
  onNavigate
}) => {
  const [activeView, setActiveView] = useState<string>('apps');

  const navItems: NavItem[] = [
    {
      id: 'apps',
      label: 'INSTALLED\nAPPLICATIONS',
      icon: '<svg width="48" height="48" viewBox="0 0 48 48"><path d="M14 12h20v4H14z M10 20h28v16H10z" fill="currentColor" opacity="0.3"/><rect x="12" y="22" width="24" height="4" fill="currentColor"/><text x="24" y="32" font-size="14" fill="currentColor" text-anchor="middle">P</text></svg>',
      count: apps.length,
      active: activeView === 'apps',
      onClick: () => { setActiveView('apps'); onNavigate('apps'); }
    },
    {
      id: 'keywords',
      label: 'KEYWORD HITS',
      icon: '<svg width="48" height="48" viewBox="0 0 48 48"><circle cx="20" cy="20" r="10" stroke="currentColor" stroke-width="2" fill="none"/><line x1="27" y1="27" x2="36" y2="36" stroke="currentColor" stroke-width="2"/><text x="20" y="24" font-size="10" fill="currentColor" text-anchor="middle">text</text></svg>',
      count: keywords.length,
      active: activeView === 'keywords',
      onClick: () => { setActiveView('keywords'); onNavigate('keywords'); }
    },
    {
      id: 'media',
      label: 'CSAM HASH HITS',
      icon: '<svg width="48" height="48" viewBox="0 0 48 48"><path d="M24 12 L32 24 L24 36 L16 24 Z" stroke="currentColor" stroke-width="2" fill="none"/><text x="24" y="27" font-size="12" fill="currentColor" text-anchor="middle">010</text></svg>',
      count: media.filter(m => m.flags && m.flags.length > 0).length,
      active: activeView === 'media',
      onClick: () => { setActiveView('media'); onNavigate('media'); }
    },
    {
      id: 'browser',
      label: 'BROWSER\nSEARCH HISTORY',
      icon: '<svg width="48" height="48" viewBox="0 0 48 48"><circle cx="24" cy="24" r="14" stroke="currentColor" stroke-width="2" fill="none"/><path d="M24 10 L28 14 M40 24 L36 28 M24 38 L20 34 M8 24 L12 20" stroke="currentColor" stroke-width="2"/><path d="M24 24 L32 18" stroke="currentColor" stroke-width="2"/></svg>',
      count: browsers.reduce((sum, b) => sum + b.history.length, 0),
      active: activeView === 'browser',
      onClick: () => { setActiveView('browser'); onNavigate('browser'); }
    }
  ];

  return (
    <div className="results-dashboard">
      <NavigationSidebar items={navItems} />
      
      <div className="results-content">
        <div className="results-header">
          <h1 className="results-title">
            {activeView === 'apps' && 'INSTALLED APPLICATIONS'}
            {activeView === 'keywords' && 'KEYWORD HITS'}
            {activeView === 'media' && 'CSAM HASH HITS - SCAN RESULTS'}
            {activeView === 'browser' && 'BROWSER SEARCH HISTORY'}
          </h1>
          <div className="scan-status scanning">
            <span className="status-text">SCANNING...</span>
            <div className="status-spinner"></div>
          </div>
        </div>

        <div className="results-visualization">
          <div className="scan-flow">
            {Array.from({ length: 9 }).map((_, i) => (
              <div key={i} className="flow-node" style={{ 
                animationDelay: `${i * 0.2}s`,
                gridColumn: (i % 3) + 1,
                gridRow: Math.floor(i / 3) + 1
              }}>
                <svg width="60" height="60" viewBox="0 0 60 60">
                  <rect x="10" y="15" width="40" height="30" stroke="var(--accent-orange)" strokeWidth="2" fill="none" strokeDasharray="4 4"/>
                  <line x1="20" y1="25" x2="40" y2="25" stroke="var(--accent-orange)" strokeWidth="1"/>
                  <line x1="20" y1="30" x2="35" y2="30" stroke="var(--accent-orange)" strokeWidth="1"/>
                  <line x1="20" y1="35" x2="38" y2="35" stroke="var(--accent-orange)" strokeWidth="1"/>
                </svg>
              </div>
            ))}
            {/* Connection lines */}
            <svg className="flow-connections" viewBox="0 0 400 400">
              <line x1="100" y1="67" x2="200" y2="67" className="connection-line" />
              <line x1="200" y1="67" x2="300" y2="67" className="connection-line" />
              <line x1="100" y1="200" x2="200" y2="200" className="connection-line" />
              <line x1="200" y1="200" x2="300" y2="200" className="connection-line" />
              <line x1="100" y1="333" x2="200" y2="333" className="connection-line" />
              <line x1="200" y1="333" x2="300" y2="333" className="connection-line" />
              
              <line x1="100" y1="100" x2="100" y2="167" className="connection-line" />
              <line x1="200" y1="100" x2="200" y2="167" className="connection-line" />
              <line x1="300" y1="100" x2="300" y2="167" className="connection-line" />
              <line x1="100" y1="233" x2="100" y2="300" className="connection-line" />
              <line x1="200" y1="233" x2="200" y2="300" className="connection-line" />
              <line x1="300" y1="233" x2="300" y2="300" className="connection-line" />
            </svg>
          </div>
        </div>

        <div className="results-table">
          <div className="table-header">
            <div className="table-col">FILE PATH</div>
            <div className="table-col">HASH VALUE</div>
            <div className="table-col">PREVIEW</div>
            <div className="table-col">FLAG</div>
          </div>
          <div className="table-body">
            {media.slice(0, 5).map((item, idx) => (
              <div key={idx} className="table-row">
                <div className="table-col file-path">{item.filePath}</div>
                <div className="table-col hash-value">{item.md5Hash || item.sha256Hash || 'N/A'}</div>
                <div className="table-col preview">
                  <div className="preview-thumbnail">
                    {item.thumbnailPath ? (
                      <img src={item.thumbnailPath} alt="Preview" />
                    ) : (
                      <div className="preview-placeholder">🖼️</div>
                    )}
                  </div>
                </div>
                <div className="table-col flag-col">
                  <button className="flag-button">FLAG</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
