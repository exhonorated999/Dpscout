import React, { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { convertFileSrc } from '@tauri-apps/api/core';
import { QuestionableApp, AppCategoryLabels } from '../types/scanner';
import { MediaFile } from '../types/media';
// Hot reload trigger
import { KeywordMatch } from '../types/keyword';
import { BrowserData } from '../types/browser';
import { SystemInfo, UsbDeviceInfo } from '../types/system';
import { IntrusionScanResults, defaultIntrusionScanOptions } from '../types/intrusion';
import { ReportMetadata, ReportScope, ReportFormat, ReportPayload, ReportGenerationResult } from '../types/report';
import { AppSettings } from '../types/settings';
import { ScanningIndicator } from './ScanningIndicator';
import { ReportConfigModal } from './ReportConfigModal';
import { IosTriageView } from './IosTriageView';
import { MediaGallery } from './MediaGallery';
import { DeviceType } from './StartScreen';
import SmsConversationView from './SmsConversationView';
import './UnifiedDashboard.css';

// Clickable file path component
const ClickableFilePath: React.FC<{ path: string }> = ({ path }) => {
  const openFileLocation = async () => {
    try {
      // Try to open file location using Tauri command
      await invoke('open_file_location', { path });
      console.log(`Opened file location: ${path}`);
    } catch (invokeError) {
      console.error('Failed to open file location:', invokeError);
      // Fallback: copy to clipboard
      try {
        await navigator.clipboard.writeText(path);
        const fileName = path.split('\\').pop() || path.split('/').pop();
        alert(`Could not open file location.\n\nPath copied to clipboard:\n${path}`);
      } catch (clipboardError) {
        alert(`File path: ${path}`);
      }
    }
  };

  // Shorten display: show drive + "..." + last 2 path segments (skip GUIDs)
  const shortenPath = (p: string) => {
    if (!p) return '';
    const sep = p.includes('/') ? '/' : '\\';
    const parts = p.split(sep).filter(Boolean);
    if (parts.length <= 3) return p;
    // Find the drive/root
    const drive = parts[0].includes(':') ? parts[0] + sep : '';
    // Take last 2 meaningful segments
    const tail = parts.slice(-2).join(sep);
    return `${drive}...${sep}${tail}`;
  };

  return (
    <button 
      className="clickable-file-path"
      onClick={openFileLocation}
      title={path}
    >
      {shortenPath(path)}
    </button>
  );
};

interface ScanModules {
  questionableApps: boolean;
  browserHistory: boolean;
  mediaScan: boolean;
  keywordSearch: boolean;
  hashMatching: boolean;
  intrusionDetection: boolean;
}

interface UnifiedDashboardProps {
  apps: QuestionableApp[];
  media: MediaFile[];
  keywords: KeywordMatch[];
  browsers: BrowserData[];
  smsMessages?: any; // SMS extraction result (Android and iOS)
  systemInfo: SystemInfo | null;
  intrusionResults?: IntrusionScanResults | null; // Intrusion detection results
  hashMatches?: any[]; // Hash match results (for Android or standalone hash scanning)
  isScanning: boolean;
  currentScanModule?: string;
  scanProgress?: any[];
  backupProgress?: number; // iOS backup progress (0-100)
  onNewScan?: () => void;
  onStopScan?: () => void;
  onGenerateReport?: () => void;
  onViewHashDetails?: () => void;
  onViewKeywordDetails?: () => void;
  deviceType?: DeviceType; // NEW: Track device type
  settings?: AppSettings; // NEW: Pass settings for report generation
  selectedDrives?: string[]; // NEW: Track selected drives for USB mode
  scannedModules?: ScanModules | null; // NEW: Track which modules were scanned
}

type ViewType = 'device-info' | 'applications' | 'keywords' | 'media-files' | 'csam-hash' | 'browser-history' | 'sms-messages' | 'intrusion-artifacts' | 'ios-triage' | 'notes';
type BrowserTab = 'history' | 'downloads' | 'credentials';
type IntrusionTab = 'event-logs' | 'persistence' | 'command-history';

export const UnifiedDashboard: React.FC<UnifiedDashboardProps> = ({
  apps,
  media,
  keywords,
  browsers,
  smsMessages = null,
  systemInfo,
  intrusionResults: passedIntrusionResults = null,
  hashMatches = [],
  isScanning,
  currentScanModule = "",
  scanProgress = [],
  backupProgress = 0,
  onNewScan,
  onStopScan,
  onViewHashDetails,
  onViewKeywordDetails,
  onGenerateReport,
  deviceType = 'windows', // Default to windows
  settings,
  selectedDrives = [],
  scannedModules = null
}) => {
  const [activeView, setActiveView] = useState<ViewType>('device-info');
  const [browserExpanded, setBrowserExpanded] = useState(false);
  const [selectedBrowser, setSelectedBrowser] = useState<BrowserData | null>(null);
  const [keywordExpanded, setKeywordExpanded] = useState(false);
  const [selectedKeyword, setSelectedKeyword] = useState<string | null>(null);
  const [activeBrowserTab, setActiveBrowserTab] = useState<BrowserTab>('history');
  const [activeIntrusionTab, setActiveIntrusionTab] = useState<IntrusionTab>('event-logs');
  const [flaggedItems, setFlaggedItems] = useState<Set<string>>(new Set());
  const [intrusionResults, setIntrusionResults] = useState<IntrusionScanResults | null>(passedIntrusionResults);
  const [isScanningIntrusion, setIsScanningIntrusion] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [showMediaGallery, setShowMediaGallery] = useState(false);
  const [scanStartTime, setScanStartTime] = useState<Date | undefined>(undefined);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanDuration, setScanDuration] = useState<string | undefined>(undefined);
  const [totalFilesScanned, setTotalFilesScanned] = useState<number | undefined>(undefined);
  const [investigatorNotes, setInvestigatorNotes] = useState<string>('');

  // Track scan start time and completion
  React.useEffect(() => {
    if (isScanning && !scanStartTime) {
      setScanStartTime(new Date());
      setScanComplete(false);
    } else if (!isScanning && scanStartTime) {
      // Calculate duration
      const endTime = new Date();
      const diff = endTime.getTime() - scanStartTime.getTime();
      const seconds = Math.floor(diff / 1000);
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = seconds % 60;
      setScanDuration(`${minutes}m ${remainingSeconds}s`);
      
      // Calculate total files SCANNED (not just results) from scan progress data
      // This shows the actual number of files examined, demonstrating thorough scanning
      const totalScanned = scanProgress.reduce((sum, progress) => {
        // Only count completed scans with actual totals
        if (progress.status === 'complete' && progress.totalItems) {
          return sum + progress.totalItems;
        }
        return sum;
      }, 0);
      
      // If no scan progress data, fall back to result counts
      const fallbackTotal = apps.length + keywords.length + media.length + browsers.reduce((sum, b) => sum + b.history.length, 0);
      
      setTotalFilesScanned(totalScanned > 0 ? totalScanned : fallbackTotal);
      
      setScanComplete(true);
      setScanStartTime(undefined);
    }
  }, [isScanning, scanStartTime, apps.length, keywords.length, media.length, browsers, scanProgress]);

  // Update local intrusion results when passed from parent
  React.useEffect(() => {
    if (passedIntrusionResults !== null) {
      setIntrusionResults(passedIntrusionResults);
    }
  }, [passedIntrusionResults]);

  const toggleFlag = (itemId: string) => {
    setFlaggedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(itemId)) {
        newSet.delete(itemId);
      } else {
        newSet.add(itemId);
      }
      return newSet;
    });
  };

  const isFlagged = (itemId: string) => flaggedItems.has(itemId);

  const handleGenerateReport = async (metadata: ReportMetadata, scope: ReportScope, formats: ReportFormat[]) => {
    setIsGeneratingReport(true);
    
    try {
      // Prepare scan parameters based on what was actually scanned
      const scanParameters = {
        applications_scanned: apps.length > 0,
        browser_history_scanned: browsers.length > 0,
        keyword_search_performed: keywords.length > 0,
        hash_matching_performed: media.some(m => m.md5Hash || m.sha256Hash),
        media_scan_performed: media.length > 0,
        intrusion_detection_performed: intrusionResults !== null,
      };

      // Get drive information from system info
      const driveScanned = systemInfo?.drives?.map(d => d.mountPoint).join(', ') || 'C:\\';

      // Format scan duration from systemInfo if available, otherwise use calculated duration
      let formattedDuration = scanDuration;
      if (systemInfo?.scan_duration_secs) {
        const seconds = systemInfo.scan_duration_secs;
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        formattedDuration = `${minutes}m ${remainingSeconds}s`;
      }

      // Prepare the payload
      const payload: ReportPayload = {
        metadata: {
          ...metadata,
          device_name: systemInfo?.computer_name,
          operating_system: systemInfo?.os_version,
          drive_scanned: driveScanned,
          scan_parameters: scanParameters,
          scan_duration: formattedDuration,
          total_flags: flaggedItems.size,
        },
        scope,
        formats,
        flagged_item_ids: Array.from(flaggedItems),
        all_data: {
          apps: apps.map((app, idx) => ({ ...app, isFlagged: flaggedItems.has(`app-${idx}`) })) as any,
          keywords: keywords.map((kw, idx) => ({ ...kw, isFlagged: flaggedItems.has(`keyword-${idx}`) })) as any,
          csam: media.map((m, idx) => ({ ...m, isFlagged: flaggedItems.has(`media-${idx}`) })) as any,
          browsers: browsers.map(browser => ({
            ...browser,
            history: browser.history?.map((h: any, idx: number) => ({
              ...h,
              isFlagged: flaggedItems.has(`browser-history-${browser.browserName}-${idx}`)
            })),
            downloads: browser.downloads?.map((d: any, idx: number) => ({
              ...d,
              isFlagged: flaggedItems.has(`browser-download-${browser.browserName}-${idx}`)
            })),
            credentials: browser.credentials?.map((c: any, idx: number) => ({
              ...c,
              isFlagged: flaggedItems.has(`browser-credential-${browser.browserName}-${idx}`)
            }))
          })) as any,
          intrusion: intrusionResults as any,
          system_info: systemInfo as any,
        },
      };

      // Prompt for password to encrypt the report
      const password = prompt('Enter your password to encrypt and save this report:');
      if (!password) {
        alert('Report generation cancelled. Password is required to save reports.');
        return;
      }

      // Call the Tauri command with password for encryption
      const result = await invoke<ReportGenerationResult>('generate_report', { payload, password });

      if (result.success) {
        // Report is now encrypted and saved to database
        // The pdf_path will contain the encrypted report ID
        if (result.pdf_path && result.pdf_path.startsWith('encrypted::')) {
          const reportId = result.pdf_path.replace('encrypted::', '');
          let message = '✓ PDF Report generated and encrypted successfully!\n\n';
          message += `The report has been saved to your encrypted database.\n`;
          message += `Report ID: ${reportId}\n\n`;
          message += 'Access your reports from the Settings > Encrypted Reports section.';
          alert(message);
        }
      } else {
        alert(`Report generation failed: ${result.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Failed to generate report:', error);
      alert(`Failed to generate report: ${error}`);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const handleOpenMediaGallery = () => {
    setShowMediaGallery(true);
  };

  const handleCloseMediaGallery = () => {
    setShowMediaGallery(false);
  };

  const handleClearMediaCache = async () => {
    // TODO: Implement clear_media_cache command in backend
    console.log('Clear media cache requested');
    alert('Clear cache feature coming soon');
  };

  // Build navigation items based on device type AND scanned modules
  const buildNavItems = () => {
    const items = [
      {
        id: 'device-info' as ViewType,
        label: 'DEVICE INFO',
        icon: '📱',
        count: systemInfo ? 1 : 0,
        expandable: false
      }
    ];

    // Only show tabs for modules that were actually scanned
    if (scannedModules) {
      // Applications (Windows, Android, or iOS, if scanned)
      if ((deviceType === 'windows' || deviceType === 'android' || deviceType === 'ios') && scannedModules.questionableApps) {
        const label = deviceType === 'android' ? 'ANDROID\nAPPLICATIONS' 
                    : deviceType === 'ios' ? 'iOS\nAPPLICATIONS'
                    : 'INSTALLED\nAPPLICATIONS';
        items.push({
          id: 'applications' as ViewType,
          label: label,
          icon: '📱',
          count: apps.length,
          expandable: false
        });
      }

      // Browser History (Windows, Android, or iOS, if scanned)
      if ((deviceType === 'windows' || deviceType === 'android' || deviceType === 'ios') && scannedModules.browserHistory) {
        items.push({
          id: 'browser-history' as ViewType,
          label: 'BROWSER\nHISTORY',
          icon: '🌐',
          count: browsers.reduce((sum, b) => sum + b.history.length, 0),
          expandable: true
        });
      }

      // SMS Messages (Android and iOS only, if scanned)
      if ((deviceType === 'android' || deviceType === 'ios') && scannedModules.smsMessages) {
        items.push({
          id: 'sms-messages' as ViewType,
          label: 'SMS/MMS\nMESSAGES',
          icon: '💬',
          count: smsMessages?.totalMessages || 0,
          expandable: false
        });
      }

      // Keywords (if scanned)
      if (scannedModules.keywordSearch) {
        items.push({
          id: 'keywords' as ViewType,
          label: 'KEYWORD HITS',
          icon: '🔍',
          count: keywords.length,
          expandable: true
        });
      }

      // Media Files (if scanned)
      if (scannedModules.mediaScan) {
        items.push({
          id: 'media-files' as ViewType,
          label: 'MEDIA\nFILES',
          icon: '🖼️',
          count: media.length,
          expandable: false
        });
      }

      // CSAM Hash (only if hash matching was enabled)
      if (scannedModules.hashMatching) {
        // Count hash matches from dedicated state or from media flags
        const hashCount = hashMatches.length > 0 
          ? hashMatches.length 
          : media.filter(m => m.flags && m.flags.some(f => f.flagType === 'HashMatch')).length;
          
        items.push({
          id: 'csam-hash' as ViewType,
          label: 'CSAM HASH HITS',
          icon: '🛡️',
          count: hashCount,
          expandable: false
        });
      }

      // Intrusion artifacts (Windows only, if scanned or currently scanning)
      if (deviceType === 'windows' && (scannedModules.intrusionDetection || isScanningIntrusion)) {
        const count = intrusionResults 
          ? (intrusionResults.eventLogAnomalies.length + 
             intrusionResults.persistenceItems.length + 
             intrusionResults.commandHistory.length)
          : 0;
        
        items.push({
          id: 'intrusion-artifacts' as ViewType,
          label: 'INTRUSION\nARTIFACTS',
          icon: '⚠️',
          count: count,
          expandable: false
        });
      }
    }

    return items;
  };

  const navItems = buildNavItems();

  const handleBrowserNavClick = () => {
    setActiveView('browser-history');
    setBrowserExpanded(!browserExpanded);
    if (!browserExpanded && browsers.length > 0 && !selectedBrowser) {
      setSelectedBrowser(browsers[0]);
    }
  };

  const handleBrowserSelect = (browser: BrowserData) => {
    setSelectedBrowser(browser);
    setActiveView('browser-history');
  };

  const handleKeywordNavClick = () => {
    setActiveView('keywords');
    setKeywordExpanded(!keywordExpanded);
  };

  const handleKeywordSelect = (keyword: string) => {
    setSelectedKeyword(keyword);
    setActiveView('keywords');
  };
  
  // Calculate keyword hit summary (memoized to avoid recomputing on every render)
  const keywordHitSummary = useMemo(() => {
    const keywordMap = new Map<string, number>();
    keywords.forEach(match => {
      match.matchedKeywords.forEach(keyword => {
        keywordMap.set(keyword, (keywordMap.get(keyword) || 0) + 1);
      });
    });
    return Array.from(keywordMap.entries())
      .map(([keyword, count]) => ({ keyword, count }))
      .sort((a, b) => b.count - a.count);
  }, [keywords]);

  const renderContent = () => {
    switch (activeView) {
      case 'device-info':
        return <DeviceInfoView systemInfo={systemInfo} deviceType={deviceType} selectedDrives={selectedDrives} />;
      case 'ios-triage':
        return <IosTriageView onToggleFlag={toggleFlag} isFlagged={isFlagged} />;
      case 'applications':
        return <ApplicationsView apps={apps} onToggleFlag={toggleFlag} isFlagged={isFlagged} />;
      case 'keywords':
        const filteredKeywords = selectedKeyword 
          ? keywords.filter(k => k.matchedKeywords.includes(selectedKeyword))
          : keywords;
        return <KeywordsView keywords={filteredKeywords} selectedKeyword={selectedKeyword} onToggleFlag={toggleFlag} isFlagged={isFlagged} onViewDetails={onViewKeywordDetails} />;
      case 'media-files':
        return <MediaFilesView media={media} onToggleFlag={toggleFlag} isFlagged={isFlagged} onOpenGallery={handleOpenMediaGallery} />;
      case 'csam-hash':
        return <CSAMHashView media={media} hashMatches={hashMatches} onToggleFlag={toggleFlag} isFlagged={isFlagged} onViewDetails={onViewHashDetails} />;
      case 'browser-history':
        return (
          <BrowserHistoryView 
            browser={selectedBrowser}
            activeTab={activeBrowserTab}
            onTabChange={setActiveBrowserTab}
            onToggleFlag={toggleFlag}
            isFlagged={isFlagged}
          />
        );
      case 'sms-messages':
        return (
          <div className="sms-messages-view">
            <div className="view-header">
              <h2>💬 SMS/MMS Messages</h2>
              <p className="view-description">
                {smsMessages 
                  ? `${smsMessages.totalMessages} messages in ${smsMessages.threads?.length || 0} conversations` 
                  : 'No SMS messages extracted'}
              </p>
              {smsMessages?.extractionSummary && (
                <p style={{ 
                  fontSize: '0.85rem', 
                  color: '#888', 
                  marginTop: '6px',
                  fontStyle: 'italic'
                }}>
                  {smsMessages.extractionSummary}
                </p>
              )}
            </div>
            {smsMessages && smsMessages.threads && smsMessages.messages ? (
              <SmsConversationView
                threads={smsMessages.threads}
                messages={smsMessages.messages}
                onToggleFlag={toggleFlag}
                isFlagged={isFlagged}
              />
            ) : (
              <div style={{textAlign: 'center', padding: '60px', color: '#666'}}>
                <div style={{fontSize: '3em', marginBottom: '20px'}}>💬</div>
                <p>No SMS messages available</p>
              </div>
            )}
          </div>
        );
      case 'intrusion-artifacts':
        return (
          <IntrusionArtifactsView
            activeTab={activeIntrusionTab}
            onTabChange={setActiveIntrusionTab}
            onToggleFlag={toggleFlag}
            isFlagged={isFlagged}
            results={intrusionResults}
            isScanning={isScanningIntrusion}
            onStartScan={async () => {
              setIsScanningIntrusion(true);
              try {
                console.log('Sending intrusion scan options:', defaultIntrusionScanOptions);
                const results = await invoke<IntrusionScanResults>('scan_intrusion_progressive', {
                  options: defaultIntrusionScanOptions
                });
                setIntrusionResults(results);
              } catch (error) {
                console.error('Intrusion scan failed:', error);
                alert(`Intrusion scan failed: ${error}`);
              } finally {
                setIsScanningIntrusion(false);
              }
            }}
          />
        );
      default:
        return <DeviceInfoView systemInfo={systemInfo} />;
    }
  };

  return (
    <div className="unified-dashboard">
      {/* Top Header */}
      <div className="dashboard-header">
        <div className="header-logo">
          <div className="logo-dots">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="dot" />
            ))}
          </div>
          <div className="logo-text">
            <div className="logo-datapilot">DATAPILOT</div>
            <div className="logo-scout">SCOUT</div>
          </div>
        </div>

        <div className="header-actions">
          <ScanningIndicator 
            isScanning={isScanning} 
            currentModule={currentScanModule}
            startTime={scanStartTime}
            scanComplete={scanComplete}
            scanDuration={scanDuration}
            totalFilesScanned={totalFilesScanned}
            onDismiss={() => setScanComplete(false)}
            onStopScan={isScanning ? onStopScan : undefined}
            backupProgress={backupProgress}
            scanProgress={scanProgress}
          />
          
          <button 
            className="header-button new-scan-button"
            onClick={onNewScan}
            disabled={isScanning}
          >
            <span className="button-icon">🔄</span>
            <span className="button-text">START NEW SCAN</span>
          </button>
          
          <button 
            className="header-button report-button"
            onClick={() => setShowReportModal(true)}
            disabled={isGeneratingReport}
          >
            <span className="button-icon">📄</span>
            <span className="button-text">{isGeneratingReport ? 'GENERATING...' : 'GENERATE REPORT'}</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="dashboard-body">
        {/* Left Sidebar Navigation */}
        <div className="dashboard-sidebar">
          {navItems.map((item) => (
            <div key={item.id} className="nav-item-container">
              <button
                className={`nav-button ${activeView === item.id ? 'active' : ''} ${
                  item.expandable && (
                    (browserExpanded && item.id === 'browser-history') ||
                    (keywordExpanded && item.id === 'keywords')
                  ) ? 'expanded' : ''
                }`}
                onClick={() => {
                  if (item.expandable && item.id === 'browser-history') {
                    handleBrowserNavClick();
                    setKeywordExpanded(false);
                  } else if (item.expandable && item.id === 'keywords') {
                    handleKeywordNavClick();
                    setBrowserExpanded(false);
                  } else {
                    setActiveView(item.id);
                    setBrowserExpanded(false);
                    setKeywordExpanded(false);
                  }
                }}
              >
                <div className="nav-icon">{item.icon}</div>
                <div className="nav-label">{item.label}</div>
                {item.count > 0 && <div className="nav-badge">{item.count}</div>}
                {item.expandable && (
                  <div className="nav-expand-icon">
                    {((browserExpanded && item.id === 'browser-history') || 
                      (keywordExpanded && item.id === 'keywords')) ? '▼' : '▶'}
                  </div>
                )}
              </button>
              
              {/* Sub-items for browsers */}
              {item.id === 'browser-history' && browserExpanded && (
                <div className="nav-sub-items">
                  {browsers.map((browser, idx) => (
                    <button
                      key={idx}
                      className={`nav-sub-button ${selectedBrowser === browser ? 'active' : ''}`}
                      onClick={() => handleBrowserSelect(browser)}
                    >
                      <div className="sub-icon">
                        {browser.browserName.includes('Chrome') ? '🔵' :
                         browser.browserName.includes('Firefox') ? '🟠' :
                         browser.browserName.includes('Edge') ? '🔷' :
                         browser.browserName.includes('Safari') ? '🔵' : '🌐'}
                      </div>
                      <div className="sub-label">
                        {browser.browserName}
                        {browser.profileName && browser.profileName !== 'Default' && (
                          <div className="sub-profile">{browser.profileName}</div>
                        )}
                      </div>
                      <div className="sub-count">{browser.history.length}</div>
                    </button>
                  ))}
                </div>
              )}
              
              {/* Sub-items for keywords */}
              {item.id === 'keywords' && keywordExpanded && (
                <div className="nav-sub-items">
                  <button
                    className={`nav-sub-button ${selectedKeyword === null ? 'active' : ''}`}
                    onClick={() => {
                      setSelectedKeyword(null);
                      setActiveView('keywords');
                    }}
                  >
                    <div className="sub-icon">📁</div>
                    <div className="sub-label">All Keywords</div>
                    <div className="sub-count">{keywords.length}</div>
                  </button>
                  {keywordHitSummary.slice(0, 20).map((kwItem, idx) => (
                    <button
                      key={idx}
                      className={`nav-sub-button ${selectedKeyword === kwItem.keyword ? 'active' : ''}`}
                      onClick={() => handleKeywordSelect(kwItem.keyword)}
                    >
                      <div className="sub-icon">🔑</div>
                      <div className="sub-label">{kwItem.keyword}</div>
                      <div className="sub-count">{kwItem.count}</div>
                    </button>
                  ))}
                  {keywordHitSummary.length > 20 && (
                    <div className="sub-item-more">
                      +{keywordHitSummary.length - 20} more keywords
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Main Content Panel */}
        <div className="dashboard-content">
          {renderContent()}
        </div>
      </div>

      {/* Flag Counter */}
      {flaggedItems.size > 0 && (
        <div className="flag-counter">
          <div className="flag-counter-icon">🚩</div>
          <div className="flag-counter-content">
            <div className="flag-counter-number">{flaggedItems.size}</div>
            <div className="flag-counter-label">FLAGGED ITEMS</div>
          </div>
        </div>
      )}

      {/* Report Configuration Modal */}
      <ReportConfigModal
        isOpen={showReportModal}
        onClose={() => setShowReportModal(false)}
        onGenerate={handleGenerateReport}
        settings={settings}
      />

      {/* Media Gallery Modal */}
      {showMediaGallery && (
        <MediaGallery 
          media={media}
          isScanning={false}
          onStartScan={() => {}}
          onClearCache={handleClearMediaCache}
          onClose={handleCloseMediaGallery}
          onToggleFlag={toggleFlag}
          isFlagged={isFlagged}
        />
      )}
    </div>
  );
};

// Device Info View
const DeviceInfoView: React.FC<{ 
  systemInfo: SystemInfo | null; 
  deviceType?: DeviceType;
  selectedDrives?: string[];
}> = ({ systemInfo, deviceType, selectedDrives = [] }) => {
  const [usbDeviceInfo, setUsbDeviceInfo] = React.useState<UsbDeviceInfo | null>(null);
  const [loadingUsbInfo, setLoadingUsbInfo] = React.useState(false);

  // Fetch USB device info if in USB mode
  React.useEffect(() => {
    console.log('DeviceInfoView: deviceType =', deviceType, 'selectedDrives =', selectedDrives);
    console.log('SystemInfo usb_device_info:', systemInfo?.usb_device_info);
    console.log('SystemInfo android_device_info:', systemInfo?.android_device_info);
    
    // First check if systemInfo already has USB device info (from scan)
    if (systemInfo?.usb_device_info) {
      console.log('Using USB device info from systemInfo');
      setUsbDeviceInfo(systemInfo.usb_device_info as UsbDeviceInfo);
      return;
    }
    
    // Otherwise, try to fetch it
    if (deviceType === 'usb' && selectedDrives.length > 0) {
      const fetchUsbInfo = async () => {
        setLoadingUsbInfo(true);
        try {
          // Get the first selected drive (remove colon and backslash if present)
          let drive = selectedDrives[0];
          drive = drive.replace(':', '').replace('\\', '').trim();
          console.log('Fetching USB info for drive:', drive);
          
          const info = await invoke<UsbDeviceInfo>('get_usb_device_info', { driveLetter: drive });
          console.log('USB device info received:', info);
          setUsbDeviceInfo(info);
        } catch (error) {
          console.error('Failed to fetch USB device info:', error);
        } finally {
          setLoadingUsbInfo(false);
        }
      };
      fetchUsbInfo();
    } else {
      console.log('Not fetching USB info - conditions not met');
    }
  }, [deviceType, selectedDrives, systemInfo]);

  // For USB mode, show USB-specific device info
  if (deviceType === 'usb') {
    if (loadingUsbInfo) {
      return (
        <div className="content-view">
          <h2 className="view-title">USB DEVICE INFORMATION</h2>
          <div className="no-data">Loading USB device information...</div>
        </div>
      );
    }

    if (!usbDeviceInfo) {
      return (
        <div className="content-view">
          <h2 className="view-title">USB DEVICE INFORMATION</h2>
          <div className="no-data">
            {selectedDrives.length === 0 
              ? 'No drives selected. Please select a USB drive in the scan configuration.'
              : 'No USB device information available. Check console for errors.'}
          </div>
          <div style={{ marginTop: '1rem', color: '#999', fontSize: '0.9rem' }}>
            Debug: deviceType={deviceType}, selectedDrives={JSON.stringify(selectedDrives)}
          </div>
        </div>
      );
    }

    return (
      <div className="content-view">
        <h2 className="view-title">USB DEVICE INFORMATION</h2>
        
        <div className="info-section">
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Drive</div>
              <div className="info-value">{usbDeviceInfo.drive_letter}:</div>
            </div>
            <div className="info-card">
              <div className="info-label">USB Name</div>
              <div className="info-value">{usbDeviceInfo.drive_name}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Size</div>
              <div className="info-value">{usbDeviceInfo.capacity_gb.toFixed(2)} GB</div>
            </div>
            <div className="info-card">
              <div className="info-label">Media Files (Images/Video)</div>
              <div className="info-value">
                {(() => {
                  try {
                    // After scan complete, use the saved total
                    if (!isScanning && totalFilesScanned && totalFilesScanned > 0) {
                      return totalFilesScanned.toLocaleString();
                    }
                    // During scan, show live progress from scan progress data
                    const hashModule = (scanProgress || []).find((p: any) => p?.moduleId === 'hash_matching');
                    const discovered = hashModule?.totalItems || 0;
                    const processed = hashModule?.itemsProcessed || 0;
                    if (discovered > 0) {
                      if (isScanning && processed < discovered) {
                        return `${processed.toLocaleString()} / ${discovered.toLocaleString()}`;
                      }
                      return discovered.toLocaleString();
                    }
                    if (usbDeviceInfo?.file_count > 0) {
                      return usbDeviceInfo.file_count.toLocaleString();
                    }
                    return isScanning ? 'Scanning...' : '—';
                  } catch {
                    return '—';
                  }
                })()}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // For Android mode, show Android device info
  if (deviceType === 'android') {
    const androidInfo = systemInfo?.android_device_info;
    
    if (!androidInfo) {
      return (
        <div className="content-view">
          <h2 className="view-title">ANDROID DEVICE INFORMATION</h2>
          <div className="no-data">Collecting device information...</div>
        </div>
      );
    }

    return (
      <div className="content-view">
        <h2 className="view-title">ANDROID DEVICE INFORMATION</h2>
        
        <div className="info-section">
          <h3 className="section-subtitle">DEVICE IDENTIFICATION</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Device Model</div>
              <div className="info-value">{androidInfo.model || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Manufacturer</div>
              <div className="info-value">{androidInfo.manufacturer || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Serial Number</div>
              <div className="info-value">{androidInfo.serialNumber || androidInfo.serial || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Phone Number</div>
              <div className="info-value">{androidInfo.phoneNumber || 'Not Available'}</div>
            </div>
          </div>
        </div>

        <div className="info-section">
          <h3 className="section-subtitle">SYSTEM DETAILS</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Android Version</div>
              <div className="info-value">{androidInfo.androidVersion || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">SDK Version</div>
              <div className="info-value">{androidInfo.sdkVersion || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Build ID</div>
              <div className="info-value">{androidInfo.buildId || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Battery Level</div>
              <div className="info-value">{androidInfo.batteryLevel || 'N/A'}</div>
            </div>
          </div>
        </div>

        <div className="info-section">
          <h3 className="section-subtitle">STORAGE INFORMATION</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Storage Used</div>
              <div className="info-value">{androidInfo.storageUsed || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Storage Total</div>
              <div className="info-value">{androidInfo.storageTotal || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Storage Available</div>
              <div className="info-value">{androidInfo.storageAvailable || androidInfo.storageFree || 'N/A'}</div>
            </div>
            {androidInfo.imei && (
              <div className="info-card">
                <div className="info-label">IMEI</div>
                <div className="info-value">{androidInfo.imei}</div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // For iOS mode, show iOS device info
  if (deviceType === 'ios') {
    const iosInfo = systemInfo?.ios_device_info;
    
    if (!iosInfo) {
      return (
        <div className="content-view">
          <h2 className="view-title">iOS DEVICE INFORMATION</h2>
          <div className="no-data">Collecting device information...</div>
        </div>
      );
    }

    return (
      <div className="content-view">
        <h2 className="view-title">iOS DEVICE INFORMATION</h2>
        
        <div className="info-section">
          <h3 className="section-subtitle">DEVICE IDENTIFICATION</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Device Name</div>
              <div className="info-value">{iosInfo.deviceName || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Model</div>
              <div className="info-value">{iosInfo.deviceModel || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Serial Number</div>
              <div className="info-value">{iosInfo.serialNumber || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">IMEI</div>
              <div className="info-value">{iosInfo.imei || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Phone Number</div>
              <div className="info-value">{iosInfo.phoneNumber || 'Not Available'}</div>
            </div>
          </div>
        </div>

        <div className="info-section">
          <h3 className="section-subtitle">SYSTEM INFORMATION</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">iOS Version</div>
              <div className="info-value">{iosInfo.iosVersion || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Build Version</div>
              <div className="info-value">{iosInfo.buildVersion || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Battery Level</div>
              <div className="info-value">{iosInfo.batteryLevel || 'N/A'}</div>
            </div>
          </div>
        </div>

        <div className="info-section">
          <h3 className="section-subtitle">STORAGE & CONNECTIVITY</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Storage</div>
              <div className="info-value">
                {iosInfo.availableCapacity && iosInfo.totalCapacity
                  ? `${iosInfo.availableCapacity} / ${iosInfo.totalCapacity}`
                  : 'N/A'}
              </div>
            </div>
            <div className="info-card">
              <div className="info-label">WiFi Address</div>
              <div className="info-value">{iosInfo.wifiAddress || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Bluetooth Address</div>
              <div className="info-value">{iosInfo.bluetoothAddress || 'N/A'}</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // For Windows mode, show full system info
  if (!systemInfo) {
    return (
      <div className="content-view">
        <h2 className="view-title">DEVICE INFORMATION</h2>
        <div className="no-data">Collecting system information...</div>
      </div>
    );
  }

  return (
    <div className="content-view">
      <h2 className="view-title">DEVICE INFORMATION</h2>
      
      <div className="info-section">
        <h3 className="section-subtitle">SYSTEM IDENTIFICATION</h3>
        <div className="info-grid">
          <div className="info-card">
            <div className="info-label">Computer Name</div>
            <div className="info-value">{systemInfo.computer_name || 'N/A'}</div>
          </div>
          <div className="info-card">
            <div className="info-label">Operating System</div>
            <div className="info-value">{systemInfo.os_version || 'N/A'}</div>
          </div>
          <div className="info-card">
            <div className="info-label">Registered Owner</div>
            <div className="info-value">{systemInfo.registered_owner || 'N/A'}</div>
          </div>
          <div className="info-card">
            <div className="info-label">Organization</div>
            <div className="info-value">{systemInfo.registered_organization || 'N/A'}</div>
          </div>
          <div className="info-card">
            <div className="info-label">Product ID</div>
            <div className="info-value">{systemInfo.product_id || 'N/A'}</div>
          </div>
          <div className="info-card">
            <div className="info-label">Domain</div>
            <div className="info-value">{systemInfo.domain || 'Not joined to domain'}</div>
          </div>
        </div>
      </div>

      {systemInfo.hardware && (
        <div className="info-section">
          <h3 className="section-subtitle">HARDWARE</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">BIOS Serial</div>
              <div className="info-value">{systemInfo.hardware.bios_serial || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Motherboard Serial</div>
              <div className="info-value">{systemInfo.hardware.motherboard_serial || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">System UUID</div>
              <div className="info-value">{systemInfo.hardware.system_uuid || 'N/A'}</div>
            </div>
          </div>
          
          {systemInfo.hardware.drives && systemInfo.hardware.drives.length > 0 && (
            <div className="drives-section">
              <h4 className="subsection-title">STORAGE DRIVES</h4>
              {systemInfo.hardware.drives.map((drive, idx) => (
                <div key={idx} className="drive-card">
                  <div className="drive-header">
                    <span className="drive-letter">{drive.letter}</span>
                    <span className="drive-label">{drive.label || 'Local Disk'}</span>
                  </div>
                  <div className="drive-details">
                    <span>Serial: {drive.serial_number}</span>
                    <span>Filesystem: {drive.filesystem}</span>
                    <span>Free: {Math.round(drive.free_space / (1024 * 1024 * 1024))} GB / {Math.round(drive.total_space / (1024 * 1024 * 1024))} GB</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {systemInfo.usb_history && systemInfo.usb_history.length > 0 && (
        <div className="info-section">
          <h3 className="section-subtitle">USB DEVICE HISTORY</h3>
          <div className="info-description">External USB storage devices previously connected to this system</div>
          <div className="data-table">
            <div className="table-header">
              <div className="table-col">DEVICE NAME</div>
              <div className="table-col">VENDOR ID</div>
              <div className="table-col">PRODUCT ID</div>
              <div className="table-col">SERIAL NUMBER</div>
              <div className="table-col">LAST CONNECTED</div>
              <div className="table-col">DRIVE LETTER</div>
            </div>
            <div className="table-body">
              {systemInfo.usb_history.map((device, idx) => (
                <div key={idx} className="table-row">
                  <div className="table-col">{device.device_name}</div>
                  <div className="table-col">{device.vendor_id || 'N/A'}</div>
                  <div className="table-col">{device.product_id || 'N/A'}</div>
                  <div className="table-col">{device.serial_number || 'N/A'}</div>
                  <div className="table-col">{device.last_connected || 'Unknown'}</div>
                  <div className="table-col">{device.drive_letter || 'N/A'}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {systemInfo.user_accounts && systemInfo.user_accounts.length > 0 && (
        <div className="info-section">
          <h3 className="section-subtitle">USER ACCOUNTS</h3>
          <div className="data-table">
            <div className="table-header">
              <div className="table-col">USERNAME</div>
              <div className="table-col">FULL NAME</div>
              <div className="table-col">ACCOUNT TYPE</div>
              <div className="table-col">LAST LOGIN</div>
            </div>
            <div className="table-body">
              {systemInfo.user_accounts.map((account, idx) => (
                <div key={idx} className="table-row">
                  <div className="table-col">{account.username}</div>
                  <div className="table-col">{account.full_name || 'N/A'}</div>
                  <div className="table-col">{account.account_type}</div>
                  <div className="table-col">{account.last_login || 'N/A'}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {systemInfo.network && (
        <div className="info-section">
          <h3 className="section-subtitle">NETWORK</h3>
          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Hostname</div>
              <div className="info-value">{systemInfo.network.hostname || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Local IP Addresses</div>
              <div className="info-value">{systemInfo.network.ip_addresses.join(', ') || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Public IP Address</div>
              <div className="info-value">{systemInfo.network.public_ip || 'N/A'}</div>
            </div>
            <div className="info-card">
              <div className="info-label">MAC Addresses</div>
              <div className="info-value">{systemInfo.network.mac_addresses.join(', ') || 'N/A'}</div>
            </div>
          </div>
        </div>
      )}

      {systemInfo.emails && systemInfo.emails.length > 0 && (
        <div className="info-section">
          <h3 className="section-subtitle">DISCOVERED EMAIL ADDRESSES</h3>
          <div className="email-list">
            {systemInfo.emails.map((email, idx) => (
              <div key={idx} className="email-item">{email}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Applications View
const ApplicationsView: React.FC<{ 
  apps: QuestionableApp[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ apps, onToggleFlag, isFlagged }) => {
  const [selectedCategory, setSelectedCategory] = React.useState<string>('all');

  // Define categories with their display names (using NEW investigative_category field)
  const categories = [
    { id: 'all', label: 'ALL APPLICATIONS', icon: '📱', matches: [] as string[] },
    { id: 'anti_forensic', label: 'ANTI-FORENSIC', icon: '🧹', matches: ['ANONYMITY_ANTI_FORENSICS'] },
    { id: 'dark_web', label: 'DARK WEB / P2P', icon: '🕸️', matches: ['DARKWEB_P2P'] },
    { id: 'vpn', label: 'VPN / REMOTE', icon: '🔒', matches: ['VPN_REMOTE_ACCESS'] },
    { id: 'crypto', label: 'CRYPTOCURRENCY', icon: '💰', matches: ['CRYPTOCURRENCY'] },
    { id: 'communications', label: 'COMMUNICATIONS', icon: '💬', matches: ['COMMUNICATIONS'] },
    { id: 'virtual_machine', label: 'VIRTUAL MACHINE', icon: '💻', matches: ['VIRTUAL_MACHINE'] },
    { id: 'productivity', label: 'PRODUCTIVITY', icon: '📊', matches: ['GENERAL_PRODUCTIVITY'] },
    { id: 'unknown', label: 'UNKNOWN', icon: '❓', matches: ['UNKNOWN'] }
  ];

  // Count apps by category (using investigative_category)
  const getCategoryCount = (categoryId: string) => {
    if (categoryId === 'all') return apps.length;
    const category = categories.find(c => c.id === categoryId);
    if (!category) return 0;
    return apps.filter(app => app.investigative_category && category.matches.includes(app.investigative_category)).length;
  };

  // Filter apps based on selected category (using investigative_category)
  const filteredApps = selectedCategory === 'all' 
    ? apps 
    : apps.filter(app => {
        const category = categories.find(c => c.id === selectedCategory);
        return category && app.investigative_category ? category.matches.includes(app.investigative_category) : false;
      });

  return (
    <div className="content-view">
      <h2 className="view-title">INSTALLED APPLICATIONS - SCAN RESULTS</h2>
      
      {apps.length === 0 ? (
        <div className="no-data">No questionable applications detected</div>
      ) : (
        <>
          {/* Category Filter Tabs */}
          <div className="category-filters">
            {categories.map((category) => {
              const count = getCategoryCount(category.id);
              return (
                <button
                  key={category.id}
                  className={`category-filter ${selectedCategory === category.id ? 'active' : ''} ${count === 0 ? 'empty' : ''}`}
                  onClick={() => setSelectedCategory(category.id)}
                  disabled={count === 0}
                >
                  <span className="filter-icon">{category.icon}</span>
                  <span className="filter-label">{category.label}</span>
                  <span className="filter-count">{count}</span>
                </button>
              );
            })}
          </div>

          {/* Applications Table */}
          {filteredApps.length === 0 ? (
            <div className="no-data">No applications found in this category</div>
          ) : (
            <div className="data-table">
              <div className="table-header">
                <div className="table-col">APPLICATION NAME</div>
                <div className="table-col">CATEGORY</div>
                <div className="table-col">INSTALL PATH</div>
                <div className="table-col">FLAG</div>
              </div>
              <div className="table-body">
                {filteredApps.map((app, idx) => {
                  // Use original apps array index for consistent flagging
                  const originalIdx = apps.indexOf(app);
                  const itemId = `app-${originalIdx}`;
                  const flagged = isFlagged(itemId);
                  const hasArtifacts = app.artifact_paths && app.artifact_paths.length > 0;
                  return (
                    <React.Fragment key={idx}>
                      <div className="table-row">
                        <div className="table-col">{app.name}</div>
                        <div className="table-col category-badge">
                          {(app.investigative_category || 'UNKNOWN').replace(/_/g, ' ')}
                          {app.confidence > 0 && (
                            <span style={{ marginLeft: '8px', fontSize: '0.8em', opacity: 0.7 }}>
                              ({Math.round(app.confidence * 100)}%)
                            </span>
                          )}
                        </div>
                        <div className="table-col">
                          <ClickableFilePath path={app.install_path} />
                        </div>
                        <div className="table-col">
                          <button 
                            className={`flag-button ${flagged ? 'flagged' : ''}`}
                            onClick={() => onToggleFlag(itemId)}
                          >
                            {flagged ? '✓ FLAGGED' : 'FLAG'}
                          </button>
                        </div>
                      </div>
                      {hasArtifacts && (
                        <div className="table-row artifact-row">
                          <div className="table-col" style={{ gridColumn: '1 / -1', paddingLeft: '2rem' }}>
                            <div className="artifact-paths">
                              <span className="artifact-label">📁 Forensic Artifacts:</span>
                              {app.artifact_paths.map((path, pidx) => (
                                <div key={pidx} className="artifact-path">
                                  <ClickableFilePath path={path} />
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// Keywords View
const KEYWORDS_PAGE_SIZE = 200;

const KeywordsView: React.FC<{ 
  keywords: KeywordMatch[];
  selectedKeyword: string | null;
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  onViewDetails?: () => void;
}> = ({ keywords, selectedKeyword, onToggleFlag, isFlagged, onViewDetails }) => {
  const [page, setPage] = useState(0);
  const totalPages = Math.max(1, Math.ceil(keywords.length / KEYWORDS_PAGE_SIZE));
  const pageStart = page * KEYWORDS_PAGE_SIZE;
  const pageEnd = Math.min(pageStart + KEYWORDS_PAGE_SIZE, keywords.length);
  const pageItems = keywords.slice(pageStart, pageEnd);

  // Reset to page 0 when keyword filter changes
  React.useEffect(() => { setPage(0); }, [selectedKeyword, keywords.length]);

  const displayTitle = selectedKeyword 
    ? `KEYWORD HITS - "${selectedKeyword}" (${keywords.length} files)`
    : `KEYWORD HITS - ALL RESULTS (${keywords.length} files)`;
    
  return (
    <div className="content-view">
      <div className="view-header-with-action">
        <h2 className="view-title">{displayTitle}</h2>
        {keywords.length > 0 && onViewDetails && (
          <button className="view-details-btn" onClick={onViewDetails}>
            📋 View Detailed Results
          </button>
        )}
      </div>
      {keywords.length === 0 ? (
        <div className="no-data">No keyword matches found</div>
      ) : (
        <>
          {keywords.length > KEYWORDS_PAGE_SIZE && (
            <div className="pagination-bar">
              <button className="pagination-btn" disabled={page === 0} onClick={() => setPage(0)}>« First</button>
              <button className="pagination-btn" disabled={page === 0} onClick={() => setPage(p => p - 1)}>‹ Prev</button>
              <span className="pagination-info">
                Showing {pageStart + 1}–{pageEnd} of {keywords.length.toLocaleString()} results (Page {page + 1} of {totalPages.toLocaleString()})
              </span>
              <button className="pagination-btn" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next ›</button>
              <button className="pagination-btn" disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Last »</button>
            </div>
          )}
          <div className="data-table">
            <div className="table-header">
              <div className="table-col">FILE PATH</div>
              <div className="table-col">MATCHED KEYWORDS</div>
              <div className="table-col">FILE SIZE</div>
              <div className="table-col">FLAG</div>
            </div>
            <div className="table-body">
              {pageItems.map((match, idx) => {
                const globalIdx = pageStart + idx;
                const itemId = `keyword-${match.filePath}-${globalIdx}`;
                const flagged = isFlagged(itemId);
                return (
                  <div key={globalIdx} className="table-row">
                    <div className="table-col">
                      <ClickableFilePath path={match.filePath} />
                    </div>
                    <div className="table-col">{match.matchedKeywords.join(', ')}</div>
                    <div className="table-col">{(match.fileSize / 1024).toFixed(2)} KB</div>
                    <div className="table-col">
                      <button 
                        className={`flag-button ${flagged ? 'flagged' : ''}`}
                        onClick={() => onToggleFlag(itemId)}
                      >
                        {flagged ? '✓ FLAGGED' : 'FLAG'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          {keywords.length > KEYWORDS_PAGE_SIZE && (
            <div className="pagination-bar">
              <button className="pagination-btn" disabled={page === 0} onClick={() => setPage(0)}>« First</button>
              <button className="pagination-btn" disabled={page === 0} onClick={() => setPage(p => p - 1)}>‹ Prev</button>
              <span className="pagination-info">
                Showing {pageStart + 1}–{pageEnd} of {keywords.length.toLocaleString()} results (Page {page + 1} of {totalPages.toLocaleString()})
              </span>
              <button className="pagination-btn" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next ›</button>
              <button className="pagination-btn" disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Last »</button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// CSAM Hash View
const CSAMHashView: React.FC<{ 
  media: MediaFile[];
  hashMatches?: any[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  onViewDetails?: () => void;
}> = ({ media, hashMatches = [], onToggleFlag, isFlagged, onViewDetails }) => {
  // Combine flagged media files and hash matches
  const flaggedMedia = media.filter(m => m.flags && m.flags.some(f => f.flagType === 'HashMatch'));
  const totalMatches = hashMatches.length > 0 ? hashMatches.length : flaggedMedia.length;

  return (
    <div className="content-view">
      <div className="view-header-with-action">
        <h2 className="view-title">CSAM HASH HITS - SCAN RESULTS</h2>
        {totalMatches > 0 && onViewDetails && (
          <button className="view-details-btn" onClick={onViewDetails}>
            📋 View Detailed Results
          </button>
        )}
      </div>
      
      {/* Scanning Visualization */}
      <div className="scan-visualization">
        <div className="scan-flow-grid">
          {[...Array(9)].map((_, i) => (
            <div key={i} className="flow-node" style={{ animationDelay: `${i * 0.15}s` }}>
              <svg width="60" height="60" viewBox="0 0 60 60">
                <rect x="10" y="15" width="40" height="30" stroke="var(--accent-orange)" strokeWidth="2" fill="none" strokeDasharray="4 4"/>
                <line x1="20" y1="25" x2="40" y2="25" stroke="var(--accent-orange)" strokeWidth="1"/>
                <line x1="20" y1="30" x2="35" y2="30" stroke="var(--accent-orange)" strokeWidth="1"/>
                <line x1="20" y1="35" x2="38" y2="35" stroke="var(--accent-orange)" strokeWidth="1"/>
              </svg>
            </div>
          ))}
        </div>
        <svg className="flow-connections" viewBox="0 0 300 300">
          {/* Horizontal connections */}
          <line x1="50" y1="50" x2="150" y2="50" className="connection-line" />
          <line x1="150" y1="50" x2="250" y2="50" className="connection-line" />
          <line x1="50" y1="150" x2="150" y2="150" className="connection-line" />
          <line x1="150" y1="150" x2="250" y2="150" className="connection-line" />
          <line x1="50" y1="250" x2="150" y2="250" className="connection-line" />
          <line x1="150" y1="250" x2="250" y2="250" className="connection-line" />
          {/* Vertical connections */}
          <line x1="50" y1="50" x2="50" y2="150" className="connection-line" />
          <line x1="150" y1="50" x2="150" y2="150" className="connection-line" />
          <line x1="250" y1="50" x2="250" y2="150" className="connection-line" />
          <line x1="50" y1="150" x2="50" y2="250" className="connection-line" />
          <line x1="150" y1="150" x2="150" y2="250" className="connection-line" />
          <line x1="250" y1="150" x2="250" y2="250" className="connection-line" />
        </svg>
      </div>

      {totalMatches === 0 ? (
        <div className="no-data">No CSAM hash matches detected</div>
      ) : (
        <div className="data-table">
          <div className="table-header">
            <div className="table-col">FILE PATH</div>
            <div className="table-col">HASH VALUE</div>
            <div className="table-col">SOURCE</div>
            <div className="table-col">FLAG</div>
          </div>
          <div className="table-body">
            {/* Display Android hash matches if available */}
            {hashMatches.length > 0 && hashMatches.map((match, idx) => {
              const itemId = `hash-match-${match.filePath}-${idx}`;
              const flagged = isFlagged(itemId);
              return (
                <div key={idx} className="table-row critical">
                  <div className="table-col">
                    <ClickableFilePath path={match.filePath} />
                    <div className="file-info">{match.fileName} ({(match.fileSize / 1024 / 1024).toFixed(2)} MB)</div>
                  </div>
                  <div className="table-col hash-value">
                    <div>{match.hashType}: {match.matchedHash}</div>
                    {match.description && <div className="hash-description">{match.description}</div>}
                  </div>
                  <div className="table-col">
                    <div>{match.listSource}</div>
                  </div>
                  <div className="table-col">
                    <button 
                      className={`flag-button ${flagged ? 'flagged' : ''}`}
                      onClick={() => onToggleFlag(itemId)}
                    >
                      {flagged ? '✓ FLAGGED' : 'FLAG'}
                    </button>
                  </div>
                </div>
              );
            })}
            
            {/* Display flagged media files (for Windows/USB scans) */}
            {hashMatches.length === 0 && flaggedMedia.map((file, idx) => {
              const itemId = `media-${file.filePath}-${idx}`;
              const flagged = isFlagged(itemId);
              return (
                <div key={idx} className="table-row">
                  <div className="table-col">
                    <ClickableFilePath path={file.filePath} />
                  </div>
                  <div className="table-col hash-value">{file.md5Hash || file.sha256Hash || 'N/A'}</div>
                  <div className="table-col preview-col">
                    <div className="preview-thumbnail">
                      {file.thumbnailPath ? (
                        <img src={file.thumbnailPath} alt="Preview" />
                      ) : (
                        <div className="preview-placeholder">🖼️</div>
                      )}
                    </div>
                  </div>
                  <div className="table-col">
                    <button 
                      className={`flag-button ${flagged ? 'flagged' : ''}`}
                      onClick={() => onToggleFlag(itemId)}
                    >
                      {flagged ? '✓ FLAGGED' : 'FLAG'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// Media Files View
const MediaFilesView: React.FC<{
  media: MediaFile[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  onOpenGallery: () => void;
}> = ({ media, onToggleFlag, isFlagged, onOpenGallery }) => {
  const images = media.filter(m => m.mediaType === 'image');
  const videos = media.filter(m => m.mediaType === 'video');
  
  return (
    <div className="content-view">
      <h2 className="view-title">MEDIA FILES - SCAN RESULTS</h2>
      
      <div className="media-stats">
        <div className="stat-card">
          <div className="stat-icon">🖼️</div>
          <div className="stat-content">
            <div className="stat-value">{images.length}</div>
            <div className="stat-label">Images</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🎥</div>
          <div className="stat-content">
            <div className="stat-value">{videos.length}</div>
            <div className="stat-label">Videos</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <div className="stat-value">{media.length}</div>
            <div className="stat-label">Total Files</div>
          </div>
        </div>
      </div>

      {media.length > 0 && (
        <div style={{ marginTop: '20px', textAlign: 'center' }}>
          <button 
            className="primary-button"
            onClick={onOpenGallery}
            style={{
              padding: '12px 24px',
              fontSize: '16px',
              fontWeight: 'bold',
              background: 'linear-gradient(135deg, var(--color-accent-red) 0%, #8B0000 100%)',
              border: 'none',
              borderRadius: '6px',
              color: 'white',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(255, 0, 51, 0.3)',
              transition: 'all 0.2s ease'
            }}
          >
            🖼️ Open Media Explorer - Gallery View
          </button>
        </div>
      )}
      
      {media.length === 0 ? (
        <div className="no-data">No media files scanned</div>
      ) : (
        <div className="data-table">
          <div className="table-header">
            <div className="table-col">PREVIEW</div>
            <div className="table-col">FILE PATH</div>
            <div className="table-col">TYPE</div>
            <div className="table-col">SIZE</div>
            <div className="table-col">DIMENSIONS</div>
            <div className="table-col">FLAG</div>
          </div>
          <div className="table-body">
            {media.slice(0, 100).map((file, idx) => {
              const itemId = `media-${file.filePath}-${idx}`;
              const flagged = isFlagged(itemId);
              return (
                <div key={idx} className="table-row">
                  <div className="table-col preview-col">
                    <div className="preview-thumbnail">
                      {file.thumbnailPath ? (
                        <img src={convertFileSrc(file.thumbnailPath)} alt="Preview" />
                      ) : (
                        <div className="preview-placeholder">
                          {file.mediaType === 'video' ? '🎥' : '🖼️'}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="table-col">
                    <ClickableFilePath path={file.filePath} />
                  </div>
                  <div className="table-col">
                    {file.mediaType === 'video' ? '🎥 Video' : '🖼️ Image'}
                  </div>
                  <div className="table-col">
                    {(file.fileSize / 1024 / 1024).toFixed(2)} MB
                  </div>
                  <div className="table-col">
                    {file.width && file.height ? `${file.width}×${file.height}` : 'N/A'}
                  </div>
                  <div className="table-col">
                    <button 
                      className={`flag-button ${flagged ? 'flagged' : ''}`}
                      onClick={() => onToggleFlag(itemId)}
                    >
                      {flagged ? '✓ FLAGGED' : 'FLAG'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
          {media.length > 100 && (
            <div className="table-footer" style={{ textAlign: 'center', padding: '20px' }}>
              <p style={{ marginBottom: '15px' }}>
                Showing first 100 of {media.length} media files.
              </p>
              <button 
                className="primary-button"
                onClick={onOpenGallery}
                style={{
                  padding: '10px 20px',
                  fontSize: '14px',
                  fontWeight: 'bold',
                  background: 'linear-gradient(135deg, var(--color-accent-red) 0%, #8B0000 100%)',
                  border: 'none',
                  borderRadius: '6px',
                  color: 'white',
                  cursor: 'pointer',
                  boxShadow: '0 4px 12px rgba(255, 0, 51, 0.3)',
                  transition: 'all 0.2s ease'
                }}
              >
                🖼️ Open Media Explorer - View All {media.length} Files
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Browser History View
const BrowserHistoryView: React.FC<{ 
  browser: BrowserData | null;
  activeTab: BrowserTab;
  onTabChange: (tab: BrowserTab) => void;
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ browser, activeTab, onTabChange, onToggleFlag, isFlagged }) => {
  if (!browser) {
    return (
      <div className="content-view">
        <h2 className="view-title">BROWSER DATA - SCAN RESULTS</h2>
        <div className="no-data">Select a browser from the sidebar to view data</div>
      </div>
    );
  }

  return (
    <div className="content-view">
      <div className="browser-header">
        <h2 className="view-title">
          {browser.browserName}
          {browser.profileName && browser.profileName !== 'Default' && (
            <span className="browser-profile"> - {browser.profileName}</span>
          )}
        </h2>
        
        <div className="browser-tabs">
          <button
            className={`browser-tab ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => onTabChange('history')}
          >
            <span className="tab-icon">📜</span>
            <span className="tab-label">BROWSER HISTORY</span>
            <span className="tab-count">{browser.history.length}</span>
          </button>
          <button
            className={`browser-tab ${activeTab === 'downloads' ? 'active' : ''}`}
            onClick={() => onTabChange('downloads')}
          >
            <span className="tab-icon">⬇️</span>
            <span className="tab-label">DOWNLOAD HISTORY</span>
            <span className="tab-count">{browser.downloads?.length || 0}</span>
          </button>
          <button
            className={`browser-tab ${activeTab === 'credentials' ? 'active' : ''}`}
            onClick={() => onTabChange('credentials')}
          >
            <span className="tab-icon">🔑</span>
            <span className="tab-label">WEBSITE USERNAMES</span>
            <span className="tab-count">{browser.credentials.length}</span>
          </button>
        </div>
      </div>

      {activeTab === 'history' && (
        <BrowserHistoryTab history={browser.history} onToggleFlag={onToggleFlag} isFlagged={isFlagged} />
      )}
      {activeTab === 'downloads' && (
        <BrowserDownloadsTab downloads={browser.downloads || []} onToggleFlag={onToggleFlag} isFlagged={isFlagged} />
      )}
      {activeTab === 'credentials' && (
        <BrowserCredentialsTab credentials={browser.credentials} onToggleFlag={onToggleFlag} isFlagged={isFlagged} />
      )}
    </div>
  );
};

// Browser History Tab
const BrowserHistoryTab: React.FC<{ 
  history: any[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ history, onToggleFlag, isFlagged }) => {
  const [sortKey, setSortKey] = React.useState<string>('visitTime');
  const [sortDir, setSortDir] = React.useState<'asc' | 'desc'>('desc');

  if (history.length === 0) {
    return <div className="no-data">No browser history found</div>;
  }

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir(key === 'url' || key === 'title' ? 'asc' : 'desc');
    }
  };

  const sortIndicator = (key: string) =>
    sortKey === key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  const sorted = [...history].sort((a, b) => {
    let cmp = 0;
    if (sortKey === 'url') cmp = (a.url || '').localeCompare(b.url || '');
    else if (sortKey === 'title') cmp = (a.title || '').localeCompare(b.title || '');
    else if (sortKey === 'visitTime') cmp = new Date(a.visitTime).getTime() - new Date(b.visitTime).getTime();
    else if (sortKey === 'visitCount') cmp = (a.visitCount || 1) - (b.visitCount || 1);
    return sortDir === 'asc' ? cmp : -cmp;
  });

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col sortable-col" onClick={() => handleSort('url')}>URL{sortIndicator('url')}</div>
        <div className="table-col sortable-col" onClick={() => handleSort('title')}>TITLE{sortIndicator('title')}</div>
        <div className="table-col sortable-col" onClick={() => handleSort('visitTime')}>VISIT TIME{sortIndicator('visitTime')}</div>
        <div className="table-col sortable-col" onClick={() => handleSort('visitCount')}>VISIT COUNT{sortIndicator('visitCount')}</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {sorted.slice(0, 500).map((item, idx) => {
          const itemId = `history-${item.url}-${idx}`;
          const flagged = isFlagged(itemId);
          return (
            <div key={idx} className="table-row">
              <div className="table-col file-path">{item.url}</div>
              <div className="table-col">{item.title}</div>
              <div className="table-col">{new Date(item.visitTime).toLocaleString()}</div>
              <div className="table-col">{item.visitCount || 1}</div>
              <div className="table-col">
                <button 
                  className={`flag-button ${flagged ? 'flagged' : ''}`}
                  onClick={() => onToggleFlag(itemId)}
                >
                  {flagged ? '✓ FLAGGED' : 'FLAG'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Browser Downloads Tab
const BrowserDownloadsTab: React.FC<{ 
  downloads: any[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ downloads, onToggleFlag, isFlagged }) => {
  if (downloads.length === 0) {
    return <div className="no-data">No download history found</div>;
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">FILE NAME</div>
        <div className="table-col">SOURCE URL</div>
        <div className="table-col">DOWNLOAD PATH</div>
        <div className="table-col">DATE</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {downloads.map((item, idx) => {
          const itemId = `download-${item.targetPath || item.path}-${idx}`;
          const flagged = isFlagged(itemId);
          const downloadPath = item.targetPath || item.path;
          return (
            <div key={idx} className="table-row">
              <div className="table-col">{item.fileName || downloadPath?.split('\\').pop()}</div>
              <div className="table-col file-path">{item.url || item.sourceUrl}</div>
              <div className="table-col">
                {downloadPath && <ClickableFilePath path={downloadPath} />}
              </div>
              <div className="table-col">{new Date(item.downloadTime || item.startTime).toLocaleString()}</div>
              <div className="table-col">
                <button 
                  className={`flag-button ${flagged ? 'flagged' : ''}`}
                  onClick={() => onToggleFlag(itemId)}
                >
                  {flagged ? '✓ FLAGGED' : 'FLAG'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Intrusion Artifacts View
const IntrusionArtifactsView: React.FC<{
  activeTab: IntrusionTab;
  onTabChange: (tab: IntrusionTab) => void;
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  results: IntrusionScanResults | null;
  isScanning: boolean;
  onStartScan: () => void;
}> = ({ activeTab, onTabChange, onToggleFlag, isFlagged, results, isScanning, onStartScan }) => {
  const eventLogCount = results?.eventLogAnomalies.length || 0;
  const persistenceCount = results?.persistenceItems.length || 0;
  const commandHistoryCount = results?.commandHistory.length || 0;

  return (
    <div className="content-view">
      <div className="browser-header">
        <h2 className="view-title">WINDOWS INTRUSION DETECTION (WIN-ID)</h2>
        
        <div className="browser-tabs">
          <button
            className={`browser-tab ${activeTab === 'event-logs' ? 'active' : ''}`}
            onClick={() => onTabChange('event-logs')}
          >
            <span className="tab-icon">📊</span>
            <span className="tab-label">EVENT LOG ANOMALIES</span>
            <span className="tab-count">{eventLogCount}</span>
          </button>
          <button
            className={`browser-tab ${activeTab === 'persistence' ? 'active' : ''}`}
            onClick={() => onTabChange('persistence')}
          >
            <span className="tab-icon">🔄</span>
            <span className="tab-label">STARTUP / PERSISTENCE</span>
            <span className="tab-count">{persistenceCount}</span>
          </button>
          <button
            className={`browser-tab ${activeTab === 'command-history' ? 'active' : ''}`}
            onClick={() => onTabChange('command-history')}
          >
            <span className="tab-icon">⌨️</span>
            <span className="tab-label">COMMAND HISTORY</span>
            <span className="tab-count">{commandHistoryCount}</span>
          </button>
        </div>
      </div>

      {activeTab === 'event-logs' && (
        <EventLogAnomaliesTab 
          onToggleFlag={onToggleFlag} 
          isFlagged={isFlagged}
          events={results?.eventLogAnomalies || []}
          isScanning={isScanning}
          onStartScan={onStartScan}
        />
      )}
      {activeTab === 'persistence' && (
        <PersistenceTab 
          onToggleFlag={onToggleFlag} 
          isFlagged={isFlagged}
          items={results?.persistenceItems || []}
          isScanning={isScanning}
          onStartScan={onStartScan}
        />
      )}
      {activeTab === 'command-history' && (
        <CommandHistoryTab 
          onToggleFlag={onToggleFlag} 
          isFlagged={isFlagged}
          commands={results?.commandHistory || []}
          isScanning={isScanning}
          onStartScan={onStartScan}
        />
      )}
    </div>
  );
};

// Event Log Anomalies Tab
const EventLogAnomaliesTab: React.FC<{
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  events: any[];
  isScanning: boolean;
  onStartScan: () => void;
}> = ({ onToggleFlag, isFlagged, events, isScanning, onStartScan }) => {
  const [expandedEvent, setExpandedEvent] = React.useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = React.useState<string>('ALL');
  const [sortByScore, setSortByScore] = React.useState<boolean>(true);

  if (isScanning) {
    return (
      <div className="intrusion-scan-prompt">
        <div className="prompt-icon">⏳</div>
        <h3>Scanning Event Logs...</h3>
        <p>Parsing .evtx files and analyzing Windows Event Logs for suspicious activity</p>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="intrusion-scan-prompt">
        <div className="prompt-icon">📊</div>
        <h3>Event Log Analysis Ready</h3>
        <p>Click "START INTRUSION SCAN" to analyze Windows Event Logs for:</p>
        <ul className="prompt-list">
          <li>🔐 Suspicious Logon Activity (Event IDs: 4624, 4625, 4648)</li>
          <li>👤 Unauthorized Account Creation (Event ID: 4720)</li>
          <li>🚨 Audit Log Tampering (Event ID: 1102)</li>
          <li>⚙️ Service Installation (Event ID: 7045)</li>
          <li>💻 PowerShell Script Block Activity (Event IDs: 4103, 4104)</li>
          <li>🔍 Sysmon Events (Process, Network, Registry)</li>
        </ul>
        <button className="start-scan-button" onClick={onStartScan}>START INTRUSION SCAN</button>
      </div>
    );
  }

  // Filter and sort events
  let filteredEvents = events;
  if (filterSeverity !== 'ALL') {
    filteredEvents = events.filter(e => e.severity === filterSeverity);
  }
  
  if (sortByScore) {
    filteredEvents = [...filteredEvents].sort((a, b) => 
      (b.suspiciousScore || 0) - (a.suspiciousScore || 0)
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return '#FF3B30';
      case 'HIGH': return '#FF9500';
      case 'MEDIUM': return '#FFCC00';
      case 'LOW': return '#34C759';
      default: return '#8E8E93';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return '#FF3B30';
    if (score >= 60) return '#FF9500';
    if (score >= 40) return '#FFCC00';
    if (score >= 20) return '#34C759';
    return '#8E8E93';
  };

  return (
    <div className="event-logs-container">
      <div className="event-logs-filters">
        <div className="filter-group">
          <label>Severity Filter:</label>
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="ALL">All ({events.length})</option>
            <option value="CRITICAL">Critical ({events.filter(e => e.severity === 'CRITICAL').length})</option>
            <option value="HIGH">High ({events.filter(e => e.severity === 'HIGH').length})</option>
            <option value="MEDIUM">Medium ({events.filter(e => e.severity === 'MEDIUM').length})</option>
            <option value="LOW">Low ({events.filter(e => e.severity === 'LOW').length})</option>
          </select>
        </div>
        <div className="filter-group">
          <label>
            <input 
              type="checkbox" 
              checked={sortByScore} 
              onChange={(e) => setSortByScore(e.target.checked)}
            />
            Sort by Suspicious Score
          </label>
        </div>
      </div>

      <div className="data-table event-logs-table">
        <div className="table-header">
          <div className="table-col table-col-small">EVENT ID</div>
          <div className="table-col table-col-medium">SEVERITY</div>
          <div className="table-col table-col-small">SCORE</div>
          <div className="table-col">DESCRIPTION</div>
          <div className="table-col table-col-medium">LOG / TIME</div>
          <div className="table-col table-col-small">FLAG</div>
        </div>
        <div className="table-body">
          {filteredEvents.map((event, idx) => {
            const itemId = `event-${event.eventId}-${idx}`;
            const flagged = isFlagged(itemId);
            const isExpanded = expandedEvent === idx;
            
            return (
              <React.Fragment key={idx}>
                <div 
                  className={`table-row event-row ${isExpanded ? 'expanded' : ''}`}
                  onClick={() => setExpandedEvent(isExpanded ? null : idx)}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="table-col table-col-small">
                    <span className="event-id-badge">
                      {event.eventId || 'N/A'}
                    </span>
                  </div>
                  <div className="table-col table-col-medium">
                    <span 
                      className="severity-badge"
                      style={{ 
                        backgroundColor: getSeverityColor(event.severity),
                        color: '#fff',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 'bold'
                      }}
                    >
                      {event.severity}
                    </span>
                  </div>
                  <div className="table-col table-col-small">
                    <span 
                      className="score-badge"
                      style={{
                        backgroundColor: getScoreColor(event.suspiciousScore || 0),
                        color: '#fff',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 'bold'
                      }}
                    >
                      {event.suspiciousScore || 0}
                    </span>
                  </div>
                  <div className="table-col">
                    <div className="event-description-line">
                      <strong>{event.artifactType}</strong>
                      <span className="expand-indicator">{isExpanded ? '▼' : '▶'}</span>
                    </div>
                    <div className="event-description-text">{event.description}</div>
                  </div>
                  <div className="table-col table-col-medium">
                    <div><strong>{event.logName}</strong></div>
                    <div style={{ fontSize: '11px', color: '#999' }}>
                      {new Date(event.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div className="table-col table-col-small">
                    <button 
                      className={`flag-button ${flagged ? 'flagged' : ''}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        onToggleFlag(itemId);
                      }}
                    >
                      {flagged ? '✓' : '⚑'}
                    </button>
                  </div>
                </div>
                
                {isExpanded && (
                  <div className="event-details-expanded">
                    <div className="event-details-grid">
                      <div className="event-detail-section">
                        <h4>Event Metadata</h4>
                        <table className="event-details-table">
                          <tbody>
                            <tr>
                              <td><strong>Event ID:</strong></td>
                              <td>{event.eventId}</td>
                            </tr>
                            <tr>
                              <td><strong>Log Name:</strong></td>
                              <td>{event.logName}</td>
                            </tr>
                            <tr>
                              <td><strong>Timestamp:</strong></td>
                              <td>{new Date(event.timestamp).toLocaleString()}</td>
                            </tr>
                            {event.computer && (
                              <tr>
                                <td><strong>Computer:</strong></td>
                                <td>{event.computer}</td>
                              </tr>
                            )}
                            {event.provider && (
                              <tr>
                                <td><strong>Provider:</strong></td>
                                <td>{event.provider}</td>
                              </tr>
                            )}
                            {event.level && (
                              <tr>
                                <td><strong>Level:</strong></td>
                                <td>{event.level}</td>
                              </tr>
                            )}
                            {event.user && (
                              <tr>
                                <td><strong>User:</strong></td>
                                <td>{event.user}</td>
                              </tr>
                            )}
                            {event.process && (
                              <tr>
                                <td><strong>Process:</strong></td>
                                <td>{event.process}</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                      
                      {event.eventData && Object.keys(event.eventData).length > 0 && (
                        <div className="event-detail-section">
                          <h4>Event Data Fields</h4>
                          <table className="event-details-table">
                            <tbody>
                              {Object.entries(event.eventData).map(([key, value]) => (
                                <tr key={key}>
                                  <td><strong>{key}:</strong></td>
                                  <td style={{ 
                                    maxWidth: '400px', 
                                    wordBreak: 'break-word',
                                    fontFamily: 'monospace',
                                    fontSize: '11px'
                                  }}>
                                    {String(value)}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}

                      <div className="event-detail-section full-width">
                        <h4>Log File Location</h4>
                        <ClickableFilePath path={event.logPath} />
                      </div>
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};

// Persistence Tab
const PersistenceTab: React.FC<{
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  items: any[];
  isScanning: boolean;
  onStartScan: () => void;
}> = ({ onToggleFlag, isFlagged, items, isScanning, onStartScan }) => {

  if (isScanning) {
    return (
      <div className="intrusion-scan-prompt">
        <div className="prompt-icon">⏳</div>
        <h3>Scanning Persistence Mechanisms...</h3>
        <p>Checking registry, startup folders, and scheduled tasks</p>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="intrusion-scan-prompt">
        <div className="prompt-icon">🔄</div>
        <h3>Persistence Mechanism Analysis Ready</h3>
        <p>Click "START INTRUSION SCAN" to check for:</p>
        <ul className="prompt-list">
          <li>🗝️ Registry Run Keys (HKLM/HKCU Software\Microsoft\Windows\CurrentVersion\Run)</li>
          <li>📁 Startup Folder Entries (All Users and User-specific)</li>
          <li>⏰ Scheduled Tasks (Suspicious or recently created tasks)</li>
          <li>🔌 Windows Services (New or modified services)</li>
          <li>🔧 WMI Event Subscriptions (Fileless persistence)</li>
        </ul>
        <button className="start-scan-button" onClick={onStartScan}>START INTRUSION SCAN</button>
      </div>
    );
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">PERSISTENCE TYPE</div>
        <div className="table-col">ENTRY NAME</div>
        <div className="table-col">TARGET PATH</div>
        <div className="table-col">LOCATION</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {items.map((item, idx) => {
          const itemId = `persistence-${item.name}-${idx}`;
          const flagged = isFlagged(itemId);
          return (
            <div key={idx} className="table-row">
              <div className="table-col">
                <span className="artifact-type-badge">{item.persistenceType}</span>
              </div>
              <div className="table-col">{item.name}</div>
              <div className="table-col">
                <ClickableFilePath path={item.targetPath} />
              </div>
              <div className="table-col file-path">{item.location}</div>
              <div className="table-col">
                <button 
                  className={`flag-button ${flagged ? 'flagged' : ''}`}
                  onClick={() => onToggleFlag(itemId)}
                >
                  {flagged ? '✓ FLAGGED' : 'FLAG'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Command History Tab
const CommandHistoryTab: React.FC<{
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
  commands: any[];
  isScanning: boolean;
  onStartScan: () => void;
}> = ({ onToggleFlag, isFlagged, commands, isScanning, onStartScan }) => {

  if (isScanning) {
    return (
      <div className="intrusion-scan-prompt">
        <div className="prompt-icon">⏳</div>
        <h3>Scanning Command History...</h3>
        <p>Analyzing PowerShell and CMD history files</p>
      </div>
    );
  }

  if (commands.length === 0) {
    return (
      <div className="intrusion-scan-prompt">
        <div className="prompt-icon">⌨️</div>
        <h3>Command History Analysis Ready</h3>
        <p>Click "START INTRUSION SCAN" to analyze:</p>
        <ul className="prompt-list">
          <li>💻 PowerShell History (ConsoleHost_history.txt)</li>
          <li>📝 Command Prompt History (doskey macros)</li>
          <li>🔍 Recent Commands Execution Artifacts</li>
          <li>🛠️ Suspicious Script Execution</li>
          <li>🌐 Network Connection Commands</li>
        </ul>
        <button className="start-scan-button" onClick={onStartScan}>START INTRUSION SCAN</button>
      </div>
    );
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">COMMAND TYPE</div>
        <div className="table-col">COMMAND</div>
        <div className="table-col">TIMESTAMP</div>
        <div className="table-col">SOURCE FILE</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {commands.map((cmd, idx) => {
          const itemId = `command-${idx}`;
          const flagged = isFlagged(itemId);
          return (
            <div key={idx} className="table-row">
              <div className="table-col">
                <span className="artifact-type-badge">{cmd.commandType}</span>
              </div>
              <div className="table-col command-text">{cmd.command}</div>
              <div className="table-col">{new Date(cmd.timestamp).toLocaleString()}</div>
              <div className="table-col">
                <ClickableFilePath path={cmd.sourcePath} />
              </div>
              <div className="table-col">
                <button 
                  className={`flag-button ${flagged ? 'flagged' : ''}`}
                  onClick={() => onToggleFlag(itemId)}
                >
                  {flagged ? '✓ FLAGGED' : 'FLAG'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Browser Credentials Tab
const BrowserCredentialsTab: React.FC<{ 
  credentials: any[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ credentials, onToggleFlag, isFlagged }) => {
  const [sortKey, setSortKey] = React.useState<string>('lastUsed');
  const [sortDir, setSortDir] = React.useState<'asc' | 'desc'>('desc');

  if (credentials.length === 0) {
    return <div className="no-data">No saved credentials found</div>;
  }

  // Extract website name from URL
  const getWebsiteName = (url: string): string => {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url;
    }
  };

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir(key === 'website' || key === 'username' ? 'asc' : 'desc');
    }
  };

  const sortIndicator = (key: string) =>
    sortKey === key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  const sorted = [...credentials].sort((a, b) => {
    let cmp = 0;
    if (sortKey === 'website') {
      cmp = getWebsiteName(a.originUrl || a.url || '').localeCompare(getWebsiteName(b.originUrl || b.url || ''));
    } else if (sortKey === 'username') {
      cmp = (a.username || '').localeCompare(b.username || '');
    } else if (sortKey === 'lastUsed') {
      const aTime = new Date(a.dateLastUsed || a.lastUsed || 0).getTime();
      const bTime = new Date(b.dateLastUsed || b.lastUsed || 0).getTime();
      cmp = aTime - bTime;
    }
    return sortDir === 'asc' ? cmp : -cmp;
  });

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col sortable-col" onClick={() => handleSort('website')}>WEBSITE{sortIndicator('website')}</div>
        <div className="table-col sortable-col" onClick={() => handleSort('username')}>USERNAME{sortIndicator('username')}</div>
        <div className="table-col sortable-col" onClick={() => handleSort('lastUsed')}>LAST USED{sortIndicator('lastUsed')}</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {sorted.map((item, idx) => {
          const originUrl = item.originUrl || item.url || item.origin || '';
          const itemId = `credential-${originUrl}-${item.username}-${idx}`;
          const flagged = isFlagged(itemId);
          const websiteName = getWebsiteName(originUrl);
          
          return (
            <div key={idx} className="table-row">
              <div className="table-col" title={originUrl}>{websiteName}</div>
              <div className="table-col">{item.username}</div>
              <div className="table-col">
                {item.dateLastUsed || item.lastUsed ? new Date(item.dateLastUsed || item.lastUsed).toLocaleString() : 'Unknown'}
              </div>
              <div className="table-col">
                <button 
                  className={`flag-button ${flagged ? 'flagged' : ''}`}
                  onClick={() => onToggleFlag(itemId)}
                >
                  {flagged ? '✓ FLAGGED' : 'FLAG'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Notes View Component
const NotesView: React.FC<{
  notes: string;
  onNotesChange: (notes: string) => void;
}> = ({ notes, onNotesChange }) => {
  return (
    <div className="content-view">
      <h2 className="view-title">INVESTIGATOR NOTES</h2>
      <div className="notes-section">
        <p className="notes-description">
          Add observations, analysis, and important findings during the investigation. 
          These notes will be included in the generated report.
        </p>
        <textarea
          className="investigator-notes-textarea"
          value={notes}
          onChange={(e) => onNotesChange(e.target.value)}
          placeholder="Enter investigator notes here...

Example:
- Device owner confirmed as John Doe
- Multiple dating apps installed (Tinder, Bumble)
- Browser history shows frequent visits to social media platforms
- Photos indicate subject was at location on 2024-01-15"
          rows={20}
        />
        <div className="notes-footer">
          <div className="notes-character-count">
            {notes.length} characters
          </div>
        </div>
      </div>
    </div>
  );
};
