import React from 'react';
import { QuestionableApp, AppCategoryLabels, AppCategoryRiskLevels } from '../types/scanner';
import './AppDetails.css';

interface AppDetailsProps {
  app: QuestionableApp | null;
}

export const AppDetails: React.FC<AppDetailsProps> = ({ app }) => {
  if (!app) {
    return (
      <div className="app-details empty">
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <p>Select an application to view details</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-details">
      <div className="details-header">
        <h2>Application Details</h2>
        <div className="alert-badge">⚠️ FLAGGED</div>
      </div>

      <div className="details-section">
        <h3 className="section-title">Basic Information</h3>
        <div className="details-grid">
          <div className="detail-item">
            <label>Application Name</label>
            <div className="detail-value">{app.name}</div>
          </div>
          
          <div className="detail-item">
            <label>Category</label>
            <div className="detail-value category-badge">
              {AppCategoryLabels[app.category]}
            </div>
          </div>
          
          <div className="detail-item">
            <label>Version</label>
            <div className="detail-value mono">{app.version}</div>
          </div>
          
          {app.publisher && (
            <div className="detail-item">
              <label>Publisher</label>
              <div className="detail-value">{app.publisher}</div>
            </div>
          )}
        </div>
      </div>

      <div className="details-section">
        <h3 className="section-title">Installation Details</h3>
        <div className="details-grid">
          <div className="detail-item">
            <label>Install Path</label>
            <div className="detail-value mono path">{app.install_path}</div>
          </div>
          
          {app.install_date && (
            <div className="detail-item">
              <label>Install Date</label>
              <div className="detail-value mono">{formatInstallDate(app.install_date)}</div>
            </div>
          )}
        </div>
      </div>

      <div className="details-section">
        <h3 className="section-title">Risk Assessment</h3>
        <div className="risk-info">
          <div className={`risk-level ${getRiskLevelClass(app.category)}`}>
            <div className="risk-indicator"></div>
            <span>{AppCategoryRiskLevels[app.category]} PRIORITY</span>
          </div>
          <p className="risk-description">
            {getRiskDescription(app.category)}
          </p>
        </div>
      </div>
    </div>
  );
};

function formatInstallDate(dateStr: string): string {
  if (dateStr.length === 8) {
    const year = dateStr.substring(0, 4);
    const month = dateStr.substring(4, 6);
    const day = dateStr.substring(6, 8);
    return `${month}/${day}/${year}`;
  }
  return dateStr;
}

function getRiskLevelClass(category: string): string {
  const level = AppCategoryRiskLevels[category as keyof typeof AppCategoryRiskLevels] || "UNKNOWN";
  switch (level) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return "unknown";
  }
}

function getRiskDescription(category: string): string {
  const descriptions: Record<string, string> = {
    SocialMedia: "Social media applications may contain relevant communications, contacts, and media. Important for communication pattern analysis and evidence collection.",
    Messaging: "Messaging applications contain direct communications and may include relevant evidence. Check for encrypted messaging apps that may obscure content.",
    Gaming: "Gaming platforms may contain chat logs, user interactions, and transaction records. Generally low risk but may be relevant for specific investigations.",
    PeerToPeer: "Peer-to-peer file sharing applications are commonly used to distribute and download copyrighted material, illegal content, or evidence. High priority for content analysis.",
    DarkWeb: "CRITICAL: Dark web and anonymity tools like Tor indicate attempts to access hidden services and conceal online activity. Immediate investigative priority.",
    VPN: "VPN applications can be used to hide internet activity and location. May indicate attempts to conceal online behavior or circumvent geographic restrictions.",
    VirtualMachine: "Virtual machine software allows running isolated operating systems. Can be used to hide activities, test malware, or maintain separate digital environments.",
    WebBrowser: "Alternative web browsers may contain browsing history, bookmarks, and cached data relevant to investigations. Standard evidence collection point.",
    CloudStorage: "Cloud storage applications synchronize files across devices. May contain evidence uploaded from or shared with other devices. Check for shared folders and recent uploads.",
    CryptoPayment: "Cryptocurrency wallets and payment applications may contain transaction records, wallet addresses, and financial evidence. Important for financial crime investigations.",
    Cleaner: "CRITICAL: Cleaner and shredder tools permanently delete data, making recovery extremely difficult or impossible. Indicator of anti-forensics activity and evidence destruction.",
    Encryption: "Encryption tools can prevent access to data. May indicate attempts to protect sensitive information from forensic analysis. Requires special handling and documentation.",
    AntiForensics: "CRITICAL: Anti-forensics tools are specifically designed to obstruct digital investigations. Immediate documentation and attention required.",
    RemoteAccess: "Remote access software allows controlling computers remotely. Can be used for legitimate IT support or for unauthorized access. Check access logs and connection history.",
    Utilities: "System utilities for file management, compression, and system maintenance. Generally low risk but may be relevant for specific evidence handling.",
    Productivity: "Standard productivity applications like office suites and note-taking apps. May contain relevant documents and communications.",
    Development: "Development tools and IDEs. May be relevant for investigations involving software development, hacking tools, or scripting.",
    Multimedia: "Media players, editors, and streaming applications. Check for downloaded content, editing history, and media libraries.",
    Unknown: "This application has been flagged but its specific risk category is unknown. Further investigation recommended."
  };
  
  return descriptions[category] || descriptions.Unknown;
}
