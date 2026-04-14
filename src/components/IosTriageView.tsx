import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { IosDevice, IosMessage, IosContact, IosCall, IosBrowserHistory, IosApp } from '../types/ios';
import './IosTriageView.css';

type IosDataTab = 'messages' | 'contacts' | 'calls' | 'browser' | 'apps';

interface IosTriageViewProps {
  onToggleFlag: (itemId: string) => void;
  isFlagged: (itemId: string) => boolean;
}

export const IosTriageView: React.FC<IosTriageViewProps> = ({ onToggleFlag, isFlagged }) => {
  const [backups, setBackups] = useState<IosDevice[]>([]);
  const [selectedBackup, setSelectedBackup] = useState<IosDevice | null>(null);
  const [activeTab, setActiveTab] = useState<IosDataTab>('messages');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [messages, setMessages] = useState<IosMessage[]>([]);
  const [contacts, setContacts] = useState<IosContact[]>([]);
  const [calls, setCalls] = useState<IosCall[]>([]);
  const [browserHistory, setBrowserHistory] = useState<IosBrowserHistory[]>([]);
  const [apps, setApps] = useState<IosApp[]>([]);

  // Search/filter states
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadBackups();
  }, []);

  const loadBackups = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<IosDevice[]>('get_ios_backups');
      setBackups(result);
      if (result.length > 0) {
        setSelectedBackup(result[0]);
      }
    } catch (err) {
      setError(`Failed to load backups: ${err}`);
      console.error('Error loading iOS backups:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadData = async (dataType: IosDataTab) => {
    if (!selectedBackup) return;

    setLoading(true);
    setError(null);
    try {
      switch (dataType) {
        case 'messages':
          const msgs = await invoke<IosMessage[]>('get_ios_messages', {
            backupPath: selectedBackup.backupPath
          });
          setMessages(msgs);
          break;
        case 'contacts':
          const cnts = await invoke<IosContact[]>('get_ios_contacts', {
            backupPath: selectedBackup.backupPath
          });
          setContacts(cnts);
          break;
        case 'calls':
          const clls = await invoke<IosCall[]>('get_ios_calls', {
            backupPath: selectedBackup.backupPath
          });
          setCalls(clls);
          break;
        case 'browser':
          const hist = await invoke<IosBrowserHistory[]>('get_ios_browser_history', {
            backupPath: selectedBackup.backupPath
          });
          setBrowserHistory(hist);
          break;
        case 'apps':
          const appsData = await invoke<IosApp[]>('get_ios_apps', {
            backupPath: selectedBackup.backupPath
          });
          setApps(appsData);
          break;
      }
    } catch (err) {
      setError(`Failed to load ${dataType}: ${err}`);
      console.error(`Error loading iOS ${dataType}:`, err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedBackup) {
      loadData(activeTab);
    }
  }, [selectedBackup, activeTab]);

  const filterMessages = () => {
    if (!searchTerm) return messages;
    const term = searchTerm.toLowerCase();
    return messages.filter(m => 
      m.messageText.toLowerCase().includes(term) ||
      m.sender.toLowerCase().includes(term)
    );
  };

  const filterContacts = () => {
    if (!searchTerm) return contacts;
    const term = searchTerm.toLowerCase();
    return contacts.filter(c =>
      c.firstName.toLowerCase().includes(term) ||
      c.lastName.toLowerCase().includes(term) ||
      c.phoneNumbers.some(p => p.includes(term)) ||
      c.emails.some(e => e.toLowerCase().includes(term))
    );
  };

  const filterCalls = () => {
    if (!searchTerm) return calls;
    const term = searchTerm.toLowerCase();
    return calls.filter(c =>
      c.phoneNumber.includes(term) ||
      c.callType.toLowerCase().includes(term)
    );
  };

  const filterBrowserHistory = () => {
    if (!searchTerm) return browserHistory;
    const term = searchTerm.toLowerCase();
    return browserHistory.filter(h =>
      h.url.toLowerCase().includes(term) ||
      h.title.toLowerCase().includes(term)
    );
  };

  const filterApps = () => {
    if (!searchTerm) return apps;
    const term = searchTerm.toLowerCase();
    return apps.filter(a =>
      a.appName.toLowerCase().includes(term) ||
      a.bundleId.toLowerCase().includes(term)
    );
  };

  if (backups.length === 0 && !loading) {
    return (
      <div className="ios-triage-view">
        <div className="no-backups">
          <h2>📱 No iOS Backups Found</h2>
          <p>No iTunes/Finder backups detected on this system.</p>
          <p className="help-text">
            To create a backup:
            <br />1. Connect your iPhone/iPad to this computer
            <br />2. Open iTunes (Windows) or Finder (Mac)
            <br />3. Select your device and click "Back Up Now"
            <br />4. Return to Hindsight and refresh
          </p>
          <button className="refresh-button" onClick={loadBackups}>
            🔄 Check Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="ios-triage-view">
      {/* Device Selector */}
      <div className="ios-device-selector">
        <h3>📱 Select iOS Backup</h3>
        <select 
          value={selectedBackup?.udid || ''} 
          onChange={(e) => {
            const backup = backups.find(b => b.udid === e.target.value);
            if (backup) setSelectedBackup(backup);
          }}
          className="backup-dropdown"
        >
          {backups.map(backup => (
            <option key={backup.udid} value={backup.udid}>
              {backup.deviceName} - {backup.deviceModel} (iOS {backup.iosVersion})
            </option>
          ))}
        </select>
        
        {selectedBackup && (
          <div className="device-details">
            <div className="detail-row">
              <span className="label">Model:</span>
              <span className="value">{selectedBackup.deviceModel}</span>
            </div>
            <div className="detail-row">
              <span className="label">iOS Version:</span>
              <span className="value">{selectedBackup.iosVersion}</span>
            </div>
            <div className="detail-row">
              <span className="label">Serial:</span>
              <span className="value">{selectedBackup.serialNumber}</span>
            </div>
            <div className="detail-row">
              <span className="label">Last Backup:</span>
              <span className="value">{selectedBackup.lastBackupDate}</span>
            </div>
            {selectedBackup.phoneNumber && (
              <div className="detail-row">
                <span className="label">Phone:</span>
                <span className="value">{selectedBackup.phoneNumber}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Data Tabs */}
      <div className="ios-data-tabs">
        <button
          className={`tab-button ${activeTab === 'messages' ? 'active' : ''}`}
          onClick={() => setActiveTab('messages')}
        >
          💬 Messages ({messages.length})
        </button>
        <button
          className={`tab-button ${activeTab === 'contacts' ? 'active' : ''}`}
          onClick={() => setActiveTab('contacts')}
        >
          👥 Contacts ({contacts.length})
        </button>
        <button
          className={`tab-button ${activeTab === 'calls' ? 'active' : ''}`}
          onClick={() => setActiveTab('calls')}
        >
          📞 Calls ({calls.length})
        </button>
        <button
          className={`tab-button ${activeTab === 'browser' ? 'active' : ''}`}
          onClick={() => setActiveTab('browser')}
        >
          🌐 Safari ({browserHistory.length})
        </button>
        <button
          className={`tab-button ${activeTab === 'apps' ? 'active' : ''}`}
          onClick={() => setActiveTab('apps')}
        >
          📦 Apps ({apps.length})
        </button>
      </div>

      {/* Search Bar */}
      <div className="ios-search-bar">
        <input
          type="text"
          placeholder={`Search ${activeTab}...`}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
        {searchTerm && (
          <button className="clear-search" onClick={() => setSearchTerm('')}>
            ✕
          </button>
        )}
      </div>

      {/* Loading/Error States */}
      {loading && <div className="loading">Loading {activeTab}...</div>}
      {error && <div className="error">{error}</div>}

      {/* Data Content */}
      {!loading && !error && selectedBackup && (
        <div className="ios-data-content">
          {activeTab === 'messages' && (
            <MessagesView 
              messages={filterMessages()} 
              onToggleFlag={onToggleFlag}
              isFlagged={isFlagged}
            />
          )}
          {activeTab === 'contacts' && (
            <ContactsView 
              contacts={filterContacts()}
              onToggleFlag={onToggleFlag}
              isFlagged={isFlagged}
            />
          )}
          {activeTab === 'calls' && (
            <CallsView 
              calls={filterCalls()}
              onToggleFlag={onToggleFlag}
              isFlagged={isFlagged}
            />
          )}
          {activeTab === 'browser' && (
            <BrowserHistoryView 
              history={filterBrowserHistory()}
              onToggleFlag={onToggleFlag}
              isFlagged={isFlagged}
            />
          )}
          {activeTab === 'apps' && (
            <AppsView 
              apps={filterApps()}
              onToggleFlag={onToggleFlag}
              isFlagged={isFlagged}
            />
          )}
        </div>
      )}
    </div>
  );
};

// Messages View Component
const MessagesView: React.FC<{
  messages: IosMessage[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ messages, onToggleFlag, isFlagged }) => {
  if (messages.length === 0) {
    return <div className="no-data">No messages found</div>;
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">SENDER</div>
        <div className="table-col">MESSAGE</div>
        <div className="table-col">DATE</div>
        <div className="table-col">SERVICE</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {messages.map((msg, idx) => {
          const itemId = `ios-msg-${msg.messageId}`;
          const flagged = isFlagged(itemId);
          return (
            <div key={idx} className="table-row">
              <div className="table-col">{msg.sender}</div>
              <div className="table-col message-text">{msg.messageText}</div>
              <div className="table-col">{msg.date}</div>
              <div className="table-col">
                <span className={`service-badge ${msg.service.toLowerCase()}`}>
                  {msg.service}
                </span>
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

// Contacts View Component
const ContactsView: React.FC<{
  contacts: IosContact[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ contacts, onToggleFlag, isFlagged }) => {
  if (contacts.length === 0) {
    return <div className="no-data">No contacts found</div>;
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">NAME</div>
        <div className="table-col">PHONE NUMBERS</div>
        <div className="table-col">EMAILS</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {contacts.map((contact, idx) => {
          const itemId = `ios-contact-${contact.recordId}`;
          const flagged = isFlagged(itemId);
          const fullName = `${contact.firstName} ${contact.lastName}`.trim();
          return (
            <div key={idx} className="table-row">
              <div className="table-col">{fullName || 'Unknown'}</div>
              <div className="table-col">
                {contact.phoneNumbers.length > 0 
                  ? contact.phoneNumbers.join(', ') 
                  : 'None'}
              </div>
              <div className="table-col">
                {contact.emails.length > 0 
                  ? contact.emails.join(', ') 
                  : 'None'}
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

// Calls View Component
const CallsView: React.FC<{
  calls: IosCall[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ calls, onToggleFlag, isFlagged }) => {
  if (calls.length === 0) {
    return <div className="no-data">No call history found</div>;
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">PHONE NUMBER</div>
        <div className="table-col">TYPE</div>
        <div className="table-col">DURATION</div>
        <div className="table-col">DATE</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {calls.map((call, idx) => {
          const itemId = `ios-call-${call.callId}`;
          const flagged = isFlagged(itemId);
          const minutes = Math.floor(call.duration / 60);
          const seconds = call.duration % 60;
          const durationStr = `${minutes}m ${seconds}s`;
          
          return (
            <div key={idx} className="table-row">
              <div className="table-col">{call.phoneNumber}</div>
              <div className="table-col">
                <span className={`call-type-badge ${call.callType.toLowerCase()}`}>
                  {call.callType}
                </span>
              </div>
              <div className="table-col">{durationStr}</div>
              <div className="table-col">{call.date}</div>
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

// Browser History View Component
const BrowserHistoryView: React.FC<{
  history: IosBrowserHistory[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ history, onToggleFlag, isFlagged }) => {
  if (history.length === 0) {
    return <div className="no-data">No browser history found</div>;
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">URL</div>
        <div className="table-col">TITLE</div>
        <div className="table-col">VISITS</div>
        <div className="table-col">LAST VISIT</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {history.map((entry, idx) => {
          const itemId = `ios-history-${idx}`;
          const flagged = isFlagged(itemId);
          return (
            <div key={idx} className="table-row">
              <div className="table-col url-col">
                <a href={entry.url} target="_blank" rel="noopener noreferrer">
                  {entry.url}
                </a>
              </div>
              <div className="table-col">{entry.title}</div>
              <div className="table-col">{entry.visitCount}</div>
              <div className="table-col">{entry.lastVisit}</div>
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

// Apps View Component
const AppsView: React.FC<{
  apps: IosApp[];
  onToggleFlag: (id: string) => void;
  isFlagged: (id: string) => boolean;
}> = ({ apps, onToggleFlag, isFlagged }) => {
  if (apps.length === 0) {
    return <div className="no-data">No apps found</div>;
  }

  return (
    <div className="data-table">
      <div className="table-header">
        <div className="table-col">APP NAME</div>
        <div className="table-col">BUNDLE ID</div>
        <div className="table-col">VERSION</div>
        <div className="table-col">TYPE</div>
        <div className="table-col">FLAG</div>
      </div>
      <div className="table-body">
        {apps.map((app, idx) => {
          const itemId = `ios-app-${app.bundleId}`;
          const flagged = isFlagged(itemId);
          return (
            <div key={idx} className="table-row">
              <div className="table-col">{app.appName}</div>
              <div className="table-col mono">{app.bundleId}</div>
              <div className="table-col">{app.version}</div>
              <div className="table-col">
                <span className={`app-type-badge ${app.isSystemApp ? 'system' : 'user'}`}>
                  {app.isSystemApp ? 'System' : 'User'}
                </span>
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
