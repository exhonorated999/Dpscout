import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button } from './Button';
import { convertToMediaProtocol } from '../utils/mediaProtocol';
import './SmsViewer.css';

interface MmsAttachment {
  id: number;
  msgId: number;
  contentType: string;
  fileName: string | null;
  filePath: string;
  fileSize: number;
  thumbnailPath: string | null;
  width: number | null;
  height: number | null;
}

interface SmsMessage {
  id: number;
  threadId: number;
  address: string;
  person: string | null;
  date: number;
  dateSent: number;
  dateFormatted: string;
  messageType: 'inbox' | 'sent' | 'draft' | 'outbox' | 'failed' | 'queued' | 'unknown';
  body: string;
  read: boolean;
  status: number;
  serviceCenter: string | null;
  subject: string | null;
  hasAttachments: boolean;
  attachmentCount: number;
  attachments: MmsAttachment[];
}

interface SmsThread {
  threadId: number;
  contactName: string | null;
  contactNumber: string;
  messageCount: number;
  snippet: string;
  lastMessageDate: number;
  lastMessageDateFormatted: string;
  unreadCount: number;
}

interface SmsExtractionResult {
  totalMessages: number;
  threads: SmsThread[];
  messages: SmsMessage[];
  dateRange: [string, string] | null;
  extractionMethod: string;
  extractionSummary?: string; // Multi-silo summary
  silosScanned?: any[]; // Multi-silo sources
}

interface SmsViewerProps {
  deviceId: string | null;
  onClose: () => void;
}

const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const SmsViewer: React.FC<SmsViewerProps> = ({ deviceId, onClose }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [extractionResult, setExtractionResult] = useState<SmsExtractionResult | null>(null);
  const [selectedThread, setSelectedThread] = useState<SmsThread | null>(null);
  const [threadMessages, setThreadMessages] = useState<SmsMessage[]>([]);
  const [viewMode, setViewMode] = useState<'threads' | 'all'>('threads');
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleExtract = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const result = await invoke<SmsExtractionResult>('extract_android_sms', {
        deviceId,
        limit: null // Get all messages
      });
      
      setExtractionResult(result);
      console.log('SMS extraction complete:', result);
    } catch (err) {
      console.error('Failed to extract SMS:', err);
      setError(err as string);
    } finally {
      setIsLoading(false);
    }
  };

  const handleThreadClick = async (thread: SmsThread) => {
    setSelectedThread(thread);
    
    try {
      const messages = await invoke<SmsMessage[]>('get_sms_thread_messages', {
        threadId: thread.threadId
      });
      setThreadMessages(messages);
    } catch (err) {
      console.error('Failed to load thread messages:', err);
      alert(`Failed to load conversation: ${err}`);
    }
  };

  const filteredMessages = extractionResult?.messages.filter(msg =>
    msg.body.toLowerCase().includes(searchQuery.toLowerCase()) ||
    msg.address.includes(searchQuery)
  ) || [];

  const filteredThreads = extractionResult?.threads.filter(thread =>
    thread.contactNumber.includes(searchQuery) ||
    thread.snippet.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (thread.contactName && thread.contactName.toLowerCase().includes(searchQuery.toLowerCase()))
  ) || [];

  if (!extractionResult) {
    return (
      <div className="sms-viewer">
        <div className="sms-header">
          <div className="header-title">
            <button className="btn-back" onClick={onClose}>← Back to Devices</button>
            <h1>💬 SMS MESSAGE VIEWER</h1>
            <p>Extract and review text messages from Android device</p>
          </div>
        </div>
        <div className="sms-extraction-prompt">
            <div className="prompt-icon">📱</div>
            <h2>Extract SMS Messages</h2>
            <p className="prompt-description">
              This tool will extract text messages from the connected Android device.
            </p>

            <div className="extraction-methods">
              <div className="method-card">
                <h3>🔓 Rooted Device</h3>
                <p>Direct database access - Fast and reliable</p>
                <ul>
                  <li>Instant extraction</li>
                  <li>All messages included</li>
                  <li>No user confirmation needed</li>
                </ul>
              </div>

              <div className="method-card">
                <h3>📦 Non-Rooted Device</h3>
                <p>Uses ADB backup - Requires user confirmation</p>
                <ul>
                  <li>User must unlock device</li>
                  <li>Confirm backup on device screen</li>
                  <li><strong>If asked for password, use: 1</strong></li>
                  <li>May take 1-2 minutes</li>
                </ul>
                <div style={{marginTop: '10px', padding: '8px', background: '#2a2d35', borderRadius: '4px', fontSize: '0.9em'}}>
                  <strong>⚠️ Password Note:</strong> If Android requests a backup password, enter <code style={{background: '#1a1c22', padding: '2px 6px', borderRadius: '3px', color: '#4CAF50'}}>1</code>
                  <br/>
                  <span style={{fontSize: '0.85em', opacity: 0.8}}>The software will automatically decrypt using this password</span>
                </div>
              </div>
            </div>

            {error && (
              <div className="extraction-error">
                <p className="error-title">❌ Extraction Failed</p>
                <p className="error-message">{error}</p>
                <p className="error-hint">
                  Make sure the device is connected, unlocked, and USB debugging is enabled.
                  For non-rooted devices, confirm the backup prompt on the device screen.
                </p>
              </div>
            )}

            <Button
              variant="primary"
              size="lg"
              glow
              onClick={handleExtract}
              disabled={isLoading}
            >
              {isLoading ? '⏳ Extracting Messages...' : '📥 Extract SMS Messages'}
            </Button>
          </div>
        </div>
    );
  }

  return (
    <div className="sms-viewer">
      <div className="sms-header">
        <div className="header-title">
          <button className="btn-back" onClick={onClose}>← Back to Devices</button>
          <h1>💬 SMS MESSAGES</h1>
          <p>
            {extractionResult.totalMessages} messages · {extractionResult.threads.length} conversations
            {extractionResult.dateRange && (
              <span className="date-range">
                {' · '}{extractionResult.dateRange[0]} to {extractionResult.dateRange[1]}
              </span>
            )}
          </p>
          <p className="extraction-method">
            Extraction method: {extractionResult.extractionMethod}
          </p>
          {extractionResult.extractionSummary && (
            <p className="extraction-summary" style={{ 
              fontSize: '0.9rem', 
              color: '#888', 
              marginTop: '8px',
              fontStyle: 'italic'
            }}>
              {extractionResult.extractionSummary}
            </p>
          )}
        </div>
        
        <div className="header-actions">
          <Button variant="secondary" size="sm" onClick={() => setViewMode(viewMode === 'threads' ? 'all' : 'threads')}>
            {viewMode === 'threads' ? '📋 All Messages' : '💬 Conversations'}
          </Button>
          <Button variant="secondary" size="sm" onClick={handleExtract} disabled={isLoading}>
            🔄 Refresh
          </Button>
        </div>
      </div>

        <div className="sms-search">
          <input
            type="text"
            placeholder="🔍 Search messages, phone numbers, or contacts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="sms-content">
          {viewMode === 'threads' ? (
            <div className="sms-layout">
              <div className="threads-panel">
                <div className="panel-header">
                  <h3>Conversations ({filteredThreads.length})</h3>
                </div>
                <div className="threads-list">
                  {filteredThreads.map(thread => (
                    <div
                      key={thread.threadId}
                      className={`thread-item ${selectedThread?.threadId === thread.threadId ? 'active' : ''} ${thread.unreadCount > 0 ? 'unread' : ''}`}
                      onClick={() => handleThreadClick(thread)}
                    >
                      <div className="thread-avatar">
                        {thread.contactName ? thread.contactName[0].toUpperCase() : '👤'}
                      </div>
                      <div className="thread-info">
                        <div className="thread-header">
                          <span className="thread-name">
                            {thread.contactName || thread.contactNumber}
                          </span>
                          <span className="thread-date">
                            {new Date(thread.lastMessageDate).toLocaleDateString()}
                          </span>
                        </div>
                        <div className="thread-snippet">{thread.snippet}</div>
                        <div className="thread-meta">
                          <span>{thread.messageCount} messages</span>
                          {thread.unreadCount > 0 && (
                            <span className="unread-badge">{thread.unreadCount} unread</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="messages-panel">
                {selectedThread ? (
                  <>
                    <div className="panel-header conversation-header">
                      <div className="conversation-title">
                        <h3>{selectedThread.contactName || selectedThread.contactNumber}</h3>
                        <p className="conversation-number">{selectedThread.contactNumber}</p>
                      </div>
                    </div>
                    <div className="messages-list">
                      {threadMessages.map((msg, index) => (
                        <div
                          key={msg.id}
                          className={`message-bubble ${msg.messageType === 'sent' ? 'sent' : 'received'}`}
                        >
                          <div className="message-content">
                            {msg.subject && (
                              <div className="message-subject">📎 {msg.subject}</div>
                            )}
                            {msg.body && (
                              <div className="message-body">{msg.body}</div>
                            )}
                            {msg.hasAttachments && msg.attachments.length > 0 && (
                              <div className="message-attachments">
                                {msg.attachments.map(att => (
                                  <div key={att.id} className="attachment-item">
                                    {att.contentType.startsWith('image/') ? (
                                      <div className="attachment-image">
                                        <img
                                          src={att.thumbnailPath ? convertToMediaProtocol(att.thumbnailPath) : convertToMediaProtocol(att.filePath)}
                                          alt={att.fileName || 'MMS Image'}
                                          onClick={() => window.open(convertToMediaProtocol(att.filePath))}
                                        />
                                      </div>
                                    ) : att.contentType.startsWith('video/') ? (
                                      <div className="attachment-video">
                                        <video
                                          src={convertToMediaProtocol(att.filePath)}
                                          controls
                                          poster={att.thumbnailPath ? convertToMediaProtocol(att.thumbnailPath) : undefined}
                                        />
                                      </div>
                                    ) : (
                                      <div className="attachment-file">
                                        <span className="file-icon">📄</span>
                                        <span className="file-name">{att.fileName || 'Attachment'}</span>
                                        <span className="file-size">{formatFileSize(att.fileSize)}</span>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                            <div className="message-meta">
                              <span className="message-time">{msg.dateFormatted}</span>
                              {msg.messageType === 'sent' && (
                                <span className="message-status">
                                  {msg.status === -1 ? '❌' : '✓'}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="no-selection">
                    <div className="no-selection-icon">💬</div>
                    <p>Select a conversation to view messages</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="all-messages-view">
              <div className="messages-grid">
                {filteredMessages.map(msg => (
                  <div key={msg.id} className={`message-card ${msg.messageType}`}>
                    <div className="message-card-header">
                      <span className="message-contact">
                        {msg.messageType === 'sent' ? 'To: ' : 'From: '}
                        {msg.person || msg.address}
                      </span>
                      <span className="message-date">{msg.dateFormatted}</span>
                    </div>
                    <div className="message-card-body">{msg.body}</div>
                    <div className="message-card-footer">
                      <span className={`message-type-badge ${msg.messageType}`}>
                        {msg.messageType.toUpperCase()}
                      </span>
                      {!msg.read && <span className="unread-indicator">●</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
  );
};
