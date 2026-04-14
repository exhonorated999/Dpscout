import { useState } from 'react';
import '../styles/SmsConversationView.css';

interface SmsMessage {
  id: number;
  threadId: number;
  address: string;
  person?: string;
  date: number;
  dateSent: number;
  dateFormatted: string;
  messageType: 'Inbox' | 'Sent' | 'Draft' | 'Outbox' | 'Failed' | 'Unknown';
  body: string;
  read: boolean;
  status: number;
}

interface SmsThread {
  threadId: number;
  contactName?: string;
  contactNumber: string;
  messageCount: number;
  snippet: string;
  lastMessageDate: number;
  lastMessageDateFormatted: string;
  unreadCount: number;
}

interface SmsConversationViewProps {
  threads: SmsThread[];
  messages: SmsMessage[];
  onToggleFlag: (type: string, id: string) => void;
  isFlagged: (type: string, id: string) => boolean;
}

export default function SmsConversationView({ threads, messages, onToggleFlag, isFlagged }: SmsConversationViewProps) {
  const [selectedThread, setSelectedThread] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Get messages for the selected thread
  const threadMessages = selectedThread !== null
    ? messages.filter(msg => msg.threadId === selectedThread).sort((a, b) => a.date - b.date)
    : [];

  // Get the selected thread details
  const currentThread = threads.find(t => t.threadId === selectedThread);

  // Filter threads by search term
  const filteredThreads = threads.filter(thread =>
    thread.contactNumber.toLowerCase().includes(searchTerm.toLowerCase()) ||
    thread.contactName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    thread.snippet.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    if (date.toDateString() === today.toDateString()) {
      return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
    } else if (date.toDateString() === yesterday.toDateString()) {
      return 'Yesterday';
    } else {
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    }
  };

  return (
    <div className="sms-conversation-container">
      {/* Left Sidebar - Thread List */}
      <div className="sms-thread-list">
        <div className="thread-list-header">
          <h3>💬 Conversations ({threads.length})</h3>
          <input
            type="text"
            placeholder="Search conversations..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="thread-search"
          />
        </div>
        
        <div className="thread-list-scroll">
          {filteredThreads.length === 0 ? (
            <div className="no-threads">No conversations found</div>
          ) : (
            filteredThreads.map(thread => (
              <div
                key={thread.threadId}
                className={`thread-item ${selectedThread === thread.threadId ? 'active' : ''}`}
                onClick={() => setSelectedThread(thread.threadId)}
              >
                <div className="thread-item-header">
                  <div className="thread-contact">
                    <div className="contact-avatar">
                      {(thread.contactName || thread.contactNumber).charAt(0).toUpperCase()}
                    </div>
                    <div className="contact-info">
                      <div className="contact-name">
                        {thread.contactName || thread.contactNumber}
                      </div>
                      {thread.contactName && (
                        <div className="contact-number">{thread.contactNumber}</div>
                      )}
                    </div>
                  </div>
                  <div className="thread-meta">
                    <div className="thread-time">{formatTime(thread.lastMessageDate)}</div>
                    <div className="thread-count">{thread.messageCount}</div>
                  </div>
                </div>
                <div className="thread-snippet">{thread.snippet}</div>
                {thread.unreadCount > 0 && (
                  <div className="unread-badge">{thread.unreadCount}</div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Right Side - Conversation View */}
      <div className="sms-conversation-area">
        {selectedThread === null ? (
          <div className="no-conversation-selected">
            <div className="empty-state-icon">💬</div>
            <h3>Select a conversation</h3>
            <p>Choose a conversation from the list to view messages</p>
          </div>
        ) : (
          <>
            {/* Conversation Header */}
            <div className="conversation-header">
              <div className="conversation-contact">
                <div className="contact-avatar-large">
                  {(currentThread?.contactName || currentThread?.contactNumber || '?').charAt(0).toUpperCase()}
                </div>
                <div>
                  <h3>{currentThread?.contactName || currentThread?.contactNumber}</h3>
                  {currentThread?.contactName && (
                    <p className="contact-number-sub">{currentThread?.contactNumber}</p>
                  )}
                  <p className="message-count-sub">{threadMessages.length} messages</p>
                </div>
              </div>
              <div className="conversation-actions">
                <button
                  className={`flag-conversation-btn ${isFlagged('sms-thread', String(selectedThread)) ? 'flagged' : ''}`}
                  onClick={() => onToggleFlag('sms-thread', String(selectedThread))}
                  title="Flag this conversation"
                >
                  {isFlagged('sms-thread', String(selectedThread)) ? '🚩 Flagged' : '⚑ Flag'}
                </button>
              </div>
            </div>

            {/* Messages Area */}
            <div className="messages-container">
              {threadMessages.length === 0 ? (
                <div className="no-messages">No messages in this conversation</div>
              ) : (
                threadMessages.map((message, index) => {
                  const isSent = message.messageType === 'Sent';
                  const showDateDivider = index === 0 || 
                    new Date(message.date).toDateString() !== new Date(threadMessages[index - 1].date).toDateString();

                  return (
                    <div key={message.id}>
                      {showDateDivider && (
                        <div className="date-divider">
                          <span>{new Date(message.date).toLocaleDateString('en-US', { 
                            weekday: 'long', 
                            year: 'numeric', 
                            month: 'long', 
                            day: 'numeric' 
                          })}</span>
                        </div>
                      )}
                      
                      <div className={`message-row ${isSent ? 'sent' : 'received'}`}>
                        <div className="message-bubble-container">
                          <div className={`message-bubble ${isSent ? 'sent' : 'received'}`}>
                            <div className="message-body">{message.body}</div>
                            <div className="message-meta">
                              <span className="message-time">
                                {new Date(message.date).toLocaleTimeString('en-US', { 
                                  hour: 'numeric', 
                                  minute: '2-digit',
                                  hour12: true 
                                })}
                              </span>
                              {isSent && message.status === 0 && (
                                <span className="message-status" title="Delivered">✓✓</span>
                              )}
                              {!message.read && !isSent && (
                                <span className="unread-indicator">●</span>
                              )}
                            </div>
                          </div>
                          <button
                            className={`message-flag-btn ${isFlagged('sms-message', String(message.id)) ? 'flagged' : ''}`}
                            onClick={() => onToggleFlag('sms-message', String(message.id))}
                            title={isFlagged('sms-message', String(message.id)) ? 'Unflag message' : 'Flag message'}
                          >
                            {isFlagged('sms-message', String(message.id)) ? '🚩' : '⚑'}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
