import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './BugReportModal.css';

interface BugReportModalProps {
  onClose: () => void;
}

interface BugReportResponse {
  ok: boolean;
  bug_id: number | null;
  intellect_id: string | null;
  message: string | null;
}

export const BugReportModal: React.FC<BugReportModalProps> = ({ onClose }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bugId, setBugId] = useState<number | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !description.trim()) return;

    setSubmitting(true);
    setError(null);

    try {
      const result = await invoke<BugReportResponse>('submit_bug_report', {
        data: {
          title: title.trim(),
          description: description.trim(),
        },
      });

      if (result.ok) {
        setBugId(result.bug_id);
        setSubmitted(true);
      } else {
        setError(result.message || 'Failed to submit bug report');
      }
    } catch (err: any) {
      setError(typeof err === 'string' ? err : 'Failed to submit bug report. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="bugreport-overlay" onClick={onClose}>
      <div className="bugreport-modal" onClick={(e) => e.stopPropagation()}>
        <button className="bugreport-close" onClick={onClose} title="Close">×</button>

        <div className="bugreport-header">
          <svg className="bugreport-icon" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M8 2l1.88 1.88M14.12 3.88L16 2M9 7.13v-1a3.003 3.003 0 116 0v1"/>
            <path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 014-4h4a4 4 0 014 4v3c0 3.3-2.7 6-6 6z"/>
            <path d="M12 20v2M6 13H2M6 17H3M18 13h4M18 17h3"/>
          </svg>
          <h2>Report a Bug</h2>
        </div>

        {submitted ? (
          <div className="bugreport-success">
            <div className="bugreport-success-icon">✓</div>
            <p>Bug report submitted — thank you!</p>
            {bugId && <p className="bugreport-id">Report ID: #{bugId}</p>}
            <button className="bugreport-btn bugreport-btn-primary" onClick={onClose}>
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="bugreport-form">
            <div className="bugreport-field">
              <label htmlFor="bug-title">Title</label>
              <input
                id="bug-title"
                type="text"
                maxLength={300}
                placeholder="Brief summary of the issue"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
                autoFocus
              />
            </div>

            <div className="bugreport-field">
              <label htmlFor="bug-desc">Description</label>
              <textarea
                id="bug-desc"
                rows={5}
                placeholder="What happened? What did you expect to happen? Steps to reproduce?"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
              />
            </div>

            {error && <div className="bugreport-error">{error}</div>}

            <div className="bugreport-actions">
              <button type="button" className="bugreport-btn bugreport-btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button
                type="submit"
                className="bugreport-btn bugreport-btn-primary"
                disabled={submitting || !title.trim() || !description.trim()}
              >
                {submitting ? 'Submitting…' : 'Submit Report'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
