import React, { useState, useEffect, useRef } from 'react';
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

// Draft persistence
// -----------------------------------------------------------------------------
// The previous implementation kept the in-progress title/description in
// component state only. If anything caused the modal to unmount — alt-tabbing
// then clicking back onto the dim overlay, accidentally hitting Esc/Cancel,
// the app reloading after a Vite HMR — the report vanished and the user had
// to retype it. We now persist every keystroke to localStorage and rehydrate
// on mount, so the draft survives until either a successful submit OR the
// user explicitly clears both fields.
const DRAFT_KEY = 'scout:bugreport:draft:v1';

interface DraftPayload {
  title: string;
  description: string;
  savedAt: number;
}

function readDraft(): DraftPayload | null {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<DraftPayload>;
    if (typeof parsed.title !== 'string' && typeof parsed.description !== 'string') return null;
    return {
      title: parsed.title || '',
      description: parsed.description || '',
      savedAt: typeof parsed.savedAt === 'number' ? parsed.savedAt : Date.now(),
    };
  } catch {
    return null;
  }
}

function writeDraft(draft: DraftPayload) {
  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  } catch {
    /* ignore quota / private-mode errors — draft is best-effort */
  }
}

function clearDraft() {
  try { localStorage.removeItem(DRAFT_KEY); } catch { /* ignore */ }
}

export const BugReportModal: React.FC<BugReportModalProps> = ({ onClose }) => {
  // Initialize from any previously-saved draft. useState's lazy initializer
  // means readDraft() runs exactly once on first render.
  const initialDraft = useRef<DraftPayload | null>(readDraft());
  const [title, setTitle] = useState(initialDraft.current?.title || '');
  const [description, setDescription] = useState(initialDraft.current?.description || '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bugId, setBugId] = useState<number | null>(null);
  const [showRestoredNotice, setShowRestoredNotice] = useState(
    Boolean(initialDraft.current && (initialDraft.current.title || initialDraft.current.description))
  );

  // Persist on every change. If both fields are empty we delete the draft
  // so reopening a fresh report doesn't show the restored-banner.
  useEffect(() => {
    if (submitted) return; // post-submit state is handled in handleSubmit
    if (title.trim() || description.trim()) {
      writeDraft({ title, description, savedAt: Date.now() });
    } else {
      clearDraft();
    }
  }, [title, description, submitted]);

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
        clearDraft(); // submitted — wipe the local draft
      } else {
        setError(result.message || 'Failed to submit bug report');
      }
    } catch (err: any) {
      setError(typeof err === 'string' ? err : 'Failed to submit bug report. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  // Close button behavior:
  //   - If both fields are empty, just close.
  //   - If anything is typed, do NOT clear the draft (already persisted).
  //     The user can reopen and continue. This is the silent-save UX, which
  //     matches what mail clients do with unsent message drafts.
  const handleClose = () => {
    onClose();
  };

  return (
    // NOTE: deliberately no onClick={onClose} on the overlay. The previous
    // version dismissed the modal whenever the user clicked the dim background,
    // which fired when they alt-tabbed back into the app — losing the draft.
    // The × button and Cancel button are the only intentional close paths.
    <div className="bugreport-overlay">
      <div className="bugreport-modal" onClick={(e) => e.stopPropagation()}>
        <button className="bugreport-close" onClick={handleClose} title="Close">×</button>

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
            <button className="bugreport-btn bugreport-btn-primary" onClick={handleClose}>
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="bugreport-form">
            {showRestoredNotice && (
              <div className="bugreport-draft-notice">
                <span>📝 We restored your previous draft. Continue editing, or clear both fields to start fresh.</span>
                <button
                  type="button"
                  className="bugreport-draft-dismiss"
                  onClick={() => setShowRestoredNotice(false)}
                  title="Dismiss"
                >
                  ×
                </button>
              </div>
            )}

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
              <button type="button" className="bugreport-btn bugreport-btn-secondary" onClick={handleClose}>
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
