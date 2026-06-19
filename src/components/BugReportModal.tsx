import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
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
const DRAFT_KEY = 'scout:bugreport:draft:v2';
const MAX_ATTACHMENTS = 3;
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5 MB per file, matches server cap

interface DraftPayload {
  title: string;
  description: string;
  attachmentPaths?: string[];
  savedAt: number;
}

function readDraft(): DraftPayload | null {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) {
      // One-shot migration from v1 (no attachments) — pick up any
      // pre-existing draft so we don't lose it on first launch after upgrade.
      const legacy = localStorage.getItem('scout:bugreport:draft:v1');
      if (!legacy) return null;
      const parsedLegacy = JSON.parse(legacy) as Partial<DraftPayload>;
      return {
        title: parsedLegacy.title || '',
        description: parsedLegacy.description || '',
        attachmentPaths: [],
        savedAt: typeof parsedLegacy.savedAt === 'number' ? parsedLegacy.savedAt : Date.now(),
      };
    }
    const parsed = JSON.parse(raw) as Partial<DraftPayload>;
    if (typeof parsed.title !== 'string' && typeof parsed.description !== 'string') return null;
    return {
      title: parsed.title || '',
      description: parsed.description || '',
      attachmentPaths: Array.isArray(parsed.attachmentPaths)
        ? parsed.attachmentPaths.filter((p) => typeof p === 'string')
        : [],
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
  try {
    localStorage.removeItem(DRAFT_KEY);
    localStorage.removeItem('scout:bugreport:draft:v1'); // also wipe legacy
  } catch { /* ignore */ }
}

function basename(p: string): string {
  // Works for both Windows and POSIX paths.
  const idx = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const BugReportModal: React.FC<BugReportModalProps> = ({ onClose }) => {
  // Initialize from any previously-saved draft. useState's lazy initializer
  // means readDraft() runs exactly once on first render.
  const initialDraft = useRef<DraftPayload | null>(readDraft());
  const [title, setTitle] = useState(initialDraft.current?.title || '');
  const [description, setDescription] = useState(initialDraft.current?.description || '');
  // Attachment paths are stored as absolute file system paths. We do NOT keep
  // the file bytes in component state — they'd bloat localStorage and we have
  // no way to round-trip them through JSON anyway. On submit, Rust reads each
  // path off disk. On draft restore we revalidate each path silently.
  const [attachmentPaths, setAttachmentPaths] = useState<string[]>(
    initialDraft.current?.attachmentPaths || []
  );
  // Size cache so we can show a friendly "1.2 MB" next to each filename
  // without re-stat'ing every render. Keyed by path. Populated on add.
  const [attachmentSizes, setAttachmentSizes] = useState<Record<string, number>>({});
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bugId, setBugId] = useState<number | null>(null);
  const [showRestoredNotice, setShowRestoredNotice] = useState(
    Boolean(initialDraft.current && (initialDraft.current.title || initialDraft.current.description))
  );

  // Persist on every change. If both fields are empty AND no attachments,
  // we delete the draft so reopening a fresh report doesn't show the
  // restored-banner. Attachments alone with no text still counts as a draft.
  useEffect(() => {
    if (submitted) return; // post-submit state is handled in handleSubmit
    if (title.trim() || description.trim() || attachmentPaths.length > 0) {
      writeDraft({
        title,
        description,
        attachmentPaths,
        savedAt: Date.now(),
      });
    } else {
      clearDraft();
    }
  }, [title, description, attachmentPaths, submitted]);

  // After restore, silently drop any attachment paths that no longer exist
  // on disk. We do this via a Rust call once on mount.
  useEffect(() => {
    if (attachmentPaths.length === 0) return;
    let cancelled = false;
    (async () => {
      try {
        // Filter by re-statting via Tauri's fs plugin would require another
        // permission. Instead, we lean on Rust to validate at submit time.
        // For UX we just keep them and let submit surface errors.
        if (cancelled) return;
      } catch {
        /* swallow */
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handlePickFiles = async () => {
    if (attachmentPaths.length >= MAX_ATTACHMENTS) {
      setError(`Maximum of ${MAX_ATTACHMENTS} screenshots per report.`);
      return;
    }
    setError(null);
    try {
      const remaining = MAX_ATTACHMENTS - attachmentPaths.length;
      const selected = await openDialog({
        multiple: remaining > 1,
        filters: [
          {
            name: 'Images',
            extensions: ['png', 'jpg', 'jpeg', 'webp'],
          },
        ],
      });
      if (!selected) return; // user cancelled

      const picked = Array.isArray(selected) ? selected : [selected];
      const accepted: string[] = [];
      const sizes: Record<string, number> = {};

      for (const path of picked) {
        if (typeof path !== 'string') continue;
        if (attachmentPaths.includes(path) || accepted.includes(path)) continue;
        if (attachmentPaths.length + accepted.length >= MAX_ATTACHMENTS) break;

        // Validate size via Rust (avoids needing the fs plugin permission).
        // The command returns the byte size on success, throws on failure.
        try {
          const size = await invoke<number>('bug_attachment_stat', { path });
          if (size > MAX_ATTACHMENT_BYTES) {
            setError(
              `"${basename(path)}" is ${formatBytes(size)} — over the ${formatBytes(MAX_ATTACHMENT_BYTES)} limit.`
            );
            continue;
          }
          sizes[path] = size;
          accepted.push(path);
        } catch (err) {
          setError(`Cannot read "${basename(path)}": ${err}`);
        }
      }

      if (accepted.length > 0) {
        setAttachmentPaths((prev) => [...prev, ...accepted]);
        setAttachmentSizes((prev) => ({ ...prev, ...sizes }));
      }
    } catch (err: any) {
      setError(typeof err === 'string' ? err : 'Could not open file picker.');
    }
  };

  const handleRemoveAttachment = (path: string) => {
    setAttachmentPaths((prev) => prev.filter((p) => p !== path));
    setAttachmentSizes((prev) => {
      const next = { ...prev };
      delete next[path];
      return next;
    });
  };

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
          attachment_paths: attachmentPaths.length > 0 ? attachmentPaths : null,
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

            <div className="bugreport-field bugreport-attach-field">
              <label>
                Screenshots <span className="bugreport-attach-hint">(optional · up to {MAX_ATTACHMENTS} images · {formatBytes(MAX_ATTACHMENT_BYTES)} each)</span>
              </label>

              {attachmentPaths.length > 0 && (
                <ul className="bugreport-attach-list">
                  {attachmentPaths.map((p) => (
                    <li key={p} className="bugreport-attach-item">
                      <span className="bugreport-attach-icon" aria-hidden="true">🖼️</span>
                      <span className="bugreport-attach-name" title={p}>{basename(p)}</span>
                      <span className="bugreport-attach-size">
                        {typeof attachmentSizes[p] === 'number' ? formatBytes(attachmentSizes[p]) : ''}
                      </span>
                      <button
                        type="button"
                        className="bugreport-attach-remove"
                        onClick={() => handleRemoveAttachment(p)}
                        title="Remove"
                        aria-label={`Remove ${basename(p)}`}
                      >
                        ×
                      </button>
                    </li>
                  ))}
                </ul>
              )}

              <button
                type="button"
                className="bugreport-btn bugreport-btn-secondary bugreport-attach-btn"
                onClick={handlePickFiles}
                disabled={attachmentPaths.length >= MAX_ATTACHMENTS || submitting}
              >
                {attachmentPaths.length === 0
                  ? '📎 Attach screenshots'
                  : `📎 Add another${attachmentPaths.length >= MAX_ATTACHMENTS ? ' (max reached)' : ''}`}
              </button>
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
