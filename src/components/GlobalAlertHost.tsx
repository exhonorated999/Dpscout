/**
 * GlobalAlertHost — renders the `appDialog` queue.
 *
 * Mounted once, next to `<App />`.  It exists so that the ~87 bare `alert()`
 * call sites scattered through the app produce a Scout-styled modal that the
 * user can actually *do something with*, instead of an OS message box that
 * can only be acknowledged.
 *
 * The two repair actions are the point of the whole change:
 *
 *   * **Copy details** — an error message is evidence about the app.  Until
 *     now an officer had to read a stack trace off the screen and retype it.
 *   * **Report this** — opens the bug reporter that already ships in Scout,
 *     with the message already pasted in.  A report that takes one click
 *     gets filed; one that takes a form does not.
 *
 * They are offered only for error-shaped messages (see `inferTone`), so a
 * "Settings saved successfully!" toast doesn't invite a bug report.
 */

import React, { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { getVersion } from '@tauri-apps/api/app';
import { Button } from './Button';
import { BugReportModal } from './BugReportModal';
import {
  getDialogSnapshot,
  resolveTopDialog,
  subscribeDialogs,
  type DialogEntry,
} from '../lib/appDialog';

interface Prefill {
  title: string;
  description: string;
}

/** Clipboard write with a fallback for webviews that refuse the async API. */
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // WebView2 can reject the async clipboard when the document is not
    // treated as a secure context.  The legacy path still works there.
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

async function buildPrefill(entry: DialogEntry): Promise<Prefill> {
  let version = 'unknown';
  try {
    version = await getVersion();
  } catch {
    /* not fatal — the report is still worth more than no report */
  }
  const occurrences = entry.count > 1 ? `\nOccurrences in this session: ${entry.count}` : '';
  return {
    title: entry.title === 'Something went wrong' ? 'Error: see details' : entry.title,
    description:
      `Scout showed this message:\n\n${entry.message}\n\n` +
      `--- what I was doing when it happened ---\n` +
      `(please describe — even one line helps a lot)\n\n` +
      `--- automatically collected ---\n` +
      `Scout version: ${version}${occurrences}`,
  };
}

export const GlobalAlertHost: React.FC = () => {
  const entry = useSyncExternalStore(subscribeDialogs, getDialogSnapshot, getDialogSnapshot);
  const [copied, setCopied] = useState(false);
  const [prefill, setPrefill] = useState<Prefill | null>(null);

  // Reset the transient "Copied" flash whenever a different dialog surfaces.
  useEffect(() => {
    setCopied(false);
  }, [entry?.id]);

  const answer = useCallback(
    (ok: boolean) => {
      if (entry) resolveTopDialog(entry.id, ok);
    },
    [entry]
  );

  // Esc dismisses: OK for an alert, Cancel for a confirm.  A confirm must
  // never be *confirmed* by a keypress that means "get out of my way".
  useEffect(() => {
    if (!entry || prefill) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        answer(entry.kind === 'alert');
      } else if (e.key === 'Enter' && entry.kind === 'alert') {
        e.preventDefault();
        answer(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [entry, prefill, answer]);

  const handleReport = async () => {
    if (!entry) return;
    const p = await buildPrefill(entry);
    // Dismiss the alert first: the message it carried is now in the report,
    // and stacking two modals just hides the one being typed into.
    answer(true);
    setPrefill(p);
  };

  if (prefill) {
    return <BugReportModal prefill={prefill} onClose={() => setPrefill(null)} />;
  }
  if (!entry) return null;

  const isError = entry.tone === 'error';
  const dismissable = entry.kind === 'confirm';

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.65)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        // Above ConfirmDialog (10000): a global alert is usually *about* the
        // thing the local dialog just tried to do.
        zIndex: 10050,
      }}
      onClick={() => dismissable && answer(false)}
      role="alertdialog"
      aria-modal="true"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#1a1d29',
          border: `1px solid ${isError ? 'rgba(239, 68, 68, 0.45)' : 'rgba(93, 207, 255, 0.25)'}`,
          borderRadius: 10,
          padding: '1.5rem 1.75rem',
          minWidth: 400,
          maxWidth: 640,
          boxShadow: '0 12px 40px rgba(0,0,0,0.55), 0 0 24px rgba(74,122,255,0.25)',
        }}
      >
        <h3
          style={{
            margin: 0,
            color: isError ? '#ff8f8f' : '#5DCFFF',
            fontSize: '1.1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span aria-hidden="true">{isError ? '⚠️' : 'ℹ️'}</span>
          <span>{entry.title}</span>
        </h3>

        <p
          style={{
            marginTop: '0.85rem',
            marginBottom: entry.count > 1 ? '0.5rem' : '1.5rem',
            color: '#e6ecf5',
            lineHeight: 1.55,
            // Call sites build messages with \n and \n\n and expect them to
            // survive — several embed numbered steps.
            whiteSpace: 'pre-wrap',
            // A 42,000-line Rust error should scroll, not push the buttons
            // off the bottom of the screen.
            maxHeight: '48vh',
            overflowY: 'auto',
            wordBreak: 'break-word',
          }}
        >
          {entry.message}
        </p>

        {entry.count > 1 && (
          <p style={{ margin: '0 0 1.25rem', color: '#8b95a7', fontSize: '0.82rem' }}>
            This happened {entry.count} times — shown once.
          </p>
        )}

        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.6rem',
            flexWrap: 'wrap',
            alignItems: 'center',
          }}
        >
          {isError && (
            <>
              {copied && (
                <span style={{ color: '#6ee7a8', fontSize: '0.82rem', marginRight: 'auto' }}>
                  Copied to clipboard
                </span>
              )}
              <Button
                variant="secondary"
                size="sm"
                onClick={async () => setCopied(await copyText(entry.message))}
              >
                Copy details
              </Button>
              <Button variant="secondary" size="sm" onClick={handleReport}>
                Report this
              </Button>
            </>
          )}
          {dismissable && (
            <Button variant="secondary" size="sm" onClick={() => answer(false)}>
              {entry.cancelLabel}
            </Button>
          )}
          <Button
            variant={dismissable && entry.danger ? 'danger' : 'primary'}
            size="sm"
            onClick={() => answer(true)}
          >
            {entry.confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default GlobalAlertHost;
