/**
 * UpdateNotification
 * ------------------
 * On app launch, asks the backend updater to check the release server. If a
 * newer signed release exists, shows a splash card in the upper-right corner
 * with the version and release notes, telling the user they can install it
 * from Settings → License & Updates.
 *
 * This is NOTIFY-ONLY. It never downloads or installs — that stays a manual
 * action in SettingsView (handleCheckAndInstallUpdate). We simply reuse the
 * updater plugin's check() here; its result carries `body` = the release
 * changelog served by the admin server (`notes` field).
 *
 * Mounted globally in main.tsx as a sibling of <App/> so it overlays every
 * screen regardless of the app's internal view state.
 */

import { useEffect, useRef, useState } from 'react';
import './UpdateNotification.css';
import { getHostPlatform } from '../lib/hostPlatform';

const DISMISS_KEY = 'scout_update_dismissed_version';
// Small delay so the check doesn't compete with the app's own startup work
// (license check, settings load, device detection).
const CHECK_DELAY_MS = 3000;

interface AvailableUpdate {
  version: string;
  currentVersion: string;
  notes: string;
}

/**
 * A release is flagged as beta by its own notes rather than by a separate
 * field, so there is only one thing to get right when publishing: write
 * "BETA" in the release notes on the admin dashboard and the badge appears.
 *
 * The badge matters because the notes box is scrollable (max-height 168px).
 * A "this is beta" line buried in the changelog can be scrolled past without
 * ever being read; the badge sits in the always-visible header instead.
 */
function isBetaRelease(notes: string, version: string): boolean {
  const haystack = `${notes} ${version}`.toLowerCase();
  return haystack.includes('beta');
}

export default function UpdateNotification() {
  const [update, setUpdate] = useState<AvailableUpdate | null>(null);
  const [closing, setClosing] = useState(false);
  const ranRef = useRef(false);

  useEffect(() => {
    // StrictMode double-invokes effects in dev; guard so we check once.
    if (ranRef.current) return;
    ranRef.current = true;

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        // G9: the Mac edition never phones home — not even to look.
        if ((await getHostPlatform()).offline) return;
        const { check } = await import('@tauri-apps/plugin-updater');
        const result = await check();
        if (cancelled || !result) return;

        // Skip if the user already dismissed this exact version.
        const dismissed = localStorage.getItem(DISMISS_KEY);
        if (dismissed === result.version) return;

        setUpdate({
          version: result.version,
          currentVersion: result.currentVersion,
          notes: (result.body || '').trim(),
        });
      } catch (err) {
        // No updater endpoint / not signed / offline — silently ignore.
        console.debug('[UpdateNotification] update check skipped:', err);
      }
    }, CHECK_DELAY_MS);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  if (!update) return null;

  const dismiss = () => {
    // Remember this version so we don't nag again until a newer one ships.
    try {
      localStorage.setItem(DISMISS_KEY, update.version);
    } catch { /* localStorage may be unavailable — non-fatal */ }
    setClosing(true);
    setTimeout(() => setUpdate(null), 240);
  };

  const beta = isBetaRelease(update.notes, update.version);

  return (
    <div className={`update-splash${closing ? ' closing' : ''}`} role="alert">
      <div className="update-splash__accent" />

      <div className="update-splash__head">
        <span className="update-splash__icon" aria-hidden>🚀</span>
        <div className="update-splash__title">
          <h4>
            Update Available
            {beta && <span className="update-splash__beta">BETA</span>}
          </h4>
          <div className="update-splash__versions">
            v{update.currentVersion} &rarr; <b>v{update.version}</b>
          </div>
        </div>
        <button
          className="update-splash__close"
          onClick={dismiss}
          aria-label="Dismiss update notification"
          title="Dismiss"
        >
          &times;
        </button>
      </div>

      {beta && (
        <div className="update-splash__beta-note">
          <b>Field-testing release.</b> If something looks wrong, slow or
          missing, send it straight to us with the bug icon at the top right
          of the start screen &mdash; next to the gear. Your reports decide
          what gets fixed next.
        </div>
      )}

      {update.notes && (
        <>
          <div className="update-splash__notes-label">What&rsquo;s new</div>
          <div className="update-splash__notes">{update.notes}</div>
        </>
      )}

      <div className="update-splash__hint">
        <span className="gear" aria-hidden>⚙️</span>
        <span>
          Install anytime from <b>Settings &rarr; License &amp; Updates</b>.
        </span>
      </div>
    </div>
  );
}
