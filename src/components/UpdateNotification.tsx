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

const DISMISS_KEY = 'scout_update_dismissed_version';
// Small delay so the check doesn't compete with the app's own startup work
// (license check, settings load, device detection).
const CHECK_DELAY_MS = 3000;

interface AvailableUpdate {
  version: string;
  currentVersion: string;
  notes: string;
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

  return (
    <div className={`update-splash${closing ? ' closing' : ''}`} role="alert">
      <div className="update-splash__accent" />

      <div className="update-splash__head">
        <span className="update-splash__icon" aria-hidden>🚀</span>
        <div className="update-splash__title">
          <h4>Update Available</h4>
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
