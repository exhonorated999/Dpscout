// G9: UI side of the offline policy. On a host where the backend refuses
// network egress (the macOS portable build), anything that would phone home is
// replaced by an explanation instead of a button that can only fail.
import React from 'react';
import { getHostPlatform } from '../lib/hostPlatform';

/** `null` while unknown, then whether this host is offline-only. */
export function useOfflineHost(): boolean | null {
  const [offline, setOffline] = React.useState<boolean | null>(null);
  React.useEffect(() => {
    let alive = true;
    getHostPlatform().then(p => { if (alive) setOffline(p.offline); });
    return () => { alive = false; };
  }, []);
  return offline;
}

export const OfflineHostNotice: React.FC<{ what: string; children?: React.ReactNode }> = ({ what, children }) => (
  <div
    role="note"
    style={{
      padding: '12px 16px',
      background: 'rgba(255, 159, 10, 0.08)',
      border: '1px solid rgba(255, 159, 10, 0.4)',
      borderRadius: 6,
      color: 'var(--color-text-primary, #fff)',
      fontSize: 13,
      lineHeight: 1.5,
    }}
  >
    <strong>🍎 Offline on macOS — {what}</strong>
    <div style={{ marginTop: 4, color: 'var(--color-text-secondary, #bbb)' }}>
      The Mac edition of Scout makes no network connections, so it leaves no network traces on the computer
      being examined. {children}
    </div>
  </div>
);
