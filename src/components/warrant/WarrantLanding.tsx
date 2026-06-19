import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './WarrantLanding.css';
import { SubmitWarrantSample } from './SubmitWarrantSample';

/**
 * Provider identifiers — kept in sync with Rust `warrant::providers::Provider`.
 * Adding a new provider here AND in Rust + setting `enabled: true` lights up the tile.
 */
export type WarrantProvider = 'meta' | 'snapchat' | 'kik' | 'discord' | 'google' | 'yahoo';

/**
 * Providers that remain available when the demo trial / paid license has
 * expired.  Everything else is greyed out until the user enters a valid
 * license key in Settings.  This list is intentionally small — Meta and
 * Google are the two highest-volume providers in the field and serve as
 * the "free forever" tier when a customer hasn't upgraded yet.
 */
const POST_EXPIRY_ALLOWED: ReadonlySet<WarrantProvider> = new Set([
  'meta',
  'google',
]);

interface LicenseInfo {
  registered: boolean;
  agency_name?: string;
  plan?: string;
  status?: string;
  expires_at?: string;
  days_remaining: number;
  is_expired: boolean;
}

interface ProviderTile {
  id: WarrantProvider;
  name: string;
  subtitle: string;
  formatHint: string;
  enabled: boolean;
  icon: React.ReactNode;
  accent: string; // brand-ish accent stripe color
}

interface WarrantLandingProps {
  onBack: () => void;
  onSelectProvider: (provider: WarrantProvider) => void;
}

// --- Brand-ish vector icons (no external assets, all inline SVG) ---

const MetaIcon = () => (
  <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
    <path
      d="M8 24 C 8 14, 18 14, 24 24 C 30 34, 40 34, 40 24 C 40 14, 30 14, 24 24 C 18 34, 8 34, 8 24 Z"
      stroke="#5b8def" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round"
    />
  </svg>
);

const SnapIcon = () => (
  <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
    <path
      d="M24 6c-7 0-12 5-12 12v6c0 3-2 5-4 6 1 2 4 3 6 4 1 4 5 6 10 6s9-2 10-6c2-1 5-2 6-4-2-1-4-3-4-6v-6c0-7-5-12-12-12z"
      stroke="#FFFC00" strokeWidth="2.5" strokeLinejoin="round"
    />
  </svg>
);

const KikIcon = () => (
  <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
    <text x="24" y="32" textAnchor="middle" fontFamily="system-ui, sans-serif"
      fontWeight="800" fontSize="20" fill="#82C341" letterSpacing="-1">Kik</text>
    <rect x="6" y="6" width="36" height="36" rx="9" stroke="#82C341" strokeWidth="2.5"/>
  </svg>
);

const DiscordIcon = () => (
  <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
    <path
      d="M16 14c-2 0-4 1-5 3-3 6-3 13-2 19 0 1 1 2 2 2 2 0 4-1 5-3 1 1 3 1 4 1h6c1 0 3 0 4-1 1 2 3 3 5 3 1 0 2-1 2-2 1-6 1-13-2-19-1-2-3-3-5-3-1 0-2 1-2 2-1 0-3-1-5-1s-4 1-5 1c0-1-1-2-2-2z"
      stroke="#5865F2" strokeWidth="2.5" strokeLinejoin="round"
    />
    <circle cx="19" cy="27" r="2" fill="#5865F2"/>
    <circle cx="29" cy="27" r="2" fill="#5865F2"/>
  </svg>
);

const GoogleIcon = () => (
  <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
    <path d="M24 24v6h9c-1 4-5 7-9 7-6 0-11-5-11-11s5-11 11-11c3 0 5 1 7 3l4-4c-3-3-7-5-11-5C15 9 7 16 7 25s8 16 17 16c10 0 16-7 16-16 0-1 0-2-1-3H24z"
      stroke="#4285F4" strokeWidth="2.5" strokeLinejoin="round"/>
  </svg>
);

// Yahoo "Y!" mark in their purple brand color.
const YahooIcon = () => (
  <svg viewBox="0 0 48 48" width="44" height="44" fill="none">
    <text x="24" y="34" textAnchor="middle" fontFamily="system-ui, sans-serif"
      fontWeight="900" fontSize="28" fill="#7B0099" letterSpacing="-1">Y!</text>
    <rect x="6" y="6" width="36" height="36" rx="9" stroke="#7B0099" strokeWidth="2.5"/>
  </svg>
);

const PROVIDERS: ProviderTile[] = [
  {
    id: 'meta',
    name: 'Meta',
    subtitle: 'Facebook / Instagram / Quest',
    formatHint: 'Meta production .zip, Quest backup, or extracted folder',
    enabled: true,
    icon: <MetaIcon />,
    accent: '#5b8def',
  },
  {
    id: 'snapchat',
    name: 'Snapchat',
    subtitle: 'Snap Inc.',
    formatHint: 'Snapchat Warrant Return (.zip or production folder)',
    enabled: true,
    icon: <SnapIcon />,
    accent: '#FFFC00',
  },
  {
    id: 'kik',
    name: 'KIK',
    subtitle: 'KIK Messenger',
    formatHint: 'Kik Warrant Return (.zip or extracted folder)',
    enabled: true,
    icon: <KikIcon />,
    accent: '#82C341',
  },
  {
    id: 'discord',
    name: 'Discord',
    subtitle: 'Discord Inc.',
    formatHint: 'Discord Data Package (.zip or folder)',
    enabled: true,
    icon: <DiscordIcon />,
    accent: '#5865F2',
  },
  {
    id: 'google',
    name: 'Google',
    subtitle: 'Google LLC',
    formatHint: 'Google Warrant Return or Takeout (.zip or folder)',
    enabled: true,
    icon: <GoogleIcon />,
    accent: '#4285F4',
  },
  {
    id: 'yahoo',
    name: 'Yahoo',
    subtitle: 'Yahoo Inc.',
    formatHint: 'Yahoo Warrant Return (.zip or YAHOO-{caseId} folder)',
    enabled: true,
    icon: <YahooIcon />,
    accent: '#7B0099',
  },
];

export const WarrantLanding: React.FC<WarrantLandingProps> = ({ onBack, onSelectProvider }) => {
  // Pull license status once on mount.  When the demo / paid license has
  // expired we still allow Meta + Google as a "free forever" tier so the
  // user can keep working on the most common returns; all other providers
  // are visibly greyed out with a license-required hint until the user
  // enters a key in Settings.
  const [licenseExpired, setLicenseExpired] = useState(false);
  const [showSampleSubmit, setShowSampleSubmit] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const info = await invoke<LicenseInfo>('get_license_status');
        if (!cancelled) setLicenseExpired(Boolean(info?.is_expired));
      } catch (err) {
        // If we can't reach the backend / offline cache, default to "not
        // expired" so we don't unfairly punish the user.  Settings will
        // surface the real status separately.
        console.warn('[WarrantLanding] get_license_status failed:', err);
        if (!cancelled) setLicenseExpired(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="warrant-landing">
      <button className="warrant-back-button" onClick={onBack} title="Back to start">
        ← Back
      </button>

      <div className="warrant-landing-content">
        <div className="warrant-header">
          <div className="warrant-header-badge">📋 WARRANT TRIAGE</div>
          <h1 className="warrant-title">Select Provider</h1>
          <p className="warrant-subtitle">
            Each provider ships warrant returns in a different format.
            Pick the one that matches the data the detective brought you.
          </p>
          {licenseExpired && (
            <div className="warrant-license-banner" role="status">
              ⚠ Your trial / license has expired. Meta and Google returns
              remain available — enter a license key in <strong>Settings</strong>
              {' '}to re-enable Snapchat, KIK, Discord, and Yahoo.
            </div>
          )}
        </div>

        <div className="provider-grid">
          {PROVIDERS.map((p) => {
            const lockedByLicense =
              licenseExpired && !POST_EXPIRY_ALLOWED.has(p.id);
            const tileEnabled = p.enabled && !lockedByLicense;
            return (
              <button
                key={p.id}
                type="button"
                className={`provider-tile ${tileEnabled ? 'enabled' : 'disabled'}${
                  lockedByLicense ? ' license-locked' : ''
                }`}
                onClick={() => tileEnabled && onSelectProvider(p.id)}
                disabled={!tileEnabled}
                style={{ ['--accent' as any]: p.accent }}
                aria-label={`${p.name} — ${
                  lockedByLicense
                    ? 'license required'
                    : p.enabled
                      ? 'available'
                      : 'coming soon'
                }`}
                title={
                  lockedByLicense
                    ? 'Trial expired — enter a license key in Settings to unlock this provider'
                    : undefined
                }
              >
                <div className="provider-accent-stripe" />
                <div className="provider-icon-wrap">{p.icon}</div>
                <div className="provider-meta">
                  <div className="provider-name">{p.name}</div>
                  <div className="provider-subtitle">{p.subtitle}</div>
                  <div className="provider-format-hint">
                    {lockedByLicense ? (
                      <span className="coming-soon-pill license-pill">
                        🔒 License required
                      </span>
                    ) : p.enabled ? (
                      <>
                        Looking for: <code>{p.formatHint}</code>
                      </>
                    ) : (
                      <span className="coming-soon-pill">Coming soon</span>
                    )}
                  </div>
                </div>
                {tileEnabled && <div className="provider-cta">Select →</div>}
              </button>
            );
          })}
        </div>

        <div className="warrant-footer-note">
          The provider you pick determines how Scout parses the return.
          Picking the wrong one will fail validation — no data is lost.
        </div>

        {/* CTA banner — submit an unsupported warrant return as a
            structural sample so we can build a real parser. */}
        <div
          className="warrant-sample-cta"
          role="button"
          tabIndex={0}
          onClick={() => setShowSampleSubmit(true)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              setShowSampleSubmit(true);
            }
          }}
        >
          <div className="warrant-sample-cta-icon">📨</div>
          <div className="warrant-sample-cta-text">
            <div className="warrant-sample-cta-title">
              Don't see your provider?
            </div>
            <div className="warrant-sample-cta-body">
              Send us a structural fingerprint of the return — no case
              content leaves your machine. We'll build a parser and
              email you when it ships.
            </div>
          </div>
          <div className="warrant-sample-cta-arrow">→</div>
        </div>
      </div>

      {showSampleSubmit && (
        <SubmitWarrantSample onClose={() => setShowSampleSubmit(false)} />
      )}
    </div>
  );
};
