import React from 'react';
import './WarrantLanding.css';

/**
 * Provider identifiers — kept in sync with Rust `warrant::providers::Provider`.
 * Adding a new provider here AND in Rust + setting `enabled: true` lights up the tile.
 */
export type WarrantProvider = 'meta' | 'snapchat' | 'kik' | 'discord' | 'google';

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
    formatHint: 'Coming soon',
    enabled: false,
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
];

export const WarrantLanding: React.FC<WarrantLandingProps> = ({ onBack, onSelectProvider }) => {
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
        </div>

        <div className="provider-grid">
          {PROVIDERS.map((p) => (
            <button
              key={p.id}
              type="button"
              className={`provider-tile ${p.enabled ? 'enabled' : 'disabled'}`}
              onClick={() => p.enabled && onSelectProvider(p.id)}
              disabled={!p.enabled}
              style={{ ['--accent' as any]: p.accent }}
              aria-label={`${p.name} — ${p.enabled ? 'available' : 'coming soon'}`}
            >
              <div className="provider-accent-stripe" />
              <div className="provider-icon-wrap">{p.icon}</div>
              <div className="provider-meta">
                <div className="provider-name">{p.name}</div>
                <div className="provider-subtitle">{p.subtitle}</div>
                <div className="provider-format-hint">
                  {p.enabled ? (
                    <>Looking for: <code>{p.formatHint}</code></>
                  ) : (
                    <span className="coming-soon-pill">Coming soon</span>
                  )}
                </div>
              </div>
              {p.enabled && (
                <div className="provider-cta">Select →</div>
              )}
            </button>
          ))}
        </div>

        <div className="warrant-footer-note">
          The provider you pick determines how Scout parses the return.
          Picking the wrong one will fail validation — no data is lost.
        </div>
      </div>
    </div>
  );
};
