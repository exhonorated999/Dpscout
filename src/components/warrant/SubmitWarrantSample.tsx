import React, { useState, useEffect, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './SubmitWarrantSample.css';

/**
 * Submit Warrant Sample — UI for the "structural fingerprint" submission flow.
 *
 * The user picks a warrant return (folder OR zip) that Scout doesn't yet
 * support, fills in a short form (provider hint + notes), and we send back
 * a JSON envelope describing the file shapes — never the case content —
 * so the parser author can build a real parser without ever touching the
 * evidence.
 *
 * Privacy:
 *   • Filenames are scrubbed (`file_NNN.ext` per parent dir)
 *   • Email / phone / UUID / high-entropy id folder names → `<redacted-*>`
 *   • Per-file `structure` blocks contain only counts/types/format tags
 *
 * Rendered as a full-screen overlay on top of WarrantLanding.
 */

interface LicenseInfo {
  registered: boolean;
  agency_name?: string;
  status?: string;
}

interface SubmitWarrantSampleProps {
  onClose: () => void;
}

type Phase =
  | 'pick'        // user is picking the path + filling the form
  | 'building'    // backend building the envelope
  | 'preview'     // user reviews the envelope before sending
  | 'submitting'  // POSTing to server
  | 'done'        // successful submit
  | 'error';      // any error

interface BuildArgs {
  rootPath: string;
  providerHint: string;
  submitterEmail: string;
  submitterNotes: string;
  agencyName: string;
  licenseKeyLast4: string;
}

interface SubmitResp {
  status: number;
  body: string;
  endpoint: string;
}

export const SubmitWarrantSample: React.FC<SubmitWarrantSampleProps> = ({ onClose }) => {
  const [phase, setPhase] = useState<Phase>('pick');
  const [errorMsg, setErrorMsg] = useState<string>('');

  // ─── form fields ──────────────────────────────────────────────────────
  const [rootPath, setRootPath] = useState<string>('');
  const [pathIsZip, setPathIsZip] = useState<boolean>(false);
  const [providerHint, setProviderHint] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [agencyName, setAgencyName] = useState<string>('');
  const [submitterEmail, setSubmitterEmail] = useState<string>('');
  const [consented, setConsented] = useState<boolean>(false);

  // ─── result state ─────────────────────────────────────────────────────
  const [envelope, setEnvelope] = useState<any>(null);
  const [submitResp, setSubmitResp] = useState<SubmitResp | null>(null);

  // Pre-fill agency from license info on mount.
  useEffect(() => {
    (async () => {
      try {
        const info = await invoke<LicenseInfo>('get_license_status');
        if (info?.agency_name) setAgencyName(info.agency_name);
      } catch {
        /* offline / no license — that's fine */
      }
    })();
  }, []);

  // ─── path pickers ─────────────────────────────────────────────────────
  async function pickFolder() {
    setErrorMsg('');
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const sel = await open({
        title: 'Select unsupported warrant folder',
        directory: true,
        multiple: false,
      });
      if (sel && typeof sel === 'string') {
        setRootPath(sel);
        setPathIsZip(false);
      }
    } catch (err: any) {
      setErrorMsg(String(err?.message || err));
    }
  }

  async function pickZip() {
    setErrorMsg('');
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const sel = await open({
        title: 'Select unsupported warrant .zip',
        filters: [{ name: 'Archive', extensions: ['zip'] }],
        multiple: false,
      });
      if (sel && typeof sel === 'string') {
        setRootPath(sel);
        setPathIsZip(true);
      }
    } catch (err: any) {
      setErrorMsg(String(err?.message || err));
    }
  }

  // ─── build envelope ───────────────────────────────────────────────────
  async function buildEnvelope() {
    setErrorMsg('');
    if (!rootPath) {
      setErrorMsg('Pick a folder or zip first.');
      return;
    }
    setPhase('building');
    try {
      const args: BuildArgs = {
        rootPath,
        providerHint: providerHint.trim(),
        submitterEmail: submitterEmail.trim(),
        submitterNotes: notes.trim(),
        agencyName: agencyName.trim(),
        licenseKeyLast4: '', // populated server-side from machine_id if needed
      };
      const env = await invoke<any>('warrant_build_sample_envelope', { args });
      setEnvelope(env);
      setPhase('preview');
    } catch (err: any) {
      setErrorMsg(String(err?.message || err));
      setPhase('error');
    }
  }

  // ─── submit ───────────────────────────────────────────────────────────
  async function submitEnvelope() {
    setErrorMsg('');
    if (!consented) {
      setErrorMsg('You must confirm the consent statement before submitting.');
      return;
    }
    setPhase('submitting');
    try {
      const resp = await invoke<SubmitResp>('warrant_submit_sample_envelope', {
        args: {
          envelope,
          endpoint: '', // use default
        },
      });
      setSubmitResp(resp);
      if (resp.status >= 200 && resp.status < 300) {
        setPhase('done');
      } else {
        setErrorMsg(
          `Server returned HTTP ${resp.status}: ${resp.body.slice(0, 400)}`
        );
        setPhase('error');
      }
    } catch (err: any) {
      setErrorMsg(String(err?.message || err));
      setPhase('error');
    }
  }

  // ─── envelope preview helpers ────────────────────────────────────────
  const envelopeJson = useMemo(
    () => (envelope ? JSON.stringify(envelope, null, 2) : ''),
    [envelope]
  );
  const envelopeSizeBytes = useMemo(() => envelopeJson.length, [envelopeJson]);
  const fileCount = envelope?.root_summary?.total_files ?? 0;
  const totalBytes = envelope?.root_summary?.total_bytes ?? 0;
  const formatCounts = envelope?.root_summary?.format_counts ?? {};

  const canBuild =
    !!rootPath &&
    providerHint.trim().length > 0 &&
    submitterEmail.trim().length > 0;

  // ─── render ───────────────────────────────────────────────────────────
  return (
    <div className="sws-backdrop" onClick={(e) => {
      if (e.target === e.currentTarget && phase !== 'building' && phase !== 'submitting') {
        onClose();
      }
    }}>
      <div className="sws-modal">
        <div className="sws-header">
          <div className="sws-header-left">
            <div className="sws-badge">📨 SUBMIT UNSUPPORTED FORMAT</div>
            <h2 className="sws-title">Help us support your provider</h2>
            <p className="sws-subtitle">
              We never see your evidence. Scout walks the return locally and
              builds a small JSON that describes only the <em>shape</em> of
              the files — folder layout, file types, key/column names, MIME
              counts. Filenames and PII-shaped folder names are scrubbed
              before anything leaves your machine.
            </p>
          </div>
          <button className="sws-close" onClick={onClose} aria-label="Close">×</button>
        </div>

        {phase === 'pick' && (
          <div className="sws-body">
            <div className="sws-field">
              <label>Warrant return</label>
              <div className="sws-path-row">
                <input
                  type="text"
                  value={rootPath}
                  readOnly
                  placeholder="No path selected"
                  className="sws-input"
                />
                <button className="sws-btn" onClick={pickFolder}>Pick Folder…</button>
                <button className="sws-btn" onClick={pickZip}>Pick .zip…</button>
              </div>
              {rootPath && (
                <div className="sws-path-hint">
                  Source: {pathIsZip ? 'zip archive' : 'folder'}
                </div>
              )}
            </div>

            <div className="sws-field">
              <label>Provider hint (required)</label>
              <input
                type="text"
                value={providerHint}
                onChange={(e) => setProviderHint(e.target.value)}
                placeholder='e.g. "T-Mobile CDR", "KIK return", "Apple iCloud zip"'
                className="sws-input"
              />
            </div>

            <div className="sws-row">
              <div className="sws-field" style={{ flex: 1 }}>
                <label>Your email (required)</label>
                <input
                  type="email"
                  value={submitterEmail}
                  onChange={(e) => setSubmitterEmail(e.target.value)}
                  placeholder="detective@agency.gov"
                  className="sws-input"
                />
              </div>
              <div className="sws-field" style={{ flex: 1 }}>
                <label>Agency</label>
                <input
                  type="text"
                  value={agencyName}
                  onChange={(e) => setAgencyName(e.target.value)}
                  placeholder="e.g. Springfield PD"
                  className="sws-input"
                />
              </div>
            </div>

            <div className="sws-field">
              <label>Notes (optional)</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                placeholder="Anything Scout should know about this return? Date served, custodian, anything unusual."
                className="sws-textarea"
              />
            </div>

            {errorMsg && <div className="sws-error">{errorMsg}</div>}

            <div className="sws-actions">
              <button className="sws-btn ghost" onClick={onClose}>Cancel</button>
              <button
                className="sws-btn primary"
                onClick={buildEnvelope}
                disabled={!canBuild}
                title={!canBuild ? 'Pick a path, provider hint, and email first' : undefined}
              >
                Build structural sample →
              </button>
            </div>
          </div>
        )}

        {phase === 'building' && (
          <div className="sws-body sws-centered">
            <div className="sws-spinner" />
            <div className="sws-status">Walking files…</div>
            <div className="sws-status-sub">
              Inspecting structure only. No case content is being read into
              the envelope.
            </div>
          </div>
        )}

        {phase === 'preview' && envelope && (
          <div className="sws-body">
            <div className="sws-stats">
              <div className="sws-stat">
                <div className="sws-stat-value">{fileCount}</div>
                <div className="sws-stat-label">files</div>
              </div>
              <div className="sws-stat">
                <div className="sws-stat-value">{formatBytes(totalBytes)}</div>
                <div className="sws-stat-label">source</div>
              </div>
              <div className="sws-stat">
                <div className="sws-stat-value">{formatBytes(envelopeSizeBytes)}</div>
                <div className="sws-stat-label">envelope size</div>
              </div>
              <div className="sws-stat">
                <div className="sws-stat-value">
                  {Object.keys(formatCounts).length}
                </div>
                <div className="sws-stat-label">formats</div>
              </div>
            </div>

            <div className="sws-formats">
              {Object.entries(formatCounts).map(([k, v]) => (
                <span key={k} className="sws-format-chip">
                  {k}: <strong>{String(v)}</strong>
                </span>
              ))}
            </div>

            <details className="sws-details">
              <summary>Preview JSON envelope (this is exactly what will be sent)</summary>
              <pre className="sws-json">{envelopeJson}</pre>
            </details>

            <label className="sws-consent">
              <input
                type="checkbox"
                checked={consented}
                onChange={(e) => setConsented(e.target.checked)}
              />
              <span>
                I confirm this envelope contains no case content. I reviewed the
                JSON above (or am satisfied with the privacy model) and
                authorize Datapilot to use it for parser development.
              </span>
            </label>

            {errorMsg && <div className="sws-error">{errorMsg}</div>}

            <div className="sws-actions">
              <button className="sws-btn ghost" onClick={() => setPhase('pick')}>
                ← Back
              </button>
              <button
                className="sws-btn primary"
                onClick={submitEnvelope}
                disabled={!consented}
              >
                Send to Datapilot →
              </button>
            </div>
          </div>
        )}

        {phase === 'submitting' && (
          <div className="sws-body sws-centered">
            <div className="sws-spinner" />
            <div className="sws-status">Sending…</div>
          </div>
        )}

        {phase === 'done' && (
          <div className="sws-body sws-centered">
            <div className="sws-success">✓</div>
            <div className="sws-status">Submitted</div>
            <div className="sws-status-sub">
              Thank you. We'll review and reach out at{' '}
              <strong>{submitterEmail || 'your email'}</strong> when a parser
              for this format ships.
            </div>
            {submitResp && (
              <div className="sws-status-sub" style={{ opacity: 0.6, marginTop: 12 }}>
                Server: HTTP {submitResp.status} via {submitResp.endpoint}
              </div>
            )}
            <div className="sws-actions" style={{ marginTop: 24 }}>
              <button className="sws-btn primary" onClick={onClose}>Close</button>
            </div>
          </div>
        )}

        {phase === 'error' && (
          <div className="sws-body">
            <div className="sws-error big">
              <strong>Something went wrong.</strong>
              <div style={{ marginTop: 8 }}>{errorMsg}</div>
            </div>
            <div className="sws-actions">
              <button className="sws-btn ghost" onClick={onClose}>Close</button>
              <button className="sws-btn primary" onClick={() => setPhase('pick')}>
                Try again
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '–';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
