/**
 * Floating, minimizable progress panel for warrant investigation
 * exports.  Lives at the top of the React tree so the user can navigate
 * around (or close the investigation detail screen) while the export
 * keeps running on the Rust side.
 *
 * Subscribes to the `warrant_export_progress` event emitted by
 * `warrant_export_investigation_report` and computes a live ETA from
 * elapsed time + fraction complete.
 */

import React, { useEffect, useRef, useState } from 'react';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import './ExportProgressPanel.css';

interface ProgressEvent {
  stage: 'started' | 'return' | 'rollup' | 'cover' | 'done';
  index: number;
  total: number;
  label: string;
}

type Phase = 'idle' | 'running' | 'done' | 'error';

interface State {
  phase: Phase;
  startedAt: number;
  total: number;
  lastIndex: number;
  lastLabel: string;
  stage: string;
  reportDir: string | null;
  errorMessage: string | null;
}

const initialState: State = {
  phase: 'idle',
  startedAt: 0,
  total: 0,
  lastIndex: 0,
  lastLabel: '',
  stage: '',
  reportDir: null,
  errorMessage: null,
};

/**
 * Singleton API surface so other components can launch an export
 * without prop-drilling.  Set by ExportProgressPanel on mount.
 */
let _api: {
  start: (investigationId: string, investigationName: string, destDir: string) => Promise<void>;
} | null = null;

export function startInvestigationExport(
  investigationId: string,
  investigationName: string,
  destDir: string,
): Promise<void> {
  if (!_api) {
    return Promise.reject(new Error('Export panel not mounted yet'));
  }
  return _api.start(investigationId, investigationName, destDir);
}

export const ExportProgressPanel: React.FC = () => {
  const [state, setState] = useState<State>(initialState);
  const [minimized, setMinimized] = useState(false);
  const [now, setNow] = useState(Date.now());
  const stateRef = useRef(state);
  stateRef.current = state;

  // ── Subscribe to Rust progress events ──────────────────────────────
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    (async () => {
      unlisten = await listen<ProgressEvent>('warrant_export_progress', (e) => {
        const p = e.payload;
        setState((prev) => {
          // Ignore events from a stale run that's no longer being tracked
          if (prev.phase === 'idle') return prev;
          if (p.stage === 'done') {
            return {
              ...prev,
              phase: 'done',
              stage: 'done',
              reportDir: p.label || prev.reportDir,
              lastIndex: prev.total,
            };
          }
          return {
            ...prev,
            stage: p.stage,
            total: p.total || prev.total,
            lastIndex: p.index || prev.lastIndex,
            lastLabel: p.label || prev.lastLabel,
          };
        });
      });
    })();
    return () => { if (unlisten) unlisten(); };
  }, []);

  // ── Live elapsed/ETA tick ──────────────────────────────────────────
  useEffect(() => {
    if (state.phase !== 'running') return;
    const id = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(id);
  }, [state.phase]);

  // ── Expose the start() API to the rest of the app ──────────────────
  useEffect(() => {
    _api = {
      start: async (investigationId, investigationName, destDir) => {
        setState({
          phase: 'running',
          startedAt: Date.now(),
          total: 0,
          lastIndex: 0,
          lastLabel: investigationName,
          stage: 'starting',
          reportDir: null,
          errorMessage: null,
        });
        setMinimized(false);
        try {
          const result = await invoke<{ reportDir: string }>(
            'warrant_export_investigation_report',
            { investigationId, destDir },
          );
          // Belt-and-suspenders: the Rust `done` event should already
          // have flipped us into 'done', but make sure reportDir is set.
          setState((prev) => ({
            ...prev,
            phase: 'done',
            reportDir: result.reportDir,
          }));
        } catch (err) {
          setState((prev) => ({
            ...prev,
            phase: 'error',
            errorMessage: String(err),
          }));
        }
      },
    };
    return () => { _api = null; };
  }, []);

  if (state.phase === 'idle') return null;

  // ── Compute progress + ETA ─────────────────────────────────────────
  const total = Math.max(state.total, 1);
  // Weight the per-return loop as 90% of the work, cover/rollup as the
  // last 10% so the bar moves naturally past the return loop into the
  // cover render.
  const returnFrac = Math.min(state.lastIndex / total, 1) * 0.9;
  const tailFrac =
    state.stage === 'rollup' ? 0.05 :
    state.stage === 'cover'  ? 0.08 :
    state.stage === 'done'   ? 0.10 : 0;
  const frac = Math.min(returnFrac + tailFrac, state.phase === 'done' ? 1 : 0.99);
  const pct = Math.round(frac * 100);

  const elapsedMs = state.phase === 'running' ? now - state.startedAt : 0;
  const etaMs =
    state.phase === 'running' && frac > 0.02
      ? (elapsedMs / frac) * (1 - frac)
      : null;

  // ── Render ─────────────────────────────────────────────────────────
  if (minimized) {
    return (
      <div
        className="export-chip"
        title={state.phase === 'done'
          ? 'Combined report ready — click to expand'
          : 'Generating combined report — click to expand'}
        onClick={() => setMinimized(false)}
      >
        {state.phase === 'running' && <div className="export-chip-spinner" />}
        {state.phase === 'done' && <div className="export-chip-check">✓</div>}
        {state.phase === 'error' && <div className="export-chip-error">!</div>}
        <span className="export-chip-pct">
          {state.phase === 'done' ? 'Done' :
           state.phase === 'error' ? 'Error' :
           `${pct}%`}
        </span>
      </div>
    );
  }

  return (
    <div className="export-panel" role="status" aria-live="polite">
      <div className="export-panel-header">
        <div className="export-panel-title">
          {state.phase === 'done'
            ? '✓ Combined report ready'
            : state.phase === 'error'
            ? 'Export failed'
            : 'Generating combined report'}
        </div>
        <div className="export-panel-controls">
          <button
            className="export-panel-btn"
            title="Minimize"
            onClick={() => setMinimized(true)}
          >
            –
          </button>
          {(state.phase === 'done' || state.phase === 'error') && (
            <button
              className="export-panel-btn"
              title="Close"
              onClick={() => setState(initialState)}
            >
              ×
            </button>
          )}
        </div>
      </div>

      {state.phase === 'running' && (
        <>
          <div className="export-panel-bar">
            <div
              className="export-panel-bar-fill"
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="export-panel-stats">
            <span>{pct}%</span>
            <span className="export-panel-stat-sep">·</span>
            <span>
              {state.lastIndex > 0
                ? `Return ${state.lastIndex} of ${state.total}`
                : 'Preparing…'}
            </span>
            {state.stage === 'rollup' && <span className="export-panel-stage">Building roll-up</span>}
            {state.stage === 'cover' && <span className="export-panel-stage">Writing cover page</span>}
          </div>
          <div className="export-panel-time">
            <span>Elapsed: {fmtDuration(elapsedMs)}</span>
            {etaMs !== null && (
              <span className="export-panel-eta">
                Remaining: ~{fmtDuration(etaMs)}
              </span>
            )}
          </div>
          {state.lastLabel && state.stage === 'return' && (
            <div className="export-panel-current" title={state.lastLabel}>
              Processing: {state.lastLabel}
            </div>
          )}
        </>
      )}

      {state.phase === 'done' && (
        <>
          <div className="export-panel-success">
            Total time: {fmtDuration(now - state.startedAt)}
          </div>
          {state.reportDir && (
            <div className="export-panel-path" title={state.reportDir}>
              {state.reportDir}
            </div>
          )}
          <div className="export-panel-actions">
            {state.reportDir && (
              <button
                className="export-panel-action-btn primary"
                onClick={async () => {
                  try {
                    await invoke('open_in_explorer', { path: state.reportDir });
                  } catch (e) {
                    console.warn('[export] open_in_explorer failed:', e);
                  }
                }}
              >
                Open folder
              </button>
            )}
            <button
              className="export-panel-action-btn"
              onClick={() => setState(initialState)}
            >
              Dismiss
            </button>
          </div>
        </>
      )}

      {state.phase === 'error' && (
        <>
          <div className="export-panel-error-msg">
            {state.errorMessage || 'Unknown error'}
          </div>
          <div className="export-panel-actions">
            <button
              className="export-panel-action-btn"
              onClick={() => setState(initialState)}
            >
              Dismiss
            </button>
          </div>
        </>
      )}
    </div>
  );
};

function fmtDuration(ms: number): string {
  if (ms < 0 || !isFinite(ms)) return '—';
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (m < 60) return `${m}m ${s.toString().padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}h ${mm}m`;
}
