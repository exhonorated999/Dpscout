import React, { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import {
  DeletedMediaSummary,
  DeletedMediaProgress,
  formatBytes,
} from '../types/system';
import './DeletedMediaPanel.css';

interface Props {
  driveLetter: string;
  /**
   * Pre-computed summary from a pipeline scan (Configure Scan → Deleted Media
   * Detection). When supplied, the panel renders it directly instead of
   * requiring the user to press "Scan". A "Re-scan" button remains available.
   */
  result?: DeletedMediaSummary | null;
  /** Error text produced by the pipeline scan for this drive, if it failed. */
  resultError?: string | null;
  /** Hide the section heading when the panel is already inside a titled view. */
  hideHeading?: boolean;
  /**
   * True while the parent pipeline scan is still running. Suppresses the
   * on-demand Scan button so the user can't launch a second concurrent scan
   * (the Rust side shares one cancel flag and one raw volume handle path).
   */
  pipelineScanning?: boolean;
}

type Phase = 'idle' | 'needs-elevation' | 'running' | 'done' | 'error';

/**
 * Deleted-media triage for a USB / SD / microSD volume.
 *
 * Detects whether deleted media files are still physically present in
 * unallocated space and estimates how many. This is a DETECTION tool — it
 * never reconstructs or extracts file data. Actual recovery is left to
 * PhotoRec or an equivalent carver.
 */
export const DeletedMediaPanel: React.FC<Props> = ({
  driveLetter,
  result = null,
  resultError = null,
  hideHeading = false,
  pipelineScanning = false,
}) => {
  const [phase, setPhase] = useState<Phase>(
    result ? 'done' : resultError ? 'error' : 'idle'
  );
  const [progress, setProgress] = useState<DeletedMediaProgress | null>(null);
  const [summary, setSummary] = useState<DeletedMediaSummary | null>(result);
  const [error, setError] = useState<string>(resultError || '');
  const [showDetails, setShowDetails] = useState(false);
  const unlistenRef = useRef<UnlistenFn | null>(null);

  // Adopt pipeline results when they arrive or change — a pipeline scan can
  // finish after this panel has already mounted.
  useEffect(() => {
    if (result) {
      setSummary(result);
      setError('');
      setPhase('done');
    } else if (resultError) {
      setError(resultError);
      setPhase(resultError.includes('ELEVATION_REQUIRED') ? 'needs-elevation' : 'error');
    }
  }, [result, resultError]);

  // Clean up the progress listener on unmount.
  useEffect(() => {
    return () => {
      if (unlistenRef.current) unlistenRef.current();
    };
  }, []);

  const startScan = async () => {
    setError('');
    setSummary(null);
    setProgress(null);

    // Raw volume reads need an elevated token.
    try {
      const elevated = await invoke<boolean>('is_elevated');
      if (!elevated) {
        setPhase('needs-elevation');
        return;
      }
    } catch {
      // If the check itself fails, let the scan attempt surface the real error.
    }

    setPhase('running');

    if (unlistenRef.current) unlistenRef.current();
    unlistenRef.current = await listen<DeletedMediaProgress>(
      'deleted-media:progress',
      (e) => setProgress(e.payload)
    );

    try {
      const result = await invoke<DeletedMediaSummary>('scan_deleted_media', {
        driveLetter,
        options: {
          scanMetadataResidue: true,
          scanUnallocated: true,
          maxBytesToScan: 0,
          maxNamedFiles: 5000,
        },
      });
      setSummary(result);
      setPhase('done');
    } catch (e) {
      const msg = String(e);
      if (msg.includes('ELEVATION_REQUIRED')) {
        setPhase('needs-elevation');
      } else {
        setError(msg);
        setPhase('error');
      }
    } finally {
      if (unlistenRef.current) {
        unlistenRef.current();
        unlistenRef.current = null;
      }
    }
  };

  const cancelScan = async () => {
    try {
      await invoke('cancel_deleted_media_scan');
    } catch {
      /* nothing actionable */
    }
  };

  const relaunchElevated = async () => {
    try {
      await invoke('relaunch_elevated');
    } catch (e) {
      setError(String(e));
      setPhase('error');
    }
  };

  return (
    <div className="dm-panel">
      <div className="dm-header">
        {!hideHeading && (
          <h3 className="section-subtitle">DELETED MEDIA (UNALLOCATED SPACE)</h3>
        )}
        {hideHeading && <h3 className="section-subtitle">{driveLetter}: VOLUME</h3>}
        {phase === 'idle' && !pipelineScanning && (
          <button className="dm-btn dm-btn-primary" onClick={startScan}>
            Scan {driveLetter}: for Deleted Media
          </button>
        )}
        {phase === 'idle' && pipelineScanning && (
          <span className="dm-hint">Queued — analyzing unallocated space…</span>
        )}
        {phase === 'running' && (
          <button className="dm-btn dm-btn-cancel" onClick={cancelScan}>
            Cancel
          </button>
        )}
        {(phase === 'done' || phase === 'error') && !pipelineScanning && (
          <button className="dm-btn" onClick={startScan}>
            Re-scan
          </button>
        )}
      </div>

      {phase === 'idle' && (
        <p className="dm-hint">
          Checks the drive's unallocated space for recoverable deleted photos and
          videos. Reports whether any are present and estimates how many — it does
          not extract them.
        </p>
      )}

      {phase === 'needs-elevation' && (
        <div className="dm-elevation">
          <div className="dm-elevation-title">Administrator rights required</div>
          <p>
            Reading unallocated space requires direct access to the drive, which
            Windows restricts to elevated processes. Scout will restart with an
            elevation prompt.
          </p>
          <button className="dm-btn dm-btn-primary" onClick={relaunchElevated}>
            Relaunch as Administrator
          </button>
        </div>
      )}

      {phase === 'running' && (
        <div className="dm-progress">
          <div className="dm-progress-bar">
            <div
              className="dm-progress-fill"
              style={{ width: `${progress?.percent ?? 0}%` }}
            />
          </div>
          <div className="dm-progress-meta">
            <span>{progress?.phase || 'Starting...'}</span>
            <span>
              {progress
                ? `${formatBytes(progress.scannedBytes)} / ${formatBytes(progress.freeBytes)} free space`
                : ''}
            </span>
          </div>
        </div>
      )}

      {phase === 'error' && <div className="dm-error">{error}</div>}

      {phase === 'done' && summary && (
        <>
          <div
            className={
              summary.deletedMediaFound ? 'dm-verdict dm-found' : 'dm-verdict dm-clean'
            }
          >
            <div className="dm-verdict-main">
              {summary.deletedMediaFound
                ? 'Deleted media detected'
                : 'No deleted media detected'}
            </div>
            {summary.deletedMediaFound && (
              <div className="dm-verdict-count">
                ~{summary.estimatedTotal.toLocaleString()} file
                {summary.estimatedTotal === 1 ? '' : 's'} potentially recoverable
              </div>
            )}
            {summary.cancelled && (
              <div className="dm-verdict-partial">
                Scan cancelled — results are partial.
              </div>
            )}
          </div>

          <div className="info-grid">
            <div className="info-card">
              <div className="info-label">Filesystem</div>
              <div className="info-value">{summary.fsType}</div>
            </div>
            <div className="info-card">
              <div className="info-label">Named Deleted Images</div>
              <div className="info-value">
                {summary.namedImageCount.toLocaleString()}
              </div>
            </div>
            <div className="info-card">
              <div className="info-label">Named Deleted Videos</div>
              <div className="info-value">
                {summary.namedVideoCount.toLocaleString()}
              </div>
            </div>
            <div className="info-card">
              <div className="info-label">Image Headers in Free Space</div>
              <div className="info-value">
                {summary.unallocatedImageHeaders.toLocaleString()}
              </div>
            </div>
            <div className="info-card">
              <div className="info-label">Video Headers in Free Space</div>
              <div className="info-value">
                {summary.unallocatedVideoHeaders.toLocaleString()}
              </div>
            </div>
            <div className="info-card">
              <div className="info-label">Free Space Scanned</div>
              <div className="info-value">
                {formatBytes(summary.scannedBytes)}
              </div>
            </div>
          </div>

          {summary.headerHits.length > 0 && (
            <div className="dm-sigs">
              <div className="dm-sigs-title">Signatures found in free space</div>
              <div className="dm-sigs-list">
                {summary.headerHits.map((h) => (
                  <span key={h.signature} className="dm-sig-chip">
                    {h.signature}
                    <b>{h.count.toLocaleString()}</b>
                  </span>
                ))}
              </div>
            </div>
          )}

          {summary.namedFiles.length > 0 && (
            <div className="dm-details">
              <button
                className="dm-details-toggle"
                onClick={() => setShowDetails((s) => !s)}
              >
                {showDetails ? '▾' : '▸'} Recoverable file names (
                {summary.namedFiles.length.toLocaleString()})
              </button>
              {showDetails && (
                <div className="dm-table-wrap">
                  <table className="dm-table">
                    <thead>
                      <tr>
                        <th>File Name</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Source</th>
                        <th>Cluster</th>
                        <th>Likely Recoverable</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.namedFiles.map((f, i) => (
                        <tr key={`${f.fileName}-${f.startCluster}-${i}`}>
                          <td className="dm-mono">{f.fileName}</td>
                          <td>{f.mediaType}</td>
                          <td>{formatBytes(f.sizeBytes)}</td>
                          <td>
                            {f.source === 'dir_entry' ? 'Directory entry' : 'MFT'}
                          </td>
                          <td className="dm-mono">{f.startCluster}</td>
                          <td>
                            <span
                              className={
                                f.likelyRecoverable ? 'dm-yes' : 'dm-maybe'
                              }
                            >
                              {f.likelyRecoverable ? 'Yes' : 'Overwritten?'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {summary.notes.length > 0 && (
            <div className="dm-notes">
              <div className="dm-notes-title">Interpretation &amp; caveats</div>
              <ul>
                {summary.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="dm-footnote">
            Scan completed in {(summary.durationMs / 1000).toFixed(1)}s · cluster
            size {formatBytes(summary.clusterSize)}
          </div>
        </>
      )}
    </div>
  );
};

export default DeletedMediaPanel;
