/**
 * WarrantInvestigationDetail — the per-investigation hub.
 *
 * Shows the roster of returns, lets the user add new ones (provider →
 * file → label), open each one in the existing single-return triage UI,
 * remove returns from the investigation, and generate the combined
 * detective-facing HTML report.
 */

import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './WarrantInvestigations.css';
import { WarrantLanding, WarrantProvider } from './WarrantLanding';
import { startInvestigationExport } from './ExportProgressPanel';

export interface CaseSummary {
  caseId: string;
  provider: string;
  providerDisplay: string;
  sourceFilename: string;
  importedAt: string;
  updatedAt: string;
  targetAccount: string | null;
  itemCount: number;
  flaggedCount: number;
  bucketedCount: number;
}

export interface ReturnDetail {
  label: string;
  summary: CaseSummary;
}

export interface Investigation {
  investigationId: string;
  name: string;
  agencyCaseNumber: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  returns: { caseId: string; label: string }[];
}

export interface InvestigationDetail {
  investigation: Investigation;
  returns: ReturnDetail[];
}

interface Props {
  investigationId: string;
  onBack: () => void;
  onOpenReturn: (caseId: string) => void;
}

function formatDate(rfc3339: string): string {
  try { return new Date(rfc3339).toLocaleString(); } catch { return rfc3339; }
}

export const WarrantInvestigationDetail: React.FC<Props> = ({
  investigationId, onBack, onOpenReturn,
}) => {
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [showProviderPicker, setShowProviderPicker] = useState(false);
  const [importing, setImporting] = useState(false);
  const [pendingLabel, setPendingLabel] = useState<{
    caseId: string; defaultLabel: string; providerDisplay: string;
  } | null>(null);
  const [showEdit, setShowEdit] = useState(false);
  const [exporting, setExporting] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const d = await invoke<InvestigationDetail>('warrant_load_investigation', {
        investigationId,
      });
      setDetail(d);
    } catch (err) {
      console.error('[warrant] load_investigation failed:', err);
      alert(`Failed to load investigation:\n${String(err)}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [investigationId]);

  // ─── Add return flow ───────────────────────────────────────────────
  async function handleProviderPicked(provider: WarrantProvider) {
    setShowProviderPicker(false);
    try {
      const { open, ask } = await import('@tauri-apps/plugin-dialog');
      const useFolder = await ask(
        'Is the warrant data already extracted into a folder?\n\n' +
          '• Yes → pick the extracted folder\n' +
          '• No  → pick the .zip archive',
        { title: 'Add return', kind: 'info', okLabel: 'Folder', cancelLabel: 'Zip file' }
      );

      let selected: string | null = null;
      if (useFolder) {
        const folder = await open({
          title: `Select ${provider} warrant folder`,
          directory: true, multiple: false,
        });
        if (folder && typeof folder === 'string') selected = folder;
      } else {
        const filters = provider === 'meta'
          ? [{ name: 'Meta Warrant Archive', extensions: ['zip'] }]
          : [{ name: 'Archive', extensions: ['zip'] }];
        const file = await open({
          title: `Select ${provider} warrant return file`,
          filters, multiple: false,
        });
        if (file && typeof file === 'string') selected = file;
      }
      if (!selected) return;

      setImporting(true);
      const result = await invoke<{ caseId: string; summary: CaseSummary }>('warrant_import', {
        provider, archivePath: selected,
      });
      // Open the label modal seeded with target_account or source filename.
      const def =
        result.summary.targetAccount ||
        result.summary.sourceFilename.replace(/\.(zip|tar|gz)$/i, '');
      setPendingLabel({
        caseId: result.caseId,
        defaultLabel: def,
        providerDisplay: result.summary.providerDisplay,
      });
    } catch (err) {
      alert(`Import failed:\n${String(err)}`);
      console.error('[warrant] import failed:', err);
    } finally {
      setImporting(false);
    }
  }

  async function handleLabelConfirmed(label: string) {
    if (!pendingLabel) return;
    const trimmed = label.trim();
    if (!trimmed) return;
    try {
      await invoke('warrant_add_return_to_investigation', {
        investigationId,
        caseId: pendingLabel.caseId,
        label: trimmed,
      });
      setPendingLabel(null);
      await load();
    } catch (err) {
      alert(`Failed to attach return to investigation:\n${String(err)}`);
    }
  }

  async function handleRemoveReturn(caseId: string, label: string) {
    if (!window.confirm(
      `Remove "${label}" from this investigation?\n\nThe return data stays on disk and can be re-attached. Click OK to remove.`
    )) return;
    try {
      await invoke('warrant_remove_return_from_investigation', {
        investigationId, caseId,
      });
      await load();
    } catch (err) {
      alert(`Remove failed:\n${String(err)}`);
    }
  }

  // ─── Combined report export ────────────────────────────────────────
  async function handleExport() {
    if (!detail || detail.returns.length === 0) {
      alert('Add at least one return before generating a report.');
      return;
    }
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        title:
          "Pick a parent folder (e.g. detective's USB root) — Scout will create the investigation folder inside it.",
        directory: true, multiple: false,
      });
      if (!selected || typeof selected !== 'string') return;

      // Hand off to the global, non-blocking export panel.  Returns
      // immediately so the user can keep working; progress + ETA +
      // "Open folder" all live in the floating panel.
      setExporting(true);
      try {
        await startInvestigationExport(
          investigationId,
          detail.investigation.name,
          selected,
        );
      } finally {
        setExporting(false);
      }
    } catch (err) {
      alert(`Export failed:\n${String(err)}`);
      setExporting(false);
    }
  }

  // ─── Render ────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="inv-screen">
        <button className="inv-back-button" onClick={onBack}>← Back</button>
        <div className="inv-loading">
          <div className="inv-spinner lg" />
          <div>Loading investigation…</div>
        </div>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="inv-screen">
        <button className="inv-back-button" onClick={onBack}>← Back</button>
        <div className="inv-loading">Investigation not found.</div>
      </div>
    );
  }

  const inv = detail.investigation;
  const totalItems = detail.returns.reduce((a, r) => a + r.summary.itemCount, 0);
  const totalFlagged = detail.returns.reduce((a, r) => a + r.summary.flaggedCount, 0);
  const totalBucketed = detail.returns.reduce((a, r) => a + r.summary.bucketedCount, 0);

  return (
    <div className="inv-screen">
      <button className="inv-back-button" onClick={onBack}>← Investigations</button>

      <div className="inv-header">
        <div className="inv-header-left">
          <div className="inv-header-badge">📁 Investigation</div>
          <h1 className="inv-title">
            {inv.name}{' '}
            <button
              className="inv-secondary-btn"
              style={{ padding: '4px 10px', fontSize: 12, marginLeft: 10 }}
              onClick={() => setShowEdit(true)}
              title="Edit investigation details"
            >
              ✎ Edit
            </button>
          </h1>
          <div className="inv-meta-row">
            {inv.agencyCaseNumber && (
              <span><span className="k">Agency case #</span>{inv.agencyCaseNumber}</span>
            )}
            <span><span className="k">Created</span>{formatDate(inv.createdAt)}</span>
            <span><span className="k">Updated</span>{formatDate(inv.updatedAt)}</span>
          </div>
          {inv.notes && <div className="inv-notes-block">{inv.notes}</div>}
        </div>
        <div style={{ display: 'flex', gap: 10, flexShrink: 0 }}>
          <button
            className="inv-secondary-btn"
            onClick={handleExport}
            disabled={exporting || detail.returns.length === 0}
            title={detail.returns.length === 0 ? 'Add a return first' : 'Generate combined HTML report'}
          >
            {exporting ? (
              <>
                <span className="inv-btn-spinner" />
                Exporting…
              </>
            ) : (
              '📄 Generate Combined Report'
            )}
          </button>
          <button className="inv-primary-btn" onClick={() => setShowProviderPicker(true)}>
            + Add Return
          </button>
        </div>
      </div>

      <div className="inv-stat-grid">
        <div className="inv-stat"><div className="num">{detail.returns.length}</div><div className="lbl">Returns</div></div>
        <div className="inv-stat acc"><div className="num">{totalItems}</div><div className="lbl">Total items</div></div>
        <div className="inv-stat flag"><div className="num">{totalFlagged}</div><div className="lbl">Flagged</div></div>
        <div className="inv-stat"><div className="num">{totalBucketed}</div><div className="lbl">Bucketed</div></div>
      </div>

      <div className="inv-section-bar">
        <span className="inv-section-title">Returns in this investigation</span>
      </div>

      <div className="inv-table-wrap">
        <table className="inv-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Label</th>
              <th>Provider</th>
              <th>Target account</th>
              <th className="num">Items</th>
              <th className="num">Flagged</th>
              <th>Imported</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {detail.returns.length === 0 ? (
              <tr className="empty-row">
                <td colSpan={8}>
                  No returns yet — click <strong>+ Add Return</strong> to import one.
                </td>
              </tr>
            ) : (
              detail.returns.map((r, idx) => (
                <tr
                  key={r.summary.caseId}
                  className="row-link"
                  onClick={() => onOpenReturn(r.summary.caseId)}
                >
                  <td className="muted">{String(idx + 1).padStart(2, '0')}</td>
                  <td className="name">{r.label}</td>
                  <td>{r.summary.providerDisplay}</td>
                  <td className="muted">{r.summary.targetAccount || '—'}</td>
                  <td className="num">{r.summary.itemCount}</td>
                  <td className="num flag-cell">{r.summary.flaggedCount}</td>
                  <td className="muted">{formatDate(r.summary.importedAt)}</td>
                  <td>
                    <button
                      className="row-action"
                      title="Remove from investigation (keeps the return data)"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRemoveReturn(r.summary.caseId, r.label);
                      }}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Provider picker — wraps the existing WarrantLanding grid in a modal */}
      {showProviderPicker && (
        <div
          className="inv-modal-backdrop"
          onClick={() => setShowProviderPicker(false)}
        >
          <div
            style={{
              background: '#0a0e1c',
              border: '1px solid rgba(93, 207, 255, 0.28)',
              borderRadius: 12,
              width: '100%',
              maxWidth: 980,
              maxHeight: '90vh',
              overflow: 'auto',
              boxShadow: '0 16px 60px rgba(0,0,0,0.55)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <WarrantLanding
              onBack={() => setShowProviderPicker(false)}
              onSelectProvider={handleProviderPicked}
            />
          </div>
        </div>
      )}

      {/* Importing overlay */}
      {importing && (
        <div className="inv-modal-backdrop">
          <div className="inv-modal">
            <h2 className="inv-modal-title">Parsing return…</h2>
            <p className="inv-modal-subtitle">This may take a minute on large archives.</p>
            <div style={{ display: 'flex', justifyContent: 'center', padding: '24px 0 8px' }}>
              <div className="inv-spinner lg" />
            </div>
          </div>
        </div>
      )}

      {/* Combined-report export is non-blocking — progress lives in the
          global ExportProgressPanel so users can keep working. */}

      {/* Label modal — appears after import succeeds */}
      {pendingLabel && (
        <LabelReturnModal
          defaultLabel={pendingLabel.defaultLabel}
          providerDisplay={pendingLabel.providerDisplay}
          onConfirm={handleLabelConfirmed}
          onCancel={() => setPendingLabel(null)}
        />
      )}

      {/* Edit investigation metadata */}
      {showEdit && (
        <EditInvestigationModal
          investigation={inv}
          onClose={() => setShowEdit(false)}
          onSaved={async () => { setShowEdit(false); await load(); }}
        />
      )}
    </div>
  );
};

// ─── Label modal ──────────────────────────────────────────────────────────

interface LabelProps {
  defaultLabel: string;
  providerDisplay: string;
  onConfirm: (label: string) => void;
  onCancel: () => void;
}

const LabelReturnModal: React.FC<LabelProps> = ({
  defaultLabel, providerDisplay, onConfirm, onCancel,
}) => {
  const [label, setLabel] = useState(defaultLabel);
  return (
    <div className="inv-modal-backdrop" onClick={onCancel}>
      <div className="inv-modal" onClick={(e) => e.stopPropagation()}>
        <h2 className="inv-modal-title">Label this return</h2>
        <p className="inv-modal-subtitle">
          {providerDisplay} return parsed successfully. Give it a label so you can tell it apart
          from other returns in this investigation (e.g. "Suspect — John Doe", "Victim Google").
        </p>
        <div className="inv-field">
          <label>Display label *</label>
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            autoFocus
          />
        </div>
        <div className="inv-modal-actions">
          <button className="inv-secondary-btn" onClick={onCancel}>Cancel</button>
          <button
            className="inv-primary-btn"
            onClick={() => onConfirm(label)}
            disabled={!label.trim()}
          >
            Add to investigation
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Edit modal ───────────────────────────────────────────────────────────

interface EditProps {
  investigation: Investigation;
  onClose: () => void;
  onSaved: () => void;
}

const EditInvestigationModal: React.FC<EditProps> = ({ investigation, onClose, onSaved }) => {
  const [name, setName] = useState(investigation.name);
  const [agency, setAgency] = useState(investigation.agencyCaseNumber || '');
  const [notes, setNotes] = useState(investigation.notes || '');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSave() {
    if (!name.trim()) { setError('Name is required.'); return; }
    setSubmitting(true);
    setError(null);
    try {
      await invoke('warrant_update_investigation', {
        investigationId: investigation.investigationId,
        name: name.trim(),
        agencyCaseNumber: agency,   // empty string clears
        notes: notes,               // empty string clears
      });
      onSaved();
    } catch (err) {
      setError(String(err));
      setSubmitting(false);
    }
  }

  return (
    <div className="inv-modal-backdrop" onClick={submitting ? undefined : onClose}>
      <div className="inv-modal" onClick={(e) => e.stopPropagation()}>
        <h2 className="inv-modal-title">Edit investigation</h2>
        {error && <div className="inv-modal-error">{error}</div>}
        <div className="inv-field">
          <label>Name *</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="inv-field">
          <label>Agency case number</label>
          <input type="text" value={agency} onChange={(e) => setAgency(e.target.value)} />
        </div>
        <div className="inv-field">
          <label>Notes</label>
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} />
        </div>
        <div className="inv-modal-actions">
          <button className="inv-secondary-btn" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="inv-primary-btn" onClick={handleSave} disabled={submitting || !name.trim()}>
            {submitting ? (
              <>
                <span className="inv-btn-spinner" />
                Saving…
              </>
            ) : (
              'Save'
            )}
          </button>
        </div>
        {submitting && (
          <div className="inv-busy-overlay">
            <div className="inv-spinner lg" />
            <div className="inv-busy-label">Saving…</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default WarrantInvestigationDetail;
