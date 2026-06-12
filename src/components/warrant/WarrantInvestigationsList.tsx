/**
 * WarrantInvestigationsList — top-level screen for the multi-return
 * warrant flow.  Replaces the old provider grid at `state === "warrant"`.
 *
 * Lists every investigation (auto-migrating any orphan returns into a
 * "Legacy Returns" investigation on first call), with a primary CTA to
 * create a new one.  Clicking a row drills into [`WarrantInvestigationDetail`].
 */

import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './WarrantInvestigations.css';

export interface InvestigationSummary {
  investigationId: string;
  name: string;
  agencyCaseNumber: string | null;
  createdAt: string;
  updatedAt: string;
  returnCount: number;
  totalItems: number;
  totalFlagged: number;
  totalBucketed: number;
}

interface Props {
  onBack: () => void;
  onOpen: (investigationId: string) => void;
}

function formatDate(rfc3339: string): string {
  try {
    return new Date(rfc3339).toLocaleString();
  } catch {
    return rfc3339;
  }
}

export const WarrantInvestigationsList: React.FC<Props> = ({ onBack, onOpen }) => {
  const [items, setItems] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const list = await invoke<InvestigationSummary[]>('warrant_list_investigations');
      setItems(list);
    } catch (err) {
      console.error('[warrant] list_investigations failed:', err);
      alert(`Failed to load investigations:\n${String(err)}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleCreated(id: string) {
    setShowCreate(false);
    await load();
    onOpen(id);
  }

  async function handleDelete(inv: InvestigationSummary, e: React.MouseEvent) {
    e.stopPropagation();
    const message =
      inv.returnCount > 0
        ? `Delete investigation "${inv.name}"?\n\nThis investigation contains ${inv.returnCount} return${inv.returnCount === 1 ? '' : 's'}. ` +
          `Click OK to ALSO delete the underlying return data. Click Cancel to keep the returns (they'll be re-attached to "Legacy Returns" on next load).`
        : `Delete investigation "${inv.name}"?`;
    const deleteReturns = window.confirm(message);
    // If they cancelled and there are returns, ask if they want to keep at all.
    if (!deleteReturns && inv.returnCount > 0) {
      const keepConfirm = window.confirm(
        `Delete investigation "${inv.name}" but KEEP the ${inv.returnCount} return${inv.returnCount === 1 ? '' : 's'}?`
      );
      if (!keepConfirm) return;
    } else if (!deleteReturns && inv.returnCount === 0) {
      // No returns and they hit cancel — abort
      return;
    }
    try {
      await invoke('warrant_delete_investigation', {
        investigationId: inv.investigationId,
        deleteReturns,
      });
      await load();
    } catch (err) {
      alert(`Delete failed:\n${String(err)}`);
    }
  }

  return (
    <div className="inv-screen">
      <button className="inv-back-button" onClick={onBack} title="Back to start">
        ← Back
      </button>

      <div className="inv-header">
        <div className="inv-header-left">
          <div className="inv-header-badge">📋 Warrant Triage</div>
          <h1 className="inv-title">Investigations</h1>
          <p className="inv-subtitle">
            One investigation per case file. Each can hold any number of warrant returns —
            multiple providers, multiple targets, or several from the same provider.
            Generate one combined HTML report for the detective when you're done.
          </p>
        </div>
        <button className="inv-primary-btn" onClick={() => setShowCreate(true)}>
          + New Investigation
        </button>
      </div>

      {loading ? (
        <div className="inv-loading">
          <div className="inv-spinner lg" />
          <div>Loading investigations…</div>
        </div>
      ) : (
        <div className="inv-table-wrap">
          <table className="inv-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Agency case #</th>
                <th className="num">Returns</th>
                <th className="num">Items</th>
                <th className="num">Flagged</th>
                <th>Updated</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr className="empty-row">
                  <td colSpan={7}>
                    No investigations yet. Create one to start importing returns.
                  </td>
                </tr>
              ) : (
                items.map((inv) => (
                  <tr
                    key={inv.investigationId}
                    className="row-link"
                    onClick={() => onOpen(inv.investigationId)}
                  >
                    <td className="name">{inv.name}</td>
                    <td className="muted">{inv.agencyCaseNumber || '—'}</td>
                    <td className="num">{inv.returnCount}</td>
                    <td className="num">{inv.totalItems}</td>
                    <td className="num flag-cell">{inv.totalFlagged}</td>
                    <td className="muted">{formatDate(inv.updatedAt)}</td>
                    <td>
                      <button
                        className="row-action"
                        title="Delete investigation"
                        onClick={(e) => handleDelete(inv, e)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateInvestigationModal
          onClose={() => setShowCreate(false)}
          onCreated={handleCreated}
        />
      )}
    </div>
  );
};

// ─── Create modal ─────────────────────────────────────────────────────────

interface CreateProps {
  onClose: () => void;
  onCreated: (id: string) => void;
}

const CreateInvestigationModal: React.FC<CreateProps> = ({ onClose, onCreated }) => {
  const [name, setName] = useState('');
  const [agency, setAgency] = useState('');
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit() {
    if (!name.trim()) {
      setError('Investigation name is required.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const inv = await invoke<{ investigationId: string }>('warrant_create_investigation', {
        name: name.trim(),
        agencyCaseNumber: agency.trim() || null,
        notes: notes.trim() || null,
      });
      onCreated(inv.investigationId);
    } catch (err) {
      setError(String(err));
      setSubmitting(false);
    }
  }

  return (
    <div className="inv-modal-backdrop" onClick={submitting ? undefined : onClose}>
      <div className="inv-modal" onClick={(e) => e.stopPropagation()}>
        <h2 className="inv-modal-title">New Investigation</h2>
        <p className="inv-modal-subtitle">
          You'll add warrant returns to this investigation in the next step.
        </p>

        {error && <div className="inv-modal-error">{error}</div>}

        <div className="inv-field">
          <label>Investigation name *</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. State v. John Doe"
            autoFocus
          />
        </div>
        <div className="inv-field">
          <label>Agency case number (optional)</label>
          <input
            type="text"
            value={agency}
            onChange={(e) => setAgency(e.target.value)}
            placeholder="e.g. 2025-001234"
          />
        </div>
        <div className="inv-field">
          <label>Notes (optional)</label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Internal notes — included on the report cover page"
          />
        </div>

        <div className="inv-modal-actions">
          <button className="inv-secondary-btn" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button
            className="inv-primary-btn"
            onClick={handleSubmit}
            disabled={submitting || !name.trim()}
          >
            {submitting ? (
              <>
                <span className="inv-btn-spinner" />
                Creating…
              </>
            ) : (
              'Create'
            )}
          </button>
        </div>

        {submitting && (
          <div className="inv-busy-overlay">
            <div className="inv-spinner lg" />
            <div className="inv-busy-label">Creating investigation…</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default WarrantInvestigationsList;
