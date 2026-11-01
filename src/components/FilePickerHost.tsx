/**
 * FilePickerHost — the in-app file/folder picker used on macOS (G10).
 *
 * Renders whatever `src/lib/filePicker.ts` has queued.  Reads directories
 * through `fs_list_dir` / `fs_places` only; never writes, never opens a
 * TCC-protected folder without Full Disk Access (the backend refuses it).
 *
 * Mounted once in main.tsx, beside GlobalAlertHost and below it in z-order
 * so an overwrite confirm can appear on top.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  currentPickRequest,
  joinPath,
  markPickerHostMounted,
  matchesFilters,
  settlePickRequest,
  splitDefaultPath,
  subscribePicker,
  withDefaultExtension,
  type PickRequest,
} from '../lib/filePicker';
import { appConfirm } from '../lib/appDialog';

interface FsEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modified: number | null;
  hidden: boolean;
  protected: boolean;
}
interface FsListing {
  path: string;
  parent: string | null;
  entries: FsEntry[];
  truncated: boolean;
}
interface FsPlace {
  label: string;
  path: string;
  kind: 'home' | 'folder' | 'drive' | 'stick' | 'root' | string;
  protected: boolean;
}

const PLACE_ICON: Record<string, string> = { stick: '🔑', home: '🏠', folder: '📁', drive: '💽', root: '🖥️' };

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

function fmtDate(ms: number | null): string {
  if (ms == null) return '';
  const d = new Date(ms);
  return isNaN(d.getTime()) ? '' : d.toLocaleString();
}

export const FilePickerHost: React.FC = () => {
  const req = useSyncExternalStore(subscribePicker, currentPickRequest);
  useEffect(() => {
    markPickerHostMounted(true);
    return () => markPickerHostMounted(false);
  }, []);
  if (!req) return null;
  // key: a fresh dialog state for every request.
  return <PickerDialog key={req.id} req={req} />;
};

const PickerDialog: React.FC<{ req: PickRequest }> = ({ req }) => {
  const isSave = req.kind === 'save';
  const isDirMode = req.kind === 'open' && !!req.options.directory;
  const multiple = req.kind === 'open' && !!req.options.multiple;
  const filters = req.options.filters;
  const initial = useMemo(() => splitDefaultPath(req.options.defaultPath), [req]);

  const [places, setPlaces] = useState<FsPlace[]>([]);
  const [listing, setListing] = useState<FsListing | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [pathInput, setPathInput] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [fileName, setFileName] = useState(initial.name);
  const [showHidden, setShowHidden] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);

  const navigate = useCallback(async (path: string) => {
    setLoading(true);
    setError('');
    try {
      const l = await invoke<FsListing>('fs_list_dir', { path });
      setListing(l);
      setPathInput(l.path);
      setSelected([]);
      listRef.current?.scrollTo(0, 0);
    } catch (e) {
      setError(String(e));
      setPathInput(path);
    } finally {
      setLoading(false);
    }
  }, []);

  // Places, then the starting folder: defaultPath's folder, else the stick
  // for saves (keep output off the examined Mac), else Home.
  useEffect(() => {
    let alive = true;
    (async () => {
      let ps: FsPlace[] = [];
      try {
        ps = await invoke<FsPlace[]>('fs_places');
      } catch (e) {
        console.warn('[FilePicker] fs_places failed', e);
      }
      if (!alive) return;
      setPlaces(ps);
      const usable = ps.filter((p) => !p.protected);
      const start =
        initial.dir ??
        (isSave ? usable.find((p) => p.kind === 'stick')?.path : undefined) ??
        usable.find((p) => p.kind === 'home')?.path ??
        usable[0]?.path ??
        '/';
      navigate(start);
    })();
    return () => {
      alive = false;
    };
  }, [initial, isSave, navigate]);

  const visible = useMemo(() => {
    if (!listing) return [];
    return listing.entries.filter((e) => {
      if (!showHidden && e.hidden) return false;
      if (e.isDir) return true;
      if (isDirMode) return true; // shown greyed so the folder isn't mistaken for empty
      return showAll || matchesFilters(e.name, filters);
    });
  }, [listing, showHidden, showAll, filters, isDirMode]);

  const cancel = useCallback(() => settlePickRequest(req.id, null), [req.id]);

  const accept = useCallback(async () => {
    if (!listing) return;
    if (isSave) {
      const raw = fileName.trim();
      if (!raw) {
        setError('Type a file name.');
        return;
      }
      if (/[\\/]/.test(raw)) {
        setError('The file name cannot contain / or \\.');
        return;
      }
      const name = withDefaultExtension(raw, filters);
      const existing = listing.entries.find((e) => e.name === name);
      if (existing?.isDir) {
        setError(`"${name}" is a folder.`);
        return;
      }
      if (existing) {
        const ok = await appConfirm(`"${name}" already exists in this folder.\n\nReplace it?`, {
          title: 'Replace file?',
          confirmLabel: 'Replace',
          danger: true,
        });
        if (!ok) return;
      }
      settlePickRequest(req.id, joinPath(listing.path, name));
      return;
    }
    if (isDirMode) {
      // A selected sub-folder wins; otherwise the folder being viewed.
      const dirs = selected.length > 0 ? selected : [listing.path];
      settlePickRequest(req.id, multiple ? dirs : dirs[0]);
      return;
    }
    if (selected.length === 0) return;
    settlePickRequest(req.id, multiple ? selected : selected[0]);
  }, [listing, isSave, fileName, filters, req.id, isDirMode, selected, multiple]);

  const onEntryClick = (e: FsEntry, ev: React.MouseEvent) => {
    if (e.protected) {
      setError(`${e.name} is protected by macOS and needs Full Disk Access.`);
      return;
    }
    setError('');
    if (isSave) {
      if (!e.isDir) setFileName(e.name);
      return;
    }
    const selectable = isDirMode ? e.isDir : !e.isDir;
    if (!selectable) return;
    if (multiple && (ev.metaKey || ev.ctrlKey)) {
      setSelected((s) => (s.includes(e.path) ? s.filter((p) => p !== e.path) : [...s, e.path]));
    } else {
      setSelected([e.path]);
    }
  };

  const onEntryDouble = (e: FsEntry) => {
    if (e.protected) return;
    if (e.isDir) {
      navigate(e.path);
    } else if (!isSave && !isDirMode) {
      settlePickRequest(req.id, multiple ? [e.path] : e.path);
    } else if (isSave) {
      setFileName(e.name);
    }
  };

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        cancel();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [cancel]);

  const title =
    req.options.title ||
    (isSave ? 'Save as' : isDirMode ? (multiple ? 'Choose folders' : 'Choose a folder') : multiple ? 'Choose files' : 'Choose a file');
  const confirmLabel = isSave ? 'Save' : isDirMode ? (selected.length ? 'Choose selected folder' : 'Choose this folder') : 'Open';
  const confirmDisabled =
    !listing || loading || (isSave ? !fileName.trim() : !isDirMode && selected.length === 0);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={title}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 10045,
        background: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          width: 'min(920px, 94vw)',
          height: 'min(620px, 88vh)',
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--color-bg-secondary, #1b1c20)',
          border: '1px solid var(--color-border, #333)',
          borderRadius: 10,
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
          color: 'var(--color-text-primary, #fff)',
          overflow: 'hidden',
          fontSize: 13,
        }}
      >
        {/* header */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--color-border, #333)' }}>
          <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 8 }}>{title}</div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              type="button"
              onClick={() => listing?.parent && navigate(listing.parent)}
              disabled={!listing?.parent || loading}
              title="Up one folder"
              style={btn}
            >
              ↑
            </button>
            <input
              value={pathInput}
              onChange={(e) => setPathInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') navigate(pathInput.trim());
              }}
              spellCheck={false}
              aria-label="Folder path"
              style={{ ...input, flex: 1, fontFamily: 'monospace' }}
            />
            <button type="button" onClick={() => navigate(pathInput.trim())} style={btn} disabled={loading}>
              Go
            </button>
          </div>
        </div>

        {/* body */}
        <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
          <div
            style={{
              width: 190,
              borderRight: '1px solid var(--color-border, #333)',
              overflowY: 'auto',
              padding: '8px 0',
              background: 'var(--color-bg-tertiary, rgba(255,255,255,0.02))',
            }}
          >
            {places.map((p) => (
              <div
                key={p.kind + p.path}
                onClick={() => (p.protected ? setError(`${p.label} needs Full Disk Access.`) : navigate(p.path))}
                title={p.protected ? `${p.path} — needs Full Disk Access` : p.path}
                style={{
                  padding: '6px 14px',
                  cursor: p.protected ? 'not-allowed' : 'pointer',
                  opacity: p.protected ? 0.45 : 1,
                  background: listing?.path === p.path ? 'rgba(99,102,241,0.25)' : undefined,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {PLACE_ICON[p.kind] ?? '📁'} {p.label}
                {p.protected ? ' 🔒' : ''}
              </div>
            ))}
          </div>

          <div ref={listRef} style={{ flex: 1, overflowY: 'auto' }}>
            {loading && <div style={{ padding: 16, opacity: 0.7 }}>Loading…</div>}
            {!loading && listing && visible.length === 0 && !error && (
              <div style={{ padding: 16, opacity: 0.6 }}>This folder is empty.</div>
            )}
            {!loading &&
              visible.map((e) => {
                const isSel = selected.includes(e.path) || (isSave && !e.isDir && e.name === fileName);
                const dim = e.protected || (isDirMode && !e.isDir);
                return (
                  <div
                    key={e.path}
                    onClick={(ev) => onEntryClick(e, ev)}
                    onDoubleClick={() => onEntryDouble(e)}
                    title={e.protected ? 'Protected by macOS — needs Full Disk Access' : e.path}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 90px 170px',
                      gap: 8,
                      padding: '5px 14px',
                      cursor: e.protected ? 'not-allowed' : 'default',
                      background: isSel ? 'rgba(99,102,241,0.35)' : undefined,
                      opacity: dim ? 0.45 : e.hidden ? 0.7 : 1,
                      userSelect: 'none',
                    }}
                  >
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {e.isDir ? '📁' : '📄'} {e.name}
                      {e.protected ? ' 🔒' : ''}
                    </span>
                    <span style={{ textAlign: 'right', opacity: 0.7 }}>{e.isDir ? '' : fmtSize(e.size)}</span>
                    <span style={{ opacity: 0.6 }}>{fmtDate(e.modified)}</span>
                  </div>
                );
              })}
            {listing?.truncated && (
              <div style={{ padding: 12, opacity: 0.7 }}>
                Showing the first {listing.entries.length.toLocaleString()} items. Type a path above to go deeper.
              </div>
            )}
          </div>
        </div>

        {/* footer */}
        <div style={{ padding: '10px 16px', borderTop: '1px solid var(--color-border, #333)' }}>
          {error && (
            <div role="alert" style={{ color: '#ff8a8a', marginBottom: 8, whiteSpace: 'pre-wrap' }}>
              {error}
            </div>
          )}
          {isSave && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
              <label htmlFor="fp-name" style={{ opacity: 0.8 }}>
                Name
              </label>
              <input
                id="fp-name"
                autoFocus
                value={fileName}
                onChange={(e) => setFileName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') accept();
                }}
                spellCheck={false}
                style={{ ...input, flex: 1 }}
              />
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <label style={{ display: 'flex', gap: 4, alignItems: 'center', opacity: 0.8 }}>
              <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} />
              Hidden items
            </label>
            {filters && filters.length > 0 && !isDirMode && (
              <label style={{ display: 'flex', gap: 4, alignItems: 'center', opacity: 0.8 }}>
                <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
                All files (not just {filters.map((f) => f.name).join(', ')})
              </label>
            )}
            <span style={{ flex: 1 }} />
            <span style={{ opacity: 0.55, fontSize: 11 }}>🍎 Scout picker — leaves no trace on this Mac</span>
            <button type="button" onClick={cancel} style={btn}>
              Cancel
            </button>
            <button
              type="button"
              onClick={accept}
              disabled={confirmDisabled}
              style={{
                ...btn,
                background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                border: 'none',
                color: '#fff',
                fontWeight: 600,
                opacity: confirmDisabled ? 0.5 : 1,
              }}
            >
              {confirmLabel}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const btn: React.CSSProperties = {
  padding: '6px 14px',
  background: 'var(--color-bg-tertiary, #2a2b31)',
  border: '1px solid var(--color-border, #444)',
  borderRadius: 6,
  color: 'var(--color-text-primary, #fff)',
  cursor: 'pointer',
  fontSize: 13,
};

const input: React.CSSProperties = {
  padding: '6px 10px',
  background: 'var(--color-bg-primary, #111)',
  border: '1px solid var(--color-border, #444)',
  borderRadius: 6,
  color: 'var(--color-text-primary, #fff)',
  fontSize: 13,
};

export default FilePickerHost;
