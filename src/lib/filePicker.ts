/**
 * filePicker — the ONE place the app asks the user for a file or folder (G10).
 *
 * Drop-in for plugin-dialog's `open` / `save` (same options, same return
 * types), so a call site migrates by changing only its import:
 *
 *     const { open } = await import('../lib/filePicker');
 *
 * Windows: forwards to the native plugin-dialog picker, unchanged.
 * macOS:   shows the in-app picker (`FilePickerHost`).  The native
 *          NSOpenPanel / NSSavePanel write recent places, sidebar state and
 *          panel preferences into the examined user's ~/Library, which breaks
 *          the Mac edition's zero-host-writes rule.  The in-app picker only
 *          reads directories, via the `fs_list_dir` / `fs_places` commands.
 *
 * Importing plugin-dialog `open`/`save` anywhere else fails `check:dialogs`.
 */
import type {
  DialogFilter,
  OpenDialogOptions,
  OpenDialogReturn,
  SaveDialogOptions,
} from '@tauri-apps/plugin-dialog';
import { getHostPlatform } from './hostPlatform';

export type { DialogFilter };

export type PickRequest =
  | { id: number; kind: 'open'; options: OpenDialogOptions; resolve: (v: string | string[] | null) => void }
  | { id: number; kind: 'save'; options: SaveDialogOptions; resolve: (v: string | null) => void };

// ── tiny external store, read by FilePickerHost via useSyncExternalStore ──
let queue: PickRequest[] = [];
let snapshot: PickRequest | null = null;
let nextId = 1;
const listeners = new Set<() => void>();

function publish() {
  snapshot = queue[0] ?? null;
  listeners.forEach((l) => l());
}

export function subscribePicker(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** The request currently on screen (stable reference between publishes). */
export function currentPickRequest(): PickRequest | null {
  return snapshot;
}

/** Called by FilePickerHost when the user picks or cancels. */
export function settlePickRequest(id: number, value: string | string[] | null) {
  const req = queue.find((r) => r.id === id);
  if (!req) return;
  queue = queue.filter((r) => r.id !== id);
  if (req.kind === 'save') req.resolve(typeof value === 'string' ? value : null);
  else req.resolve(value);
  publish();
}

/** Whether this host uses the in-app picker rather than the native one. */
export async function usesInAppPicker(): Promise<boolean> {
  try {
    return (await getHostPlatform()).os === 'macos';
  } catch {
    return false;
  }
}

/**
 * True once a FilePickerHost has mounted.  If none ever does (a bug), the
 * request falls back to the native picker rather than hanging forever.
 */
let hostMounted = false;
export function markPickerHostMounted(mounted: boolean) {
  hostMounted = mounted;
}

export async function pickOpen<T extends OpenDialogOptions>(options?: T): Promise<OpenDialogReturn<T>> {
  if (hostMounted && (await usesInAppPicker())) {
    return new Promise((resolve) => {
      queue = [
        ...queue,
        { id: nextId++, kind: 'open', options: options ?? {}, resolve: resolve as (v: string | string[] | null) => void },
      ];
      publish();
    });
  }
  const dlg = await import('@tauri-apps/plugin-dialog');
  return dlg.open(options);
}

export async function pickSave(options?: SaveDialogOptions): Promise<string | null> {
  if (hostMounted && (await usesInAppPicker())) {
    return new Promise((resolve) => {
      queue = [...queue, { id: nextId++, kind: 'save', options: options ?? {}, resolve }];
      publish();
    });
  }
  const dlg = await import('@tauri-apps/plugin-dialog');
  return dlg.save(options);
}

// Drop-in names, so `const { open } = await import('../lib/filePicker')`
// is the whole migration at a call site.
export { pickOpen as open, pickSave as save };

// ── pure helpers (shared with the host component; unit-testable) ──

/** Does `name` pass the dialog filters?  No filters, or any `*`, passes all. */
export function matchesFilters(name: string, filters: DialogFilter[] | undefined): boolean {
  if (!filters || filters.length === 0) return true;
  const lower = name.toLowerCase();
  return filters.some((f) =>
    f.extensions.some((ext) => ext === '*' || lower.endsWith('.' + ext.toLowerCase().replace(/^\./, '')))
  );
}

/** Split a defaultPath into (folder, file name) using either separator. */
export function splitDefaultPath(p: string | undefined): { dir: string | null; name: string } {
  if (!p) return { dir: null, name: '' };
  const i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  if (i < 0) return { dir: null, name: p };
  const dir = p.slice(0, i) || p.slice(0, i + 1); // keep "/" for root
  return { dir, name: p.slice(i + 1) };
}

/** Join a folder and a name with the folder's own separator. */
export function joinPath(dir: string, name: string): string {
  const sep = dir.includes('\\') && !dir.includes('/') ? '\\' : '/';
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

/** Add the first filter's extension when the typed name has none of them. */
export function withDefaultExtension(name: string, filters: DialogFilter[] | undefined): string {
  if (!filters || filters.length === 0) return name;
  if (matchesFilters(name, filters)) return name;
  const ext = filters[0].extensions.find((e) => e !== '*');
  return ext ? `${name}.${ext.replace(/^\./, '')}` : name;
}
