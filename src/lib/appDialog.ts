/**
 * appDialog — a global dialog queue that works outside React components.
 *
 * WHY THIS EXISTS
 * ---------------
 * `tauri-plugin-dialog` injects an init script into every webview that
 * replaces the DOM globals:
 *
 *     window.alert   = (msg) => invoke("plugin:dialog|message", { message: msg })
 *     window.confirm = async (msg) => invoke("plugin:dialog|confirm", { message: msg })
 *
 * `components/ConfirmDialog.tsx` already fixed the `confirm` half for React
 * components via the `useDialog()` hook.  The `alert` half was never fixed,
 * and there are ~87 bare `alert(...)` call sites left.  Each one produces a
 * bare OS message box that:
 *
 *   * looks nothing like Scout, in front of a customer,
 *   * cannot be copied — an officer reads a stack trace off the screen and
 *     retypes it into an e-mail, or more often just doesn't report it,
 *   * offers no route into the bug reporter that already ships in the app.
 *
 * Because a bare `alert(x)` resolves to `window.alert` *at call time*, patching
 * the global upgrades all 87 sites at once with no edits.  That is the whole
 * point of doing it here rather than site-by-site: an edit to 87 call sites
 * across 20 files is 87 chances to change behaviour by accident.
 *
 * DESIGN NOTES
 * ------------
 * * **No React import.**  Half the call sites are module-level helpers, not
 *   components (see `exportWarrantReport` in App.tsx, which says in a comment
 *   that it "cannot use the shared useDialog() hook").  A hook could never
 *   have covered them; this module can.
 *
 * * **Never lose a message.**  If nothing has mounted a host — an early boot
 *   failure, or a crash that takes the React tree down — the queue drains to
 *   the original injected `alert` after a short grace period.  An unstyled
 *   dialog is bad; a swallowed error message is worse.
 *
 * * **Identical messages collapse.**  A native `alert` inside a loop was
 *   survivable because each call blocked.  A queue is not: 400 files failing
 *   to hash would mean 400 modals.  Repeats increment a counter on the
 *   existing entry instead.
 *
 * * **`window.confirm` is deliberately NOT patched.**  It cannot be made
 *   synchronous, so `if (!window.confirm(x))` is broken however we define it.
 *   Use `appConfirm()` (or `useDialog().showConfirm` inside a component) and
 *   let `npm run lint:dialogs` fail the build on the global.
 */

export type DialogTone = 'info' | 'error';

/** A queued request.  The host renders the head of the queue only. */
export interface DialogEntry {
  id: number;
  kind: 'alert' | 'confirm';
  title: string;
  message: string;
  tone: DialogTone;
  confirmLabel: string;
  cancelLabel: string;
  danger: boolean;
  /** How many identical messages this single entry stands for. */
  count: number;
}

export interface AlertOptions {
  title?: string;
  /** Override the inferred tone.  Controls whether repair actions appear. */
  tone?: DialogTone;
}

export interface ConfirmOptions {
  title?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
}

interface QueuedEntry extends DialogEntry {
  /** Every caller that is waiting on this entry — see the collapse rule. */
  resolvers: Array<(ok: boolean) => void>;
}

/** Grace period before we give up on a host and use the native dialog. */
const FALLBACK_MS = 2500;

/**
 * Error-shaped wording.  Only used to decide whether to offer "Copy details"
 * and "Report this" — a wrong guess costs two extra buttons, never a lost
 * message, so a word list is proportionate here.
 */
const ERROR_WORDS =
  /\b(fail(ed|s|ure)?|error|cannot|can't|could ?n[o']t|unable|invalid|denied|refused|missing|not found|no such|timed? ?out|panic(ked)?|unsupported|corrupt)\b/i;

/** Wording that is positive even though it may contain a scary word. */
const SUCCESS_MARKERS = /^\s*[✓✔]|\bsucce(ss|eded|ssfully)\b|\bcomplete(d)?\b/i;

export function inferTone(message: string): DialogTone {
  if (SUCCESS_MARKERS.test(message)) return 'info';
  return ERROR_WORDS.test(message) ? 'error' : 'info';
}

/**
 * Derive a window title from the message when the caller gave none.  Most
 * existing call sites read like "Hash scan failed: {err}", so the words
 * before the first colon are usually a better title than a generic one.
 */
function inferTitle(message: string, tone: DialogTone): string {
  const firstLine = message.split('\n', 1)[0].trim();
  const colon = firstLine.indexOf(':');
  if (colon > 0 && colon <= 60) {
    const head = firstLine.slice(0, colon).trim();
    // Reject a time ("03:33:11") or a drive path ("C:\...") masquerading as
    // a label.
    if (head.length >= 4 && !/^\d+$/.test(head) && !/^[A-Za-z]$/.test(head)) {
      return head;
    }
  }
  return tone === 'error' ? 'Something went wrong' : 'Scout';
}

let nextId = 1;
const queue: QueuedEntry[] = [];
const listeners = new Set<() => void>();

/**
 * Immutable view of the queue head.  `useSyncExternalStore` compares
 * snapshots with `Object.is`, so this is replaced only when something the
 * host can see has actually changed — never rebuilt per read, which would
 * loop forever.
 */
let snapshot: DialogEntry | null = null;

let nativeAlert: ((message?: unknown) => void) | null = null;
let fallbackTimer: ReturnType<typeof setTimeout> | null = null;

function publish() {
  const top = queue[0];
  snapshot = top
    ? {
        id: top.id,
        kind: top.kind,
        title: top.title,
        message: top.message,
        tone: top.tone,
        confirmLabel: top.confirmLabel,
        cancelLabel: top.cancelLabel,
        danger: top.danger,
        count: top.count,
      }
    : null;
  listeners.forEach((l) => l());
}

/** Drain everything to the native dialog — the no-host escape hatch. */
function drainToNative() {
  fallbackTimer = null;
  if (listeners.size > 0 || queue.length === 0) return;
  const pending = queue.splice(0, queue.length);
  publish();
  for (const e of pending) {
    try {
      nativeAlert?.(e.count > 1 ? `${e.message}\n\n(${e.count} occurrences)` : e.message);
    } catch {
      /* the webview is beyond helping at this point */
    }
    // A confirm with no UI must answer "no": the caller is about to gate a
    // destructive action on it, and silence has to mean don't.
    e.resolvers.forEach((r) => r(false));
  }
}

function armFallback() {
  if (fallbackTimer !== null || listeners.size > 0) return;
  fallbackTimer = setTimeout(drainToNative, FALLBACK_MS);
}

function enqueue(entry: Omit<QueuedEntry, 'id' | 'count' | 'resolvers'>): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    // Collapse repeats of an alert.  Confirms are never collapsed: each one
    // is a separate decision and deserves its own answer.
    if (entry.kind === 'alert') {
      const dup = queue.find(
        (q) => q.kind === 'alert' && q.message === entry.message && q.title === entry.title
      );
      if (dup) {
        dup.count += 1;
        dup.resolvers.push(resolve);
        publish();
        armFallback();
        return;
      }
    }
    queue.push({ ...entry, id: nextId++, count: 1, resolvers: [resolve] });
    publish();
    armFallback();
  });
}

// ─── Public API ──────────────────────────────────────────────────────────

/** In-app replacement for `alert()`.  Resolves when the user dismisses it. */
export function appAlert(message: string, opts?: AlertOptions): Promise<void> {
  const text = String(message ?? '');
  const tone = opts?.tone ?? inferTone(text);
  return enqueue({
    kind: 'alert',
    title: opts?.title ?? inferTitle(text, tone),
    message: text,
    tone,
    confirmLabel: 'OK',
    cancelLabel: 'Close',
    danger: false,
  }).then(() => undefined);
}

/**
 * In-app replacement for `window.confirm()`, usable outside components.
 * Resolves `true` only if the user pressed the confirm button.
 */
export function appConfirm(message: string, opts?: ConfirmOptions): Promise<boolean> {
  const text = String(message ?? '');
  return enqueue({
    kind: 'confirm',
    title: opts?.title ?? 'Confirm',
    message: text,
    tone: 'info',
    confirmLabel: opts?.confirmLabel ?? 'OK',
    cancelLabel: opts?.cancelLabel ?? 'Cancel',
    danger: opts?.danger ?? false,
  });
}

// ─── Host plumbing (used by GlobalAlertHost) ─────────────────────────────

export function subscribeDialogs(listener: () => void): () => void {
  listeners.add(listener);
  if (fallbackTimer !== null) {
    clearTimeout(fallbackTimer);
    fallbackTimer = null;
  }
  return () => {
    listeners.delete(listener);
    // The host went away with work still queued — start the countdown again
    // rather than stranding it.
    if (listeners.size === 0 && queue.length > 0) armFallback();
  };
}

export function getDialogSnapshot(): DialogEntry | null {
  return snapshot;
}

/** Answer the head of the queue and advance.  No-op if it already moved. */
export function resolveTopDialog(id: number, ok: boolean) {
  const top = queue[0];
  if (!top || top.id !== id) return;
  queue.shift();
  publish();
  top.resolvers.forEach((r) => r(ok));
}

// ─── Global patch ────────────────────────────────────────────────────────

interface PatchedWindow extends Window {
  __scoutDialogPatched?: boolean;
}

/**
 * Route `window.alert` into the queue.  Idempotent, and it keeps a reference
 * to whatever `alert` was there first (tauri's injected one in the app, the
 * real browser one under `vite dev` in a plain tab) for the fallback path.
 */
export function installDialogPatch() {
  if (typeof window === 'undefined') return;
  const w = window as PatchedWindow;
  if (w.__scoutDialogPatched) return;
  w.__scoutDialogPatched = true;

  const original = w.alert;
  nativeAlert = typeof original === 'function' ? original.bind(w) : null;

  // Signature matches the DOM's `(message?: any) => void`, so every existing
  // `alert(...)` call site keeps compiling and keeps its fire-and-forget
  // behaviour.  Note this is not a regression in blocking: the injected
  // tauri `alert` was already async and non-blocking.
  w.alert = (message?: unknown) => {
    void appAlert(String(message ?? ''));
  };
}

// Patched on import so alerts fired during the first render are captured.
installDialogPatch();
