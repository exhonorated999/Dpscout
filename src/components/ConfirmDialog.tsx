/**
 * ConfirmDialog — the app's replacement for `window.confirm()`.
 *
 * WHY THIS EXISTS
 * ---------------
 * `tauri-plugin-dialog` injects an init script into every webview that
 * overwrites the DOM globals:
 *
 *     window.alert   = function(msg){ invoke("plugin:dialog|message", {message: msg}) }
 *     window.confirm = async function(msg){ return await invoke("plugin:dialog|confirm", {message: msg}) }
 *
 * So `window.confirm()` returns a **Promise**, not a boolean. Two things break:
 *
 *   1. `if (!window.confirm(...)) return;` — a Promise is always truthy, so the
 *      guard never fires and Cancel is silently ignored. Every destructive
 *      action in the app ran regardless of what the user clicked.
 *   2. Passing the result to `invoke()` sends `{}` to Rust, which serde rejects
 *      with `invalid type: map, expected a boolean`.
 *
 * Both were live bugs. Use `useDialog()` below instead of the globals.
 *
 * This modal is also genuinely modal from the caller's point of view: nothing
 * runs until the promise resolves, so a success `alert()` can no longer race
 * ahead of the user's answer (the original "Settings bugs #1 and #2").
 */

import React, { useState, useCallback } from 'react';
import { Button } from './Button';

export type DialogKind = 'confirm' | 'alert' | 'choice';

/** Answer from a three-way dialog. `alt` is the middle button. */
export type DialogAnswer = 'confirm' | 'alt' | 'cancel';

export interface DialogState {
  kind: DialogKind;
  title: string;
  message: string;
  confirmLabel?: string;
  /** Middle button, only rendered for `kind === 'choice'`. */
  altLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  resolve: (value: DialogAnswer) => void;
}

export interface ConfirmOptions {
  title?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
}

export interface ChoiceOptions extends ConfirmOptions {
  altLabel?: string;
}

export function useDialog() {
  const [dialog, setDialog] = useState<DialogState | null>(null);

  /** Two-way OK/Cancel. Resolves true only if the user pressed the OK button. */
  const showConfirm = useCallback(
    (message: string, opts?: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setDialog({
          kind: 'confirm',
          title: opts?.title || 'Confirm',
          message,
          confirmLabel: opts?.confirmLabel || 'OK',
          cancelLabel: opts?.cancelLabel || 'Cancel',
          danger: opts?.danger,
          resolve: (v) => resolve(v === 'confirm'),
        });
      }),
    []
  );

  /**
   * Three-way dialog for "do the big thing / do the small thing / back out".
   * Exists because expressing that with two chained confirms is ambiguous —
   * the user cannot tell what Cancel on the first dialog will do.
   */
  const showChoice = useCallback(
    (message: string, opts?: ChoiceOptions) =>
      new Promise<DialogAnswer>((resolve) => {
        setDialog({
          kind: 'choice',
          title: opts?.title || 'Confirm',
          message,
          confirmLabel: opts?.confirmLabel || 'OK',
          altLabel: opts?.altLabel || 'Alternative',
          cancelLabel: opts?.cancelLabel || 'Cancel',
          danger: opts?.danger,
          resolve,
        });
      }),
    []
  );

  /** Message box. Awaitable, so callers can sequence follow-up work. */
  const showAlert = useCallback(
    (message: string, opts?: { title?: string; confirmLabel?: string }) =>
      new Promise<void>((resolve) => {
        setDialog({
          kind: 'alert',
          title: opts?.title || 'Notice',
          message,
          confirmLabel: opts?.confirmLabel || 'OK',
          resolve: () => resolve(),
        });
      }),
    []
  );

  // Resolve outside the state updater: React can invoke an updater twice in
  // StrictMode, and a resolve() belongs in an event handler, not a reducer.
  const handleResponse = (value: DialogAnswer) => {
    if (!dialog) return;
    const resolve = dialog.resolve;
    setDialog(null);
    resolve(value);
  };

  return { dialog, showConfirm, showChoice, showAlert, handleResponse };
}

export const DialogModal: React.FC<{
  dialog: DialogState | null;
  onResponse: (value: DialogAnswer) => void;
}> = ({ dialog, onResponse }) => {
  if (!dialog) return null;
  const dismissable = dialog.kind !== 'alert';
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.65)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 10000,
      }}
      onClick={() => dismissable && onResponse('cancel')}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#1a1d29',
          border: '1px solid rgba(93, 207, 255, 0.25)',
          borderRadius: 10,
          padding: '1.5rem 1.75rem',
          minWidth: 380,
          maxWidth: 520,
          boxShadow: '0 12px 40px rgba(0,0,0,0.55), 0 0 24px rgba(74,122,255,0.25)',
        }}
      >
        <h3 style={{ margin: 0, color: '#5DCFFF', fontSize: '1.1rem' }}>{dialog.title}</h3>
        <p
          style={{
            marginTop: '0.85rem',
            marginBottom: '1.5rem',
            color: '#e6ecf5',
            lineHeight: 1.55,
            whiteSpace: 'pre-wrap',
          }}
        >
          {dialog.message}
        </p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', flexWrap: 'wrap' }}>
          {dismissable && (
            <Button variant="secondary" size="sm" onClick={() => onResponse('cancel')}>
              {dialog.cancelLabel}
            </Button>
          )}
          {dialog.kind === 'choice' && (
            <Button variant="secondary" size="sm" onClick={() => onResponse('alt')}>
              {dialog.altLabel}
            </Button>
          )}
          <Button
            variant={dismissable && dialog.danger ? 'danger' : 'primary'}
            size="sm"
            onClick={() => onResponse('confirm')}
          >
            {dialog.confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
};
