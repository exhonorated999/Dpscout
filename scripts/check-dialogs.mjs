/**
 * check-dialogs — fails the build if code reaches for a dialog global that
 * does not work in this app.
 *
 * WHY A SCRIPT AND NOT ESLINT
 * ---------------------------
 * This project has no ESLint config and no ESLint dependency.  Standing one
 * up means choosing a plugin set and a parser, then triaging whatever the
 * whole existing codebase has to say about itself — a separate job from
 * "stop this one class of bug coming back".  This is ~150 lines, needs no
 * install, and runs anywhere Node does.  If ESLint arrives later, port these
 * three rules to `no-restricted-properties`/`no-restricted-imports` and
 * delete this file.
 *
 * WHAT IT BANS AND WHY
 * --------------------
 *  1. `window.confirm(...)`
 *     tauri-plugin-dialog replaces it with an **async** function, so the
 *     classic `if (!window.confirm(msg)) return;` guard never fires — a
 *     Promise is always truthy.  Every destructive action guarded that way
 *     ran no matter which button the user pressed.  That was a real bug
 *     fixed across the app; this stops it coming back.
 *     Use `appConfirm()` (anywhere) or `useDialog().showConfirm` (components).
 *
 *  2. Assigning to `window.alert` / `window.confirm`
 *     Only `src/lib/appDialog.ts` may patch those globals.  A second patch
 *     would silently win depending on module import order.
 *
 *  3. Importing `message` / `confirm` / `ask` from `@tauri-apps/plugin-dialog`
 *     — statically or via `const { ask } = await import(...)`, which is how
 *     this codebase actually loads it.  Those draw an OS message box,
 *     bypassing the in-app modal and its "Copy details" / "Report this"
 *     actions.  The file-picker exports (`open`, `save`) are fine and are
 *     not flagged.
 *
 * Comments are excluded from every rule.  String *contents* are excluded too
 * for the `window.*` rules — a string holding "window.confirm(" is not a
 * call — but kept for the import rules, which have to read the specifier.
 *
 * Usage:  node scripts/check-dialogs.mjs [--self-test]
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const SRC = join(ROOT, 'src');

/** The only module allowed to import tauri-plugin-dialog (it wraps open/save). */
const FILE_PICKER = join('src', 'lib', 'filePicker.ts');

/** Files allowed to mention the banned globals in real code. */
const ALLOWLIST = new Set([
  join('src', 'lib', 'appDialog.ts'), // defines the patch
]);

/**
 * Blank out comments and string/template contents, preserving every other
 * character's position so reported line/column numbers stay truthful.
 *
 * Written as an explicit state machine rather than a regex because a regex
 * cannot tell `// window.confirm()` in a comment from a real call, and a
 * guard that cries wolf gets deleted.
 */
function stripNonCode(src, blankStrings = true) {
  const out = Array.from(src);
  let i = 0;
  const n = src.length;
  let state = 'code'; // code | line | block | single | double | template
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (state === 'code') {
      if (c === '/' && c2 === '/') {
        state = 'line';
        out[i] = ' ';
        out[i + 1] = ' ';
        i += 2;
        continue;
      }
      if (c === '/' && c2 === '*') {
        state = 'block';
        out[i] = ' ';
        out[i + 1] = ' ';
        i += 2;
        continue;
      }
      if (c === "'") { state = 'single'; i++; continue; }
      if (c === '"') { state = 'double'; i++; continue; }
      if (c === '`') { state = 'template'; i++; continue; }
      i++;
      continue;
    }
    if (state === 'line') {
      if (c === '\n') { state = 'code'; i++; continue; }
      out[i] = ' ';
      i++;
      continue;
    }
    if (state === 'block') {
      if (c === '*' && c2 === '/') {
        state = 'code';
        out[i] = ' ';
        out[i + 1] = ' ';
        i += 2;
        continue;
      }
      if (c !== '\n') out[i] = ' ';
      i++;
      continue;
    }
    // Inside a string: honour escapes, keep newlines.  Contents are blanked
    // only when the caller asked for it — the import rule has to read the
    // module specifier, which *is* a string literal.
    if (c === '\\') {
      if (blankStrings) {
        out[i] = ' ';
        if (i + 1 < n && src[i + 1] !== '\n') out[i + 1] = ' ';
      }
      i += 2;
      continue;
    }
    if (
      (state === 'single' && c === "'") ||
      (state === 'double' && c === '"') ||
      (state === 'template' && c === '`')
    ) {
      state = 'code';
      i++;
      continue;
    }
    // An unterminated quote would otherwise swallow the rest of the file.
    if (c === '\n' && state !== 'template') {
      state = 'code';
      i++;
      continue;
    }
    if (c !== '\n' && blankStrings) out[i] = ' ';
    i++;
  }
  return out.join('');
}

/**
 * `view` picks which stripped form of the file a rule reads:
 *   'code'        comments *and* string contents blanked — a string that
 *                 happens to contain "window.confirm(" is not a call.
 *   'withStrings' comments blanked, strings intact — the import rule has to
 *                 read the module specifier to know which package it is.
 */
const RULES = [
  {
    view: 'code',
    re: /\bwindow\s*\.\s*confirm\s*\(/g,
    msg: 'window.confirm() is async here and never guards anything — use appConfirm() from src/lib/appDialog, or useDialog().showConfirm in a component.',
  },
  {
    view: 'code',
    re: /\bwindow\s*\.\s*(?:alert|confirm)\s*=/g,
    msg: 'Only src/lib/appDialog.ts may patch the dialog globals — a second patch wins or loses by import order.',
  },
  {
    view: 'withStrings',
    re: /import\s*\{[^}]*\b(?:message|confirm|ask)\b[^}]*\}\s*from\s*['"]@tauri-apps\/plugin-dialog['"]/g,
    msg: 'plugin-dialog message/confirm/ask draw an OS box with no Copy/Report actions — use appAlert/appConfirm. (open/save file pickers are fine.)',
  },
  {
    // The dynamic form is how this codebase actually loads plugin-dialog —
    // 12 of 13 call sites.  A rule that only understood static imports missed
    // a real `ask` in WarrantInvestigationDetail.tsx, which is why this
    // exists.  `const { open, save } = await import(...)` stays legal.
    view: 'withStrings',
    re: /\{[^}]*\b(?:message|confirm|ask)\b[^}]*\}\s*=\s*await\s+import\s*\(\s*['"]@tauri-apps\/plugin-dialog['"]\s*\)/g,
    msg: 'plugin-dialog message/confirm/ask draw an OS box with no Copy/Report actions — use appAlert/appConfirm, or useDialog().showConfirm in a component. (open/save file pickers are fine.)',
  },
  {
    // G10: every file/folder picker goes through src/lib/filePicker.ts, which
    // swaps in the in-app picker on macOS (the native NSOpenPanel writes
    // recents/prefs into the examined Mac's ~/Library).  Type-only imports
    // are harmless and allowed.
    view: 'withStrings',
    re: /import\s+(?!type\b)[^;]*?from\s*['"]@tauri-apps\/plugin-dialog['"]|import\s*\(\s*['"]@tauri-apps\/plugin-dialog['"]\s*\)/g,
    allowIn: [join('src', 'lib', 'filePicker.ts')],
    msg: 'Pick files through src/lib/filePicker (pickOpen/pickSave, or `const { open } = await import(\'../lib/filePicker\')`) — the native picker leaves traces on a Mac.',
  },
];

function ruleAllows(rule, rel) {
  if (!rule.allowIn) return false;
  const norm = rel.split('/').join(sep);
  return rule.allowIn.includes(rel) || rule.allowIn.includes(norm);
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
      walk(p, out);
    } else if (/\.(ts|tsx)$/.test(name)) {
      out.push(p);
    }
  }
  return out;
}

function check() {
  const violations = [];
  for (const file of walk(SRC)) {
    const rel = relative(ROOT, file);
    if (ALLOWLIST.has(rel) || ALLOWLIST.has(rel.split('/').join(sep))) continue;
    const raw = readFileSync(file, 'utf8');
    const views = {
      code: stripNonCode(raw, true),
      withStrings: stripNonCode(raw, false),
    };
    for (const rule of RULES) {
      if (ruleAllows(rule, rel)) continue;
      const code = views[rule.view];
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(code)) !== null) {
        const upto = code.slice(0, m.index);
        const line = upto.split('\n').length;
        const col = m.index - upto.lastIndexOf('\n');
        violations.push(`${rel}:${line}:${col}\n    ${rule.msg}`);
      }
    }
  }
  if (violations.length > 0) {
    console.error(`\ncheck-dialogs: ${violations.length} violation(s)\n`);
    for (const v of violations) console.error('  ' + v + '\n');
    process.exit(1);
  }
  console.log('check-dialogs: clean');
}

/** Proves the comment/string stripping actually works. */
function selfTest() {
  const cases = [
    ['if (!window.confirm("x")) return;', 1, 'bare call'],
    ['// never use window.confirm(msg)', 0, 'line comment'],
    ['/* window.confirm( */', 0, 'block comment'],
    ['const s = "window.confirm(";', 0, 'double-quoted string'],
    ['const s = `window.confirm(`;', 0, 'template string'],
    ["const s = 'a\\'b'; window.confirm(1);", 1, 'escaped quote then real call'],
    ['window.alert = () => {};', 1, 'global reassignment'],
    ["import { message } from '@tauri-apps/plugin-dialog';", 2, 'banned import (also bypasses filePicker)'],
    ["// import { message } from '@tauri-apps/plugin-dialog';", 0, 'commented-out banned import'],
    ["/* import { ask } from '@tauri-apps/plugin-dialog'; */", 0, 'block-commented banned import'],
    ["import { open as o } from '@tauri-apps/plugin-dialog';", 1, 'native picker outside filePicker.ts'],
    ["import { open as o } from '@tauri-apps/plugin-dialog';", 0, 'native picker inside filePicker.ts', FILE_PICKER],
    ["import type { DialogFilter } from '@tauri-apps/plugin-dialog';", 0, 'type-only import'],
    ["const { open, ask } = await import('@tauri-apps/plugin-dialog');", 2, 'banned dynamic import (also bypasses filePicker)'],
    ["const { open, save } = await import('@tauri-apps/plugin-dialog');", 1, 'dynamic native picker outside filePicker.ts'],
    ["const dlg = await import('@tauri-apps/plugin-dialog');", 0, 'dynamic native picker inside filePicker.ts', FILE_PICKER],
    ["const { open } = await import('../lib/filePicker');", 0, 'the approved picker'],
    ["// const { ask } = await import('@tauri-apps/plugin-dialog');", 0, 'commented dynamic import'],
    ['await appConfirm("really?");', 0, 'the approved call'],
  ];
  let failed = 0;
  for (const [src, want, label, file = join('src', 'x.tsx')] of cases) {
    const views = {
      code: stripNonCode(src, true),
      withStrings: stripNonCode(src, false),
    };
    let got = 0;
    for (const rule of RULES) {
      if (ruleAllows(rule, file)) continue;
      rule.re.lastIndex = 0;
      got += (views[rule.view].match(rule.re) || []).length;
    }
    const ok = got === want;
    if (!ok) failed++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label} (expected ${want}, got ${got})`);
  }
  if (failed > 0) {
    console.error(`\ncheck-dialogs self-test: ${failed} case(s) failed`);
    process.exit(1);
  }
  console.log('\ncheck-dialogs self-test: all cases pass');
}

if (process.argv.includes('--self-test')) selfTest();
else check();
