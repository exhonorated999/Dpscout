/**
 * check-dialog-runtime — executes the `src/lib/appDialog.ts` queue against a
 * fake `window` in plain Node.
 *
 * WHY THIS EXISTS
 * ---------------
 * `tsc` proves the dialog queue compiles.  It cannot prove the two promises
 * this module makes to the rest of the app, both of which are invisible until
 * something has already gone wrong in front of a user:
 *
 *   1. No message is ever swallowed.  If React never mounts — early-boot
 *      crash, dead component tree — queued messages must still surface, via
 *      the original `window.alert` that was captured before patching.
 *   2. An unanswerable confirm resolves FALSE.  Callers gate destructive work
 *      on `await appConfirm(...)`.  Silence has to mean "don't".
 *
 * Rule 2 is the one worth a test file.  Getting it backwards deletes a user's
 * evidence, and no typecheck or manual click-through would ever catch it,
 * because the only way to reach that branch is to break the UI first.
 *
 * The module keeps state at module scope (the queue, the patch guard), so the
 * two scenarios cannot share a process.  This script bundles the TS once and
 * then re-spawns itself per scenario.
 *
 * Usage:  node scripts/check-dialog-runtime.mjs
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const SELF = fileURLToPath(import.meta.url);

/* ── tiny assert helper, shared by both scenarios ─────────────────────── */
let fails = 0;
const ok = (cond, label, extra = '') => {
  if (!cond) fails++;
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${label}${extra ? ' :: ' + extra : ''}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Stand in for a browser global object, and capture native alert calls. */
function fakeWindow() {
  const nativeCalls = [];
  globalThis.window = globalThis;
  globalThis.alert = (m) => nativeCalls.push(String(m));
  return nativeCalls;
}

/* ── scenario 1: a host is mounted ────────────────────────────────────── */
async function hostScenario(bundle) {
  const nativeCalls = fakeWindow();
  const {
    appAlert, appConfirm, subscribeDialogs, getDialogSnapshot,
    resolveTopDialog, inferTone,
  } = await import(bundle);

  let renders = 0;
  subscribeDialogs(() => { renders++; });

  // A bare `alert(...)` — the form used at ~87 existing call sites — must be
  // picked up without those sites being edited.
  alert('Export failed: disk full');
  let s = getDialogSnapshot();
  ok(s !== null, 'bare alert() enqueued an entry');
  ok(s.message === 'Export failed: disk full', 'message preserved', s && s.message);
  ok(s.kind === 'alert', 'kind is alert', s && s.kind);
  ok(s.tone === 'error', 'error tone inferred from "failed"', s && s.tone);
  ok(nativeCalls.length === 0, 'native alert unused while a host is mounted');

  // useSyncExternalStore compares snapshots with Object.is and will loop
  // forever if a fresh object is handed back on every read.
  ok(getDialogSnapshot() === s, 'snapshot reference stable across reads');

  // A native alert in a loop was survivable because it blocked. A queue is
  // not: 400 failing files must not mean 400 modals.
  const p1 = appAlert('Export failed: disk full');
  const p2 = appAlert('Export failed: disk full');
  s = getDialogSnapshot();
  ok(s.count === 3, 'identical alerts collapse into one entry', 'count=' + s.count);

  let settled = 0;
  p1.then(() => settled++);
  p2.then(() => settled++);
  resolveTopDialog(s.id, true);
  await sleep(10);
  ok(settled === 2, 'every collapsed waiter resolves', 'settled=' + settled);
  ok(getDialogSnapshot() === null, 'queue empties after resolve');

  appAlert('Saved 12 files');
  s = getDialogSnapshot();
  ok(s.tone === 'info', 'success text is not styled as an error', s.tone);
  resolveTopDialog(s.id, true);

  // Each confirm is a separate decision, so they are never collapsed.
  const c1 = appConfirm('Delete this case?');
  const c2 = appConfirm('Delete this case?');
  s = getDialogSnapshot();
  ok(s.kind === 'confirm', 'confirm kind', s.kind);
  resolveTopDialog(s.id, true);
  s = getDialogSnapshot();
  ok(s !== null, 'a second identical confirm is NOT collapsed');
  resolveTopDialog(s.id, false);
  ok((await c1) === true, 'first confirm resolved true');
  ok((await c2) === false, 'second confirm resolved false');

  ok(inferTone('Could not open file') === 'error', 'tone: "could not"');
  ok(inferTone("Couldn't reach server") === 'error', 'tone: "couldn\'t"');
  ok(inferTone('\u2713 Scan complete') === 'info', 'tone: check mark + complete');
  ok(inferTone('Scan complete: 3 errors found') === 'info',
     'tone: a summary mentioning errors is still a success');

  ok(renders > 0, 'host notified of changes', 'renders=' + renders);
  ok(nativeCalls.length === 0, 'native alert never used in this scenario');
}

/* ── scenario 2: no host, ever ────────────────────────────────────────── */
async function fallbackScenario(bundle) {
  const nativeCalls = fakeWindow();
  const { appAlert, appConfirm, getDialogSnapshot } = await import(bundle);

  const alertDone = appAlert('Import failed: bad zip');
  const confirmAnswer = appConfirm('Overwrite the existing export?');

  ok(nativeCalls.length === 0, 'nothing drains immediately (host gets a grace period)');
  ok(getDialogSnapshot() !== null, 'entry queued while waiting for a host');

  await sleep(3200); // FALLBACK_MS is 2500

  ok(nativeCalls.length === 2, 'both messages reached the native alert',
     'got=' + nativeCalls.length);
  ok(nativeCalls.some((m) => m.includes('Import failed: bad zip')),
     'alert text survived the fallback');
  ok(nativeCalls.some((m) => m.includes('Overwrite the existing export?')),
     'confirm text survived the fallback');

  let alertSettled = false;
  alertDone.then(() => { alertSettled = true; });
  await sleep(10);
  ok(alertSettled, 'appAlert promise settles after draining (no hung await)');

  // The contract that matters.
  const answer = await confirmAnswer;
  ok(answer === false, 'an unanswerable confirm resolves FALSE, never true',
     String(answer));
  ok(getDialogSnapshot() === null, 'queue drained empty');
}

/* ── driver ───────────────────────────────────────────────────────────── */
const SCENARIOS = { host: hostScenario, fallback: fallbackScenario };

async function runChild(name) {
  const bundle = process.env.SCOUT_DIALOG_BUNDLE;
  if (!bundle) throw new Error('SCOUT_DIALOG_BUNDLE not set');
  // A bare `C:\...` path is not a valid import specifier on Windows.
  await SCENARIOS[name](pathToFileURL(bundle).href);
  if (fails > 0) {
    console.error(`\n${name} scenario: ${fails} assertion(s) failed`);
    process.exit(1);
  }
  console.log(`\n${name} scenario: all assertions pass`);
}

async function runParent() {
  let esbuild;
  try {
    esbuild = await import('esbuild');
  } catch {
    console.error(
      'check-dialog-runtime: esbuild not resolvable.\n' +
      '  It normally comes in with vite. If that changed, run:\n' +
      '    npm i -D esbuild'
    );
    process.exit(1);
  }

  const dir = mkdtempSync(join(tmpdir(), 'scout-dialog-'));
  const out = join(dir, 'appDialog.mjs');
  try {
    await esbuild.build({
      entryPoints: [join(ROOT, 'src', 'lib', 'appDialog.ts')],
      bundle: true,
      format: 'esm',
      platform: 'neutral',
      outfile: out,
      logLevel: 'silent',
    });
    writeFileSync(join(dir, 'package.json'), '{"type":"module"}');

    let failedScenarios = 0;
    for (const name of Object.keys(SCENARIOS)) {
      console.log(`\n── ${name} ──`);
      const r = spawnSync(process.execPath, [SELF, '--scenario', name], {
        stdio: 'inherit',
        env: { ...process.env, SCOUT_DIALOG_BUNDLE: out },
      });
      if (r.status !== 0) failedScenarios++;
    }

    if (failedScenarios > 0) {
      console.error(`\ncheck-dialog-runtime: ${failedScenarios} scenario(s) failed`);
      process.exit(1);
    }
    console.log('\ncheck-dialog-runtime: all scenarios pass');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const idx = process.argv.indexOf('--scenario');
if (idx !== -1) await runChild(process.argv[idx + 1]);
else await runParent();
