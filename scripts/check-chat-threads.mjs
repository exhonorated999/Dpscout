/**
 * check-chat-threads — executes `src/lib/chatThreads.ts` against fixtures
 * shaped like real warrant returns.
 *
 * WHY THIS EXISTS
 * ---------------
 * This module decides which messages belong to the same conversation and
 * which side of it each message sits on. Both failure modes are silent and
 * plausible-looking:
 *
 *   - A wrong thread key splits one conversation into two half-conversations,
 *     each of which renders as a tidy monologue. That is exactly what shipped:
 *     Meta leaves `recipient` empty on 1:1 threads, the key fell through to
 *     the author, and every Meta chat appeared one-sided.
 *   - A wrong owner marks the suspect's words as the victim's, or vice versa,
 *     with no visible error anywhere.
 *
 * Neither shows up in a typecheck and neither looks wrong on screen unless you
 * already know the answer. Hence fixtures with known answers.
 *
 * Usage:  node scripts/check-chat-threads.mjs
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const SELF = fileURLToPath(import.meta.url);

let fails = 0;
const ok = (cond, label, extra = '') => {
  if (!cond) fails++;
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${label}${extra ? ' :: ' + extra : ''}`);
};

/* ── fixtures ─────────────────────────────────────────────────────────── */

// Meta: a 1:1 Messenger thread. `recipient` is null and `participants` is
// empty — exactly what the observed preservation return looked like — but
// every row carries the same threadId. Authors are decorated with the
// Facebook id.
const META = [
  { id: 'm1', section: 'unified_messages', author: 'ETest UserOne (Facebook: 100001)',
    recipient: null, timestamp: '2024-01-09 19:08:22 UTC',
    rawFields: { threadId: '29202235737044', participants: [] } },
  { id: 'm2', section: 'unified_messages', author: 'ETest UserTwo (Facebook: 59791010034992)',
    recipient: null, timestamp: '2024-01-09 19:25:07 UTC',
    rawFields: { threadId: '29202235737044', participants: [] } },
  { id: 'm3', section: 'unified_messages', author: 'ETest UserOne (Facebook: 100001)',
    recipient: null, timestamp: '2024-01-09 22:38:28 UTC',
    rawFields: { threadId: '29202235737044', participants: [] } },
  // A second conversation, so the owner is inferable.
  { id: 'm4', section: 'unified_messages', author: 'ETest UserOne (Facebook: 100001)',
    recipient: null, timestamp: '2024-01-10 08:00:00 UTC',
    rawFields: { threadId: '88888888', participants: [] } },
  { id: 'm5', section: 'unified_messages', author: 'Third Party (Facebook: 222)',
    recipient: null, timestamp: '2024-01-10 08:05:00 UTC',
    rawFields: { threadId: '88888888', participants: [] } },
];

// Snapchat: no threadId, but `recipient` already holds the canonical other
// party, and timestamps are in a format that does NOT sort as a string.
const SNAP = [
  { id: 's1', section: 'unified_messages', author: 'icecube086', recipient: 'ariana_covtez',
    timestamp: 'Sun Oct 09 04:35:05 UTC 2022', rawFields: { conversationId: 'c-aaa' } },
  { id: 's2', section: 'unified_messages', author: 'ariana_covtez', recipient: 'icecube086',
    timestamp: 'Sun Oct 09 04:37:46 UTC 2022', rawFields: { conversationId: 'c-aaa' } },
  { id: 's3', section: 'unified_messages', author: 'icecube086', recipient: 'ariana_covtez',
    timestamp: 'Sun Oct 09 04:40:06 UTC 2022', rawFields: { conversationId: 'c-aaa' } },
  { id: 's4', section: 'unified_messages', author: 'icecube086', recipient: 'banana',
    timestamp: 'Mon Oct 10 11:00:00 UTC 2022', rawFields: { conversationId: 'c-bbb' } },
  { id: 's5', section: 'unified_messages', author: 'banana', recipient: 'icecube086',
    timestamp: 'Mon Oct 10 11:01:00 UTC 2022', rawFields: { conversationId: 'c-bbb' } },
  // Non-message rows carrying the owner as author must not vote.
  { id: 'b1', section: 'bio', author: 'icecube086', recipient: null,
    timestamp: null, rawFields: {} },
];

// No conversation id anywhere: the pre-existing fallback path.
const BARE = [
  { id: 'x1', section: 'unified_messages', author: 'alice', recipient: 'bob',
    timestamp: '2024-03-01 10:00:00 UTC', rawFields: {} },
  { id: 'x2', section: 'unified_messages', author: 'bob', recipient: 'alice',
    timestamp: '2024-03-01 10:01:00 UTC', rawFields: {} },
  { id: 'x3', section: 'unified_messages', author: 'alice', recipient: 'carol',
    timestamp: '2024-03-02 10:00:00 UTC', rawFields: {} },
  { id: 'x4', section: 'unified_messages', author: 'carol', recipient: 'alice',
    timestamp: '2024-03-02 10:02:00 UTC', rawFields: {} },
];

async function run(mod) {
  const {
    sameParty, normParty, explicitThreadId, partiesOf,
    inferOwner, matchOwner, buildThreads, parseTs,
  } = mod;

  /* ── identity matching ───────────────────────────────────────────── */
  ok(sameParty('alice', 'Alice'), 'identity: case-insensitive');
  ok(sameParty('ETest UserTwo (Facebook: 59791010034992)', '59791010034992'),
     'identity: bare id matches a decorated name');
  ok(sameParty('ETest UserTwo (Facebook: 59791010034992)', 'ETest UserTwo'),
     'identity: undecorated name matches a decorated one');
  ok(!sameParty('alice', 'bob'), 'identity: different people do not match');
  ok(!sameParty('alice', ''), 'identity: empty never matches');
  ok(!sameParty(null, null), 'identity: null never matches');
  // Two different people at the same provider must stay distinct.
  ok(!sameParty('Jane (Facebook: 111)', 'Jane (Facebook: 222)'),
     'identity: same display name, different id, stays distinct');
  ok(normParty('  ETest UserOne (Facebook: 100001) ') === 'etest userone',
     'normalise strips decoration and folds case', normParty('ETest UserOne (Facebook: 100001)'));

  /* ── the Meta bug ────────────────────────────────────────────────── */
  ok(explicitThreadId(META[0]) !== null, 'meta: threadId is found in rawFields');
  ok(partiesOf(META[0]).length === 1, 'meta: empty participants + null recipient = 1 party');

  const metaOwner = inferOwner(META);
  ok(metaOwner.inferred === 'ETest UserOne (Facebook: 100001)',
     'meta: owner inferred as the party in both threads', String(metaOwner.inferred));
  ok(metaOwner.reason === 'ubiquitous', 'meta: reason reported', metaOwner.reason);

  const metaThreads = buildThreads(META, metaOwner.inferred);
  ok(metaThreads.length === 2, 'meta: two conversations, NOT one per speaker',
     'got ' + metaThreads.length);
  const big = metaThreads.find((t) => t.list.length === 3);
  ok(!!big, 'meta: the 1:1 thread kept all three messages');
  ok(big && big.name === 'ETest UserTwo (Facebook: 59791010034992)',
     'meta: thread named after the other party, not the owner',
     big && big.name);
  // The whole point: both directions present in one thread.
  const authors = new Set(big.list.map((m) => m.author));
  ok(authors.size === 2, 'meta: both sides of the conversation are in one thread');

  /* ── owner matching against a recorded target account ────────────── */
  ok(matchOwner(metaOwner.candidates, '100001') === 'ETest UserOne (Facebook: 100001)',
     'target account given as a bare id resolves to the decorated name');
  ok(matchOwner(metaOwner.candidates, 'ETest UserOne') === 'ETest UserOne (Facebook: 100001)',
     'target account given as a plain name resolves too');
  ok(matchOwner(metaOwner.candidates, 'nobody@example.com') === null,
     'a target account that names no participant yields null');
  ok(matchOwner(metaOwner.candidates, null) === null, 'no target account yields null');

  /* ── Snapchat ────────────────────────────────────────────────────── */
  const snapOwner = inferOwner(SNAP);
  ok(snapOwner.inferred === 'icecube086', 'snap: owner inferred', String(snapOwner.inferred));
  const icecube = snapOwner.candidates.find((c) => c.name === 'icecube086');
  ok(icecube && icecube.threads === 2,
     'snap: bio row did not inflate the owner thread count',
     icecube && String(icecube.threads));

  const snapThreads = buildThreads(SNAP.filter((i) => i.section === 'unified_messages'), 'icecube086');
  ok(snapThreads.length === 2, 'snap: two threads', 'got ' + snapThreads.length);
  const ariana = snapThreads.find((t) => t.name === 'ariana_covtez');
  ok(!!ariana, 'snap: thread named after the counterparty');
  ok(ariana && ariana.list.length === 3, 'snap: both directions grouped together',
     ariana && String(ariana.list.length));
  ok(ariana && ariana.list.map((m) => m.id).join(',') === 's1,s2,s3',
     'snap: message order is parser order, untouched',
     ariana && ariana.list.map((m) => m.id).join(','));

  // Thread ordering must use real time, not string comparison: "Mon Oct 10"
  // sorts before "Sun Oct 09" alphabetically but is later in fact.
  ok(snapThreads[0].name === 'banana',
     'snap: most recent thread first despite unsortable timestamp strings',
     snapThreads[0].name);
  ok(parseTs('Sun Oct 09 04:35:05 UTC 2022') !== null, 'snap timestamp format parses');
  ok(parseTs('2024-01-09 19:08:22 UTC') !== null, 'meta timestamp format parses');
  ok(parseTs('not a date') === null, 'unparseable timestamp yields null, not NaN');
  ok(parseTs(null) === null, 'missing timestamp yields null');

  /* ── fallback path with no conversation id ───────────────────────── */
  const bareOwner = inferOwner(BARE);
  ok(bareOwner.inferred === 'alice', 'bare: owner inferred without any thread id',
     String(bareOwner.inferred));
  const bareThreads = buildThreads(BARE, 'alice');
  ok(bareThreads.length === 2, 'bare: grouped into two conversations',
     'got ' + bareThreads.length);
  const bobThread = bareThreads.find((t) => t.name === 'bob');
  ok(bobThread && bobThread.list.length === 2,
     'bare: both directions collapse to one thread when the owner is known');

  /* ── refusing to guess ───────────────────────────────────────────── */
  const single = inferOwner([
    { id: 'q1', section: 'unified_messages', author: 'alice', recipient: 'bob',
      timestamp: null, rawFields: { threadId: 't1' } },
    { id: 'q2', section: 'unified_messages', author: 'bob', recipient: 'alice',
      timestamp: null, rawFields: { threadId: 't1' } },
  ]);
  ok(single.inferred === null,
     'a single conversation does not say who owns it — no guess is made',
     String(single.inferred));
  ok(single.reason === 'no-clear-winner', 'refusal is reported', single.reason);
  ok(inferOwner([]).reason === 'no-data', 'empty input reports no-data');

  // With no owner, nothing is marked outgoing and the thread still holds
  // together on its id.
  const noOwner = buildThreads(META, null);
  ok(noOwner.length === 2, 'no owner: threads still group by id', 'got ' + noOwner.length);
  const b2 = noOwner.find((t) => t.list.length === 3);
  ok(b2 && b2.name.includes('UserOne') && b2.name.includes('UserTwo'),
     'no owner: thread names everyone rather than picking a side', b2 && b2.name);
}

/* ── driver ───────────────────────────────────────────────────────────── */
if (process.env.SCOUT_CHAT_BUNDLE) {
  await run(await import(pathToFileURL(process.env.SCOUT_CHAT_BUNDLE).href));
  if (fails > 0) {
    console.error(`\ncheck-chat-threads: ${fails} assertion(s) failed`);
    process.exit(1);
  }
  console.log('\ncheck-chat-threads: all assertions pass');
} else {
  let esbuild;
  try {
    esbuild = await import('esbuild');
  } catch {
    console.error(
      'check-chat-threads: esbuild not resolvable.\n' +
      '  It normally comes in with vite. If that changed, run:\n' +
      '    npm i -D esbuild'
    );
    process.exit(1);
  }
  const dir = mkdtempSync(join(tmpdir(), 'scout-chat-'));
  const out = join(dir, 'chatThreads.mjs');
  try {
    await esbuild.build({
      entryPoints: [join(ROOT, 'src', 'lib', 'chatThreads.ts')],
      bundle: true, format: 'esm', platform: 'neutral',
      outfile: out, logLevel: 'silent',
    });
    const r = spawnSync(process.execPath, [SELF], {
      stdio: 'inherit',
      env: { ...process.env, SCOUT_CHAT_BUNDLE: out },
    });
    process.exit(r.status === 0 ? 0 : 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
