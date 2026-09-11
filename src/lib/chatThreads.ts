/**
 * chatThreads — turning a flat list of parsed messages back into
 * conversations.
 *
 * This is pure logic, deliberately kept out of the React component, because
 * getting it wrong does not look like a bug: it looks like evidence. A wrong
 * thread key hides half a conversation; a wrong owner puts one person's words
 * in another person's mouth. Both render perfectly happily. So it lives here,
 * where `scripts/check-chat-threads.mjs` can execute it.
 *
 * Three rules, each of which was learned from a real return:
 *
 *  1. The provider's own conversation id wins.  Meta leaves `recipient` empty
 *     on a 1:1 thread, so grouping by participant strings put each speaker in
 *     a separate thread and every conversation read as a monologue. The
 *     `threadId` was in `raw_fields` the whole time.
 *
 *  2. Identity comparison must be loose.  Providers decorate names
 *     ("ETest UserTwo (Facebook: 59791010034992)") while the case's target
 *     account is recorded bare. An exact compare misses, and a missed owner
 *     means nothing is ever marked outgoing.
 *
 *  3. An inferred owner is a guess and has to be labelled as one.  The
 *     account holder is the participant who appears in the most distinct
 *     conversations — counterparties appear in one. That is a strong signal,
 *     not a certainty, so `inferOwner` reports *why* it decided and refuses
 *     to guess when the data does not separate anyone.
 */

/** Minimal shape this module needs; `WarrantItem` satisfies it structurally. */
export interface ChatMessage {
  id: string;
  section?: string;
  author?: string | null;
  recipient?: string | null;
  timestamp?: string | null;
  rawFields?: Record<string, any>;
}

export interface Thread<T> {
  /** Stable grouping key — the provider's id when there is one. */
  key: string;
  /** Human label: the other participants, or the raw id if we know nobody. */
  name: string;
  list: T[];
  /** Most recent parseable timestamp in the thread, or null. */
  last: number | null;
}

export interface OwnerCandidate {
  name: string;
  /** How many distinct conversations this participant appears in. */
  threads: number;
}

export interface OwnerInference {
  candidates: OwnerCandidate[];
  /** Best guess, or null when the data does not single anyone out. */
  inferred: string | null;
  reason: 'ubiquitous' | 'no-clear-winner' | 'no-data';
}

/** Trailing provider id decoration, e.g. "Jane Doe (Facebook: 123456789)". */
export const PARTY_ID_SUFFIX = /\s*\((?:[^():]*:)?\s*(\d{4,})\s*\)\s*$/;

/** Sentinel for "no owner" in the picker — cannot collide with a real name. */
export const NO_OWNER = '\u0000none';

export function partyId(s: string): string | null {
  const m = s.match(PARTY_ID_SUFFIX);
  return m ? m[1] : null;
}

/** Comparable form of a participant name: undecorated, trimmed, folded. */
export function normParty(s: string | null | undefined): string {
  if (!s) return '';
  return s.replace(PARTY_ID_SUFFIX, '').trim().toLowerCase();
}

/**
 * Loose identity match. Exact, then undecorated name, then the embedded
 * numeric id — a target account is often recorded as the bare id while the
 * export writes "Name (Service: id)".
 */
export function sameParty(
  a: string | null | undefined,
  b: string | null | undefined
): boolean {
  if (!a || !b) return false;
  const A = a.trim();
  const B = b.trim();
  if (!A || !B) return false;
  if (A.toLowerCase() === B.toLowerCase()) return true;

  const na = normParty(A);
  const nb = normParty(B);
  if (na && nb && na === nb) return true;

  // An id counts whether it is embedded in a decorated name or standing alone.
  const idA = partyId(A) || (/^\d{4,}$/.test(A) ? A : null);
  const idB = partyId(B) || (/^\d{4,}$/.test(B) ? B : null);
  if (idA && idB && idA === idB) return true;

  return false;
}

const THREAD_ID_KEYS = [
  'threadId', 'thread_id', 'conversationId', 'conversation_id',
  'chatId', 'chat_id', 'groupId', 'group_id',
];

/** The provider's own conversation id, when it gave us one. */
export function explicitThreadId(item: ChatMessage): string | null {
  const raw = item.rawFields || {};
  for (const k of THREAD_ID_KEYS) {
    const v = raw[k];
    if (typeof v === 'string' && v.trim()) return `${k}:${v.trim()}`;
    if (typeof v === 'number' && Number.isFinite(v)) return `${k}:${v}`;
  }
  return null;
}

/** Everyone named on a message, author first. */
export function partiesOf(item: ChatMessage): string[] {
  const out: string[] = [];
  if (item.author && item.author.trim()) out.push(item.author.trim());

  const ps = (item.rawFields || {}).participants;
  if (Array.isArray(ps)) {
    for (const p of ps) if (typeof p === 'string' && p.trim()) out.push(p.trim());
  }

  // Meta joins multiple recipients with ", ".
  if (item.recipient && item.recipient.trim()) {
    for (const r of item.recipient.split(',')) {
      const t = r.trim();
      if (t) out.push(t);
    }
  }
  return out;
}

/** Grouping key, falling back to the other party when there is no id. */
export function threadKey(item: ChatMessage, owner: string | null): string {
  const explicit = explicitThreadId(item);
  if (explicit) return explicit;
  const a = item.author || '';
  const r = item.recipient || '';
  const other = sameParty(a, owner) ? r : sameParty(r, owner) ? a : r || a;
  return `pair:${normParty(other) || 'unknown'}`;
}

/**
 * Best-effort epoch ms. Used only for display grouping and thread ordering —
 * never to reorder messages, which stay in parser order. Providers write
 * timestamps in incompatible formats ("Sun Oct 09 04:35:05 UTC 2022" vs
 * "2024-01-09 19:08:22 UTC"), and re-sorting evidence on a guessed parse is
 * not a risk worth taking for cosmetics.
 */
export function parseTs(s: string | null | undefined): number | null {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

export function dayKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * Work out which participant is the account holder.
 *
 * The holder is party to every conversation in their own export; each
 * counterparty is party to one. Requires a clear winner — at least two
 * conversations and strictly more than the runner-up — because a return
 * containing a single chat genuinely does not say who owns it, and a coin
 * flip there would mislabel every message in the case.
 */
export function inferOwner(items: ChatMessage[]): OwnerInference {
  const threadsByParty = new Map<string, Set<string>>();
  const seen = new Map<string, string>(); // normalised → first spelling

  for (const it of items) {
    // Only conversations vote. Other sections carry an `author` too
    // (Snapchat stamps the owner on bio and device records), and counting
    // those would hand the owner free "threads" nobody spoke in.
    if (it.section && it.section !== 'unified_messages') continue;
    const key = threadKey(it, null);
    for (const p of partiesOf(it)) {
      const n = normParty(p);
      if (!n) continue;
      if (!seen.has(n)) seen.set(n, p);
      let set = threadsByParty.get(n);
      if (!set) { set = new Set(); threadsByParty.set(n, set); }
      set.add(key);
    }
  }

  const candidates = Array.from(threadsByParty.entries())
    .map(([n, set]) => ({ name: seen.get(n) || n, threads: set.size }))
    .sort((a, b) => b.threads - a.threads || a.name.localeCompare(b.name));

  if (candidates.length === 0) {
    return { candidates, inferred: null, reason: 'no-data' };
  }
  if (
    candidates.length > 1 &&
    candidates[0].threads >= 2 &&
    candidates[0].threads > candidates[1].threads
  ) {
    return { candidates, inferred: candidates[0].name, reason: 'ubiquitous' };
  }
  return { candidates, inferred: null, reason: 'no-clear-winner' };
}

/** Pick the candidate that a case's recorded target account refers to. */
export function matchOwner(
  candidates: OwnerCandidate[],
  target: string | null | undefined
): string | null {
  if (!target) return null;
  const hit = candidates.find((c) => sameParty(c.name, target));
  return hit ? hit.name : null;
}

/**
 * Group messages into conversations. Message order within a thread is the
 * order they arrived in — parsers emit chronologically, and that is more
 * trustworthy than re-deriving order from mixed-format timestamps.
 */
export function buildThreads<T extends ChatMessage>(
  items: T[],
  owner: string | null
): Thread<T>[] {
  const map = new Map<string, T[]>();
  for (const it of items) {
    const key = threadKey(it, owner);
    let list = map.get(key);
    if (!list) { list = []; map.set(key, list); }
    list.push(it);
  }

  const arr: Thread<T>[] = Array.from(map.entries()).map(([key, list]) => {
    // Name the thread after whoever is not the owner. With no owner we show
    // everyone, which is honest and still readable.
    const counts = new Map<string, { label: string; n: number }>();
    for (const it of list) {
      for (const p of partiesOf(it)) {
        if (sameParty(p, owner)) continue;
        const n = normParty(p);
        if (!n) continue;
        const e = counts.get(n);
        if (e) e.n += 1;
        else counts.set(n, { label: p, n: 1 });
      }
    }
    const named = Array.from(counts.values()).sort(
      (a, b) => b.n - a.n || a.label.localeCompare(b.label)
    );
    const name =
      named.length === 0
        ? key.startsWith('pair:')
          ? 'Unknown'
          : key.slice(key.indexOf(':') + 1)
        : named.slice(0, 3).map((x) => x.label).join(', ') +
          (named.length > 3 ? ` +${named.length - 3}` : '');

    let last: number | null = null;
    for (const it of list) {
      const t = parseTs(it.timestamp);
      if (t !== null && (last === null || t > last)) last = t;
    }
    return { key, name, list, last };
  });

  // Most recent conversation first, like any chat client. Threads whose
  // timestamps we could not parse sort last, alphabetically.
  arr.sort((x, y) => {
    if (x.last !== null && y.last !== null) return y.last - x.last;
    if (x.last !== null) return -1;
    if (y.last !== null) return 1;
    return x.name.localeCompare(y.name);
  });
  return arr;
}
