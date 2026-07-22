/**
 * Batching, self-healing thumbnail loader.
 *
 * WHY: rendering hundreds of cached thumbnails per page one-`invoke`-at-a-time
 * both saturates WebView2's asset:// pool (blank tiles) AND pays per-call IPC
 * overhead (slow fill). Instead we:
 *   1. Coalesce many tile requests into a single `get_thumbnails_batch` call.
 *   2. Inline each thumbnail as a base64 data URL (no connection-pool limit).
 *   3. Self-heal: if a tile's cached thumbnail is missing (e.g. %TEMP% was
 *      cleared, or generation failed during the scan), the backend regenerates
 *      it from the original source file — so tiles that used to stay blank now
 *      render.
 *
 * Results are cached in-memory so scrolling back to a tile is free.
 */

import { invoke } from '@tauri-apps/api/core';

export interface ThumbRequest {
  /** Unique, stable id for the tile (use the media filePath). */
  key: string;
  /** Existing cached thumbnail path, if known (may be empty/stale). */
  thumbPath?: string;
  /** Original media file — lets the backend regenerate a missing thumbnail. */
  sourcePath?: string;
  /** "image" | "video" — required for source regeneration. */
  mediaType?: 'image' | 'video';
}

interface BatchResp {
  key: string;
  dataUrl: string | null;
  thumbPath: string | null;
}

// How many tiles to resolve per IPC round-trip, and how long to wait to let a
// burst of requests coalesce. 24 keeps each payload modest while collapsing
// ~250 tiles into ~10 calls.
const BATCH_SIZE = 24;
const FLUSH_DELAY_MS = 16;

const cache = new Map<string, string>();                 // key -> data URL (hits only)
const inflight = new Map<string, Promise<string | null>>();

interface Deferred {
  req: ThumbRequest;
  resolve: (v: string | null) => void;
}
let queue: Deferred[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleFlush(): void {
  if (flushTimer != null) return;
  flushTimer = setTimeout(flush, FLUSH_DELAY_MS);
}

async function flush(): Promise<void> {
  flushTimer = null;
  if (queue.length === 0) return;

  const batch = queue.splice(0, BATCH_SIZE);
  const items = batch.map((d) => ({
    key: d.req.key,
    thumbPath: d.req.thumbPath || null,
    sourcePath: d.req.sourcePath || null,
    mediaType: d.req.mediaType || null,
  }));

  try {
    const resp = await invoke<BatchResp[]>('get_thumbnails_batch', { items });
    const byKey = new Map(resp.map((r) => [r.key, r]));
    for (const d of batch) {
      const url = byKey.get(d.req.key)?.dataUrl ?? null;
      if (url) cache.set(d.req.key, url);
      inflight.delete(d.req.key);
      d.resolve(url);
    }
  } catch {
    // Whole-batch failure (e.g. command missing on a stale binary): resolve
    // null so callers fall back gracefully instead of hanging on a spinner.
    for (const d of batch) {
      inflight.delete(d.req.key);
      d.resolve(null);
    }
  }

  // Drain the rest.
  if (queue.length > 0) scheduleFlush();
}

/**
 * Resolve a tile's thumbnail as a base64 data URL (or null if none could be
 * produced). Deduped by key and cached. Requests are batched automatically.
 */
export function loadThumbnail(req: ThumbRequest): Promise<string | null> {
  const cached = cache.get(req.key);
  if (cached) return Promise.resolve(cached);

  const existing = inflight.get(req.key);
  if (existing) return existing;

  const p = new Promise<string | null>((resolve) => {
    queue.push({ req, resolve });
  });
  inflight.set(req.key, p);
  scheduleFlush();
  return p;
}

/** Clear the in-memory cache (e.g. after the on-disk thumbnail cache is wiped). */
export function clearThumbnailDataUrlCache(): void {
  cache.clear();
  inflight.clear();
  queue = [];
  if (flushTimer != null) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
}
