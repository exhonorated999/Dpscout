// Host OS detection for the device picker and macOS-specific UI.
//
// The authoritative answer comes from the Rust `get_host_platform` command
// (std::env::consts::OS + the `portable` feature + Full Disk Access probe).
// `guessHostOs()` is a synchronous user-agent sniff used only for the first
// paint so the start screen doesn't flash the wrong computer card.
import { invoke } from '@tauri-apps/api/core';

export interface HostPlatform {
  /** `std::env::consts::OS`: "windows" | "macos" | "linux" */
  os: string;
  portable: boolean;
  /** macOS only: whether Scout can read TCC-protected folders (Safari, Desktop…). */
  fullDiskAccess: boolean;
  /** G9: true when the backend refuses all network egress (the macOS portable build). */
  offline: boolean;
}

/**
 * Dev-only Mac UI preview: `VITE_MAC_PREVIEW=true npm run dev` (see
 * `Launch-ScoutMacPreview.bat`) makes a Windows dev build present itself as a
 * Mac host with mocked drives and canned results, so the macOS UI can be
 * reviewed without a Mac. `import.meta.env.DEV` is statically `false` in
 * `vite build`, so this constant — and every branch it guards — is compiled
 * out of anything that ships.
 */
export const MAC_PREVIEW: boolean =
  import.meta.env.DEV && import.meta.env.VITE_MAC_PREVIEW === 'true';

export function guessHostOs(): 'macos' | 'windows' {
  if (import.meta.env.DEV && MAC_PREVIEW) return 'macos';
  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  const s = `${nav?.platform ?? ''} ${nav?.userAgent ?? ''}`;
  return /Mac/i.test(s) ? 'macos' : 'windows';
}

let cached: Promise<HostPlatform> | null = null;

export function getHostPlatform(refresh = false): Promise<HostPlatform> {
  if (import.meta.env.DEV && MAC_PREVIEW) {
    return Promise.resolve({ os: 'macos', portable: true, fullDiskAccess: false, offline: true });
  }
  if (!cached || refresh) {
    cached = invoke<HostPlatform>('get_host_platform').catch(() => ({
      os: guessHostOs(),
      portable: import.meta.env.VITE_PORTABLE === 'true',
      fullDiskAccess: false,
      offline: guessHostOs() === 'macos',
    }));
  }
  return cached;
}

/** True on a host where Scout must make no network calls (G9). */
export async function isOfflineHost(): Promise<boolean> {
  return (await getHostPlatform()).offline;
}

// MAC_PREVIEW stand-in for the backend's drain-on-read skipped-folder list.
let previewSkipped: string[] = [];
export function setPreviewSkippedProtected(paths: string[]): void {
  previewSkipped = [...paths];
}

/** Protected folders the last scan had to skip (drains the backend list). */
export async function takeSkippedProtectedPaths(): Promise<string[]> {
  if (import.meta.env.DEV && MAC_PREVIEW) {
    const p = previewSkipped;
    previewSkipped = [];
    return p;
  }
  try {
    return await invoke<string[]>('take_skipped_protected_paths');
  } catch {
    return [];
  }
}

// The backend list drains on read, so accumulate it here for the current scan.
let skippedThisScan: string[] = [];

/** Call at scan start: discard anything recorded by an earlier scan. */
export async function resetSkippedProtected(): Promise<void> {
  skippedThisScan = [];
  await takeSkippedProtectedPaths();
}

/** Pull newly skipped folders and return everything skipped this scan. */
export async function refreshSkippedProtected(): Promise<string[]> {
  for (const p of await takeSkippedProtectedPaths()) {
    if (!skippedThisScan.includes(p)) skippedThisScan.push(p);
  }
  return [...skippedThisScan];
}
