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
}

export function guessHostOs(): 'macos' | 'windows' {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  const s = `${nav?.platform ?? ''} ${nav?.userAgent ?? ''}`;
  return /Mac/i.test(s) ? 'macos' : 'windows';
}

let cached: Promise<HostPlatform> | null = null;

export function getHostPlatform(refresh = false): Promise<HostPlatform> {
  if (!cached || refresh) {
    cached = invoke<HostPlatform>('get_host_platform').catch(() => ({
      os: guessHostOs(),
      portable: import.meta.env.VITE_PORTABLE === 'true',
      fullDiskAccess: false,
    }));
  }
  return cached;
}

/** Protected folders the last scan had to skip (drains the backend list). */
export async function takeSkippedProtectedPaths(): Promise<string[]> {
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
