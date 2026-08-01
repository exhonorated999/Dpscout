// Lightweight telemetry helper. Fire-and-forget: never throws, never
// blocks UI. Server-side allow-list keeps untrusted event names from
// landing in the database, but we mirror the list here so a typo in
// a component fails loudly in the dev console.
import { invoke } from "@tauri-apps/api/core";

export type TelemetryEvent =
  | "warrant_triage_opened"
  | "hash_scan_run"
  | "intrusion_scan_run"
  | "ios_triage_opened"
  | "android_triage_opened"
  | "deleted_media_scan_run";

const ALLOWED = new Set<TelemetryEvent>([
  "warrant_triage_opened",
  "hash_scan_run",
  "intrusion_scan_run",
  "ios_triage_opened",
  "android_triage_opened",
  "deleted_media_scan_run",
]);

export function trackEvent(name: TelemetryEvent): void {
  if (!ALLOWED.has(name)) {
    console.warn("[telemetry] unknown event:", name);
    return;
  }
  // Fire and forget — failures are swallowed; the Rust side is the
  // source of truth and persists to disk on every call.
  invoke("telemetry_track_event", { eventName: name }).catch((err) => {
    console.debug("[telemetry] track failed (non-fatal):", err);
  });
}
