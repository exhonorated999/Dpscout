/**
 * WarrantTriageView — 3-pane interactive triage UI for an imported warrant case.
 *
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  TOP BAR — provider · target · imported · counts · "Export Report"  │
 *   ├──────────────┬─────────────────────────────────┬────────────────────┤
 *   │  SECTIONS    │  ITEM LIST (virtual scroll)     │  DETAIL PANEL      │
 *   │  BUCKETS     │  card-per-item, click→detail    │  raw fields, note, │
 *   │  + New       │                                 │  bucket, flag,     │
 *   │              │                                 │  attachments       │
 *   └──────────────┴─────────────────────────────────┴────────────────────┘
 *
 * All state changes go through the Rust commands defined in
 * `warrant::commands` so reload-from-disk is the source of truth.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ScanningIndicator } from "../ScanningIndicator";
import { LocationMapView, LocationOverviewMap } from "./LocationMapView";
import { trackEvent } from "../../lib/telemetry";
import "./WarrantTriageView.css";

// ─── Types (mirrors of Rust shapes) ─────────────────────────────────────

export interface Bucket {
  id: string;
  name: string;
  color: string;
  description?: string | null;
  seeded?: boolean;
}

export interface WarrantItem {
  id: string;
  section: string;
  sectionDisplay: string;
  timestamp?: string | null;
  author?: string | null;
  recipient?: string | null;
  bodyText?: string | null;
  summary?: string | null;
  rawFields: Record<string, any>;
  attachments: string[];
  bucket?: string | null;
  note?: string | null;
  isFlagged: boolean;
}

export interface WarrantCase {
  caseId: string;
  provider: string;
  providerDisplay: string;
  sourceFilename: string;
  importedAt: string;
  targetAccount?: string | null;
  dateRange?: string | null;
  generatedAtSource?: string | null;
  mediaRoot?: string | null;
}

export interface CaseDetail {
  case: WarrantCase;
  items: WarrantItem[];
  buckets: Bucket[];
}

// ─── Scan result types (mirror src-tauri/src/warrant/scan.rs) ───────────

export interface HashHit {
  filename: string;
  sha1: string;
  sizeBytes: number;
  listName?: string | null;
  category?: string | null;
  description?: string | null;
}

export interface HashScanResult {
  ranAt: string;
  filesScanned: number;
  filesTotal: number;
  durationMs: number;
  hits: HashHit[];
}

export interface KeywordHit {
  itemId: string;
  section: string;
  keyword: string;
  field: string;
  snippet: string;
}

export interface KeywordScanResult {
  ranAt: string;
  listsUsed: string[];
  keywordCount: number;
  itemsScanned: number;
  durationMs: number;
  hits: KeywordHit[];
}

export interface CaseScanResults {
  hashScan?: HashScanResult | null;
  keywordScan?: KeywordScanResult | null;
}

export interface KeywordListSummary {
  name: string;
  keywordCount: number;
}

export interface HashListSummary {
  name: string;
  source: string;
  hashCount: number;
}

interface WarrantTriageViewProps {
  caseId: string;
  onBack: () => void;
  onExport?: (caseId: string) => void;
  /** When set, the back button shows "← <name>" instead of "← Back". */
  parentInvestigationName?: string | null;
}

// ─── Component ──────────────────────────────────────────────────────────

const SECTION_LABELS: Record<string, string> = {
  unified_messages: "Messages",
  photos: "Photos",
  // Generic catalog (unrecognized-format fallback)
  media: "Media",
  documents: "Documents",
  manifest: "File Manifest",
  status_updates: "Status Updates",
  wallposts: "Wall Posts",
  posts_to_other_walls: "Posts to Others",
  shares: "Shares",
  ip_addresses: "IP Addresses",
  registration_ip: "Registration IP",
  about_me: "About",
  bio: "Bio",
  ncmec_reports: "NCMEC Reports",
  request_parameters: "Request Parameters",
  // Quest export sections
  friends: "Friends",
  social_connections: "Social",
  worlds_visited: "Worlds Visited",
  worlds_progress: "Worlds Progress",
  worlds_saved: "Worlds Saved",
  apps: "Apps",
  orders: "Orders",
  achievements: "Achievements",
  recently_viewed: "Recently Viewed",
  cloud_backups: "Cloud Backups",
  entitlements: "Entitlements",
  subscriptions: "Subscriptions",
  app_invites_sent: "Invites Sent",
  app_invites_recv: "Invites Received",
  gifts_sent: "Gifts Sent",
  group_chats: "Group Chats",
  events: "Events",
  watch_history: "Watch History",
  vr_sessions: "VR Sessions",
  profile_photos: "Profile Photos",
  notification_emails: "Email Notifications",
  payment_methods: "Payment Methods",
  device_info: "Device Info",
  environment: "Space Data",
  reviews: "Reviews",
  settings: "Settings",
  parental: "Parental",
  app_presence: "App Presence",
  location: "Location History",
  emotes: "Emotes",
  // Discord
  servers: "Servers",
  // Snapchat
  memories: "Memories",
  snap_history: "Snap History",
  call_logs: "Call Logs",
  ai_conversations: "My AI Chats",
  login_history: "Login History",
  videos: "Videos",
  // Google
  change_history: "Account Changes",
  emails: "Emails",
  drive_files: "Drive Files",
  // Yahoo
  account_action: "Account Actions",
  // Kik
  blocks: "Blocked Users",
  media_messages: "Media Messages",
  group_media: "Group Media",
  // X (Twitter)
  x_account: "Account",
  tweets: "Posts / Tweets",
  direct_messages: "Direct Messages",
  followers: "Followers",
  following: "Following",
  ip_audit: "IP / Login Audit",
  devices: "Devices",
  personalization: "Personalization",
  ad_data: "Ad Data",
  x_metadata: "Account Metadata",
  audio: "Audio",
};

const NEW_BUCKET_COLORS = [
  "#ef4444", "#f97316", "#eab308", "#22c55e",
  "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899",
];

export const WarrantTriageView: React.FC<WarrantTriageViewProps> = ({
  caseId,
  onBack,
  onExport,
  parentInvestigationName,
}) => {
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  // sectionFilter "overview" is the synthetic dashboard view (default landing).
  const [sectionFilter, setSectionFilter] = useState<string | null>("overview");
  const [bucketFilter, setBucketFilter] = useState<string | "unbucketed" | "flagged" | null>(null);
  const [search, setSearch] = useState("");

  // View mode for the center pane: list vs grid.  Null = auto (grid when
  // the current filter is image-heavy, list otherwise).
  const [viewMode, setViewMode] = useState<"list" | "grid" | null>(null);

  // Selection
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  // New-bucket form
  const [newBucketName, setNewBucketName] = useState("");
  const [newBucketColor, setNewBucketColor] = useState(NEW_BUCKET_COLORS[0]);

  // Report export busy indicator.  Snapchat warrants can have 80k+ items,
  // so the HTML build takes a while — give the user a friendly overlay
  // instead of leaving them wondering if the app froze.
  const [exporting, setExporting] = useState(false);
  const [exportPhase, setExportPhase] = useState<string>("");

  // ─── Scan state (ephemeral — in-memory until export) ──────────────────
  const [scanResults, setScanResults] = useState<CaseScanResults>({});
  const [keywordLists, setKeywordLists] = useState<KeywordListSummary[]>([]);
  const [selectedKwLists, setSelectedKwLists] = useState<Set<string>>(new Set());
  const [hashLists, setHashLists] = useState<HashListSummary[]>([]);
  const [selectedHashLists, setSelectedHashLists] = useState<Set<string>>(new Set());
  const [hashScanBusy, setHashScanBusy] = useState(false);
  const [kwScanBusy, setKwScanBusy] = useState(false);
  const [hashScanStart, setHashScanStart] = useState<Date | null>(null);
  const [kwScanStart, setKwScanStart] = useState<Date | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // ─── Load case ─────────────────────────────────────────────────────────

  const reload = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const d = await invoke<CaseDetail>("warrant_load_case", { caseId });
      setDetail(d);
      // Don't auto-select on overview; first click into a section will select.
    } catch (e: any) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    reload();
  }, [reload]);

  // Telemetry: fire once per case open. Triage view is the canonical
  // "user is using the warrant feature" signal for sales analytics.
  useEffect(() => {
    trackEvent("warrant_triage_opened");
    // Intentionally empty deps: we want one event per mount, not per
    // re-render. Re-mounting on a different caseId is a separate open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ─── Load keyword lists + cached scan results on mount ────────────────
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [kwLists, hLists, cached] = await Promise.all([
          invoke<KeywordListSummary[]>("warrant_list_keyword_lists"),
          invoke<HashListSummary[]>("warrant_list_hash_lists"),
          invoke<CaseScanResults>("warrant_get_scan_results", { caseId }),
        ]);
        if (cancelled) return;
        setKeywordLists(kwLists);
        setHashLists(hLists);
        setScanResults(cached || {});
        // Pre-select all lists by default — matches phone/PC scan UX.
        if (kwLists.length > 0) {
          setSelectedKwLists(new Set(kwLists.map((l) => l.name)));
        }
        if (hLists.length > 0) {
          setSelectedHashLists(new Set(hLists.map((l) => l.name)));
        }
      } catch (e) {
        // Non-fatal — scan is optional.
        // eslint-disable-next-line no-console
        console.warn("warrant scan init failed:", e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [caseId]);

  // ─── Scan handlers ─────────────────────────────────────────────────────
  const runHashScan = useCallback(async () => {
    setScanError(null);
    if (hashLists.length > 0 && selectedHashLists.size === 0) {
      setScanError("Select at least one hash list to run a scan.");
      return;
    }
    setHashScanBusy(true);
    setHashScanStart(new Date());
    try {
      // If everything is selected (or no picker), send null = all lists.
      const sendAll =
        hashLists.length === 0 || selectedHashLists.size === hashLists.length;
      const res = await invoke<HashScanResult>("warrant_run_hash_scan", {
        caseId,
        listNames: sendAll ? null : Array.from(selectedHashLists),
      });
      setScanResults((prev) => ({ ...prev, hashScan: res }));
    } catch (e: any) {
      setScanError(`Hash scan failed: ${e}`);
    } finally {
      setHashScanBusy(false);
      setHashScanStart(null);
    }
  }, [caseId, hashLists, selectedHashLists]);

  const runKeywordScan = useCallback(async () => {
    setScanError(null);
    if (selectedKwLists.size === 0) {
      setScanError("Select at least one keyword list to run a scan.");
      return;
    }
    setKwScanBusy(true);
    setKwScanStart(new Date());
    try {
      const res = await invoke<KeywordScanResult>("warrant_run_keyword_scan", {
        caseId,
        listNames: Array.from(selectedKwLists),
      });
      setScanResults((prev) => ({ ...prev, keywordScan: res }));
    } catch (e: any) {
      setScanError(`Keyword scan failed: ${e}`);
    } finally {
      setKwScanBusy(false);
      setKwScanStart(null);
    }
  }, [caseId, selectedKwLists]);

  const clearHashScan = useCallback(async () => {
    try {
      await invoke("warrant_clear_scan", { caseId, scanType: "hash" });
      setScanResults((prev) => ({ ...prev, hashScan: null }));
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn("clear hash scan failed:", e);
    }
  }, [caseId]);

  const clearKeywordScan = useCallback(async () => {
    try {
      await invoke("warrant_clear_scan", { caseId, scanType: "keyword" });
      setScanResults((prev) => ({ ...prev, keywordScan: null }));
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn("clear keyword scan failed:", e);
    }
  }, [caseId]);

  const toggleKwList = useCallback((name: string) => {
    setSelectedKwLists((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const toggleHashList = useCallback((name: string) => {
    setSelectedHashLists((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  // ─── Derived data ──────────────────────────────────────────────────────

  const itemsBySection = useMemo(() => {
    const m: Record<string, number> = {};
    if (!detail) return m;
    for (const it of detail.items) m[it.section] = (m[it.section] || 0) + 1;
    return m;
  }, [detail]);

  /** Lowercase-filename → first matching item ID. Used to click-through
   *  a hash hit to the corresponding Photos item. */
  const itemIdByFilename = useMemo(() => {
    const m = new Map<string, string>();
    if (!detail) return m;
    for (const it of detail.items) {
      for (const att of it.attachments || []) {
        const key = (att.split(/[\\/]/).pop() || att).toLowerCase();
        if (!m.has(key)) m.set(key, it.id);
      }
    }
    return m;
  }, [detail]);

  const itemsByBucket = useMemo(() => {
    const m: Record<string, number> = {};
    let unbucketed = 0;
    let flagged = 0;
    if (!detail) return { byBucket: m, unbucketed, flagged };
    for (const it of detail.items) {
      if (it.bucket) m[it.bucket] = (m[it.bucket] || 0) + 1;
      else unbucketed++;
      if (it.isFlagged) flagged++;
    }
    return { byBucket: m, unbucketed, flagged };
  }, [detail]);

  const filteredItems = useMemo(() => {
    if (!detail) return [];
    // The "overview" filter is a synthetic dashboard view — it doesn't
    // filter the items list at all (we render cards instead).  Return [] so
    // the center pane stays empty if anything tries to draw items in that
    // mode (it shouldn't — see the body switch below).
    if (sectionFilter === "overview") return [];
    const q = search.trim().toLowerCase();
    return detail.items.filter((it) => {
      if (sectionFilter && it.section !== sectionFilter) return false;
      if (bucketFilter === "unbucketed" && it.bucket) return false;
      if (bucketFilter === "flagged" && !it.isFlagged) return false;
      if (bucketFilter && bucketFilter !== "unbucketed" && bucketFilter !== "flagged") {
        if (it.bucket !== bucketFilter) return false;
      }
      if (q) {
        const hay = [
          it.summary, it.bodyText, it.author, it.recipient, it.note,
          ...Object.values(it.rawFields || {}).map((v) => (typeof v === "string" ? v : "")),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [detail, sectionFilter, bucketFilter, search]);

  const selectedItem = useMemo(
    () => filteredItems.find((i) => i.id === selectedItemId) ?? detail?.items.find((i) => i.id === selectedItemId) ?? null,
    [filteredItems, detail, selectedItemId]
  );

  // Auto-pick grid view when the current filter is image-heavy (photos
  // section, or >=60% of visible items have an image attachment).
  const autoViewMode: "list" | "grid" = useMemo(() => {
    if (filteredItems.length === 0) return "list";
    if (sectionFilter === "photos") return "grid";
    const withImages = filteredItems.filter((it) => {
      if (it.attachments.length === 0) return false;
      const ext = (it.attachments[0].split(".").pop() || "").toLowerCase();
      return ["jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff", "ico"].includes(ext);
    }).length;
    return withImages / filteredItems.length >= 0.6 ? "grid" : "list";
  }, [filteredItems, sectionFilter]);

  const effectiveViewMode: "list" | "grid" = viewMode ?? autoViewMode;

  // ─── Mutations ─────────────────────────────────────────────────────────

  const assignBucket = useCallback(
    async (itemId: string, bucketId: string | null) => {
      // Optimistic update — patch local state immediately, skip the
      // full-page reload spinner.  Rollback on error.
      let prevBucket: string | null | undefined;
      setDetail((d) => {
        if (!d) return d;
        return {
          ...d,
          items: d.items.map((it) => {
            if (it.id !== itemId) return it;
            prevBucket = it.bucket ?? null;
            return { ...it, bucket: bucketId };
          }),
        };
      });
      try {
        await invoke("warrant_assign_bucket", { caseId, itemId, bucketId });
      } catch (e: any) {
        // Rollback
        setDetail((d) =>
          d
            ? {
                ...d,
                items: d.items.map((it) =>
                  it.id === itemId ? { ...it, bucket: prevBucket ?? null } : it
                ),
              }
            : d
        );
        setError(String(e));
      }
    },
    [caseId]
  );

  const setNote = useCallback(
    async (itemId: string, note: string) => {
      try {
        await invoke("warrant_set_note", { caseId, itemId, note: note || null });
        // Optimistic local update — avoid a full reload while the user is typing
        setDetail((d) =>
          d
            ? {
                ...d,
                items: d.items.map((it) =>
                  it.id === itemId ? { ...it, note: note || null } : it
                ),
              }
            : d
        );
      } catch (e: any) {
        setError(String(e));
      }
    },
    [caseId]
  );

  const toggleFlag = useCallback(
    async (itemId: string, flagged: boolean) => {
      // Optimistic update — flip the flag locally so the row updates
      // instantly, no full-page spinner.  Rollback on error.
      setDetail((d) =>
        d
          ? {
              ...d,
              items: d.items.map((it) =>
                it.id === itemId ? { ...it, isFlagged: flagged } : it
              ),
            }
          : d
      );
      try {
        await invoke("warrant_set_flag", { caseId, itemId, flagged });
      } catch (e: any) {
        // Rollback
        setDetail((d) =>
          d
            ? {
                ...d,
                items: d.items.map((it) =>
                  it.id === itemId ? { ...it, isFlagged: !flagged } : it
                ),
              }
            : d
        );
        setError(String(e));
      }
    },
    [caseId]
  );

  /** Flag every item that's referenced by a list of attachment filenames.
   *  Used by the "Flag all hits" button on the Hash Scan card — every hit
   *  is a filename in linked_media, and (post-backfill) every linked_media
   *  file has a corresponding Photos item with that filename in its
   *  `attachments` array. */
  const flagItemsByFilenames = useCallback(
    async (filenames: string[]) => {
      if (!detail) return;
      const want = new Set(
        filenames.map((f) => (f.split(/[\\/]/).pop() || f).toLowerCase())
      );
      const itemIds = detail.items
        .filter((it) =>
          (it.attachments || []).some((a) => want.has(a.toLowerCase()))
        )
        .map((it) => it.id);
      if (itemIds.length === 0) return;
      const idSet = new Set(itemIds);
      // Optimistic local update — flip flag immediately, no full reload.
      setDetail((d) =>
        d
          ? {
              ...d,
              items: d.items.map((it) =>
                idSet.has(it.id) ? { ...it, isFlagged: true } : it
              ),
            }
          : d
      );
      try {
        await Promise.all(
          itemIds.map((id) =>
            invoke("warrant_set_flag", { caseId, itemId: id, flagged: true })
          )
        );
      } catch (e: any) {
        setError(String(e));
      }
    },
    [caseId, detail]
  );

  /** Bulk flag-by-item-id, for the keyword scan's "Flag all hits" button. */
  const flagItemsByIds = useCallback(
    async (itemIds: string[]) => {
      const unique = Array.from(new Set(itemIds));
      if (unique.length === 0) return;
      const idSet = new Set(unique);
      // Optimistic local update — flip flag immediately, no full reload.
      setDetail((d) =>
        d
          ? {
              ...d,
              items: d.items.map((it) =>
                idSet.has(it.id) ? { ...it, isFlagged: true } : it
              ),
            }
          : d
      );
      try {
        await Promise.all(
          unique.map((id) =>
            invoke("warrant_set_flag", { caseId, itemId: id, flagged: true })
          )
        );
      } catch (e: any) {
        setError(String(e));
      }
    },
    [caseId]
  );

  const createBucket = useCallback(async () => {
    const name = newBucketName.trim();
    if (!name) return;
    try {
      await invoke<Bucket>("warrant_create_bucket", {
        caseId,
        name,
        color: newBucketColor,
        description: null,
      });
      setNewBucketName("");
      await reload();
    } catch (e: any) {
      setError(String(e));
    }
  }, [caseId, newBucketName, newBucketColor, reload]);

  const deleteBucket = useCallback(
    async (bucketId: string) => {
      const b = detail?.buckets.find((x) => x.id === bucketId);
      if (!b) return;
      if (!window.confirm(`Delete bucket "${b.name}"? Items assigned to it will become unbucketed.`)) {
        return;
      }
      try {
        await invoke("warrant_delete_bucket", { caseId, bucketId });
        if (bucketFilter === bucketId) setBucketFilter(null);
        await reload();
      } catch (e: any) {
        setError(String(e));
      }
    },
    [caseId, bucketFilter, detail, reload]
  );

  const openMedia = useCallback(
    async (filename: string) => {
      try {
        await invoke("warrant_open_media", { caseId, filename });
      } catch (e: any) {
        setError(String(e));
      }
    },
    [caseId]
  );

  // ─── Render ────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="warrant-triage-view loading">
        <div className="wt-loading-box">
          <div className="wt-loading-title">Loading case</div>
          <div className="wt-loading-bar">
            <div className="wt-loading-bar-fill" />
          </div>
          <div className="wt-loading-hint">
            Reading parsed warrant data from disk…
          </div>
        </div>
      </div>
    );
  }

  if (error && !detail) {
    return (
      <div className="warrant-triage-view error">
        <div className="error-box">
          <h2>Could not load case</h2>
          <pre>{error}</pre>
          <button onClick={onBack}>Back</button>
        </div>
      </div>
    );
  }

  if (!detail) return null;

  const sections = Object.keys(itemsBySection).sort(
    (a, b) => itemsBySection[b] - itemsBySection[a]
  );

  return (
    <div className="warrant-triage-view">
      {exporting && (
        <div className="wt-export-overlay" role="dialog" aria-label="Exporting report">
          <div className="wt-export-card">
            <div className="wt-export-pulse">
              <div className="wt-export-pulse-ring" />
              <div className="wt-export-pulse-ring r2" />
              <div className="wt-export-pulse-core">📄</div>
            </div>
            <h3>Building report</h3>
            <p>{exportPhase || "Preparing…"}</p>
            <p className="wt-export-hint">
              Scout copies media, builds thumbnails, then writes a self-contained
              HTML viewer. Large warrant returns (50k+ items) can take a couple
              minutes — please don't close the app.
            </p>
          </div>
        </div>
      )}
      {/* ─── Top bar ─── */}
      <header className="wt-topbar">
        <button
          className="wt-back"
          onClick={onBack}
          title={parentInvestigationName ? "Back to investigation" : "Back to investigations"}
        >
          ← {parentInvestigationName || "Investigations"}
        </button>
        <div className="wt-case-meta">
          <div className="wt-provider-pill">{detail.case.providerDisplay}</div>
          {detail.case.targetAccount && (
            <div className="wt-target">Target: <strong>{detail.case.targetAccount}</strong></div>
          )}
          {detail.case.dateRange && <div className="wt-daterange">{detail.case.dateRange}</div>}
          <div className="wt-source" title={detail.case.sourceFilename}>
            📦 {detail.case.sourceFilename}
          </div>
        </div>
        <div className="wt-counts">
          <span><strong>{detail.items.length}</strong> items</span>
          <span>· <strong>{itemsByBucket.flagged}</strong> flagged</span>
          <span>
            · <strong>{detail.items.length - itemsByBucket.unbucketed}</strong> bucketed
          </span>
        </div>
        <button
          className="wt-export"
          onClick={async () => {
            if (!onExport || exporting) return;
            setExporting(true);
            setExportPhase("Waiting for destination folder…");
            // Yield once so the overlay paints before the OS dialog
            // (otherwise it lags behind the modal).
            await new Promise((r) => setTimeout(r, 0));
            try {
              setExportPhase(
                `Building report (${detail.items.length.toLocaleString()} items)… ` +
                  `this can take a minute for large warrant returns.`
              );
              await onExport(caseId);
            } catch (e) {
              // Errors are surfaced by the handler itself (alert).
              console.warn("[warrant] export error:", e);
            } finally {
              setExporting(false);
              setExportPhase("");
            }
          }}
          title="Export interactive HTML report (Step 5)"
          disabled={!onExport || exporting}
        >
          {exporting ? "Exporting…" : "Export Report"}
        </button>
      </header>

      {error && (
        <div className="wt-error-banner">
          {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      <div className={`wt-body ${sectionFilter === "overview" ? "overview-mode" : ""}`}>
        {/* ─── Left pane: filters ─── */}
        <aside className="wt-sidebar">
          <div className="wt-sidebar-section">
            <h3>Search</h3>
            <input
              className="wt-search"
              placeholder="Search items…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="wt-sidebar-section">
            <h3>Sections</h3>
            <ul className="wt-filter-list">
              <li
                className={`wt-filter-row ${sectionFilter === "overview" ? "active" : ""}`}
                onClick={() => setSectionFilter("overview")}
              >
                <span>📊 Overview</span>
              </li>
              <li
                className={`wt-filter-row ${sectionFilter === null ? "active" : ""}`}
                onClick={() => setSectionFilter(null)}
              >
                <span>All sections</span>
                <span className="count">{detail.items.length}</span>
              </li>
              {sections.map((s) => (
                <li
                  key={s}
                  className={`wt-filter-row ${sectionFilter === s ? "active" : ""}`}
                  onClick={() => setSectionFilter((prev) => (prev === s ? null : s))}
                >
                  <span>{SECTION_LABELS[s] || s}</span>
                  <span className="count">{itemsBySection[s]}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="wt-sidebar-section">
            <h3>Triage</h3>
            <ul className="wt-filter-list">
              <li
                className={`wt-filter-row ${bucketFilter === "flagged" ? "active" : ""}`}
                onClick={() => setBucketFilter((p) => (p === "flagged" ? null : "flagged"))}
              >
                <span>🚩 Flagged</span>
                <span className="count">{itemsByBucket.flagged}</span>
              </li>
              <li
                className={`wt-filter-row ${bucketFilter === "unbucketed" ? "active" : ""}`}
                onClick={() => setBucketFilter((p) => (p === "unbucketed" ? null : "unbucketed"))}
              >
                <span>Unbucketed</span>
                <span className="count">{itemsByBucket.unbucketed}</span>
              </li>
            </ul>
          </div>

          <div className="wt-sidebar-section">
            <h3>
              Buckets
              <span
                className="wt-help-icon"
                title={
                  "Buckets are evidence categories you assign to each item " +
                  "as you review the warrant return.\n\n" +
                  "Example workflow:\n" +
                  "• See a photo that's clearly CSAM → assign 'CSAM' bucket\n" +
                  "• See a chat about a drug deal → 'Drug Evidence'\n" +
                  "• See contacts repeatedly involved → 'Contacts of Interest'\n" +
                  "• Junk/unrelated → 'Unrelated'\n\n" +
                  "Buckets become the table of contents in the HTML report " +
                  "you export back to the detective. They can also click a " +
                  "bucket to see only items of that category."
                }
              >
                ?
              </span>
            </h3>
            <ul className="wt-bucket-list">
              {detail.buckets.map((b) => (
                <li
                  key={b.id}
                  className={`wt-bucket-row ${bucketFilter === b.id ? "active" : ""}`}
                  onClick={() => setBucketFilter((p) => (p === b.id ? null : b.id))}
                  style={{ ["--bucket-color" as any]: b.color }}
                >
                  <span className="bucket-dot" style={{ background: b.color }} />
                  <span className="bucket-name">{b.name}</span>
                  <span className="count">{itemsByBucket.byBucket[b.id] || 0}</span>
                  <button
                    className="bucket-del"
                    title="Delete bucket"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteBucket(b.id);
                    }}
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>

            <form
              className="wt-new-bucket"
              onSubmit={(e) => {
                e.preventDefault();
                createBucket();
              }}
            >
              <input
                placeholder="New bucket name…"
                value={newBucketName}
                onChange={(e) => setNewBucketName(e.target.value)}
              />
              <div className="wt-color-row">
                {NEW_BUCKET_COLORS.map((c) => (
                  <button
                    type="button"
                    key={c}
                    className={`color-swatch ${newBucketColor === c ? "selected" : ""}`}
                    style={{ background: c }}
                    onClick={() => setNewBucketColor(c)}
                    aria-label={`Pick ${c}`}
                  />
                ))}
              </div>
              <button type="submit" disabled={!newBucketName.trim()}>
                + Add bucket
              </button>
            </form>
          </div>
        </aside>

        {/* ─── Center pane: overview cards OR item list ─── */}
        {sectionFilter === "overview" ? (
          <main className="wt-overview">
            <CaseOverview
              detail={detail}
              itemsBySection={itemsBySection}
              itemsByBucket={itemsByBucket}
              onJumpToSection={(s) => setSectionFilter(s)}
              onJumpToFlagged={() => {
                setSectionFilter(null);
                setBucketFilter("flagged");
              }}
              onJumpToUnbucketed={() => {
                setSectionFilter(null);
                setBucketFilter("unbucketed");
              }}
              onJumpToBucket={(bid) => {
                setSectionFilter(null);
                setBucketFilter(bid);
              }}
              scanResults={scanResults}
              keywordLists={keywordLists}
              selectedKwLists={selectedKwLists}
              onToggleKwList={toggleKwList}
              onSelectAllKwLists={() =>
                setSelectedKwLists(new Set(keywordLists.map((l) => l.name)))
              }
              onClearKwListSelection={() => setSelectedKwLists(new Set())}
              hashLists={hashLists}
              selectedHashLists={selectedHashLists}
              onToggleHashList={toggleHashList}
              onSelectAllHashLists={() =>
                setSelectedHashLists(new Set(hashLists.map((l) => l.name)))
              }
              onClearHashListSelection={() => setSelectedHashLists(new Set())}
              hashScanBusy={hashScanBusy}
              kwScanBusy={kwScanBusy}
              hashScanStart={hashScanStart}
              kwScanStart={kwScanStart}
              scanError={scanError}
              onClearScanError={() => setScanError(null)}
              onRunHashScan={runHashScan}
              onRunKeywordScan={runKeywordScan}
              onClearHashScan={clearHashScan}
              onClearKeywordScan={clearKeywordScan}
              itemIdByFilename={itemIdByFilename}
              onFlagHashHits={flagItemsByFilenames}
              onFlagKeywordHits={flagItemsByIds}
              onOpenItem={(id) => {
                const it = detail.items.find((x) => x.id === id);
                if (!it) return;
                setSectionFilter(it.section);
                setBucketFilter(null);
                setSelectedItemId(id);
              }}
            />
          </main>
        ) : (
          <main className="wt-itemlist">
          <div className="wt-itemlist-header">
            <span className="wt-itemlist-count">
              {filteredItems.length} of {detail.items.length}
            </span>
            <div className="wt-view-toggle">
              <button
                type="button"
                className={`wt-view-btn ${effectiveViewMode === "list" ? "active" : ""}`}
                onClick={() => setViewMode("list")}
                title="List view"
                aria-label="List view"
              >
                {/* hamburger icon */}
                <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
                  <rect x="2" y="3" width="12" height="1.5" fill="currentColor" />
                  <rect x="2" y="7.25" width="12" height="1.5" fill="currentColor" />
                  <rect x="2" y="11.5" width="12" height="1.5" fill="currentColor" />
                </svg>
              </button>
              <button
                type="button"
                className={`wt-view-btn ${effectiveViewMode === "grid" ? "active" : ""}`}
                onClick={() => setViewMode("grid")}
                title="Grid view"
                aria-label="Grid view"
              >
                {/* 2x2 grid icon */}
                <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
                  <rect x="2" y="2" width="5" height="5" fill="currentColor" />
                  <rect x="9" y="2" width="5" height="5" fill="currentColor" />
                  <rect x="2" y="9" width="5" height="5" fill="currentColor" />
                  <rect x="9" y="9" width="5" height="5" fill="currentColor" />
                </svg>
              </button>
            </div>
            {(sectionFilter || bucketFilter || search) && (
              <button
                className="wt-clear-filters"
                onClick={() => {
                  setSectionFilter(null);
                  setBucketFilter(null);
                  setSearch("");
                }}
              >
                Clear filters
              </button>
            )}
          </div>
          {effectiveViewMode === "grid" && sectionFilter !== "location" ? (
            <ItemGrid
              items={filteredItems}
              buckets={detail.buckets}
              selectedId={selectedItemId}
              onSelect={setSelectedItemId}
              caseId={caseId}
            />
          ) : sectionFilter === "unified_messages" ? (
            <ChatView
              items={filteredItems}
              buckets={detail.buckets}
              selectedId={selectedItemId}
              onSelect={setSelectedItemId}
              caseId={caseId}
              owner={detail.case.targetAccount || null}
            />
          ) : sectionFilter === "location" ? (
            <LocationMapView
              items={filteredItems}
              buckets={detail.buckets}
              selectedId={selectedItemId}
              onSelect={setSelectedItemId}
            />
          ) : sectionFilter === "emails" ? (
            <EmailSplitView
              items={filteredItems}
              buckets={detail.buckets}
              selectedId={selectedItemId}
              onSelect={setSelectedItemId}
              caseId={caseId}
            />
          ) : (
            <ItemList
              items={filteredItems}
              buckets={detail.buckets}
              selectedId={selectedItemId}
              onSelect={setSelectedItemId}
              caseId={caseId}
            />
          )}
        </main>
        )}

        {/* ─── Right pane: detail (hidden in overview mode) ─── */}
        {sectionFilter !== "overview" && (
          <aside className="wt-detail">
            {selectedItem ? (
              <DetailPanel
                item={selectedItem}
                buckets={detail.buckets}
                caseId={caseId}
                onAssignBucket={(b) => assignBucket(selectedItem.id, b)}
                onSetNote={(n) => setNote(selectedItem.id, n)}
                onToggleFlag={(f) => toggleFlag(selectedItem.id, f)}
                onOpenMedia={openMedia}
              />
            ) : (
              <div className="wt-detail-empty">Select an item to view details.</div>
            )}
          </aside>
        )}
      </div>
    </div>
  );
};

// ─── CaseOverview — dashboard cards (default landing) ──────────────────

interface CaseOverviewProps {
  detail: CaseDetail;
  itemsBySection: Record<string, number>;
  itemsByBucket: { byBucket: Record<string, number>; unbucketed: number; flagged: number };
  onJumpToSection: (section: string) => void;
  onJumpToFlagged: () => void;
  onJumpToUnbucketed: () => void;
  onJumpToBucket: (bucketId: string) => void;
  // Scan integration
  scanResults: CaseScanResults;
  keywordLists: KeywordListSummary[];
  selectedKwLists: Set<string>;
  onToggleKwList: (name: string) => void;
  onSelectAllKwLists: () => void;
  onClearKwListSelection: () => void;
  hashLists: HashListSummary[];
  selectedHashLists: Set<string>;
  onToggleHashList: (name: string) => void;
  onSelectAllHashLists: () => void;
  onClearHashListSelection: () => void;
  hashScanBusy: boolean;
  kwScanBusy: boolean;
  hashScanStart: Date | null;
  kwScanStart: Date | null;
  scanError: string | null;
  onClearScanError: () => void;
  onRunHashScan: () => void;
  onRunKeywordScan: () => void;
  onClearHashScan: () => void;
  onClearKeywordScan: () => void;
  itemIdByFilename: Map<string, string>;
  onFlagHashHits: (filenames: string[]) => void | Promise<void>;
  onFlagKeywordHits: (itemIds: string[]) => void | Promise<void>;
  onOpenItem: (itemId: string) => void;
}

const SECTION_ICONS: Record<string, string> = {
  unified_messages: "💬",
  photos: "📷",
  status_updates: "📝",
  wallposts: "📌",
  posts_to_other_walls: "📤",
  shares: "🔗",
  ip_addresses: "🌐",
  registration_ip: "📡",
  about_me: "👤",
  bio: "👤",
  ncmec_reports: "⚠️",
  request_parameters: "📋",
  // Quest export sections
  friends: "👥",
  social_connections: "🤝",
  worlds_visited: "🌍",
  worlds_progress: "🎮",
  worlds_saved: "💾",
  apps: "📱",
  orders: "🧾",
  achievements: "🏆",
  recently_viewed: "🕒",
  cloud_backups: "☁️",
  entitlements: "🎟️",
  subscriptions: "🔁",
  app_invites_sent: "📨",
  app_invites_recv: "📩",
  gifts_sent: "🎁",
  group_chats: "💬",
  events: "📅",
  watch_history: "▶️",
  vr_sessions: "🥽",
  profile_photos: "🖼️",
  notification_emails: "✉️",
  payment_methods: "💳",
  device_info: "🖥️",
  environment: "📐",
  reviews: "⭐",
  settings: "⚙️",
  parental: "🛡️",
  app_presence: "🟢",
  location: "📍",
  emotes: "😀",
  // Discord
  servers: "🏰",
  // Snapchat
  memories: "📚",
  snap_history: "👻",
  call_logs: "📞",
  ai_conversations: "🤖",
  login_history: "🔐",
  videos: "🎬",
  // Google
  change_history: "📝",
  emails: "✉️",
  drive_files: "📁",
  // Yahoo
  account_action: "🛠️",
  // Kik
  blocks: "🚫",
  media_messages: "🖼️",
  group_media: "🎞️",
  // X (Twitter)
  x_account: "👤",
  tweets: "🐦",
  direct_messages: "✉️",
  followers: "👥",
  following: "➡️",
  ip_audit: "🌐",
  devices: "📱",
  personalization: "🎯",
  ad_data: "📢",
  x_metadata: "🗂️",
  audio: "🎧",
};

const CaseOverview: React.FC<CaseOverviewProps> = ({
  detail,
  itemsBySection,
  itemsByBucket,
  onJumpToSection,
  onJumpToFlagged,
  onJumpToUnbucketed,
  onJumpToBucket,
  scanResults,
  keywordLists,
  selectedKwLists,
  onToggleKwList,
  onSelectAllKwLists,
  onClearKwListSelection,
  hashLists,
  selectedHashLists,
  onToggleHashList,
  onSelectAllHashLists,
  onClearHashListSelection,
  hashScanBusy,
  kwScanBusy,
  hashScanStart,
  kwScanStart,
  scanError,
  onClearScanError,
  onRunHashScan,
  onRunKeywordScan,
  onClearHashScan,
  onClearKeywordScan,
  itemIdByFilename,
  onFlagHashHits,
  onFlagKeywordHits,
  onOpenItem,
}) => {
  // Pull bio text(s) directly from the items so we don't have to make
  // a second backend call.
  const bioItems = detail.items.filter((i) => i.section === "bio");
  const reqParamsItems = detail.items.filter((i) => i.section === "request_parameters");
  const locationItems = detail.items.filter((i) => i.section === "location");

  // Group bio fields by their parser-supplied section header so we can
  // route them into different overview cards.  Keys are the section
  // titles emitted by google.rs::emit_bio() (e.g. "Subscriber Information",
  // "Hangouts User Info", "Categories With No Records Returned").
  const bioGroups: Record<string, Array<{ label: string; value: string }>> = {};
  for (const it of bioItems) {
    const raw = (it.rawFields || {}) as Record<string, unknown>;
    const fields = Array.isArray(raw.fields)
      ? (raw.fields as Array<{ label?: string; value?: string; section?: string }>)
      : null;
    if (!fields || fields.length === 0) continue;
    let current = "Bio";
    for (const f of fields) {
      if (f && typeof f.section === "string") {
        current = f.section;
        if (!bioGroups[current]) bioGroups[current] = [];
        continue;
      }
      if (f && f.label && f.value) {
        if (!bioGroups[current]) bioGroups[current] = [];
        bioGroups[current].push({ label: f.label, value: f.value });
      }
    }
  }
  const subscriberRows = bioGroups["Subscriber Information"] || [];
  const noRecordsRows = bioGroups["Categories With No Records Returned"] || [];
  // Anything left for the Bio card (Hangouts, Google Chat, etc.) excluding
  // the groups we re-routed elsewhere.
  const ROUTED_AWAY = new Set([
    "Subscriber Information",
    "Categories With No Records Returned",
    "Imported From",
  ]);
  const bioCardGroups = Object.entries(bioGroups).filter(
    ([k, v]) => !ROUTED_AWAY.has(k) && v.length > 0
  );

  const sectionsSorted = Object.keys(itemsBySection).sort(
    (a, b) => itemsBySection[b] - itemsBySection[a]
  );

  const totalBucketed = detail.items.length - itemsByBucket.unbucketed;

  // Format ISO date strings for display.  Falls back to the raw string.
  const fmtDate = (s?: string | null) => {
    if (!s) return "—";
    try {
      const d = new Date(s);
      if (isNaN(d.getTime())) return s;
      return d
        .toISOString()
        .replace("T", " ")
        .replace(/\.\d+Z$/, " UTC");
    } catch {
      return s;
    }
  };

  const fmtBytes = (n: number) => {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const fmtDuration = (ms: number) => {
    if (ms < 1000) return `${ms} ms`;
    const s = ms / 1000;
    if (s < 60) return `${s.toFixed(1)}s`;
    const m = Math.floor(s / 60);
    return `${m}m ${Math.round(s - m * 60)}s`;
  };

  const hashScan = scanResults.hashScan;
  const kwScan = scanResults.keywordScan;

  return (
    <div className="wt-overview-scroll">
      <div className="wt-overview-grid">
        {/* Account Info */}
        <section className="wt-card wt-card-account">
          <header className="wt-card-header">
            <span className="wt-card-icon">📋</span>
            <h3>Account</h3>
          </header>
          <dl className="wt-kv wt-bio-kv">
            <dt>Service</dt>
            <dd>{detail.case.providerDisplay}</dd>
            {detail.case.targetAccount && (
              <>
                <dt>Target ID</dt>
                <dd>
                  <code>{detail.case.targetAccount}</code>
                </dd>
              </>
            )}
            {detail.case.dateRange && (
              <>
                <dt>Date Range</dt>
                <dd>{detail.case.dateRange}</dd>
              </>
            )}
            {detail.case.generatedAtSource && (
              <>
                <dt>Generated</dt>
                <dd>{fmtDate(detail.case.generatedAtSource)}</dd>
              </>
            )}
            <dt>Imported</dt>
            <dd>{fmtDate(detail.case.importedAt)}</dd>
            {subscriberRows.length > 0 && (
              <>
                <dt className="wt-bio-section">Subscriber Information</dt>
                <dd className="wt-bio-section-spacer" />
                {subscriberRows.map((r, i) => (
                  <React.Fragment key={`sub-${i}`}>
                    <dt>{r.label}</dt>
                    <dd style={{ whiteSpace: "pre-line" }}>{r.value}</dd>
                  </React.Fragment>
                ))}
              </>
            )}
          </dl>
        </section>

        {/* Bio */}
        <section className="wt-card wt-card-bio">
          <header className="wt-card-header">
            <span className="wt-card-icon">👤</span>
            <h3>Bio</h3>
          </header>
          {bioCardGroups.length === 0 ? (
            <div className="wt-card-empty">No bio data in this return.</div>
          ) : (
            <dl className="wt-kv wt-bio-kv">
              {bioCardGroups.flatMap(([section, rows]) => [
                <React.Fragment key={`h-${section}`}>
                  <dt className="wt-bio-section">{section}</dt>
                  <dd className="wt-bio-section-spacer" />
                </React.Fragment>,
                ...rows.map((r, i) => (
                  <React.Fragment key={`${section}-${i}`}>
                    <dt>{r.label}</dt>
                    <dd style={{ whiteSpace: "pre-line" }}>{r.value}</dd>
                  </React.Fragment>
                )),
              ])}
            </dl>
          )}
        </section>

        {/* Triage Progress */}
        <section className="wt-card wt-card-triage">
          <header className="wt-card-header">
            <span className="wt-card-icon">🎯</span>
            <h3>Triage Progress</h3>
          </header>
          <div className="wt-triage-stats">
            <button
              type="button"
              className="wt-triage-stat clickable"
              onClick={onJumpToFlagged}
            >
              <span className="stat-num flag">{itemsByBucket.flagged}</span>
              <span className="stat-label">🚩 Flagged</span>
            </button>
            <div className="wt-triage-stat">
              <span className="stat-num good">{totalBucketed}</span>
              <span className="stat-label">Bucketed</span>
            </div>
            <button
              type="button"
              className="wt-triage-stat clickable"
              onClick={onJumpToUnbucketed}
            >
              <span className="stat-num warn">{itemsByBucket.unbucketed}</span>
              <span className="stat-label">Unbucketed</span>
            </button>
          </div>
          {detail.buckets.length > 0 && (
            <div className="wt-bucket-chips">
              {detail.buckets.map((b) => {
                const n = itemsByBucket.byBucket[b.id] || 0;
                return (
                  <button
                    type="button"
                    key={b.id}
                    className="wt-bucket-chip-btn"
                    onClick={() => onJumpToBucket(b.id)}
                    style={{ borderColor: b.color }}
                  >
                    <span className="dot" style={{ background: b.color }} />
                    <span className="name">{b.name}</span>
                    <span className="n">{n}</span>
                  </button>
                );
              })}
            </div>
          )}
          {noRecordsRows.length > 0 && (
            <div className="wt-no-records">
              <div className="wt-no-records-header">
                <span className="wt-no-records-icon">∅</span>
                <span className="wt-no-records-title">No Records Returned</span>
                <span className="wt-no-records-count">
                  {noRecordsRows
                    .map((r) => (r.value.match(/\n/g) || []).length + 1)
                    .reduce((a, b) => a + b, 0)}
                </span>
              </div>
              <div className="wt-no-records-list">
                {noRecordsRows.flatMap((r) =>
                  r.value.split("\n").map((cat, i) => (
                    <span className="wt-no-records-chip" key={`${r.label}-${i}`}>
                      {cat}
                    </span>
                  ))
                )}
              </div>
            </div>
          )}
        </section>

        {/* Locations preview — placed in row 2 next to Triage Progress
            so Bio / Account have the full first row to breathe. */}
        {locationItems.length > 0 && (
          <LocationOverviewMap
            items={locationItems}
            onOpenAll={() => onJumpToSection("location")}
          />
        )}

        {/* Data Summary — clickable category tiles */}
        <section className="wt-card wt-card-summary">
          <header className="wt-card-header">
            <span className="wt-card-icon">📊</span>
            <h3>Data Summary</h3>
          </header>
          <div className="wt-summary-tiles">
            {sectionsSorted.map((s) => {
              if (s === "request_parameters" || s === "bio") return null;
              return (
                <button
                  type="button"
                  key={s}
                  className="wt-summary-tile"
                  onClick={() => onJumpToSection(s)}
                  title={`Open ${SECTION_LABELS[s] || s}`}
                >
                  <span className="tile-icon">{SECTION_ICONS[s] || "•"}</span>
                  <span className="tile-count">{itemsBySection[s]}</span>
                  <span className="tile-label">{SECTION_LABELS[s] || s}</span>
                </button>
              );
            })}
          </div>
        </section>

        {/* ─── Hash Scan ─── */}
        <section className="wt-card wt-card-scan wt-card-hash-scan">
          <header className="wt-card-header">
            <span className="wt-card-icon">#️⃣</span>
            <h3>Hash Scan</h3>
            <span className="wt-card-sub">SHA-1 vs. loaded hash databases</span>
          </header>

          {scanError && (
            <div className="wt-scan-error">
              <span>{scanError}</span>
              <button onClick={onClearScanError}>×</button>
            </div>
          )}

          {hashScanBusy ? (
            <div className="wt-scan-running">
              <ScanningIndicator
                isScanning={true}
                currentModule="Warrant media · hash matching"
                startTime={hashScanStart ?? undefined}
              />
            </div>
          ) : !hashScan ? (
            <div className="wt-scan-empty">
              {hashLists.length === 0 ? (
                <p className="wt-scan-empty-text muted">
                  No hash lists are loaded. Import a list (Project VIC or your
                  own) from the main Scout app's Hash Lists settings page to
                  enable this scan.
                </p>
              ) : (
                <>
                  <p className="wt-scan-empty-text">
                    No scan conducted. Pick one or more hash lists, then
                    SHA-1/SHA-256-match every media file in this return.
                  </p>
                  <div className="wt-kw-list-picker">
                    <div className="wt-kw-list-picker-header">
                      <span>Hash lists ({selectedHashLists.size}/{hashLists.length} selected)</span>
                      <div className="wt-kw-list-picker-actions">
                        <button type="button" onClick={onSelectAllHashLists}>All</button>
                        <button type="button" onClick={onClearHashListSelection}>None</button>
                      </div>
                    </div>
                    <ul className="wt-kw-list-options">
                      {hashLists.map((l) => (
                        <li key={l.name}>
                          <label>
                            <input
                              type="checkbox"
                              checked={selectedHashLists.has(l.name)}
                              onChange={() => onToggleHashList(l.name)}
                            />
                            <span className="wt-kw-list-name" title={l.source ? `${l.name} · ${l.source}` : l.name}>
                              {l.name}
                            </span>
                            <span className="wt-kw-list-count">
                              {l.hashCount.toLocaleString()}
                            </span>
                          </label>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <button
                    type="button"
                    className="wt-scan-run-btn"
                    onClick={onRunHashScan}
                    disabled={hashScanBusy || selectedHashLists.size === 0}
                  >
                    {hashScanBusy ? "Scanning…" : "▶ Run Hash Scan"}
                  </button>
                </>
              )}
            </div>
          ) : (
            <>
              <div className="wt-scan-stats">
                <div className="wt-scan-stat">
                  <span className={`stat-num ${hashScan.hits.length > 0 ? "alert" : "good"}`}>
                    {hashScan.hits.length}
                  </span>
                  <span className="stat-label">Hits</span>
                </div>
                <div className="wt-scan-stat">
                  <span className="stat-num">{hashScan.filesScanned}</span>
                  <span className="stat-label">Files Scanned</span>
                </div>
                <div className="wt-scan-stat">
                  <span className="stat-num muted">{hashScan.filesTotal}</span>
                  <span className="stat-label">Files Total</span>
                </div>
                <div className="wt-scan-stat">
                  <span className="stat-num muted">{fmtDuration(hashScan.durationMs)}</span>
                  <span className="stat-label">Duration</span>
                </div>
              </div>

              <div className="wt-scan-meta">
                Last run: {fmtDate(hashScan.ranAt)}
              </div>

              {hashScan.hits.length > 0 && (
                <div className="wt-scan-hits">
                  <div className="wt-scan-hits-title">
                    Top hits ({Math.min(hashScan.hits.length, 10)} of {hashScan.hits.length})
                  </div>
                  <ul className="wt-scan-hits-list">
                    {hashScan.hits.slice(0, 10).map((h, idx) => {
                      const baseName =
                        (h.filename.split(/[\\/]/).pop() || h.filename).toLowerCase();
                      const targetId = itemIdByFilename.get(baseName);
                      return (
                        <li
                          key={idx}
                          className={`wt-scan-hit ${targetId ? "clickable" : ""}`}
                          onClick={() => targetId && onOpenItem(targetId)}
                          title={targetId ? "Open matching item" : "No matching item"}
                        >
                          <div className="wt-scan-hit-main">
                            <span className="wt-scan-hit-name" title={h.filename}>
                              {h.filename.split(/[\\/]/).pop() || h.filename}
                            </span>
                            <span className="wt-scan-hit-size">{fmtBytes(h.sizeBytes)}</span>
                          </div>
                          <div className="wt-scan-hit-meta">
                            {h.listName && <span className="wt-scan-hit-list">{h.listName}</span>}
                            {h.category && <span className="wt-scan-hit-cat">{h.category}</span>}
                            <code className="wt-scan-hit-hash" title={h.sha1}>
                              {h.sha1.slice(0, 12)}…
                            </code>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}

              <div className="wt-scan-actions">
                {hashScan.hits.length > 0 && (
                  <button
                    type="button"
                    className="wt-scan-flag-btn"
                    onClick={() => onFlagHashHits(hashScan.hits.map((h) => h.filename))}
                    title="Flag every item whose attachment matched a hash"
                  >
                    🚩 Flag all hits
                  </button>
                )}
                <button
                  type="button"
                  className="wt-scan-run-btn"
                  onClick={onRunHashScan}
                  disabled={hashScanBusy}
                >
                  {hashScanBusy ? "Scanning…" : "⟳ Re-run"}
                </button>
                <button
                  type="button"
                  className="wt-scan-clear-btn"
                  onClick={onClearHashScan}
                  disabled={hashScanBusy}
                >
                  ✕ Clear
                </button>
              </div>
            </>
          )}
        </section>

        {/* ─── Keyword Scan ─── */}
        <section className="wt-card wt-card-scan wt-card-kw-scan">
          <header className="wt-card-header">
            <span className="wt-card-icon">🔍</span>
            <h3>Keyword Scan</h3>
            <span className="wt-card-sub">Text-field search across all items</span>
          </header>

          {kwScanBusy ? (
            <div className="wt-scan-running">
              <ScanningIndicator
                isScanning={true}
                currentModule="Warrant text · keyword matching"
                startTime={kwScanStart ?? undefined}
              />
            </div>
          ) : !kwScan ? (
            <div className="wt-scan-empty">
              {keywordLists.length === 0 ? (
                <p className="wt-scan-empty-text muted">
                  No keyword lists are installed on this machine. Add lists from
                  the main Scout app's Settings → Keyword Lists to enable this
                  scan.
                </p>
              ) : (
                <>
                  <p className="wt-scan-empty-text">
                    No scan conducted. Pick one or more keyword lists, then
                    search every text field on every item.
                  </p>
                  <div className="wt-kw-list-picker">
                    <div className="wt-kw-list-picker-header">
                      <span>Keyword lists ({selectedKwLists.size}/{keywordLists.length} selected)</span>
                      <div className="wt-kw-list-picker-actions">
                        <button type="button" onClick={onSelectAllKwLists}>All</button>
                        <button type="button" onClick={onClearKwListSelection}>None</button>
                      </div>
                    </div>
                    <ul className="wt-kw-list-options">
                      {keywordLists.map((l) => (
                        <li key={l.name}>
                          <label>
                            <input
                              type="checkbox"
                              checked={selectedKwLists.has(l.name)}
                              onChange={() => onToggleKwList(l.name)}
                            />
                            <span className="wt-kw-list-name">{l.name}</span>
                            <span className="wt-kw-list-count">{l.keywordCount}</span>
                          </label>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <button
                    type="button"
                    className="wt-scan-run-btn"
                    onClick={onRunKeywordScan}
                    disabled={kwScanBusy || selectedKwLists.size === 0}
                  >
                    {kwScanBusy ? "Scanning…" : "▶ Run Keyword Scan"}
                  </button>
                </>
              )}
            </div>
          ) : (
            <>
              <div className="wt-scan-stats">
                <div className="wt-scan-stat">
                  <span className={`stat-num ${kwScan.hits.length > 0 ? "alert" : "good"}`}>
                    {kwScan.hits.length}
                  </span>
                  <span className="stat-label">Hits</span>
                </div>
                <div className="wt-scan-stat">
                  <span className="stat-num">{kwScan.keywordCount}</span>
                  <span className="stat-label">Keywords</span>
                </div>
                <div className="wt-scan-stat">
                  <span className="stat-num muted">{kwScan.itemsScanned}</span>
                  <span className="stat-label">Items Scanned</span>
                </div>
                <div className="wt-scan-stat">
                  <span className="stat-num muted">{fmtDuration(kwScan.durationMs)}</span>
                  <span className="stat-label">Duration</span>
                </div>
              </div>

              <div className="wt-scan-meta">
                Last run: {fmtDate(kwScan.ranAt)} · Lists: {kwScan.listsUsed.join(", ")}
              </div>

              {kwScan.hits.length > 0 && (
                <div className="wt-scan-hits">
                  <div className="wt-scan-hits-title">
                    Top hits ({Math.min(kwScan.hits.length, 10)} of {kwScan.hits.length})
                  </div>
                  <ul className="wt-scan-hits-list">
                    {kwScan.hits.slice(0, 10).map((h, idx) => (
                      <li
                        key={idx}
                        className="wt-scan-hit clickable"
                        onClick={() => onOpenItem(h.itemId)}
                        title="Open item"
                      >
                        <div className="wt-scan-hit-main">
                          <span className="wt-scan-hit-kw">{h.keyword}</span>
                          <span className="wt-scan-hit-section">
                            {SECTION_LABELS[h.section] || h.section}
                          </span>
                        </div>
                        <div className="wt-scan-hit-snippet">{h.snippet}</div>
                        <div className="wt-scan-hit-field">in {h.field}</div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="wt-scan-actions">
                {kwScan.hits.length > 0 && (
                  <button
                    type="button"
                    className="wt-scan-flag-btn"
                    onClick={() => onFlagKeywordHits(kwScan.hits.map((h) => h.itemId))}
                    title="Flag every item that matched a keyword"
                  >
                    🚩 Flag all hits
                  </button>
                )}
                <button
                  type="button"
                  className="wt-scan-run-btn"
                  onClick={onRunKeywordScan}
                  disabled={kwScanBusy || selectedKwLists.size === 0}
                >
                  {kwScanBusy ? "Scanning…" : "⟳ Re-run"}
                </button>
                <button
                  type="button"
                  className="wt-scan-clear-btn"
                  onClick={onClearKeywordScan}
                  disabled={kwScanBusy}
                >
                  ✕ Clear
                </button>
              </div>
            </>
          )}
        </section>

        {/* Preservation / Source */}
        <section className="wt-card wt-card-source">
          <header className="wt-card-header">
            <span className="wt-card-icon">📦</span>
            <h3>Source File</h3>
          </header>
          <dl className="wt-kv">
            <dt>File</dt>
            <dd className="wt-mono break">{detail.case.sourceFilename}</dd>
            {reqParamsItems.length > 0 &&
              reqParamsItems.map((it) => (
                <React.Fragment key={it.id}>
                  {Object.entries(it.rawFields || {})
                    .filter(([k]) => !k.startsWith("__"))
                    .slice(0, 8)
                    .map(([k, v]) => (
                      <React.Fragment key={k}>
                        <dt>{k}</dt>
                        <dd>{typeof v === "string" ? v : JSON.stringify(v)}</dd>
                      </React.Fragment>
                    ))}
                </React.Fragment>
              ))}
          </dl>
        </section>
      </div>
    </div>
  );
};

// ─── ItemList — virtualized via window-aware slice ───────────────────────

interface ItemListProps {
  items: WarrantItem[];
  buckets: Bucket[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  caseId: string;
}

const ROW_HEIGHT = 110;
const OVERSCAN = 6;

// ─── Email helpers ─────────────────────────────────────────────────────
// Parse "Display Name <addr@host>" → {name, addr}.
function parseAddress(raw: string | undefined | null): { name: string; addr: string } {
  if (!raw) return { name: "", addr: "" };
  const s = raw.trim();
  const m = s.match(/^\s*"?([^"<]*?)"?\s*<\s*([^>]+)\s*>\s*$/);
  if (m) {
    return { name: m[1].trim(), addr: m[2].trim() };
  }
  if (s.includes("@")) return { name: "", addr: s };
  return { name: s, addr: "" };
}

// Pull a 1-line preview from a multi-line email body.  Strips quoted
// reply blocks, MIME boilerplate, and excess whitespace.
function emailPreview(body: string | null | undefined, max = 140): string {
  if (!body) return "";
  const lines = body.split(/\r?\n/);
  const keep: string[] = [];
  for (const ln of lines) {
    const t = ln.trim();
    if (!t) continue;
    if (t.startsWith(">")) continue;
    if (/^on .+wrote:$/i.test(t)) break;
    if (/^-{2,}\s*original message/i.test(t)) break;
    keep.push(t);
    if (keep.join(" ").length > max) break;
  }
  const joined = keep.join(" ").replace(/\s+/g, " ");
  return joined.length > max ? joined.slice(0, max).trimEnd() + "…" : joined;
}

// Format an email date string into "Mon DD" / "Mon DD, YYYY" depending on
// how recent it is.  Falls back to raw string on parse failure.
function fmtEmailDate(s: string | undefined | null): string {
  if (!s) return "";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  const now = new Date();
  const sameYear = d.getFullYear() === now.getFullYear();
  const month = d.toLocaleString(undefined, { month: "short" });
  const day = d.getDate();
  if (sameYear) {
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    // diff in ms
    const diff = now.getTime() - d.getTime();
    if (diff < 1000 * 60 * 60 * 24) return `${hh}:${mm}`;
    return `${month} ${day}`;
  }
  return `${month} ${day}, ${d.getFullYear()}`;
}

const ItemList: React.FC<ItemListProps> = ({ items, buckets, selectedId, onSelect, caseId }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(600);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight));
    el.addEventListener("scroll", onScroll, { passive: true });
    ro.observe(el);
    setViewportH(el.clientHeight);
    return () => {
      el.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, []);

  const bucketsById = useMemo(() => {
    const m: Record<string, Bucket> = {};
    for (const b of buckets) m[b.id] = b;
    return m;
  }, [buckets]);

  const totalH = items.length * ROW_HEIGHT;
  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const end = Math.min(items.length, Math.ceil((scrollTop + viewportH) / ROW_HEIGHT) + OVERSCAN);

  if (items.length === 0) {
    return <div className="wt-itemlist-empty">No items match the current filters.</div>;
  }

  return (
    <div className="wt-itemlist-scroll" ref={scrollRef}>
      <div style={{ height: totalH, position: "relative" }}>
        {items.slice(start, end).map((it, i) => {
          const idx = start + i;
          const bucket = it.bucket ? bucketsById[it.bucket] : null;
          return (
            <ItemRow
              key={it.id}
              item={it}
              bucket={bucket}
              top={idx * ROW_HEIGHT}
              selected={it.id === selectedId}
              onSelect={() => onSelect(it.id)}
              caseId={caseId}
            />
          );
        })}
      </div>
    </div>
  );
};

// ─── EmailSplitView — Gmail-style inbox+reader (Aperture parity) ───────
// Replaces the flat ItemList for the "emails" section.  Left column is a
// compact inbox list; right column is a full-width reader showing the
// selected email's subject + header + body.  Right detail pane keeps the
// triage controls (flag/bucket/notes).

interface EmailSplitViewProps {
  items: WarrantItem[];
  buckets: Bucket[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  caseId: string;
}

const EmailSplitView: React.FC<EmailSplitViewProps> = ({ items, selectedId, onSelect }) => {
  // Auto-select the first email when nothing is selected so the reader
  // pane never sits empty on load.
  useEffect(() => {
    if (!selectedId && items.length > 0) {
      onSelect(items[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items.length]);

  const selected = items.find((i) => i.id === selectedId) || null;

  return (
    <div className="wt-email-split">
      <div className="wt-email-list">
        {items.length === 0 ? (
          <div className="wt-empty">No emails match the current filters.</div>
        ) : (
          items.map((it) => (
            <EmailListRow
              key={it.id}
              item={it}
              selected={it.id === selectedId}
              onSelect={() => onSelect(it.id)}
            />
          ))
        )}
      </div>
      <div className="wt-email-reader">
        {selected ? (
          <EmailDetailCard item={selected} />
        ) : (
          <div className="wt-empty wt-email-empty">Select an email to read it here.</div>
        )}
      </div>
    </div>
  );
};

const EmailListRow: React.FC<{
  item: WarrantItem;
  selected: boolean;
  onSelect: () => void;
}> = ({ item, selected, onSelect }) => {
  const raw = (item.rawFields || {}) as Record<string, any>;
  const fromStr = typeof raw.from === "string" ? raw.from : item.author || "";
  const subject = typeof raw.subject === "string" ? raw.subject : "(no subject)";
  const from = parseAddress(fromStr);
  const senderName = from.name || from.addr || "(unknown sender)";
  const avatarChar = (from.name || from.addr || "?").trim().charAt(0).toUpperCase() || "?";
  const date = fmtEmailDate(item.timestamp);
  const preview = emailPreview(item.bodyText);
  const hasAttach = item.attachments.length > 0;

  return (
    <div
      className={`wt-email-li ${selected ? "selected" : ""} ${item.isFlagged ? "flagged" : ""}`}
      onClick={onSelect}
    >
      <div className="wt-email-avatar" aria-hidden>{avatarChar}</div>
      <div className="wt-email-li-body">
        <div className="wt-email-li-top">
          <span className="wt-email-from">{senderName}</span>
          {hasAttach && <span className="wt-email-attach" title={`${item.attachments.length} attachment(s)`}>📎</span>}
          {item.isFlagged && <span className="wt-email-flag">🚩</span>}
          <span className="wt-email-date">{date}</span>
        </div>
        <div className="wt-email-subject">{subject}</div>
        {preview && <div className="wt-email-preview">{preview}</div>}
      </div>
    </div>
  );
};

interface ItemRowProps {
  item: WarrantItem;
  bucket: Bucket | null;
  top: number;
  selected: boolean;
  onSelect: () => void;
  caseId: string;}

const ItemRow: React.FC<ItemRowProps> = ({ item, bucket, top, selected, onSelect, caseId }) => {
  const { thumb, loading, hasMedia } = useMediaThumb(item, caseId);
  const label = SECTION_LABELS[item.section] || item.section;

  // Build an inline detail strip — a few key fields from raw_fields that
  // matter for triage at a glance.  Hidden when redundant with summary.
  const detailChips = useMemo(() => {
    const raw = (item.rawFields || {}) as Record<string, unknown>;
    const want: Array<[string, string]> = [];
    const seen = new Set<string>();
    const push = (label: string, key: string) => {
      const v = raw[key];
      let str: string | null = null;
      if (typeof v === "string") str = v.trim();
      else if (typeof v === "number") str = String(v);
      else if (typeof v === "boolean") str = v ? "Yes" : "No";
      if (!str || !str.trim()) return;
      if (seen.has(str.toLowerCase())) return;
      if (str.length > 80) return;
      // skip if value already shown in summary/body
      const sum = (item.summary || "").toLowerCase();
      if (sum.includes(str.toLowerCase())) return;
      seen.add(str.toLowerCase());
      want.push([label, str]);
    };
    // section-aware key picks
    switch (item.section) {
      case "ip_addresses":
        push("UA", "userAgent");
        push("Login OK", "wasLoginSuccessful");
        // Discord aggregated IPs
        push("Hits", "count");
        push("First", "firstSeen");
        push("Last", "lastSeen");
        break;
      case "location":
        push("Lat", "latitude");
        push("Lng", "longitude");
        push("When", "time");
        // Snapchat geo_locations
        push("When", "timestamp");
        push("± m", "accuracyMeters");
        break;
      case "apps":
      case "app_presence":
        push("Status", "status");
        push("Granted", "grantedTime");
        push("Last used", "lastUsed");
        break;
      case "orders":
        push("Total", "totalAmount");
        push("Status", "status");
        push("Date", "orderDate");
        break;
      case "vr_sessions":
        push("Duration", "duration");
        push("App", "appName");
        break;
      case "worlds_visited":
      case "worlds_saved":
      case "worlds_progress":
        push("Visits", "totalVisits");
        push("Last", "lastVisitTime");
        break;
      case "achievements":
        push("Game", "appName");
        push("Earned", "earnedTime");
        break;
      case "payment_methods":
        push("Method", "paymentCredentialDescription");
        push("Updated", "updatedTime");
        break;
      case "gifts_sent":
      case "gifts_received":
        // Quest exports only include app + timestamps + status (no recipient).
        // Show all four so investigators can correlate with messages.
        push("App", "appName");
        push("Status", "status");
        push("Purchased", "purchasedTime");
        push("Updated", "updateTime");
        break;
      // ── Discord ──
      case "servers":
        push("ID", "guildId");
        push("Name", "name");
        break;
      case "device_info":
        push("OS", "os");
        push("OS ver", "osVersion");
        push("Browser", "browser");
        push("Client", "clientVersion");
        push("Hits", "count");
        push("Last", "lastSeen");
        // Snapchat device_advertising_id
        push("Type", "idType");
        push("HMS", "isHms");
        push("Recorded", "timeRecorded");
        break;
      case "social_connections":
        push("Type", "type");
        push("Name", "name");
        push("Verified", "verified");
        break;
      case "friends":
        push("Platform", "platform");
        push("Contacts", "friendCount");
        // Snapchat-specific friend fields
        push("Username", "username");
        push("Type", "relationship");
        push("Direction", "direction");
        push("Created", "creationTimestamp");
        break;
      // ── Snapchat ──
      case "memories":
        push("Source", "sourceType");
        push("Saved", "timestamp");
        push("Dur", "duration");
        push("Encrypted", "encrypted");
        break;
      case "snap_history":
        // CSV row dumped verbatim (column names depend on Snapchat schema)
        push("Type", "snap_type");
        push("From", "sender_username");
        push("To", "recipient_username");
        push("Sent", "timestamp");
        push("Status", "status");
        break;
      case "call_logs":
        push("Direction", "direction");
        push("Other", "recipient_username");
        push("Duration", "duration");
        push("When", "timestamp");
        push("Type", "type");
        break;
      case "ai_conversations":
        push("Conv", "conversation_id");
        push("Dir", "direction");
        push("When", "timestamp");
        break;
      case "login_history":
        push("IP", "IP Address");
        push("Device", "Device");
        push("OS", "OS");
        push("When", "Time");
        push("Status", "Status");
        break;
      case "videos":
        // raw_fields: { filename, sender, recipient, timestamp, ... }
        push("From", "sender");
        push("To", "recipient");
        push("When", "timestamp");
        push("Linked", "linkedMessageId");
        break;
      case "bio":
        // Bio is a SINGLE consolidated item.  We surface select fields as
        // inline chips so the section list shows useful identifiers at a
        // glance — `Username · Email · User ID …`.
        {
          // Consolidated structure: raw_fields.fields = [{label, value}].
          const fields = Array.isArray(raw.fields)
            ? (raw.fields as Array<{ label?: string; value?: string }>)
            : null;
          if (fields && fields.length > 0) {
            const wanted = ["Username", "Email", "Phone", "User ID", "Account IP"];
            for (const lbl of wanted) {
              const f = fields.find(
                (x) => typeof x?.label === "string" && x.label === lbl
              );
              const v = (f?.value || "").trim();
              if (!v || v.length > 80) continue;
              const sum = (item.summary || "").toLowerCase();
              if (sum.includes(v.toLowerCase())) continue;
              if (seen.has(v.toLowerCase())) continue;
              seen.add(v.toLowerCase());
              want.push([lbl, v]);
            }
            break;
          }
          // Legacy: bio data may also live under .data (older parses).
          const data = (raw.data || {}) as Record<string, unknown>;
          const pushNested = (label: string, key: string) => {
            const v = data[key];
            if (typeof v === "string" && v.trim()) {
              const t = v.trim();
              if (t.length > 80) return;
              const sum = (item.summary || "").toLowerCase();
              if (sum.includes(t.toLowerCase())) return;
              if (seen.has(t.toLowerCase())) return;
              seen.add(t.toLowerCase());
              want.push([label, t]);
            }
          };
          pushNested("Username", "username");
          pushNested("Email", "email");
          pushNested("Phone", "phone");
          pushNested("IP", "ip");
          pushNested("ID", "id");
        }
        break;
    }
    return want;
  }, [item]);

  return (
    <div
      className={`wt-item-row ${selected ? "selected" : ""} ${item.isFlagged ? "flagged" : ""} ${
        item.section === "emails" ? "email-row" : ""
      }`}
      style={{ top, height: ROW_HEIGHT }}
      onClick={onSelect}
    >
      {item.section === "emails" ? (
        <EmailRowBody item={item} />
      ) : (
        <>
          {thumb ? (
            <img className="wt-item-thumb" src={thumb} alt="" loading="lazy" />
          ) : loading && hasMedia ? (
            <div className="wt-item-thumb-loading"><div className="wt-spinner" /></div>
          ) : (
            <div className="wt-item-thumb-placeholder">{label.charAt(0)}</div>
          )}
          <div className="wt-item-main">
            <div className="wt-item-headline">
              <span className="wt-item-section">{label}</span>
              {item.timestamp && <span className="wt-item-ts">{item.timestamp}</span>}
              {item.isFlagged && <span className="wt-item-flag">🚩</span>}
            </div>
            <div className="wt-item-summary">{item.summary || item.bodyText || "—"}</div>
            {detailChips.length > 0 && (
              <div className="wt-item-chips">
                {detailChips.map(([k, v]) => (
                  <span className="wt-item-chip" key={k}>
                    <span className="wt-item-chip-k">{k}</span>
                    <span className="wt-item-chip-v">{v}</span>
                  </span>
                ))}
              </div>
            )}
            {(item.author || item.recipient) && (
              <div className="wt-item-people">
                {item.author && <span>{item.author}</span>}
                {item.recipient && <span> → {item.recipient}</span>}
              </div>
            )}
          </div>
        </>
      )}
      {bucket && (
        <div className="wt-item-bucket-chip" style={{ background: bucket.color }}>
          {bucket.name}
        </div>
      )}
    </div>
  );
};

// Inbox-style row body for `section === "emails"`.
const EmailRowBody: React.FC<{ item: WarrantItem }> = ({ item }) => {
  const raw = (item.rawFields || {}) as Record<string, any>;
  const fromStr = typeof raw.from === "string" ? raw.from : item.author || "";
  const subject = typeof raw.subject === "string" ? raw.subject : "(no subject)";
  const from = parseAddress(fromStr);
  const senderName = from.name || from.addr || "(unknown sender)";
  const avatarChar = (from.name || from.addr || "?").trim().charAt(0).toUpperCase() || "?";
  const date = fmtEmailDate(item.timestamp);
  const preview = emailPreview(item.bodyText);
  const hasAttach = item.attachments.length > 0;
  const labels = typeof raw.labels === "string"
    ? raw.labels.split(",").map((s: string) => s.trim()).filter(Boolean).slice(0, 4)
    : [];

  return (
    <>
      <div className="wt-email-avatar" aria-hidden>{avatarChar}</div>
      <div className="wt-email-body">
        <div className="wt-email-top">
          <span className="wt-email-from">{senderName}</span>
          {hasAttach && <span className="wt-email-attach" title={`${item.attachments.length} attachment(s)`}>📎</span>}
          {item.isFlagged && <span className="wt-email-flag">🚩</span>}
          <span className="wt-email-date">{date}</span>
        </div>
        <div className="wt-email-subject">{subject}</div>
        {preview && <div className="wt-email-preview">{preview}</div>}
        {labels.length > 0 && (
          <div className="wt-email-labels">
            {labels.map((l: string) => (
              <span className="wt-email-label" key={l}>{l}</span>
            ))}
          </div>
        )}
      </div>
    </>
  );
};

// ─── ItemGrid — non-virtualized tile layout for photo-heavy sections ────

interface ItemGridProps {
  items: WarrantItem[];
  buckets: Bucket[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  caseId: string;
}

const ItemGrid: React.FC<ItemGridProps> = ({ items, buckets, selectedId, onSelect, caseId }) => {
  const bucketsById = useMemo(() => {
    const m: Record<string, Bucket> = {};
    for (const b of buckets) m[b.id] = b;
    return m;
  }, [buckets]);

  if (items.length === 0) {
    return <div className="wt-empty">No items match the current filters.</div>;
  }

  return (
    <div className="wt-grid-scroll">
      <div className="wt-grid">
        {items.map((it) => (
          <ItemTile
            key={it.id}
            item={it}
            bucket={it.bucket ? bucketsById[it.bucket] : null}
            selected={it.id === selectedId}
            onSelect={() => onSelect(it.id)}
            caseId={caseId}
          />
        ))}
      </div>
    </div>
  );
};

interface ItemTileProps {
  item: WarrantItem;
  bucket: Bucket | null;
  selected: boolean;
  onSelect: () => void;
  caseId: string;
}

const ItemTile: React.FC<ItemTileProps> = ({ item, bucket, selected, onSelect, caseId }) => {
  const { thumb, loading, hasMedia } = useMediaThumb(item, caseId);
  const label = SECTION_LABELS[item.section] || item.section;
  return (
    <div
      className={`wt-tile ${selected ? "selected" : ""} ${item.isFlagged ? "flagged" : ""}`}
      onClick={onSelect}
    >
      <div className="wt-tile-media">
        {thumb ? (
          <img src={thumb} alt="" loading="lazy" />
        ) : loading && hasMedia ? (
          <div className="wt-tile-media-loading">
            <div className="wt-spinner" />
          </div>
        ) : (
          <div className="wt-tile-media-placeholder">{label.charAt(0)}</div>
        )}
        {item.isFlagged && <span className="wt-tile-flag" title="Flagged">🚩</span>}
        {bucket && (
          <span
            className="wt-tile-bucket"
            style={{ background: bucket.color }}
            title={bucket.name}
          >
            {bucket.name}
          </span>
        )}
      </div>
      <div className="wt-tile-meta">
        <div className="wt-tile-caption">
          {item.summary || item.bodyText || label}
        </div>
        {item.timestamp && <div className="wt-tile-ts">{item.timestamp}</div>}
      </div>
    </div>
  );
};

// ─── ChatAttachments — inline thumbnails inside chat bubbles ─────────────
//
// Renders both kinds of attachments emitted by the Discord parser:
//   1. Files that were successfully downloaded to the case media dir
//      (item.attachments[]) → rendered as image thumbnails (or filename
//      chips for non-images).
//   2. URL-only attachments where the CDN link was expired or returned an
//      error (raw_fields.attachmentLinks with status != "downloaded") →
//      rendered as a filename chip with a status badge.

interface ChatAttachmentsProps {
  item: WarrantItem;
  caseId: string;
}

const ChatAttachments: React.FC<ChatAttachmentsProps> = ({ item, caseId }) => {
  const localFiles = item.attachments || [];
  const links = Array.isArray((item.rawFields as Record<string, unknown> | undefined)?.attachmentLinks)
    ? ((item.rawFields as Record<string, unknown>).attachmentLinks as Array<{
        url?: string;
        filename?: string;
        savedAs?: string | null;
        status?: string;
      }>)
    : [];

  // Build a set of saved-as names so we don't render the same attachment
  // as both a thumbnail AND a chip.
  const savedSet = new Set<string>(
    links.map((l) => l.savedAs || "").filter(Boolean)
  );
  // Local files that came from `attachments` but weren't recorded in links
  // (e.g. for messages parsed before attachmentLinks was added).
  const orphanLocal = localFiles.filter((f) => !savedSet.has(f));

  // URL-only (not downloaded).
  const urlOnly = links.filter(
    (l) => !l.savedAs && l.status !== "downloaded" && l.url
  );

  if (localFiles.length === 0 && urlOnly.length === 0 && orphanLocal.length === 0) {
    return null;
  }

  return (
    <div className="wt-chat-attachments">
      {localFiles.map((f) => (
        <ChatAttachmentThumb key={`l-${f}`} filename={f} caseId={caseId} />
      ))}
      {urlOnly.map((l, i) => (
        <a
          key={`u-${i}`}
          className="wt-chat-attachment-chip url-only"
          href={l.url || "#"}
          target="_blank"
          rel="noreferrer"
          onClick={(e) => e.stopPropagation()}
          title={l.url}
        >
          <span className="att-icon">📎</span>
          <span className="att-name">{l.filename || "attachment"}</span>
          {l.status === "expired" && <span className="att-badge">expired</span>}
          {l.status === "url_only" && <span className="att-badge">offline</span>}
        </a>
      ))}
    </div>
  );
};

const ChatAttachmentThumb: React.FC<{ filename: string; caseId: string }> = ({
  filename,
  caseId,
}) => {
  const key = `${caseId}|${filename}`;
  const cached = thumbCache.has(key) ? thumbCache.get(key)! : null;
  const [thumb, setThumb] = useState<string | null>(cached);
  const [loading, setLoading] = useState<boolean>(!thumbCache.has(key));

  useEffect(() => {
    if (thumbCache.has(key)) {
      setThumb(thumbCache.get(key)!);
      setLoading(false);
      return;
    }
    let cancelled = false;
    let promise = thumbInflight.get(key);
    if (!promise) {
      promise = thumbAcquire()
        .then(() =>
          invoke<string | null>("warrant_get_thumbnail", { caseId, filename })
        )
        .then((url) => {
          thumbCache.set(key, url ?? null);
          thumbInflight.delete(key);
          thumbRelease();
          return url ?? null;
        })
        .catch(() => {
          thumbCache.set(key, null);
          thumbInflight.delete(key);
          thumbRelease();
          return null;
        });
      thumbInflight.set(key, promise);
    }
    promise.then((url) => {
      if (!cancelled) {
        setThumb(url);
        setLoading(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [key, caseId, filename]);

  const isImageLike = /\.(jpe?g|png|gif|webp|bmp|heic|heif)$/i.test(filename);

  if (loading) {
    return (
      <div className="wt-chat-attachment-thumb loading">
        <div className="wt-spinner" />
      </div>
    );
  }
  if (thumb) {
    return (
      <img
        className="wt-chat-attachment-thumb"
        src={thumb}
        alt={filename}
        loading="lazy"
      />
    );
  }
  // No thumbnail (non-image or decode failure) — show filename chip.
  return (
    <div className="wt-chat-attachment-chip">
      <span className="att-icon">{isImageLike ? "🖼️" : "📎"}</span>
      <span className="att-name">{filename}</span>
    </div>
  );
};

// ─── ChatView — conversational layout for unified_messages ───────────────
//
// Renders each message as a chat bubble.  Bubbles are right-aligned and
// blue when the author matches the case's target_account (the export
// owner), left-aligned and grey otherwise.  Messages are grouped by
// thread (recipient) with a sticky header and date separators.

interface ChatViewProps {
  items: WarrantItem[];
  buckets: Bucket[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  caseId: string;
  owner: string | null;
}

const ChatView: React.FC<ChatViewProps> = ({ items, buckets: _buckets, selectedId, onSelect, caseId, owner }) => {
  // Group by thread (= recipient when incoming, OR the other party when
  // outgoing). We use the non-owner participant as the canonical thread key.
  const threads = useMemo(() => {
    const map = new Map<string, WarrantItem[]>();
    for (const it of items) {
      const a = it.author || "";
      const r = it.recipient || "";
      const other =
        owner && a && a.toLowerCase() === owner.toLowerCase()
          ? r
          : owner && r && r.toLowerCase() === owner.toLowerCase()
          ? a
          : r || a || "Unknown";
      const key = other || "Unknown";
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(it);
    }
    // Sort threads by most-recent timestamp.
    const arr = Array.from(map.entries()).map(([name, list]) => {
      // items arrive in input order; keep that for chronological display
      return { name, list };
    });
    arr.sort((x, y) => x.name.localeCompare(y.name));
    return arr;
  }, [items, owner]);

  const [activeThread, setActiveThread] = useState<string | null>(
    threads.length > 0 ? threads[0].name : null
  );

  // If filters change and the active thread is gone, snap to the first.
  useEffect(() => {
    if (!activeThread || !threads.find((t) => t.name === activeThread)) {
      setActiveThread(threads.length > 0 ? threads[0].name : null);
    }
  }, [threads, activeThread]);

  if (items.length === 0) {
    return <div className="wt-itemlist-empty">No messages match the current filters.</div>;
  }

  const active = threads.find((t) => t.name === activeThread) || threads[0];

  return (
    <div className="wt-chat">
      <aside className="wt-chat-threads">
        <div className="wt-chat-threads-header">Threads ({threads.length})</div>
        {threads.map((t) => (
          <button
            key={t.name}
            className={`wt-chat-thread ${t.name === activeThread ? "active" : ""}`}
            onClick={() => setActiveThread(t.name)}
          >
            <span className="wt-chat-thread-avatar">{t.name.charAt(0).toUpperCase()}</span>
            <span className="wt-chat-thread-name">{t.name}</span>
            <span className="wt-chat-thread-count">{t.list.length}</span>
          </button>
        ))}
      </aside>
      <div className="wt-chat-stream">
        {active ? (
          <>
            <div className="wt-chat-stream-header">
              <span className="wt-chat-stream-avatar">{active.name.charAt(0).toUpperCase()}</span>
              <div>
                <div className="wt-chat-stream-title">{active.name}</div>
                <div className="wt-chat-stream-sub">{active.list.length} messages</div>
              </div>
            </div>
            <div className="wt-chat-stream-body">
              {active.list.map((m) => {
                const isOut =
                  owner && m.author && m.author.toLowerCase() === owner.toLowerCase();
                const isSel = m.id === selectedId;
                return (
                  <div
                    key={m.id}
                    className={`wt-chat-row ${isOut ? "out" : "in"} ${isSel ? "selected" : ""} ${m.isFlagged ? "flagged" : ""}`}
                    onClick={() => onSelect(m.id)}
                  >
                    {!isOut && (
                      <div className="wt-chat-avatar">
                        {(m.author || "?").charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="wt-chat-bubble">
                      {!isOut && m.author && (
                        <div className="wt-chat-author">{m.author}</div>
                      )}
                      {(m.bodyText || m.summary) && (
                        <div className="wt-chat-body">
                          {m.bodyText || m.summary}
                        </div>
                      )}
                      <ChatAttachments item={m} caseId={caseId} />
                      <div className="wt-chat-meta">
                        {m.timestamp && <span>{m.timestamp}</span>}
                        {m.isFlagged && <span>🚩</span>}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        ) : (
          <div className="wt-itemlist-empty">Pick a thread.</div>
        )}
      </div>
    </div>
  );
};

// Module-level thumbnail cache: `${caseId}|${filename}` → data URL (or null
// if the file isn't a decodable image).  Survives unmount/remount within a
// session so scrolling through 1000s of items doesn't re-decode photos.
const thumbCache = new Map<string, string | null>();
const thumbInflight = new Map<string, Promise<string | null>>();

// Concurrency cap — too many parallel Tauri invokes saturate the Rust
// thread pool and lock up the UI when the Photos grid mounts 60+ tiles
// at once.  Queue beyond N active jobs.
const THUMB_MAX_CONCURRENT = 4;
let thumbActive = 0;
const thumbQueue: Array<() => void> = [];
function thumbAcquire(): Promise<void> {
  return new Promise((resolve) => {
    const tryStart = () => {
      if (thumbActive < THUMB_MAX_CONCURRENT) {
        thumbActive += 1;
        resolve();
      } else {
        thumbQueue.push(tryStart);
      }
    };
    tryStart();
  });
}
function thumbRelease() {
  thumbActive = Math.max(0, thumbActive - 1);
  const next = thumbQueue.shift();
  if (next) next();
}

interface ThumbState {
  thumb: string | null;
  loading: boolean;
  hasMedia: boolean;
}

function useMediaThumb(item: WarrantItem, caseId: string): ThumbState {
  const filename = item.attachments[0];
  const hasMedia = !!filename;
  const key = filename ? `${caseId}|${filename}` : "";
  const cached = key && thumbCache.has(key) ? thumbCache.get(key)! : null;
  const initialResolved = key ? thumbCache.has(key) : true;
  const [thumb, setThumb] = useState<string | null>(cached);
  const [loading, setLoading] = useState<boolean>(hasMedia && !initialResolved);

  useEffect(() => {
    if (!filename) {
      setThumb(null);
      setLoading(false);
      return;
    }
    if (thumbCache.has(key)) {
      setThumb(thumbCache.get(key)!);
      setLoading(false);
      return;
    }
    setLoading(true);
    let cancelled = false;
    let promise = thumbInflight.get(key);
    if (!promise) {
      promise = thumbAcquire()
        .then(() =>
          invoke<string | null>("warrant_get_thumbnail", {
            caseId,
            filename,
          })
        )
        .then((url) => {
          thumbCache.set(key, url ?? null);
          thumbInflight.delete(key);
          thumbRelease();
          return url ?? null;
        })
        .catch(() => {
          thumbCache.set(key, null);
          thumbInflight.delete(key);
          thumbRelease();
          return null;
        });
      thumbInflight.set(key, promise);
    }
    promise.then((url) => {
      if (!cancelled) {
        setThumb(url);
        setLoading(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [key, caseId, filename]);

  return { thumb, loading, hasMedia };
}

// ─── DetailPanel ────────────────────────────────────────────────────────

interface DetailPanelProps {
  item: WarrantItem;
  buckets: Bucket[];
  caseId: string;
  onAssignBucket: (bucketId: string | null) => void;
  onSetNote: (note: string) => void;
  onToggleFlag: (flagged: boolean) => void;
  onOpenMedia: (filename: string) => void;
}

const DetailPanel: React.FC<DetailPanelProps> = ({
  item, buckets, onAssignBucket, onSetNote, onToggleFlag, onOpenMedia,
}) => {
  // Local note state with debounce to avoid hammering Rust on every keystroke.
  const [noteLocal, setNoteLocal] = useState(item.note ?? "");
  useEffect(() => {
    setNoteLocal(item.note ?? "");
  }, [item.id, item.note]);

  useEffect(() => {
    const t = window.setTimeout(() => {
      if ((noteLocal || "") !== (item.note || "")) {
        onSetNote(noteLocal);
      }
    }, 400);
    return () => window.clearTimeout(t);
  }, [noteLocal]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="wt-detail-panel">
      <div className="wt-detail-header">
        <div className="wt-detail-section-label">
          {SECTION_LABELS[item.section] || item.section}
        </div>
        <div className="wt-detail-id" title={item.id}>{item.id}</div>
      </div>

      <div className="wt-detail-actions">
        <label className="wt-flag-toggle">
          <input
            type="checkbox"
            checked={item.isFlagged}
            onChange={(e) => onToggleFlag(e.target.checked)}
          />
          🚩 Flag for review
        </label>

        <div className="wt-bucket-picker">
          <label>Bucket:</label>
          <select
            value={item.bucket || ""}
            onChange={(e) => onAssignBucket(e.target.value || null)}
          >
            <option value="">— Unassigned —</option>
            {buckets.map((b) => (
              <option key={b.id} value={b.id}>{b.name}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="wt-detail-note">
        <label>Notes</label>
        <textarea
          value={noteLocal}
          onChange={(e) => setNoteLocal(e.target.value)}
          placeholder="Add investigator notes (autosaved)…"
          rows={3}
        />
      </div>

      {item.attachments.length > 0 && (
        <div className="wt-detail-attachments">
          <label>Attachments ({item.attachments.length})</label>
          <div className="wt-attachment-grid">
            {item.attachments.map((a) => (
              <button
                key={a}
                className="wt-attachment-tile"
                onClick={() => onOpenMedia(a)}
                title={`Open ${a}`}
              >
                <span className="att-icon">📎</span>
                <span className="att-name">{a}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {item.section === "bio" && (() => {
        const raw = (item.rawFields || {}) as Record<string, unknown>;
        const fields = Array.isArray(raw.fields)
          ? (raw.fields as Array<{ label?: string; value?: string }>)
          : [];
        if (fields.length === 0) return null;
        return (
          <div className="wt-detail-bio-card">
            <div className="wt-detail-bio-header">
              <span className="wt-card-icon">👤</span>
              <h3>Bio</h3>
            </div>
            <dl className="wt-kv wt-kv-bio">
              {fields
                .filter((f) => f && f.label && f.value)
                .map((f, i) => (
                  <React.Fragment key={i}>
                    <dt>{f.label}</dt>
                    <dd>{f.value}</dd>
                  </React.Fragment>
                ))}
            </dl>
          </div>
        );
      })()}

      {/* Email body rendered in main pane (EmailSplitView), not here. */}

      <div className="wt-detail-fields">
        <label>All fields</label>
        <table>
          <tbody>
            {Object.entries(item.rawFields || {})
              // For consolidated bio items, hide the verbose `fields`
              // array — it's already rendered above as a clean KV table.
              .filter(([k]) => !(item.section === "bio" && k === "fields"))
              .map(([k, v]) => (
                <tr key={k}>
                  <td className="key">{k}</td>
                  <td className="val">{renderValue(v)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Gmail-style detail card for `section === "emails"`.
const EmailDetailCard: React.FC<{ item: WarrantItem }> = ({ item }) => {
  const raw = (item.rawFields || {}) as Record<string, any>;
  const fromStr = typeof raw.from === "string" ? raw.from : item.author || "";
  const toStr = typeof raw.to === "string" ? raw.to : item.recipient || "";
  const ccStr = typeof raw.cc === "string" ? raw.cc : "";
  const bccStr = typeof raw.bcc === "string" ? raw.bcc : "";
  const subject = typeof raw.subject === "string" ? raw.subject : "(no subject)";
  const date = typeof raw.date === "string" ? raw.date : item.timestamp || "";
  const messageId = typeof raw.messageId === "string" ? raw.messageId : "";
  const labels = typeof raw.labels === "string"
    ? raw.labels.split(",").map((s: string) => s.trim()).filter(Boolean)
    : [];
  const ips = Array.isArray(raw.receivedIps) ? raw.receivedIps : [];
  const from = parseAddress(fromStr);
  const avatar = (from.name || from.addr || "?").trim().charAt(0).toUpperCase() || "?";

  return (
    <div className="wt-detail-email-card">
      <div className="wt-detail-email-subject">{subject}</div>
      <div className="wt-detail-email-header">
        <div className="wt-detail-email-avatar">{avatar}</div>
        <div className="wt-detail-email-meta">
          <div className="wt-detail-email-from">
            <span className="from-name">{from.name || from.addr}</span>
            {from.name && from.addr && (
              <span className="from-addr">&lt;{from.addr}&gt;</span>
            )}
          </div>
          <div className="wt-detail-email-recipients">
            {toStr && (
              <div><span className="rcpt-k">to</span> <span className="rcpt-v">{toStr}</span></div>
            )}
            {ccStr && (
              <div><span className="rcpt-k">cc</span> <span className="rcpt-v">{ccStr}</span></div>
            )}
            {bccStr && (
              <div><span className="rcpt-k">bcc</span> <span className="rcpt-v">{bccStr}</span></div>
            )}
          </div>
        </div>
        {date && <div className="wt-detail-email-date">{date}</div>}
      </div>
      {labels.length > 0 && (
        <div className="wt-detail-email-labels">
          {labels.map((l) => (
            <span className="wt-email-label" key={l}>{l}</span>
          ))}
        </div>
      )}
      {(messageId || ips.length > 0) && (
        <div className="wt-detail-email-techmeta">
          {messageId && (
            <div><span className="k">Message-ID</span> <code>{messageId}</code></div>
          )}
          {ips.length > 0 && (
            <div><span className="k">Received from</span> <code>{ips.join(", ")}</code></div>
          )}
        </div>
      )}
      <div className="wt-detail-email-body">
        {item.bodyText ? item.bodyText : <span className="muted">(no body extracted)</span>}
      </div>
    </div>
  );
};

function renderValue(v: any): React.ReactNode {
  if (v == null) return <span className="muted">—</span>;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return <pre className="json-blob">{JSON.stringify(v, null, 2)}</pre>;
}

export default WarrantTriageView;
