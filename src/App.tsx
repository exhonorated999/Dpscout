import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { clearThumbnailDataUrlCache } from "./utils/thumbnailLoader";
import { listen } from "@tauri-apps/api/event";
import { StartScreen, DeviceType } from "./components/StartScreen";
import { ScanView } from "./components/ScanView";
import { SettingsView } from "./components/SettingsView";
import { ReportView } from "./components/ReportView";
import { BrowserView } from "./components/BrowserView";
import { KeywordResults } from "./components/KeywordResults";
import { HashResults } from "./components/HashResults";
import { AndroidView } from "./components/AndroidView";
import { IosView } from "./components/IosView";
import { OverviewPanel } from "./components/OverviewPanel";
import { HexagonBackground } from "./components/HexagonBackground";
import { UnifiedDashboard } from "./components/UnifiedDashboard";
import { ScanConfig, ScanModules, KeywordScanConfig } from "./components/ScanConfig";
import { QuestionableApp } from "./types/scanner";
import { AppSettings, defaultSettings } from "./types/settings";
import { MediaFile, MediaScanOptions, defaultMediaScanOptions } from "./types/media";
import { BrowserData } from "./types/browser";
import { KeywordMatch, KeywordScanOptions, KeywordList } from "./types/keyword";
import { ScanProgress as ScanProgressType, ReportFormat } from "./types/report";
import { SystemInfo, DeletedMediaSummary, DeletedMediaDriveResult } from "./types/system";
import { IntrusionScanResults, IntrusionScanOptions, defaultIntrusionScanOptions } from "./types/intrusion";
import { useScanSession } from "./hooks/useScanSession";
import { RegistrationScreen } from "./components/RegistrationScreen";
import { WarrantTriageView } from "./components/warrant/WarrantTriageView";
import { WarrantInvestigationsList } from "./components/warrant/WarrantInvestigationsList";
import { WarrantInvestigationDetail } from "./components/warrant/WarrantInvestigationDetail";
import { ExportProgressPanel } from "./components/warrant/ExportProgressPanel";
import { trackEvent } from "./lib/telemetry";
import "./App.css";

type AppState = "start" | "config" | "scanning" | "results" | "settings" | "media" | "report" | "browser" | "keywords" | "hashes" | "android" | "ios" | "overview" | "warrant" | "warrant_investigation" | "warrant_triage";

interface User {
  username: string;
}

interface LicenseInfo {
  registered: boolean;
  agency_name?: string;
  plan?: string;
  status?: string;
  expires_at?: string;
  days_remaining: number;
  is_expired: boolean;
}

function App() {
  // Agency registration + license check
  const [isAgencyRegistered, setIsAgencyRegistered] = useState<boolean | null>(null); // null = loading
  const [licenseExpired, setLicenseExpired] = useState(false);
  const [licenseDaysRemaining, setLicenseDaysRemaining] = useState(0);
  const [, setCurrentUser] = useState<User | null>(null);

  const [state, setState] = useState<AppState>("start");
  const [apps, setApps] = useState<QuestionableApp[]>([]);
  const [mediaFiles, setMediaFiles] = useState<MediaFile[]>([]);
  const [browsers, setBrowsers] = useState<BrowserData[]>([]);
  const [keywordMatches, setKeywordMatches] = useState<KeywordMatch[]>([]);
  const [hashMatches, setHashMatches] = useState<any[]>([]);
  const [smsMessages, setSmsMessages] = useState<any>(null); // SMS extraction result
  const [intrusionResults, setIntrusionResults] = useState<IntrusionScanResults | null>(null);
  // Deleted-media (unallocated space) triage — one entry per scanned drive.
  const [deletedMediaResults, setDeletedMediaResults] = useState<DeletedMediaDriveResult[]>([]);
  // Active warrant triage case (set after import or "Open" from case list)
  const [warrantCaseId, setWarrantCaseId] = useState<string | null>(null);
  // Active investigation (parent of warrantCaseId, if any) — used for
  // breadcrumb back-navigation from the per-return triage view.
  const [warrantInvestigationId, setWarrantInvestigationId] = useState<string | null>(null);
  const [warrantInvestigationParentForReturn, setWarrantInvestigationParentForReturn] =
    useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStopped, setScanStopped] = useState(false);
  const scanCancelledRef = useRef(false);
  const [isScanningMedia, setIsScanningMedia] = useState(false);
  const [isScanningBrowser, setIsScanningBrowser] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [scanProgress, setScanProgress] = useState<ScanProgressType[]>([]);
  const [currentScanModule, setCurrentScanModule] = useState<string>("");
  const [backupProgress, setBackupProgress] = useState<number>(0); // iOS backup progress percentage
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [isLoadingSystemInfo, setIsLoadingSystemInfo] = useState(false);
  const [selectedDeviceType, setSelectedDeviceType] = useState<DeviceType>('windows');
  const [selectedDrives, setSelectedDrives] = useState<string[]>([]);
  const [scannedModules, setScannedModules] = useState<ScanModules | null>(null);

  // Priority order for selected lists (highest priority first, by list name)
  // Captured when the scan starts, used by results screens to group hits in user order.
  const [hashListPriority, setHashListPriority] = useState<string[]>([]);
  const [keywordListPriority, setKeywordListPriority] = useState<string[]>([]);
  // Map of keyword (lowercase) -> source list name. Built when scan starts.
  const [keywordToListMap, setKeywordToListMap] = useState<Record<string, string>>({});
  
  // Progressive scan session hook
  const { resetSession } = useScanSession();

  // Merge hash matches into media files' flags so FLAGGED tab works
  useEffect(() => {
    if (hashMatches.length === 0 || mediaFiles.length === 0) return;

    // Build a Map of matched file paths (normalized to lowercase backslash)
    const matchedPaths = new Map<string, any>();
    for (const match of hashMatches) {
      const key = (match.filePath || '').toLowerCase().replace(/\//g, '\\');
      if (key) matchedPaths.set(key, match);
    }

    let updated = false;
    const newMedia = mediaFiles.map(mf => {
      const key = mf.filePath.toLowerCase().replace(/\//g, '\\');
      const hashHit = matchedPaths.get(key);
      if (hashHit && !mf.flags.some(f => f.type === 'hash_match')) {
        updated = true;
        return {
          ...mf,
          flags: [...mf.flags, {
            type: 'hash_match' as const,
            severity: 'critical' as const,
            reason: `Hash match: ${hashHit.matchedHash || 'unknown'} (${hashHit.hashType || 'unknown'})`,
            source: hashHit.listName || 'Hash Database',
          }],
        };
      }
      return mf;
    });

    if (updated) {
      console.log('🔗 Merged hash matches into media files for FLAGGED tab');
      setMediaFiles(newMedia);
    }
  }, [hashMatches, mediaFiles.length]);

  // Initialize app on mount — check agency registration + license
  useEffect(() => {
    console.log('🚀 App mounted - initializing');
    initializeApp();
    loadSettings();
  }, []);

  async function initializeApp() {
    try {
      console.log('📁 Initializing app directories');
      await invoke('initialize_app');
      console.log('✅ Directories initialized');
      setCurrentUser({ username: 'forensic' });

      // Check if agency is registered locally
      const registered = await invoke<boolean>('is_agency_registered');
      console.log('📋 Agency registered:', registered);
      setIsAgencyRegistered(registered);

      if (registered) {
        // Check license status from server (with offline fallback)
        try {
          const licenseInfo = await invoke<LicenseInfo>('get_license_status');
          console.log('🔑 License info:', licenseInfo);
          setLicenseExpired(licenseInfo.is_expired);
          setLicenseDaysRemaining(licenseInfo.days_remaining);
        } catch (err) {
          console.warn('⚠️ Failed to check license, allowing access:', err);
          setLicenseExpired(false);
        }
      }
    } catch (error) {
      console.error('❌ Failed to initialize app:', error);
      // Fallback: allow access if init fails
      setIsAgencyRegistered(true);
      setLicenseExpired(false);
    }
  }

  function handleLogout() {
    // Simplified - just reset to start screen
    setState('start');
    // Clear all scan data
    setApps([]);
    setMediaFiles([]);
    setBrowsers([]);
    setKeywordMatches([]);
    resetSession();
  }

  async function loadSettings() {
    try {
      const loaded = await invoke<AppSettings>("get_settings");
      // Ensure all required fields exist with defaults
      const settingsWithDefaults: AppSettings = {
        officer_name: loaded.officer_name || undefined,
        agency_name: loaded.agency_name || undefined,
        badge_number: loaded.badge_number || undefined,
        keywordLists: loaded.keywordLists || [],
        hashLists: loaded.hashLists || [],
        customApps: loaded.customApps || [],
        scanOptions: loaded.scanOptions || {
          enableQuestionableApps: true,
          enableBrowserHistory: false,
          enableKeywordSearch: false,
          enableMediaScan: false,
          enableHashMatching: false,
          scanDepth: 'standard',
          includeSystemDirs: false,
        }
      };
      setSettings(settingsWithDefaults);
    } catch (error) {
      console.error("Failed to load settings:", error);
      // Use default settings if load fails
    }
  }

  async function saveSettings(newSettings: AppSettings) {
    try {
      console.log("Saving settings:", newSettings);
      await invoke("save_app_settings", { settings: newSettings });
      setSettings(newSettings);
      alert("Settings saved successfully!");
    } catch (error) {
      console.error("Failed to save settings:", error);
      console.error("Settings object:", newSettings);
      alert(`Failed to save settings: ${error}`);
    }
  }

  function showScanConfig(deviceType: DeviceType) {
    setSelectedDeviceType(deviceType);
    // All device types go to config screen
    setState("config");
  }

  // Android device scanning
  function captureListPriority(keywordConfig?: KeywordScanConfig, hashConfig?: any) {
    // Hash list priority (enabled lists, in user order)
    const hashLists: Array<{ name: string; enabled: boolean }> = hashConfig?.selectedHashLists || [];
    setHashListPriority(hashLists.filter(l => l.enabled).map(l => l.name));

    // Keyword list priority + keyword -> list map
    const kwLists: Array<{ name: string; keywords: string[]; enabled: boolean }> =
      (keywordConfig as any)?.selectedLists || [];
    setKeywordListPriority(kwLists.filter(l => l.enabled).map(l => l.name));
    const kwMap: Record<string, string> = {};
    for (const list of kwLists) {
      if (!list.enabled) continue;
      for (const kw of list.keywords || []) {
        const k = (kw || '').toLowerCase();
        if (k && !(k in kwMap)) kwMap[k] = list.name; // first list wins (priority order)
      }
    }
    setKeywordToListMap(kwMap);
  }

  async function startAndroidScan(modules: ScanModules, keywordConfig?: KeywordScanConfig, hashConfig?: any) {
    try {
      trackEvent("android_triage_opened");
      captureListPriority(keywordConfig, hashConfig);
      // Get selected Android device from keywordConfig
      const selectedDevice = keywordConfig?.selectedDevice;
      console.log("Starting Android scan, device:", selectedDevice, "modules:", modules, "deviceType:", selectedDeviceType);
      console.log("Hash config:", hashConfig);
      
      if (!selectedDevice) {
        alert('No Android device selected');
        return;
      }

      // Store which modules were scanned
      setScannedModules(modules);
      
      // Go to results dashboard for live updates
      setState("results");
      setIsScanning(true);
      setScanStopped(false);
      scanCancelledRef.current = false;
      // Clear the Rust-side cancellation flag so a previous cancel doesn't
      // immediately kill this new scan run.
      try {
        await invoke('reset_scan_cancellation');
      } catch (err) {
        console.warn('reset_scan_cancellation invoke failed (non-fatal):', err);
      }
      // Clear ALL previous scan state to prevent stale data
      setApps([]);
      setMediaFiles([]);
      setHashMatches([]);
      setBrowsers([]);
      setSmsMessages(null);
      setKeywordMatches([]);
      setCurrentScanModule("Android Device");
      
      const progressList: ScanProgressType[] = [];
      
      // Helper to force UI update between operations — double-rAF ensures
      // the browser actually paints before we continue, preventing white-screen freezes
      const forceUIUpdate = () => new Promise<void>(resolve => {
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      });
      
      // ─── PHASE 1: Device Info (always) ───────────────────────────────
      setIsLoadingSystemInfo(true);
      try {
        const androidDeviceInfo = await invoke("get_android_device_info", { serial: selectedDevice });
        console.log("Android device info collected:", androidDeviceInfo);
        setSystemInfo({
          android_device_info: androidDeviceInfo,
          computer_name: androidDeviceInfo.deviceName || "Unknown",
          os_version: `Android ${androidDeviceInfo.androidVersion}` || "Unknown",
        } as any);
      } catch (error) {
        console.error("Failed to collect Android device info:", error);
      } finally {
        setIsLoadingSystemInfo(false);
      }
      
      await forceUIUpdate();
      
      // ─── PHASE 2: Android Applications ──────────────────────────────
      if (modules.questionableApps && !scanCancelledRef.current) {
        setCurrentScanModule("Android Applications");
        try {
          const androidApps = await invoke<any[]>("get_android_apps", { serial: selectedDevice });
          console.log("Android apps received:", androidApps);
          
          const convertedApps = androidApps.map(app => ({
            name: app.appName || app.packageName || "Unknown App",
            category: "Unknown" as any,
            install_path: app.packageName || "Unknown",
            version: app.version || "Unknown",
            install_date: app.installTime || null,
            publisher: null,
            artifact_paths: [],
            investigative_category: "COMMUNICATIONS",
            function_category: "COMMUNICATIONS",
            confidence: 0.5,
          }));
          
          setApps(convertedApps);
          progressList.push({
            module: "Apps",
            status: "completed",
            count: convertedApps.length,
            details: `Found ${convertedApps.length} apps`
          });
        } catch (error) {
          console.error("Failed to scan Android apps:", error);
          progressList.push({
            module: "Apps",
            status: "failed",
            count: 0,
            details: `Error: ${error}`
          });
        }
        
        await forceUIUpdate();
      }
      
      // ─── PHASE 3: SMS/MMS Messages ──────────────────────────────────
      if (modules.smsMessages && !scanCancelledRef.current) {
        setCurrentScanModule("SMS/MMS Messages");
        try {
          const smsResult = await invoke<any>("extract_android_sms", { 
            deviceId: selectedDevice,
            limit: null
          });
          
          console.log("SMS extraction complete:", smsResult);
          setSmsMessages(smsResult);
          
          progressList.push({
            module: "SMS",
            status: "completed",
            count: smsResult.totalMessages || 0,
            details: `Found ${smsResult.totalMessages || 0} messages in ${smsResult.threads?.length || 0} conversations`
          });
        } catch (error) {
          console.error("Failed to extract SMS:", error);
          progressList.push({
            module: "SMS",
            status: "failed",
            count: 0,
            details: `Error: ${error}`
          });
        }
        
        await forceUIUpdate();
      }
      
      // ─── PHASE 4: CSAM Hash Matching ────────────────────────────────
      if (modules.hashMatching && !scanCancelledRef.current) {
        trackEvent("hash_scan_run");
        setCurrentScanModule("Hash Matching (CSAM)");
        
        // Listen for live hash matches and progress from backend
        const { listen } = await import("@tauri-apps/api/event");
        
        const unlistenHashMatch = await listen("android:hash_match", (event: any) => {
          if (scanCancelledRef.current) return;
          const hashMatch = event.payload;
          console.log("⚠️ LIVE ANDROID HASH MATCH:", hashMatch.fileName);
          setHashMatches(prev => [...prev, hashMatch]);
        });
        
        // Debounce progress updates with rAF to prevent re-render flooding
        let pendingProgressData: any = null;
        let progressRafId: number | null = null;
        const unlistenProgress = await listen("android:hash_scan_progress", (event: any) => {
          if (scanCancelledRef.current) return;
          pendingProgressData = event.payload;
          if (progressRafId === null) {
            progressRafId = requestAnimationFrame(() => {
              progressRafId = null;
              if (pendingProgressData) {
                const data = pendingProgressData;
                setCurrentScanModule(
                  data.status === "discovering" 
                    ? "Hash Matching (CSAM) - Discovering files..."
                    : `Hash Matching (CSAM) - ${data.filesScanned}/${data.totalFiles} files (${data.matchesFound} hits)`
                );
              }
            });
          }
        });
        
        try {
          const selectedHashLists = hashConfig?.selectedHashLists
            ?.filter((list: any) => list.enabled)
            .map((list: any) => list.name) || [];
          
          console.log("Hash scan using lists:", selectedHashLists.length > 0 ? selectedHashLists : "all available lists");
          
          const matches = await invoke<any[]>("scan_android_media_hashes", { 
            serial: selectedDevice,
            selectedHashListIds: selectedHashLists.length > 0 ? selectedHashLists : null
          });
          
          console.log("Hash scan complete:", matches.length, "matches found");
          
          // Set final results (replaces any live-accumulated matches with authoritative list)
          setHashMatches(matches);
          
          progressList.push({
            module: "Hash Matching",
            status: "completed",
            count: matches.length,
            details: matches.length > 0 
              ? `⚠️ CRITICAL: ${matches.length} hash match${matches.length > 1 ? 'es' : ''} found!`
              : `No hash matches found`
          });
        } catch (error) {
          console.error("Failed to scan hashes:", error);
          progressList.push({
            module: "Hash Matching",
            status: "failed",
            count: 0,
            details: `Error: ${error}`
          });
        } finally {
          unlistenHashMatch();
          unlistenProgress();
          if (progressRafId !== null) cancelAnimationFrame(progressRafId);
        }
        
        await forceUIUpdate();
      }

      // ─── PHASE 5: Media Files ───────────────────────────────────────
      if (modules.mediaScan && !scanCancelledRef.current) {
        setCurrentScanModule("Media Files");
        try {
          const androidMediaFiles = await invoke<any[]>("scan_android_media", { serial: selectedDevice });
          
          const convertedMediaFiles = androidMediaFiles.map((file, index) => {
            const mediaType = file.fileType === "Image" ? "image" : file.fileType === "Video" ? "video" : "unknown";
            return {
              id: `android-media-${index}`,
              filePath: file.path || "",
              fileName: file.filename || "Unknown",
              fileSize: Number(file.sizeBytes) || 0,
              extension: file.filename ? file.filename.split('.').pop() || "" : "",
              mediaType: mediaType,
              thumbnailPath: "",
              dateCreated: file.createdDate || "Unknown",
              dateModified: file.modifiedDate || "Unknown",
              flags: [],
              isAndroidFile: true,
              androidSerial: selectedDevice,
            };
          });
          
          setMediaFiles(convertedMediaFiles);
          progressList.push({
            module: "Media",
            status: "completed",
            count: convertedMediaFiles.length,
            details: `Found ${convertedMediaFiles.length} media files`
          });
        } catch (error) {
          console.error("Failed to scan media:", error);
          progressList.push({
            module: "Media",
            status: "failed",
            count: 0,
            details: `Error: ${error}`
          });
        }
        
        // NOTE: The useEffect for merging hash matches into media files will
        // automatically fire when both hashMatches and mediaFiles are populated.
        // No need for manual merge here.
        
        await forceUIUpdate();
      }

      // ─── PHASE 6: Browser History ──────────────────────────────────
      if (modules.browserHistory && !scanCancelledRef.current) {
        setCurrentScanModule("Browser History");
        try {
          const browserData = await invoke<any[]>("scan_android_browsers", { serial: selectedDevice });
          
          console.log("Browser data received:", browserData);
          setBrowsers(browserData as any);
          progressList.push({
            module: "Browser",
            status: "completed",
            count: browserData.reduce((acc: number, browser: any) => acc + (browser.history?.length || 0), 0),
            details: `Found ${browserData.length} browser(s) with history`
          });
        } catch (error) {
          console.error("Failed to scan browsers:", error);
          progressList.push({
            module: "Browser",
            status: "failed",
            count: 0,
            details: `Error: ${error}`
          });
        }
        
        await forceUIUpdate();
      }
      
      setScanProgress(progressList);
      setIsScanning(false);
      setCurrentScanModule("");
      
    } catch (error) {
      console.error("Android scan failed:", error);
      alert(`Android scan failed: ${error}`);
      setIsScanning(false);
      setState("start");
    }
  }

  // iOS device scanning - Progressive scan with live updates
  async function startIosScan(modules: ScanModules, keywordConfig?: KeywordScanConfig, hashConfig?: any) {
    try {
      trackEvent("ios_triage_opened");
      captureListPriority(keywordConfig, hashConfig);
      const selectedDevice = keywordConfig?.selectedDevice;
      const backend: 'afc' | 'mtp' = (keywordConfig as any)?.iosBackend === 'mtp' ? 'mtp' : 'afc';
      console.log(`Starting iOS ${backend.toUpperCase()} scan, device: ${selectedDevice}, modules:`, modules);

      // Build hash list NAMES (enabled only) for matching.
      // The backend (check_hash_filtered) filters by hash_lists.name, not id —
      // and our id field can be either a settings-json string or "db-<int>",
      // neither of which is the canonical list name.
      const enabledHashListIds: string[] = (hashConfig?.selectedHashLists || [])
        .filter((l: any) => l.enabled)
        .map((l: any) => l.name);
      console.log(`[iOS] sending ${enabledHashListIds.length} hash list(s) for matching:`, enabledHashListIds);

      // iOS supports: media scan + hash matching only (for now).
      const iosModules: ScanModules = {
        mediaScan: true,
        hashMatching: true,
        questionableApps: false,
        browserHistory: false,
        keywordSearch: false,
        intrusionDetection: false,
        smsMessages: false,
      };

      setScannedModules(iosModules);
      setState("results");
      setIsScanning(true);
      setApps([]);
      setMediaFiles([]);
      setKeywordMatches([]);
      setHashMatches([]);
      setBrowsers([]);

      const forceUIUpdate = () => new Promise<void>(resolve => setTimeout(resolve, 0));

      // STEP 1: Get device info (best-effort via pymobiledevice3)
      setCurrentScanModule("Detecting iOS Device");
      setIsLoadingSystemInfo(true);
      try {
        if (selectedDevice) {
          const deviceInfo = await invoke<any>("get_ios_device_info_python", { udid: selectedDevice });
          console.log("iOS device info:", deviceInfo);
          setSystemInfo({
            ios_device_info: deviceInfo,
            computer_name: deviceInfo.deviceName || "iOS Device",
            os_version: `iOS ${deviceInfo.iosVersion}`,
          } as any);
        }
      } catch (error) {
        console.warn("Could not get detailed device info:", error);
        setSystemInfo({
          ios_device_info: {},
          computer_name: `iOS Device (${backend.toUpperCase()})`,
          os_version: "iOS",
        } as any);
      } finally {
        setIsLoadingSystemInfo(false);
      }
      await forceUIUpdate();

      // ─── AFC LIVE PATH (default) ──────────────────────────────────────────
      if (backend === 'afc') {
        setCurrentScanModule("Connecting via AFC (live triage)…");
        const mediaAccum: MediaFile[] = [];
        const matchAccum: any[] = [];

        // Classify extension → MediaType for the dashboard tally cards.
        const IMAGE_EXTS = new Set(['jpg','jpeg','png','gif','bmp','webp','heic','heif','tiff','tif','dng','raw','cr2','nef','arw','svg','ico']);
        const VIDEO_EXTS = new Set(['mp4','mov','m4v','avi','mkv','wmv','webm','3gp','3g2','flv','mpg','mpeg','mts','m2ts','hevc']);
        const classify = (ext: string): 'image' | 'video' | 'unknown' => {
          if (IMAGE_EXTS.has(ext)) return 'image';
          if (VIDEO_EXTS.has(ext)) return 'video';
          return 'unknown';
        };

        // Subscribe to streaming events from the Rust sidecar bridge.
        const unlisteners: Array<() => void> = [];

        const offFile = await listen<any>("ios:file_hash", (evt) => {
          const p = evt.payload || {};
          const name: string = p.name || (p.path ? String(p.path).split('/').pop() : '') || 'unknown';
          const ext = (name.includes('.') ? name.split('.').pop() : '')?.toLowerCase() || '';
          const mediaType = classify(ext);
          const sizeNum = typeof p.size === 'number' ? p.size : Number(p.size) || 0;
          mediaAccum.push({
            id: `afc-${mediaAccum.length}-${p.path || name}`,
            filePath: p.path || '',
            fileName: name,
            fileSize: sizeNum,
            extension: ext,
            mediaType,
            thumbnailPath: '',
            dateModified: p.mtime ? String(p.mtime) : undefined,
            sha256Hash: p.sha256,
            md5Hash: p.md5,
            flags: [],
            metadata: undefined,
            isIosAfcFile: true,
            iosUdid: selectedDevice || undefined,
          });
          // Throttle: bulk-flush every 25 items so React doesn't thrash.
          if (mediaAccum.length % 25 === 0) {
            setMediaFiles([...mediaAccum]);
          }
        });
        unlisteners.push(offFile);

        const offMatch = await listen<any>("ios:hash_match", (evt) => {
          matchAccum.push(evt.payload);
          setHashMatches([...matchAccum]);
        });
        unlisteners.push(offMatch);

        // Track current priority phase so progress updates can label it.
        let currentPhase = "starting";
        const phaseLabel: Record<string, string> = {
          starting: "starting",
          images: "images (fast hash pass)",
          videos: "videos (large files — slower)",
          other: "other files",
        };

        const offProgress = await listen<any>("ios:walk_progress", (evt) => {
          const p = evt.payload || {};
          setCurrentScanModule(
            `AFC [${phaseLabel[currentPhase] || currentPhase}]: ${p.filesDone} files • ${(p.bytesDone / 1024 / 1024).toFixed(1)} MB • ${(p.elapsedSec || 0).toFixed(1)}s`
          );
        });
        unlisteners.push(offProgress);

        const offWarn = await listen<any>("ios:walk_warn", (evt) => {
          console.warn("[iOS AFC] walk warn:", evt.payload);
        });
        unlisteners.push(offWarn);

        // Priority-phase indicator: images → videos → other. Tells the
        // operator the fast (image) hash pass is the one actively
        // running, so the empty Hash Matches panel is meaningful.
        const offPhase = await listen<any>("ios:walk_phase", (evt) => {
          const p = evt.payload || {};
          if (p.state === "started") {
            currentPhase = p.phase || "starting";
            setCurrentScanModule(`AFC: hashing ${phaseLabel[currentPhase] || currentPhase}…`);
          } else if (p.state === "complete") {
            console.log(`[iOS AFC] phase ${p.phase} done: ${p.filesDone} files, ${(p.bytesDone / 1024 / 1024).toFixed(1)} MB`);
          }
        });
        unlisteners.push(offPhase);

        // Complete + stopped both finalize.
        const finalize = (label: string) => {
          setMediaFiles([...mediaAccum]);
          setHashMatches([...matchAccum]);
          setIsScanning(false);
          setCurrentScanModule("");
          console.log(`iOS AFC ${label}: ${mediaAccum.length} files, ${matchAccum.length} matches`);
          unlisteners.forEach(u => u());
        };
        const offComplete = await listen<any>("ios:walk_complete", () => finalize("complete"));
        unlisteners.push(offComplete);
        const offStopped = await listen<any>("ios:walk_stopped", () => finalize("stopped"));
        unlisteners.push(offStopped);

        try {
          await invoke("start_ios_live_triage_afc", {
            udid: selectedDevice || null,
            options: {
              roots: ["/DCIM", "/Downloads", "/Recordings"],
              algos: ["sha256"],
              minBytes: 0,
              hashLists: enabledHashListIds,
            },
          });
          console.log("AFC live triage started — events streaming.");
        } catch (e) {
          console.error("AFC live triage failed to start:", e);
          alert(`AFC live triage failed: ${e}\n\nFalling back is available — re-run with the "MTP (legacy)" transport selected.`);
          unlisteners.forEach(u => u());
          setIsScanning(false);
          setState("start");
        }
        return; // Event-driven from here on.
      }

      // ─── MTP LEGACY PATH ──────────────────────────────────────────────────
      // STEP 2: Copy media files from iPhone via MTP
      setCurrentScanModule("Copying Media Files from iPhone (via MTP)...");
      console.log("Starting MTP media copy...");

      let mtpResult: any;
      try {
        mtpResult = await invoke<any>("scan_ios_mtp_media");
        console.log(`MTP copy complete: ${mtpResult.totalFiles} files, ${(mtpResult.totalSizeBytes / 1024 / 1024).toFixed(1)} MB`);
        console.log("Temp directory:", mtpResult.tempDirectory);
      } catch (error) {
        console.error("MTP media copy failed:", error);
        alert(`Failed to access iPhone media via MTP.\n\n${error}\n\nEnsure:\n1. iPhone is unlocked\n2. You tapped "Trust This Computer"\n3. iPhone appears in File Explorer under This PC`);
        setIsScanning(false);
        setState("start");
        return;
      }
      await forceUIUpdate();

      // STEP 3: Display media files
      if (mtpResult.mediaFiles && mtpResult.mediaFiles.length > 0) {
        setCurrentScanModule(`Found ${mtpResult.totalFiles} media files — preparing list...`);
        const convertedMedia = mtpResult.mediaFiles.map((file: any) => ({
          path: file.filePath,
          name: file.fileName,
          size: file.fileSize,
          type: file.fileName.split('.').pop()?.toLowerCase() || 'unknown',
          created: null,
          modified: null,
          accessed: null,
          metadata: { source: 'mtp', fileType: file.fileType },
          thumbnail: null,
          flags: [],
        }));
        setMediaFiles(convertedMedia);
        console.log(`Loaded ${convertedMedia.length} media files into results`);
      }
      await forceUIUpdate();

      // STEP 4: Hash scan on copied media files
      setCurrentScanModule("Hash Scan (Media Files)");
      try {
        console.log("Running hash scan on MTP media at:", mtpResult.tempDirectory);
        const hashResults = await invoke<any[]>('scan_for_hash_matches', {
          options: {
            scanPaths: [mtpResult.tempDirectory],
            maxFileSize: 524288000, // 500MB
            minFileSize: 50000, // 50KB — filters system icons that pollute VIC DB
          }
        });
        console.log("Hash scan complete:", hashResults.length, "matches");
        if (hashResults.length > 0) {
          setHashMatches(hashResults);
        }
      } catch (error) {
        console.error("Hash scan failed:", error);
      }
      await forceUIUpdate();

      setIsScanning(false);
      setCurrentScanModule("");
      console.log("iOS MTP scan complete");

    } catch (error) {
      console.error("iOS scan failed:", error);
      setIsScanning(false);
      alert(`iOS scan failed: ${error}`);
      setState("start");
    }
  }

  // New progressive scan function using events
  // Disabled for now - kept for future use
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async function startProgressiveScan(modules: ScanModules, keywordConfig?: KeywordScanConfig) {
    try {
      // Reset previous session
      resetSession();
      setState("scanning");
      
      // Start the progressive scan which will emit events
      await invoke("start_progressive_scan", {
        scanApps: modules.questionableApps,
        scanBrowser: modules.browserHistory,
        scanKeywords: modules.keywordSearch,
        scanMedia: modules.mediaScan,
      });
      
      // Transition to results view
      setState("results");
    } catch (error) {
      console.error("Failed to start progressive scan:", error);
      alert(`Scan failed: ${error}`);
      setState("start");
    }
  }

  async function startScan(modules: ScanModules, keywordConfig?: KeywordScanConfig, hashConfig?: any) {
    // Capture priority order (enabled lists only, in user-chosen order) for results grouping.
    captureListPriority(keywordConfig, hashConfig);

    // Handle Android scanning
    if (selectedDeviceType === 'android') {
      await startAndroidScan(modules, keywordConfig, hashConfig);
      return;
    }
    
    // Handle iOS scanning  
    if (selectedDeviceType === 'ios') {
      await startIosScan(modules, keywordConfig, hashConfig);
      return;
    }
    
    // Windows and USB drive scanning only
    if (selectedDeviceType !== 'windows' && selectedDeviceType !== 'usb') {
      alert('Invalid device type selected');
      return;
    }
    
    // Store selected drives if provided in keywordConfig
    if (keywordConfig?.selectedDrives) {
      setSelectedDrives(keywordConfig.selectedDrives);
    }
    
    // Store which modules were scanned
    setScannedModules(modules);
    
    // Track scan start time
    const scanStartTime = Date.now();
    
    // Go directly to results dashboard for live updates
    setState("results");
    setIsScanning(true);
    setApps([]);
    setBrowsers([]);
    setMediaFiles([]);
    setKeywordMatches([]);
    setHashMatches([]);
    setIntrusionResults(null);
    setDeletedMediaResults([]);
    setSystemInfo(null);
    scanCancelledRef.current = false;
    setScanStopped(false);
    // Clear the Rust-side cancellation flag so a previous cancel doesn't
    // immediately kill this new scan run.
    try {
      await invoke('reset_scan_cancellation');
    } catch (err) {
      console.warn('reset_scan_cancellation invoke failed (non-fatal):', err);
    }
    setCurrentScanModule("System Information");
    
    const progressList: ScanProgressType[] = [];

    try {
      // Collect device info — lightweight for USB, full system info for Windows
      setIsLoadingSystemInfo(true);
      try {
        if (selectedDeviceType === 'usb' && keywordConfig?.selectedDrives && keywordConfig.selectedDrives.length > 0) {
          // USB mode: skip heavy system info, just get drive name/size (instant)
          const drive = keywordConfig.selectedDrives[0].replace(':', '').replace('\\', '').trim();
          const usbInfo = await invoke("get_usb_device_info", { driveLetter: drive });
          const minimalSysInfo: any = {
            scan_id: crypto.randomUUID?.() || Date.now().toString(),
            scan_timestamp: new Date().toISOString(),
            computer_name: "USB Scan",
            os_version: "",
            usb_device_info: usbInfo,
          };
          setSystemInfo(minimalSysInfo);
          console.log("USB device info collected (instant):", usbInfo);
        } else {
          // Windows mode: collect full system info (in background, don't block scans)
          const sysInfoPromise = invoke<SystemInfo>("get_system_info").then(sysInfo => {
            setSystemInfo(sysInfo);
            console.log("System info collected:", sysInfo);
          }).catch(error => {
            console.error("Failed to collect system info:", error);
          });
          // Don't await — let it complete in background while scans start
        }
      } catch (error) {
        console.error("Failed to collect device info:", error);
      } finally {
        setIsLoadingSystemInfo(false);
      }

      // Scan Questionable Apps
      if (modules.questionableApps && !scanCancelledRef.current) {
        setCurrentScanModule("Questionable Applications");
        const appProgress: ScanProgressType = {
          moduleId: "apps",
          moduleName: "Questionable Applications",
          status: "scanning",
          currentItem: "Scanning registry and directories...",
          itemsProcessed: 0,
          totalItems: 100,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(appProgress);
        setScanProgress([...progressList]);

        const result = await invoke<QuestionableApp[]>("scan_questionable_applications");
        console.log("APP SCAN RESULT:", result);
        console.log("Number of apps found:", result.length);
        if (result.length > 0) {
          console.log("First app:", result[0]);
          console.log("Categories in first 10 apps:", result.slice(0, 10).map(a => ({ 
            name: a.name, 
            investigative: a.investigative_category,
            function: a.function_category,
            confidence: a.confidence 
          })));
          
          // Statistics
          const categoryStats: Record<string, number> = {};
          result.forEach(app => {
            categoryStats[app.investigative_category] = (categoryStats[app.investigative_category] || 0) + 1;
          });
          console.log("Category breakdown:", categoryStats);
          console.log("High confidence (>0.7):", result.filter(a => a.confidence > 0.7).length);
          console.log("Unknown apps:", result.filter(a => a.investigative_category === "UNKNOWN").length);
        }
        setApps(result);
        appProgress.status = "complete";
        appProgress.percentage = 100;
        setScanProgress([...progressList]);
      }

      // Scan Browser History
      if (modules.browserHistory && !scanCancelledRef.current) {
        setCurrentScanModule("Browser History");
        const browserProgress: ScanProgressType = {
          moduleId: "browser",
          moduleName: "Browser History",
          status: "scanning",
          currentItem: "Extracting browser data...",
          itemsProcessed: 0,
          totalItems: 100,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(browserProgress);
        setScanProgress([...progressList]);

        // For USB/external drive scans, only scan browser data ON those drives (not the host C:)
        // For Windows scans of C:, use host system env vars (default)
        const isExternalDriveScan = selectedDeviceType === 'usb' || 
          (selectedDeviceType === 'windows' && keywordConfig?.selectedDrives && 
           keywordConfig.selectedDrives.length > 0 && 
           !keywordConfig.selectedDrives.some((d: string) => d.toUpperCase().startsWith('C')));
        
        const result = await invoke<BrowserData[]>("scan_browser_history", {
          targetDrives: isExternalDriveScan && keywordConfig?.selectedDrives 
            ? keywordConfig.selectedDrives 
            : null
        });
        setBrowsers(result);
        browserProgress.status = "complete";
        browserProgress.percentage = 100;
        setScanProgress([...progressList]);
      }

      // Scan Keywords
      if (modules.keywordSearch && !scanCancelledRef.current) {
        setCurrentScanModule("Keyword Search");
        const keywordProgress: ScanProgressType = {
          moduleId: "keywords",
          moduleName: "Keyword Search",
          status: "scanning",
          currentItem: "Loading keyword lists...",
          itemsProcessed: 0,
          totalItems: 100,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(keywordProgress);
        setScanProgress([...progressList]);

        // Use provided config or defaults
        const config = keywordConfig || {
          scanPaths: [],
          scanFileNames: true,
          scanFilePaths: true,
          scanFileContents: false,
          selectedLists: [],
        };

        // Use selected lists from config, or load all lists
        let keywordLists: KeywordList[];
        if (config.selectedLists && config.selectedLists.length > 0) {
          // Filter to only enabled lists from the selection
          keywordLists = config.selectedLists
            .filter(list => list.enabled)
            .map(list => ({
              name: list.name,
              keywords: list.keywords,
              enabled: list.enabled
            }));
        } else {
          // Load all lists if none were pre-selected
          keywordLists = await invoke<KeywordList[]>("load_keyword_lists");
        }
        
        if (keywordLists.length === 0) {
          alert("No keyword lists selected! Please select at least one keyword list.");
        } else {
          // Get scan paths based on selected drives
          let scanPaths: string[];
          if (config.selectedDrives && config.selectedDrives.length > 0) {
            scanPaths = await invoke<string[]>("get_scan_paths_for_selected_drives", { drives: config.selectedDrives });
          } else {
            scanPaths = await invoke<string[]>("get_keyword_scan_paths");
          }
          
          const totalKeywords = keywordLists.reduce((sum, list) => sum + list.keywords.length, 0);
          keywordProgress.currentItem = `Preparing to scan ${config.selectedDrives?.length || 0} drive(s) with ${totalKeywords} keywords from ${keywordLists.length} list(s)...`;
          setScanProgress([...progressList]);

          // Scan for keywords with progress
          const options: KeywordScanOptions = {
            scanPaths,
            keywordLists,
            scanFileNames: config.scanFileNames,
            scanFilePaths: config.scanFilePaths,
            scanFileContents: config.scanFileContents,
            caseSensitive: false,
            maxFileSizeMb: 10,
            fileExtensions: [],
          };

          // Setup event listener for progress updates
          const { listen } = await import("@tauri-apps/api/event");
          let lastKwProgressUpdate = 0;
          const unlisten = await listen("scan:module_progress", (event: any) => {
            const data = event.payload;
            if (data.module === "keywords") {
              const now = Date.now();
              if (now - lastKwProgressUpdate < 300) return; // Throttle
              lastKwProgressUpdate = now;
              keywordProgress.percentage = data.progress;
              keywordProgress.currentItem = data.current_item || "Scanning...";
              keywordProgress.itemsProcessed = data.items_processed || 0;
              keywordProgress.totalItems = data.total_items || 0;
              setScanProgress([...progressList]);
            }
          });

          try {
            const result = await invoke<KeywordMatch[]>("scan_keywords_progressive", { options });
            setKeywordMatches(result);
            keywordProgress.status = "complete";
            keywordProgress.percentage = 100;
          } catch (error) {
            keywordProgress.status = "error";
            console.error("Keyword scan error:", error);
          } finally {
            unlisten();
          }
          
          setScanProgress([...progressList]);
        }
      }

      // Scan Intrusion Detection (runs before media scan for faster results)
      if (modules.intrusionDetection && !scanCancelledRef.current) {
        trackEvent("intrusion_scan_run");
        setCurrentScanModule("Intrusion Detection");
        const intrusionProgress: ScanProgressType = {
          moduleId: "intrusion",
          moduleName: "Intrusion Detection",
          status: "scanning",
          currentItem: "Analyzing event logs and persistence mechanisms...",
          itemsProcessed: 0,
          totalItems: 100,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(intrusionProgress);
        setScanProgress([...progressList]);

        try {
          const options: IntrusionScanOptions = defaultIntrusionScanOptions;
          const result = await invoke<IntrusionScanResults>("scan_intrusion_progressive", { options });
          setIntrusionResults(result);
          intrusionProgress.status = "complete";
          intrusionProgress.percentage = 100;
        } catch (error) {
          intrusionProgress.status = "error";
          console.error("Intrusion detection scan error:", error);
        }
        
        setScanProgress([...progressList]);
      }

      // Deleted Media Detection (unallocated space) — read-only raw volume triage.
      // Runs per selected drive and needs an elevated token.
      if (modules.deletedMedia && !scanCancelledRef.current) {
        trackEvent("deleted_media_scan_run");
        setCurrentScanModule("Deleted Media Detection");

        const drivesToScan = (keywordConfig?.selectedDrives && keywordConfig.selectedDrives.length > 0)
          ? keywordConfig.selectedDrives
          : selectedDrives;

        const dmProgress: ScanProgressType = {
          moduleId: "deleted_media",
          moduleName: "Deleted Media Detection",
          status: "scanning",
          currentItem: "Reading filesystem metadata...",
          itemsProcessed: 0,
          totalItems: 100,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(dmProgress);
        setScanProgress([...progressList]);

        const { listen } = await import("@tauri-apps/api/event");
        const unlistenDm = await listen<any>("deleted-media:progress", (event) => {
          const p = event.payload;
          dmProgress.percentage = p.percent;
          dmProgress.currentItem = p.phase;
          dmProgress.itemsProcessed = p.percent;
          setScanProgress([...progressList]);
        });

        try {
          const results: DeletedMediaDriveResult[] = [];
          for (const rawDrive of drivesToScan) {
            if (scanCancelledRef.current) break;
            const letter = rawDrive.replace(':', '').replace('\\', '').trim();
            try {
              const summary = await invoke<DeletedMediaSummary>("scan_deleted_media", {
                driveLetter: letter,
                options: {
                  scanMetadataResidue: true,
                  scanUnallocated: true,
                  maxBytesToScan: 0,
                  maxNamedFiles: 5000,
                },
              });
              results.push({ driveLetter: letter, summary, error: null });
            } catch (error) {
              const msg = String(error);
              console.error(`Deleted-media scan failed on ${letter}:`, msg);
              results.push({ driveLetter: letter, summary: null, error: msg });
            }
            // Publish incrementally so the dashboard fills in per drive.
            setDeletedMediaResults([...results]);
          }
          dmProgress.status = results.some(r => r.summary) ? "complete" : "error";
          dmProgress.percentage = 100;
        } catch (error) {
          dmProgress.status = "error";
          console.error("Deleted media detection error:", error);
        } finally {
          unlistenDm();
        }

        setScanProgress([...progressList]);
      }

      // Scan for CSAM Hash Matches (INDEPENDENT of media scan)
      if (modules.hashMatching && !scanCancelledRef.current) {
        trackEvent("hash_scan_run");
        setCurrentScanModule("CSAM Hash Matching");
        const hashProgress: ScanProgressType = {
          moduleId: "hash_matching",
          moduleName: "CSAM Hash Matching",
          status: "scanning",
          currentItem: "Checking files against CSAM hash database...",
          itemsProcessed: 0,
          totalItems: 0,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(hashProgress);
        setScanProgress([...progressList]);

        // Setup event listeners for progress updates AND live hash matches
        const { listen } = await import("@tauri-apps/api/event");
        
        // Listen for live hash matches (CRITICAL for immediate triage)
        const unlistenHashMatch = await listen("scan:hash_match", (event: any) => {
          if (scanCancelledRef.current) return; // Stop accumulating after user cancelled
          const hashMatch = event.payload;
          console.log("⚠️ LIVE HASH MATCH:", hashMatch.fileName);
          // Add match immediately to state for live display
          setHashMatches(prevMatches => [...prevMatches, hashMatch]);
        });
        
        const unlisten = await listen("scan:module_progress", (event: any) => {
          const data = event.payload;
          if (data.module === "hash_matching") {
            hashProgress.percentage = data.progress;
            hashProgress.currentItem = data.current_item || "Checking...";
            hashProgress.itemsProcessed = data.items_processed || 0;
            hashProgress.totalItems = data.total_items || 0;
            setScanProgress(prev => [...prev.filter(p => p.moduleId !== "hash_matching"), hashProgress]);
          }
        });

        try {
          // Get scan paths for hash scanning
          // Hash scanner uses its own tiered directory traversal (Tier 1/2/3)
          // which expects DRIVE ROOTS (e.g., "C:\"), not user subdirectories.
          // The keyword scan paths (Downloads, Pictures, etc.) are too narrow.
          let hashScanPaths: string[];
          if (keywordConfig?.selectedDrives && keywordConfig.selectedDrives.length > 0) {
            // Convert drive letters to root paths for the tiered scanner
            hashScanPaths = keywordConfig.selectedDrives.map((d: string) => {
              if (d.endsWith('\\') || d.endsWith('/')) return d;
              if (d.endsWith(':')) return d + '\\';
              return d + ':\\';
            });
          } else {
            // Default: scan C:\ drive root
            hashScanPaths = ['C:\\'];
          }
          
          const selectedHashListNames = hashConfig?.selectedHashLists
            ?.filter((list: any) => list.enabled)
            .map((list: any) => list.name) || [];
          
          console.log("Hash scan using lists:", selectedHashListNames.length > 0 ? selectedHashListNames : "all available lists");
          
          const hashScanOptions = {
            scanPaths: hashScanPaths,
            maxFileSize: 500 * 1024 * 1024, // 500MB max per file
            minFileSize: 50000, // 50KB — filters system icons that pollute VIC DB
            scanMode: selectedDeviceType === 'usb' ? 'usb' : 'windows',
            selectedHashListNames: selectedHashListNames.length > 0 ? selectedHashListNames : null,
          };
          
          const matches = await invoke<any[]>("scan_for_hash_matches", { options: hashScanOptions });
          console.log("Hash scan complete:", matches.length, "matches found");
          
          // Store hash matches
          setHashMatches(matches);
          
          hashProgress.status = "complete";
          hashProgress.percentage = 100;
        } catch (error) {
          hashProgress.status = "error";
          console.error("Hash scan error:", error);
          alert(`Hash scan failed: ${error}`);
        } finally {
          unlisten();
          unlistenHashMatch();
        }
        
        setScanProgress([...progressList]);
      }

      // Scan Media (runs LAST because it takes the longest time)
      if (modules.mediaScan && !scanCancelledRef.current) {
        setCurrentScanModule("Media Files");
        const mediaProgress: ScanProgressType = {
          moduleId: "media",
          moduleName: "Media Files",
          status: "scanning",
          currentItem: "Preparing to scan for images and videos...",
          itemsProcessed: 0,
          totalItems: 0,
          percentage: 0,
          estimatedTimeRemaining: 0,
          startTime: Date.now(),
          itemsPerSecond: 0,
        };
        progressList.push(mediaProgress);
        setScanProgress([...progressList]);

        // Setup event listener for progress updates
        const { listen } = await import("@tauri-apps/api/event");
        
        // Listen for individual media files as they're found
        let mediaBatch: MediaFile[] = [];
        let mediaFlushTimer: ReturnType<typeof setTimeout> | null = null;
        const unlistenMediaFound = await listen("scan:media_found", (event: any) => {
          const mediaFile = event.payload as MediaFile;
          mediaBatch.push(mediaFile);
          // Flush batch every 500ms to avoid per-file re-renders
          if (!mediaFlushTimer) {
            mediaFlushTimer = setTimeout(() => {
              const batch = mediaBatch.splice(0);
              if (batch.length > 0) {
                setMediaFiles(prevFiles => [...prevFiles, ...batch]);
              }
              mediaFlushTimer = null;
            }, 500);
          }
        });
        
        let lastMediaProgressUpdate = 0;
        const unlisten = await listen("scan:module_progress", (event: any) => {
          const data = event.payload;
          if (data.module === "media") {
            const now = Date.now();
            if (now - lastMediaProgressUpdate < 300) return; // Throttle to max ~3 updates/sec
            lastMediaProgressUpdate = now;
            mediaProgress.percentage = data.progress;
            mediaProgress.currentItem = data.current_item || "Scanning...";
            mediaProgress.itemsProcessed = data.items_processed || 0;
            mediaProgress.totalItems = data.total_items || 0;
            setScanProgress([...progressList]);
          }
        });

        try {
          // Get scan paths based on selected drives
          let scanPaths: string[];
          if (keywordConfig?.selectedDrives && keywordConfig.selectedDrives.length > 0) {
            scanPaths = await invoke<string[]>("get_scan_paths_for_selected_drives", { drives: keywordConfig.selectedDrives });
          } else {
            // Get default scan paths (Documents, Downloads, Desktop, Pictures, Videos, Recycle Bin, etc.)
            scanPaths = await invoke<string[]>("get_keyword_scan_paths");
          }
          
          const mediaOptions: MediaScanOptions = {
            ...defaultMediaScanOptions,
            scanPaths: scanPaths,
            checkKeywords: modules.keywordSearch,
          };
          
          const result = await invoke<MediaFile[]>("scan_media_progressive", { options: mediaOptions });
          // Final result will contain all files, but we've already been adding them progressively
          // Only update if we didn't get progressive updates
          if (mediaFiles.length === 0) {
            setMediaFiles(result);
          }
          mediaProgress.status = "complete";
          mediaProgress.percentage = 100;
        } catch (error) {
          mediaProgress.status = "error";
          console.error("Media scan error:", error);
        } finally {
          unlisten();
          unlistenMediaFound();
          // Flush any remaining media batch
          if (mediaFlushTimer) clearTimeout(mediaFlushTimer);
          if (mediaBatch.length > 0) {
            const remaining = mediaBatch.splice(0);
            setMediaFiles(prevFiles => [...prevFiles, ...remaining]);
          }
        }
        
        setScanProgress([...progressList]);
      }

      // Scan complete - calculate duration and update system info
      const scanEndTime = Date.now();
      const scanDurationSecs = Math.floor((scanEndTime - scanStartTime) / 1000);
      
      // Update system info with scan duration
      // Use functional updater to avoid stale closure — systemInfo in this
      // closure is from when handleStartScan was created, not the current value
      setSystemInfo(prev => prev ? { ...prev, scan_duration_secs: scanDurationSecs } : prev);
      
      console.log(`✓ Scan completed in ${scanDurationSecs} seconds`);
      setCurrentScanModule("");
    } catch (error) {
      if (!scanCancelledRef.current) {
        console.error("Scan failed:", error);
        alert(`Scan failed: ${error}`);
        setState("start");
        setScanProgress([]);
      }
      setCurrentScanModule("");
    } finally {
      setIsScanning(false);
    }
  }

  async function handleStopScan() {
    // If already stopping, ignore double-clicks
    if (scanCancelledRef.current) {
      console.log('[Cancel Scan] Already in progress, ignoring duplicate click');
      return;
    }
    scanCancelledRef.current = true;
    setScanStopped(true);
    setCurrentScanModule('Stopping scan...');
    try {
      await invoke('cancel_scan');
    } catch (err) {
      console.warn('cancel_scan invoke failed:', err);
    }
    // Safety net: if the Rust scan refuses to return within 5 seconds
    // (e.g. a scan module that doesn't honor cancellation), force the UI
    // back to a stopped state so the user isn't stuck on "Stopping scan...".
    // The scan promise's finally block will still fire whenever Rust eventually
    // returns; setIsScanning(false) is idempotent.
    setTimeout(() => {
      // Only force-stop if we're still in cancelled+scanning state
      if (scanCancelledRef.current) {
        console.warn('[Cancel Scan] Grace period expired, forcing UI to stopped state');
        setIsScanning(false);
        setCurrentScanModule('');
      }
    }, 5000);
  }

  function handleNewScan() {
    setState("start");
    setApps([]);
  }

  function openSettings() {
    setState("settings");
  }

  function openWarrant() {
    setState("warrant");
  }

  function closeWarrant() {
    setWarrantInvestigationId(null);
    setState("start");
  }

  function openInvestigation(id: string) {
    setWarrantInvestigationId(id);
    setState("warrant_investigation");
  }

  function backToInvestigationList() {
    setWarrantInvestigationId(null);
    setState("warrant");
  }

  async function openReturnFromInvestigation(caseId: string) {
    setWarrantCaseId(caseId);
    // Track the parent investigation for the breadcrumb in the triage UI.
    if (warrantInvestigationId) {
      setWarrantInvestigationParentForReturn(warrantInvestigationId);
    } else {
      try {
        const owner = await invoke<string | null>('warrant_find_investigation_for_return', {
          caseId,
        });
        setWarrantInvestigationParentForReturn(owner);
      } catch {
        setWarrantInvestigationParentForReturn(null);
      }
    }
    setState("warrant_triage");
  }

  function closeWarrantTriage() {
    setWarrantCaseId(null);
    if (warrantInvestigationParentForReturn) {
      // Go back to the parent investigation detail.
      const parent = warrantInvestigationParentForReturn;
      setWarrantInvestigationParentForReturn(null);
      setWarrantInvestigationId(parent);
      setState("warrant_investigation");
    } else {
      setState("warrant");
    }
  }

  async function handleWarrantExport(caseId: string) {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        title:
          "Pick a parent folder (e.g. the detective's USB root) — Scout will create a uniquely-named report folder inside it.",
        directory: true,
        multiple: false,
      });
      if (!selected || typeof selected !== "string") return null;

      const result = await invoke<{ reportDir: string }>("warrant_export_report", {
        caseId,
        destDir: selected,
      });
      const openIt = window.confirm(
        `Report exported to:\n${result.reportDir}\n\nOpen the folder now?`
      );
      if (openIt) {
        try {
          await invoke("open_in_explorer", { path: result.reportDir });
        } catch (e) {
          console.warn("[warrant] open_in_explorer failed:", e);
        }
      }
      return result;
    } catch (err: any) {
      alert(`Export failed:\n${String(err)}`);
      console.error("[warrant] export failed:", err);
      throw err;
    }
  }

  async function closeSettings() {
    // Re-check license status when leaving settings (user may have activated a key)
    try {
      const licenseInfo = await invoke<LicenseInfo>('get_license_status');
      setLicenseExpired(licenseInfo.is_expired);
      setLicenseDaysRemaining(licenseInfo.days_remaining);
    } catch (err) {
      console.warn('Failed to refresh license on settings close:', err);
    }
    if (mediaFiles.length > 0) setState("media");
    else if (apps.length > 0) setState("results");
    else setState("start");
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  function openAndroidScan() {
    setState("android");
  }

  async function startMediaScan() {
    setState("media");
    setIsScanningMedia(true);
    setMediaFiles([]);

    try {
      // Get default scan paths (Documents, Downloads, Desktop, Pictures, Videos, etc.)
      const scanPaths = await invoke<string[]>("get_keyword_scan_paths");
      
      const options: MediaScanOptions = {
        ...defaultMediaScanOptions,
        scanPaths: scanPaths,
        checkKeywords: false,
      };
      const result = await invoke<MediaFile[]>("scan_media", { options });
      setMediaFiles(result);
    } catch (error) {
      console.error("Media scan failed:", error);
      alert(`Media scan failed: ${error}`);
    } finally {
      setIsScanningMedia(false);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async function clearThumbnailCache() {
    try {
      await invoke("clear_thumbnails");
      clearThumbnailDataUrlCache();
      alert("Thumbnail cache cleared");
    } catch (error) {
      console.error("Failed to clear cache:", error);
      alert(`Failed to clear cache: ${error}`);
    }
  }

  async function startBrowserScan() {
    setState("browser");
    setIsScanningBrowser(true);
    setBrowsers([]);

    try {
      const result = await invoke<BrowserData[]>("scan_browser_history", { targetDrives: null });
      setBrowsers(result);
    } catch (error) {
      console.error("Browser scan failed:", error);
      alert(`Browser scan failed: ${error}`);
    } finally {
      setIsScanningBrowser(false);
    }
  }

  async function startKeywordScan() {
    setState("keywords");
    setIsScanning(true);
    setKeywordMatches([]);

    try {
      // Load keyword lists
      const keywordLists = await invoke<KeywordList[]>("load_keyword_lists");
      
      if (keywordLists.length === 0) {
        alert("No keyword lists found! Please add .txt files to the keyword_lists folder.");
        setState("start");
        setIsScanning(false);
        return;
      }

      // Get default scan paths
      const scanPaths = await invoke<string[]>("get_keyword_scan_paths");

      // Scan for keywords
      const options: KeywordScanOptions = {
        scanPaths,
        keywordLists,
        scanFileNames: true,
        scanFilePaths: true,
        scanFileContents: false,
        caseSensitive: false,
        maxFileSizeMb: 10,
        fileExtensions: [],
      };

      const result = await invoke<KeywordMatch[]>("scan_keywords", { options });
      setKeywordMatches(result);
    } catch (error) {
      console.error("Keyword scan failed:", error);
      alert(`Keyword scan failed: ${error}`);
    } finally {
      setIsScanning(false);
    }
  }

  function exportBrowserData(browser: BrowserData) {
    alert(`Exporting browser data for ${browser.browserName} (${browser.profileName})...\n\nThis will generate a comprehensive report including:\n- ${browser.history.length} history entries\n- ${browser.bookmarks.length} bookmarks\n- ${browser.credentials.length} saved credentials`);
    // TODO: Implement actual export via Tauri command
  }

  function openReport() {
    setState("report");
  }

  function closeReport() {
    if (mediaFiles.length > 0) setState("media");
    else if (apps.length > 0) setState("results");
    else setState("start");
  }

  async function exportReport(format: ReportFormat) {
    try {
      alert(`Exporting report as ${format.toUpperCase()}...\n\nThis feature will generate a complete forensic report including:\n- System information\n- All detected applications\n- Flagged media files\n- Hash matches\n- Timestamps and metadata`);
      // TODO: Implement actual report export via Tauri command
    } catch (error) {
      console.error("Export failed:", error);
      alert(`Failed to export report: ${error}`);
    }
  }

  // ========================================
  // REGISTRATION + LICENSE GATE
  // ========================================

  // Loading state while checking registration
  if (isAgencyRegistered === null) {
    return (
      <>
        <HexagonBackground />
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          height: '100vh', color: 'var(--color-text-secondary)', fontSize: '18px'
        }}>
          Initializing...
        </div>
      </>
    );
  }

  // Show registration screen if not registered
  if (!isAgencyRegistered) {
    return (
      <RegistrationScreen
        onRegistrationComplete={() => {
          setIsAgencyRegistered(true);
          setLicenseExpired(false);
          setLicenseDaysRemaining(60);
        }}
      />
    );
  }

  // If license expired, restrict navigation. Settings is always reachable.
  // The Warrant Triage flow stays open as a "free forever" tier — but only the
  // Meta + Google parsers, enforced in WarrantLanding's provider picker
  // (POST_EXPIRY_ALLOWED). All other modules redirect back to Settings.
  const POST_EXPIRY_ALLOWED_STATES = [
    'settings',
    'start',
    'warrant',
    'warrant_investigation',
    'warrant_triage',
  ];
  if (licenseExpired && !POST_EXPIRY_ALLOWED_STATES.includes(state)) {
    setState('settings');
  }
  
  // Debug logging removed — was causing console flood on every render

  // ========================================
  // AFTER REGISTRATION - STATE ROUTING
  // ========================================

  // Scanning state removed - now scans happen live in the results dashboard
  // if (state === "scanning") {
  //   if (scanProgress.length > 0) {
  //     return (
  //       <>
  //         <HexagonBackground />
  //         <ScanProgress progress={scanProgress} />
  //         {showProcessingOverlay && <ProcessingOverlay message={processingMessage} />}
  //       </>
  //     );
  //   }
  // }

  if (state === "config") {
    return (
      <>
        <HexagonBackground />
        <ScanConfig
          onStartScan={startScan}
          onBack={() => setState("start")}
          deviceType={selectedDeviceType}
        />
      </>
    );
  }

  if (state === "settings") {
    return (
      <>
        <HexagonBackground />
        <SettingsView 
          settings={settings} 
          onSave={saveSettings} 
          onClose={closeSettings} 
        />
      </>
    );
  }

  if (state === "report") {
    return (
      <>
        <HexagonBackground />
        <ReportView
          apps={apps}
          media={mediaFiles}
          onExport={exportReport}
          onClose={closeReport}
        />
      </>
    );
  }

  // Media view moved to UnifiedDashboard
  if (state === "media") {
    setState("results");
    return null;
  }

  if (state === "browser") {
    return (
      <>
        <HexagonBackground />
        <BrowserView
          browsers={browsers}
          isScanning={isScanningBrowser}
          onStartScan={startBrowserScan}
          onBack={() => setState("results")}
          onExportBrowser={exportBrowserData}
        />
      </>
    );
  }

  if (state === "keywords") {
    return (
      <>
        <HexagonBackground />
        <KeywordResults
          matches={keywordMatches}
          isScanning={isScanning}
          onStartScan={startKeywordScan}
          onBack={() => setState("results")}
          listPriority={keywordListPriority}
          keywordToListMap={keywordToListMap}
        />
      </>
    );
  }

  if (state === "hashes") {
    // Filter media files to only show hash matches
    const hashMatches = mediaFiles.filter(f => 
      f.flags.some(flag => flag.type === 'hash_match')
    );
    
    return (
      <>
        <HexagonBackground />
        <HashResults
          matches={hashMatches}
          isScanning={isScanningMedia}
          onStartScan={startMediaScan}
          onBack={() => setState("results")}
          listPriority={hashListPriority}
        />
      </>
    );
  }

  if (state === "android") {
    return (
      <>
        <HexagonBackground />
        <AndroidView
          onBack={() => setState("start")}
        />
      </>
    );
  }

  async function performIosScan() {
    try {
      trackEvent("ios_triage_opened");
      console.log("Starting iOS automatic scan");
      
      // Get connected iOS devices
      const devices = await invoke<any[]>("get_ios_devices");
      if (!devices || devices.length === 0) {
        alert("No iOS devices detected. Please connect your iPhone and ensure it is unlocked and trusted.");
        setState("start");
        return;
      }
      
      const device = devices[0]; // Use first connected device
      const udid = device.udid;
      
      console.log("Found iOS device:", device);
      
      // Set device type and transition to results view with scanning state
      setDeviceType('ios');
      setState("results");
      setIsScanning(true);
      setCurrentScanModule("iOS Device");
      setApps([]);
      setMediaFiles([]);
      setBrowsers([]);
      setKeywords([]);
      setHashMatches([]);
      
      // Show device info immediately
      setSystemInfo({
        ios_device_info: device,
        computer_name: device.deviceName || "iOS Device",
        os_version: `iOS ${device.iosVersion}`,
      } as any);
      
      // Set scannedModules IMMEDIATELY so tabs appear right away (gives user instant feedback)
      setScannedModules({
        questionableApps: true,  // iOS triage: scan apps
        browserHistory: false,   // iOS triage: browser history removed (too slow with backup)
        mediaScan: true,         // iOS triage: scan media files
        keywordSearch: false,    // iOS triage: keywords not implemented yet
        hashMatching: true,      // iOS triage: hash matching
        intrusionDetection: false,
        smsMessages: false,      // SMS not yet implemented for iOS
      });
      
      // Perform full triage scan
      setCurrentScanModule("iOS Full Triage Scan");
      const results: any = await invoke('perform_ios_live_triage', {
        udid: udid,
        keywordLists: [],
        hashLists: []
      });
      
      console.log('iOS triage complete:', results);
      
      // Convert and set results
      if (results.appsFound && results.appsFound.length > 0) {
        const convertedApps = results.appsFound.map((app: any) => ({
          name: app.appName || app.bundleId,
          category: "Unknown" as any,
          install_path: app.bundleId,
          version: app.version || "Unknown",
          install_date: null,
          publisher: null,
          artifact_paths: [],
          investigative_category: "COMMUNICATIONS",
          function_category: "COMMUNICATIONS",
          confidence: 0.5,
        }));
        setApps(convertedApps);
      }
      
      // Update device info from triage results
      if (results.deviceInfo) {
        setSystemInfo({
          ios_device_info: results.deviceInfo,
          computer_name: results.deviceInfo.deviceName || "iOS Device",
          os_version: `iOS ${results.deviceInfo.iosVersion}`,
        } as any);
      }
      
      if (results.hashMatches && results.hashMatches.length > 0) {
        setHashMatches(results.hashMatches);
      }
      
      if (results.keywordMatches && results.keywordMatches.length > 0) {
        setKeywords(results.keywordMatches);
      }
      
      if (results.browserHistory && results.browserHistory.length > 0) {
        const iosBrowser = {
          browserName: "Safari",
          packageName: "com.apple.mobilesafari",
          history: results.browserHistory.map((entry: any) => ({
            url: entry.url,
            title: entry.title,
            visitCount: entry.visitCount,
            lastVisit: entry.lastVisit,
          })),
          downloads: [],
          bookmarks: [],
          credentials: []
        };
        setBrowsers([iosBrowser]);
      }
      
      // scannedModules already set at scan start for instant tab visibility
      
      setIsScanning(false);
      setCurrentScanModule("");
      setState("results"); // Show UnifiedDashboard with iOS results
      
    } catch (error) {
      console.error("iOS scan failed:", error);
      setIsScanning(false);
      alert(`iOS scan failed: ${error}`);
      setState("start");
    }
  }

  if (state === "overview") {
    return (
      <>
        <HexagonBackground />
        <div className="app-container">
          <OverviewPanel 
            systemInfo={systemInfo} 
            isLoading={isLoadingSystemInfo}
          />
        </div>
      </>
    );
  }

  if (state === "warrant_triage" && warrantCaseId) {
    return (
      <>
        <HexagonBackground />
        <WarrantTriageView
          caseId={warrantCaseId}
          onBack={closeWarrantTriage}
          onExport={handleWarrantExport}
          parentInvestigationName={
            warrantInvestigationParentForReturn ? "Investigation" : null
          }
        />
      </>
    );
  }

  if (state === "warrant_investigation" && warrantInvestigationId) {
    return (
      <>
        <HexagonBackground />
        <WarrantInvestigationDetail
          investigationId={warrantInvestigationId}
          onBack={backToInvestigationList}
          onOpenReturn={openReturnFromInvestigation}
        />
      </>
    );
  }

  if (state === "warrant") {
    return (
      <>
        <HexagonBackground />
        <WarrantInvestigationsList
          onBack={closeWarrant}
          onOpen={openInvestigation}
        />
      </>
    );
  }

  if (state === "start") {
    return (
      <>
        <HexagonBackground />
        {licenseExpired ? (
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100vh',
            gap: '24px',
            textAlign: 'center',
            padding: '40px'
          }}>
            <div style={{ fontSize: '64px' }}>🔒</div>
            <h1 style={{ color: 'var(--color-text-primary)', margin: 0, fontSize: '28px' }}>
              <span style={{ color: '#fff' }}>DATAPILOT</span>{' '}
              <span style={{ color: '#6B8AFF' }}>SCOUT</span>
            </h1>
            <h2 style={{ color: '#ef4444', margin: 0 }}>License Expired</h2>
            <p style={{ color: 'var(--color-text-secondary)', maxWidth: '440px', lineHeight: 1.6 }}>
              Your trial or license has expired. Enter a valid license key in Settings to
              restore full access. In the meantime, <strong>Warrant Triage</strong> stays
              available for <strong>Meta</strong> and <strong>Google</strong> returns.
            </p>
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', justifyContent: 'center' }}>
              <button
                onClick={openWarrant}
                style={{
                  padding: '14px 40px',
                  background: 'linear-gradient(135deg, var(--primary-blue), var(--accent-blue))',
                  border: 'none',
                  borderRadius: '8px',
                  color: '#fff',
                  fontSize: '16px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                  letterSpacing: '1px'
                }}
              >
                📋 Warrant Triage
              </button>
              <button
                onClick={openSettings}
                style={{
                  padding: '14px 40px',
                  background: 'transparent',
                  border: '1px solid var(--accent-blue)',
                  borderRadius: '8px',
                  color: '#fff',
                  fontSize: '16px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                  letterSpacing: '1px'
                }}
              >
                ⚙️ Open Settings
              </button>
            </div>
          </div>
        ) : (
          <>
            <StartScreen 
              onBeginScan={showScanConfig} 
              onOpenSettings={openSettings}
              onOpenWarrant={openWarrant}
            />
            {licenseDaysRemaining > 0 && licenseDaysRemaining <= 60 && (
              <div style={{
                position: 'fixed',
                bottom: '16px',
                right: '16px',
                background: licenseDaysRemaining <= 7 ? 'rgba(239, 68, 68, 0.9)' : 'rgba(245, 158, 11, 0.9)',
                color: '#fff',
                padding: '8px 16px',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 600,
                zIndex: 9999,
                backdropFilter: 'blur(8px)'
              }}>
                {licenseDaysRemaining <= 7 ? '⚠️' : 'ℹ️'} Trial: {licenseDaysRemaining} day{licenseDaysRemaining !== 1 ? 's' : ''} remaining
              </div>
            )}
          </>
        )}
      </>
    );
  }

  // Results state - show unified dashboard
  if (state === "results") {
    return (
      <>
        <HexagonBackground />
        <UnifiedDashboard
          apps={apps}
          media={mediaFiles}
          keywords={keywordMatches}
          browsers={browsers}
          smsMessages={smsMessages}
          systemInfo={systemInfo}
          intrusionResults={intrusionResults}
          deletedMediaResults={deletedMediaResults}
          hashMatches={hashMatches}
          isScanning={isScanning}
          currentScanModule={currentScanModule}
          scanProgress={scanProgress}
          backupProgress={backupProgress}
          onNewScan={handleNewScan}
          onGenerateReport={openReport}
          onViewHashDetails={() => setState("hashes")}
          onViewKeywordDetails={() => setState("keywords")}
          deviceType={selectedDeviceType}
          settings={settings}
          selectedDrives={selectedDrives}
          scannedModules={scannedModules}
          onStopScan={handleStopScan}
          scanStopped={scanStopped}
        />
      </>
    );
  }
  
  // Default fallback - shouldn't reach here normally
  return (
    <>
      <HexagonBackground />
      <StartScreen 
        onBeginScan={showScanConfig} 
        onOpenSettings={openSettings}
        onOpenWarrant={openWarrant}
      />
    </>
  );
}

/**
 * Top-level wrapper that keeps `ExportProgressPanel` mounted for the
 * lifetime of the app.  This lets a warrant-investigation export keep
 * showing live progress even if the user navigates away from the
 * investigation detail screen.
 */
function AppWithGlobalOverlays() {
  return (
    <>
      <App />
      <ExportProgressPanel />
    </>
  );
}

export default AppWithGlobalOverlays;
