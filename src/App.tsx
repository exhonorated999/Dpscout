import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
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
import { SystemInfo } from "./types/system";
import { IntrusionScanResults, IntrusionScanOptions, defaultIntrusionScanOptions } from "./types/intrusion";
import { useScanSession } from "./hooks/useScanSession";
import { RegistrationScreen } from "./components/RegistrationScreen";
import "./App.css";

type AppState = "start" | "config" | "scanning" | "results" | "settings" | "media" | "report" | "browser" | "keywords" | "hashes" | "android" | "ios" | "overview";

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
  async function startAndroidScan(modules: ScanModules, keywordConfig?: KeywordScanConfig, hashConfig?: any) {
    try {
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
      scanCancelledRef.current = false;
      setApps([]);
      setMediaFiles([]);
      setCurrentScanModule("Android Device");
      
      const progressList: ScanProgressType[] = [];
      
      // Helper to force UI update between operations
      const forceUIUpdate = () => new Promise<void>(resolve => setTimeout(resolve, 0));
      
      // Collect Android device information
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
      
      // Force UI update so device info is visible
      await forceUIUpdate();
      
      // Scan Android apps if selected
      if (modules.questionableApps && !scanCancelledRef.current) {
        setCurrentScanModule("Android Applications");
        try {
          const androidApps = await invoke<any[]>("get_android_apps", { serial: selectedDevice });
          console.log("Android apps received:", androidApps);
          console.log("First app sample:", androidApps[0]);
          
          // Convert Android apps to QuestionableApp format
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
          
          console.log("Converted apps:", convertedApps);
          console.log("First converted app:", convertedApps[0]);
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
        
        // Force UI update so apps are visible before continuing
        await forceUIUpdate();
      }
      
      // Scan browser history if selected
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
        
        // Force UI update so browser data is visible
        await forceUIUpdate();
      }

      // Scan media files if selected
      if (modules.mediaScan && !scanCancelledRef.current) {
        setCurrentScanModule("Media Files");
        try {
          const androidMediaFiles = await invoke<any[]>("scan_android_media", { serial: selectedDevice });
          
          // Convert to standard media file format
          const convertedMediaFiles = androidMediaFiles.map((file, index) => {
            const mediaType = file.fileType === "Image" ? "image" : file.fileType === "Video" ? "video" : "unknown";
            console.log(`Converting file: ${file.filename}, fileType: ${file.fileType}, mediaType: ${mediaType}, size: ${file.sizeBytes}`);
            return {
              id: `android-media-${index}`,
              filePath: file.path || "",  // Android device path
              fileName: file.filename || "Unknown",
              fileSize: Number(file.sizeBytes) || 0,
              extension: file.filename ? file.filename.split('.').pop() || "" : "",
              mediaType: mediaType,
              thumbnailPath: "",  // Will be generated when file is pulled
              dateCreated: file.createdDate || "Unknown",
              dateModified: file.modifiedDate || "Unknown",
              flags: [], // Initialize empty flags array
              // Android-specific metadata
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
        
        // Force UI update so media files are visible
        await forceUIUpdate();
      }

      // Scan for hash matches if selected
      if (modules.hashMatching && !scanCancelledRef.current) {
        setCurrentScanModule("Hash Matching (CSAM)");
        try {
          // Get selected hash list names from hashConfig
          const selectedHashLists = hashConfig?.selectedHashLists
            ?.filter(list => list.enabled)
            .map(list => list.name) || [];
          
          console.log("Hash scan using lists:", selectedHashLists.length > 0 ? selectedHashLists : "all available lists");
          
          const matches = await invoke<any[]>("scan_android_media_hashes", { 
            serial: selectedDevice,
            selectedHashListIds: selectedHashLists.length > 0 ? selectedHashLists : null
          });
          
          console.log("Hash scan complete:", matches.length, "matches found");
          
          // Store hash matches in state
          setHashMatches(matches);
          
          // Add to scan progress
          progressList.push({
            module: "Hash Matching",
            status: matches.length > 0 ? "completed" : "completed",
            count: matches.length,
            details: matches.length > 0 
              ? `⚠️ CRITICAL: ${matches.length} hash match${matches.length > 1 ? 'es' : ''} found!`
              : `No hash matches found`
          });

          // Update media files with hash match flags (if media was scanned)
          if (matches.length > 0 && modules.mediaScan) {
            setMediaFiles(prevMediaFiles => {
              return prevMediaFiles.map(mediaFile => {
                const match = matches.find((m: any) => m.filePath === mediaFile.filePath);
                if (match) {
                  return {
                    ...mediaFile,
                    flags: [
                      ...mediaFile.flags,
                      {
                        flagType: "HashMatch",
                        severity: "Critical",
                        reason: match.description || "Known CSAM hash match",
                        source: match.listSource || "Hash Database"
                      }
                    ],
                    md5Hash: match.md5Hash,
                    sha256Hash: match.sha256Hash,
                  };
                }
                return mediaFile;
              });
            });
          }
        } catch (error) {
          console.error("Failed to scan hashes:", error);
          progressList.push({
            module: "Hash Matching",
            status: "failed",
            count: 0,
            details: `Error: ${error}`
          });
        }
        
        // Force UI update so hash matches are visible
        await forceUIUpdate();
      }

      // Extract SMS messages if selected
      if (modules.smsMessages && !scanCancelledRef.current) {
        setCurrentScanModule("SMS/MMS Messages");
        try {
          const smsResult = await invoke<any>("extract_android_sms", { 
            deviceId: selectedDevice,
            limit: null // Get all messages
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
        
        // Force final UI update so SMS messages are visible
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
      const selectedDevice = keywordConfig?.selectedDevice;
      console.log("Starting iOS MTP live scan, device:", selectedDevice, "modules:", modules);

      // Override modules: iOS MTP only supports media scan + hash matching
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
          computer_name: "iOS Device (MTP)",
          os_version: "iOS",
        } as any);
      } finally {
        setIsLoadingSystemInfo(false);
      }
      await forceUIUpdate();

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
    setSystemInfo(null);
    scanCancelledRef.current = false;
    setScanStopped(false);
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

      // Scan for CSAM Hash Matches (INDEPENDENT of media scan)
      if (modules.hashMatching && !scanCancelledRef.current) {
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
          // Get scan paths based on selected drives
          let scanPaths: string[];
          if (keywordConfig?.selectedDrives && keywordConfig.selectedDrives.length > 0) {
            scanPaths = await invoke<string[]>("get_scan_paths_for_selected_drives", { drives: keywordConfig.selectedDrives });
          } else {
            // Get default scan paths (Documents, Downloads, Desktop, Pictures, Videos, etc.)
            scanPaths = await invoke<string[]>("get_keyword_scan_paths");
          }
          
          const hashScanOptions = {
            scanPaths: scanPaths,
            maxFileSize: 500 * 1024 * 1024, // 500MB max per file
            scanMode: selectedDeviceType === 'usb' ? 'usb' : 'windows',
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
            scanPaths: scanPaths
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
    scanCancelledRef.current = true;
    setScanStopped(true);
    try {
      await invoke('cancel_scan');
    } catch (err) {
      console.warn('cancel_scan invoke failed:', err);
    }
    setIsScanning(false);
    setCurrentScanModule('');
  }

  function handleNewScan() {
    setState("start");
    setApps([]);
  }

  function openSettings() {
    setState("settings");
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

  // If license expired, force user to settings only
  if (licenseExpired && state !== 'settings') {
    // Auto-redirect to settings with a message
    if (state !== 'start') {
      setState('settings');
    }
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
            <p style={{ color: 'var(--color-text-secondary)', maxWidth: '400px', lineHeight: 1.6 }}>
              Your trial or license has expired. Please enter a valid license key in Settings to continue using all features.
            </p>
            <button
              onClick={openSettings}
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
              ⚙️ Open Settings
            </button>
          </div>
        ) : (
          <>
            <StartScreen 
              onBeginScan={showScanConfig} 
              onOpenSettings={openSettings}
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
      />
    </>
  );
}

export default App;
