export interface IntrusionScanResults {
  eventLogAnomalies: EventLogAnomaly[];
  persistenceItems: PersistenceItem[];
  commandHistory: CommandHistoryItem[];
  userAccountChanges: UserAccountChange[];
  remoteAccessIndicators: RemoteAccessIndicator[];
  securityToolTampering: SecurityTamperingItem[];
  networkIndicators: NetworkIndicator[];
  malwareIndicators: MalwareIndicator[];
  browserHijacking: BrowserHijackingItem[];
  summary: IntrusionSummary;
}

export interface EventLogAnomaly {
  artifactType: string;
  eventId: number;
  timestamp: string;
  description: string;
  logPath: string;
  logName: string;
  severity: string;
  user?: string;
  process?: string;
  eventData?: Record<string, string>;
  computer?: string;
  provider?: string;
  level?: string;
  suspiciousScore: number;
}

export interface PersistenceItem {
  persistenceType: string;
  name: string;
  targetPath: string;
  location: string;
  timestamp?: string;
  suspicious: boolean;
}

export interface CommandHistoryItem {
  commandType: string;
  command: string;
  timestamp: string;
  sourcePath: string;
  suspicious: boolean;
}

export interface UserAccountChange {
  changeType: string;
  username: string;
  timestamp: string;
  details: string;
  isAdmin: boolean;
  suspicious: boolean;
  riskScore: number;
}

export interface RemoteAccessIndicator {
  indicatorType: string;
  toolName: string;
  timestamp?: string;
  sourceIp?: string;
  username?: string;
  details: string;
  riskLevel: string;
}

export interface SecurityTamperingItem {
  tamperType: string;
  component: string;
  timestamp?: string;
  details: string;
  registryKey?: string;
  riskLevel: string;
}

export interface NetworkIndicator {
  indicatorType: string;
  destination: string;
  port?: number;
  protocol?: string;
  timestamp?: string;
  details: string;
  threatIntel?: string;
  riskScore: number;
}

export interface MalwareIndicator {
  indicatorType: string;
  filePath: string;
  processName?: string;
  hash?: string;
  timestamp?: string;
  details: string;
  riskScore: number;
}

export interface BrowserHijackingItem {
  hijackType: string;
  browser: string;
  itemName: string;
  value: string;
  timestamp?: string;
  riskLevel: string;
}

export interface IntrusionSummary {
  totalArtifacts: number;
  criticalFindings: number;
  highRiskFindings: number;
  mediumRiskFindings: number;
  lowRiskFindings: number;
  overallRiskScore: number;
  recommendations: string[];
}

export interface IntrusionScanOptions {
  scanEventLogs: boolean;
  scanPersistence: boolean;
  scanCommandHistory: boolean;
  scanUserAccounts: boolean;
  scanRemoteAccess: boolean;
  scanSecurityTampering: boolean;
  scanNetwork: boolean;
  scanMalware: boolean;
  scanBrowserHijacking: boolean;
  targetDrive?: string;
}

export const defaultIntrusionScanOptions: IntrusionScanOptions = {
  scanEventLogs: true,
  scanPersistence: true,
  scanCommandHistory: true,
  scanUserAccounts: true,
  scanRemoteAccess: true,
  scanSecurityTampering: true,
  scanNetwork: true,
  scanMalware: true,
  scanBrowserHijacking: true,
  targetDrive: undefined,
};
