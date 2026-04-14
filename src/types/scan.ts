import { SystemInfo } from "./system";
import { QuestionableApp } from "./scanner";
import { BrowserData } from "./browser";
import { KeywordMatch } from "./keyword";
import { MediaFile } from "./media";

// Module names for different scan types
export type ModuleName = 
  | "system_info"
  | "apps"
  | "browser"
  | "keywords"
  | "hashes"
  | "media";

// Module status states
export type ModuleState = 
  | "pending"     // Not yet started
  | "running"     // Currently executing
  | "complete"    // Finished successfully
  | "error";      // Failed with error

// Status information for a single scan module
export interface ModuleStatus {
  name: ModuleName;
  display_name: string;
  status: ModuleState;
  progress?: number;          // 0-100 percentage
  current_item?: string;      // Currently processing item
  items_processed?: number;   // Number of items completed
  total_items?: number;       // Total items to process
  started_at?: string;        // ISO timestamp
  completed_at?: string;      // ISO timestamp
  error?: string;             // Error message if failed
  result_count?: number;      // Number of results found
}

// Complete scan session state
export interface ScanSession {
  id: string;
  system_info: SystemInfo | null;
  modules: ModuleStatus[];
  results: ScanResults;
  started_at: string;
  completed_at: string | null;
}

// All scan results in one place
export interface ScanResults {
  apps: QuestionableApp[];
  browsers: BrowserData[];
  keywords: KeywordMatch[];
  hashes: HashMatch[];
  media: MediaFile[];
}

// Hash match result (placeholder for now)
export interface HashMatch {
  file_path: string;
  hash: string;
  hash_type: string;
  matched_list: string;
  file_size: number;
  modified_date: string;
}

// Scan update events from backend
export type ScanEvent = 
  | { type: "system_info"; data: SystemInfo }
  | { type: "module_started"; module: ModuleName }
  | { type: "module_progress"; module: ModuleName; progress: number; current_item?: string; items_processed?: number; total_items?: number }
  | { type: "module_complete"; module: ModuleName; result_count: number }
  | { type: "module_error"; module: ModuleName; error: string }
  | { type: "apps_result"; apps: QuestionableApp[] }
  | { type: "browser_result"; browsers: BrowserData[] }
  | { type: "keyword_match"; match: KeywordMatch }
  | { type: "hash_match"; match: HashMatch }
  | { type: "media_found"; file: MediaFile }
  | { type: "scan_complete" };

// Helper function to create initial module status
export function createModuleStatus(name: ModuleName, displayName: string): ModuleStatus {
  return {
    name,
    display_name: displayName,
    status: "pending",
    progress: 0,
    result_count: 0,
  };
}

// Helper function to create empty scan session
export function createEmptyScanSession(systemInfo: SystemInfo): ScanSession {
  return {
    id: systemInfo.scan_id,
    system_info: systemInfo,
    modules: [],
    results: {
      apps: [],
      browsers: [],
      keywords: [],
      hashes: [],
      media: [],
    },
    started_at: systemInfo.scan_timestamp,
    completed_at: null,
  };
}

// Helper function to get module by name
export function getModule(session: ScanSession, name: ModuleName): ModuleStatus | undefined {
  return session.modules.find(m => m.name === name);
}

// Helper function to check if all modules are complete
export function isSessionComplete(session: ScanSession): boolean {
  return session.modules.every(m => m.status === "complete" || m.status === "error");
}

// Helper function to count running modules
export function getRunningModulesCount(session: ScanSession): number {
  return session.modules.filter(m => m.status === "running").length;
}

// Helper function to get total result count
export function getTotalResultCount(session: ScanSession): number {
  return (
    session.results.apps.length +
    session.results.browsers.length +
    session.results.keywords.length +
    session.results.hashes.length +
    session.results.media.length
  );
}

// Helper function to get completion percentage
export function getSessionProgress(session: ScanSession): number {
  if (session.modules.length === 0) return 0;
  
  const totalProgress = session.modules.reduce((sum, module) => {
    if (module.status === "complete") return sum + 100;
    if (module.status === "running") return sum + (module.progress || 0);
    return sum;
  }, 0);
  
  return Math.round(totalProgress / session.modules.length);
}
