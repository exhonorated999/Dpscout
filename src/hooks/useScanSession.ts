import { useState, useEffect, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  ScanSession,
  ScanResults,
  ModuleStatus,
  ModuleName,
  createModuleStatus,
  createEmptyScanSession,
} from "../types/scan";
import { SystemInfo } from "../types/system";
import { QuestionableApp } from "../types/scanner";
import { BrowserData } from "../types/browser";
import { KeywordMatch } from "../types/keyword";
import { MediaFile } from "../types/media";

export function useScanSession() {
  const [session, setSession] = useState<ScanSession | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Initialize session when system info is received
  const handleSystemInfo = useCallback((systemInfo: SystemInfo) => {
    const newSession = createEmptyScanSession(systemInfo);
    setSession(newSession);
    setIsScanning(true);
  }, []);

  // Handle module started event
  const handleModuleStarted = useCallback((moduleName: ModuleName) => {
    setSession((prev) => {
      if (!prev) return prev;

      const existingModule = prev.modules.find((m) => m.name === moduleName);
      if (existingModule) {
        // Update existing module
        return {
          ...prev,
          modules: prev.modules.map((m) =>
            m.name === moduleName
              ? { ...m, status: "running", started_at: new Date().toISOString() }
              : m
          ),
        };
      } else {
        // Add new module
        const displayNames: Record<ModuleName, string> = {
          system_info: "System Information",
          apps: "Questionable Applications",
          browser: "Browser History",
          keywords: "Keyword Search",
          hashes: "Hash Database",
          media: "Media Scanner",
        };

        const newModule = createModuleStatus(moduleName, displayNames[moduleName]);
        newModule.status = "running";
        newModule.started_at = new Date().toISOString();

        return {
          ...prev,
          modules: [...prev.modules, newModule],
        };
      }
    });
  }, []);

  // Handle module progress event
  const handleModuleProgress = useCallback(
    (
      moduleName: ModuleName,
      progress: number,
      currentItem?: string,
      itemsProcessed?: number,
      totalItems?: number
    ) => {
      setSession((prev) => {
        if (!prev) return prev;

        return {
          ...prev,
          modules: prev.modules.map((m) =>
            m.name === moduleName
              ? {
                  ...m,
                  progress,
                  current_item: currentItem,
                  items_processed: itemsProcessed,
                  total_items: totalItems,
                }
              : m
          ),
        };
      });
    },
    []
  );

  // Handle module complete event
  const handleModuleComplete = useCallback((moduleName: ModuleName, resultCount: number) => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        modules: prev.modules.map((m) =>
          m.name === moduleName
            ? {
                ...m,
                status: "complete",
                progress: 100,
                completed_at: new Date().toISOString(),
                result_count: resultCount,
              }
            : m
        ),
      };
    });
  }, []);

  // Handle module error event
  const handleModuleError = useCallback((moduleName: ModuleName, error: string) => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        modules: prev.modules.map((m) =>
          m.name === moduleName
            ? {
                ...m,
                status: "error",
                completed_at: new Date().toISOString(),
                error,
              }
            : m
        ),
      };
    });
  }, []);

  // Handle apps result
  const handleAppsResult = useCallback((apps: QuestionableApp[]) => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        results: {
          ...prev.results,
          apps,
        },
      };
    });
  }, []);

  // Handle browser result
  const handleBrowserResult = useCallback((browsers: BrowserData[]) => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        results: {
          ...prev.results,
          browsers,
        },
      };
    });
  }, []);

  // Handle keyword match (incremental)
  const handleKeywordMatch = useCallback((match: KeywordMatch) => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        results: {
          ...prev.results,
          keywords: [...prev.results.keywords, match],
        },
      };
    });
  }, []);

  // Handle media found (incremental)
  const handleMediaFound = useCallback((file: MediaFile) => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        results: {
          ...prev.results,
          media: [...prev.results.media, file],
        },
      };
    });
  }, []);

  // Handle scan complete
  const handleScanComplete = useCallback(() => {
    setSession((prev) => {
      if (!prev) return prev;

      return {
        ...prev,
        completed_at: new Date().toISOString(),
      };
    });
    setIsScanning(false);
  }, []);

  // Set up event listeners
  useEffect(() => {
    const unlistenPromises = [
      listen("scan:system_info", (event) => {
        handleSystemInfo(event.payload as SystemInfo);
      }),
      listen("scan:module_started", (event: any) => {
        handleModuleStarted(event.payload.module);
      }),
      listen("scan:module_progress", (event: any) => {
        const { module, progress, current_item, items_processed, total_items } = event.payload;
        handleModuleProgress(module, progress, current_item, items_processed, total_items);
      }),
      listen("scan:module_complete", (event: any) => {
        const { module, result_count } = event.payload;
        handleModuleComplete(module, result_count);
      }),
      listen("scan:module_error", (event: any) => {
        const { module, error } = event.payload;
        handleModuleError(module, error);
      }),
      listen("scan:apps_result", (event) => {
        handleAppsResult(event.payload as QuestionableApp[]);
      }),
      listen("scan:browser_result", (event) => {
        handleBrowserResult(event.payload as BrowserData[]);
      }),
      listen("scan:keyword_match", (event) => {
        handleKeywordMatch(event.payload as KeywordMatch);
      }),
      listen("scan:media_found", (event) => {
        handleMediaFound(event.payload as MediaFile);
      }),
      listen("scan:complete", () => {
        handleScanComplete();
      }),
    ];

    // Cleanup listeners on unmount
    return () => {
      Promise.all(unlistenPromises).then((unlistenFns) => {
        unlistenFns.forEach((unlisten) => unlisten());
      });
    };
  }, [
    handleSystemInfo,
    handleModuleStarted,
    handleModuleProgress,
    handleModuleComplete,
    handleModuleError,
    handleAppsResult,
    handleBrowserResult,
    handleKeywordMatch,
    handleMediaFound,
    handleScanComplete,
  ]);

  // Reset session
  const resetSession = useCallback(() => {
    setSession(null);
    setIsScanning(false);
  }, []);

  return {
    session,
    isScanning,
    resetSession,
  };
}
