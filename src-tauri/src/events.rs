use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};

/// Event names for scan updates
pub const EVENT_SYSTEM_INFO: &str = "scan:system_info";
pub const EVENT_MODULE_STARTED: &str = "scan:module_started";
pub const EVENT_MODULE_PROGRESS: &str = "scan:module_progress";
pub const EVENT_MODULE_COMPLETE: &str = "scan:module_complete";
pub const EVENT_MODULE_ERROR: &str = "scan:module_error";
pub const EVENT_APPS_RESULT: &str = "scan:apps_result";
pub const EVENT_BROWSER_RESULT: &str = "scan:browser_result";
pub const EVENT_KEYWORD_MATCH: &str = "scan:keyword_match";
pub const EVENT_HASH_MATCH: &str = "scan:hash_match";
pub const EVENT_MEDIA_FOUND: &str = "scan:media_found";
pub const EVENT_SCAN_COMPLETE: &str = "scan:complete";

/// Module names
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleName {
    SystemInfo,
    Apps,
    Browser,
    Keywords,
    Hashes,
    HashMatching, // Dedicated hash scanning module
    Media,
}

/// Module started event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStartedEvent {
    pub module: ModuleName,
}

/// Module progress event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleProgressEvent {
    pub module: ModuleName,
    pub progress: u8,
    pub current_item: Option<String>,
    pub items_processed: Option<usize>,
    pub total_items: Option<usize>,
}

/// Module complete event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleCompleteEvent {
    pub module: ModuleName,
    pub result_count: usize,
}

/// Module error event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleErrorEvent {
    pub module: ModuleName,
    pub error: String,
}

/// Event emitter helper struct
pub struct ScanEventEmitter {
    app: AppHandle,
}

impl ScanEventEmitter {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }

    pub fn emit_module_started(&self, module: ModuleName) {
        let event = ModuleStartedEvent { module };
        let _ = self.app.emit(EVENT_MODULE_STARTED, event);
    }

    pub fn emit_module_progress(
        &self,
        module: ModuleName,
        progress: u8,
        current_item: Option<String>,
        items_processed: Option<usize>,
        total_items: Option<usize>,
    ) {
        let event = ModuleProgressEvent {
            module,
            progress,
            current_item,
            items_processed,
            total_items,
        };
        let _ = self.app.emit(EVENT_MODULE_PROGRESS, event);
    }

    pub fn emit_module_complete(&self, module: ModuleName, result_count: usize) {
        let event = ModuleCompleteEvent { module, result_count };
        let _ = self.app.emit(EVENT_MODULE_COMPLETE, event);
    }

    pub fn emit_module_error(&self, module: ModuleName, error: String) {
        let event = ModuleErrorEvent { module, error };
        let _ = self.app.emit(EVENT_MODULE_ERROR, event);
    }

    pub fn emit_apps_result<T: Serialize>(&self, apps: &T) {
        let _ = self.app.emit(EVENT_APPS_RESULT, apps);
    }

    pub fn emit_browser_result<T: Serialize>(&self, browsers: &T) {
        let _ = self.app.emit(EVENT_BROWSER_RESULT, browsers);
    }

    pub fn emit_keyword_match<T: Serialize>(&self, match_data: &T) {
        let _ = self.app.emit(EVENT_KEYWORD_MATCH, match_data);
    }

    pub fn emit_hash_match<T: Serialize>(&self, match_data: &T) {
        let _ = self.app.emit(EVENT_HASH_MATCH, match_data);
    }

    pub fn emit_media_found<T: Serialize>(&self, file: &T) {
        let _ = self.app.emit(EVENT_MEDIA_FOUND, file);
    }

    pub fn emit_scan_complete(&self) {
        let _ = self.app.emit(EVENT_SCAN_COMPLETE, ());
    }

    pub fn emit_system_info<T: Serialize>(&self, system_info: &T) {
        let _ = self.app.emit(EVENT_SYSTEM_INFO, system_info);
    }
}
