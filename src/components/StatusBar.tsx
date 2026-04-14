import { ModuleStatus } from "../types/scan";
import "./StatusBar.css";

interface StatusBarProps {
  modules: ModuleStatus[];
  onModuleClick?: (moduleName: string) => void;
}

export function StatusBar({ modules, onModuleClick }: StatusBarProps) {
  if (modules.length === 0) {
    return null;
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pending":
        return "⏸";
      case "running":
        return "⟳";
      case "complete":
        return "✓";
      case "error":
        return "✗";
      default:
        return "?";
    }
  };

  const getStatusClass = (status: string) => {
    return `status-${status}`;
  };

  return (
    <div className="status-bar">
      <div className="status-bar-header">
        <h3>Scan Modules</h3>
        <div className="status-summary">
          {modules.filter((m) => m.status === "complete").length} / {modules.length} Complete
        </div>
      </div>

      <div className="status-modules">
        {modules.map((module) => (
          <div
            key={module.name}
            className={`status-module ${getStatusClass(module.status)} ${
              onModuleClick ? "clickable" : ""
            }`}
            onClick={() => onModuleClick && onModuleClick(module.name)}
          >
            <div className="module-header">
              <span className="module-icon">{getStatusIcon(module.status)}</span>
              <span className="module-name">{module.display_name}</span>
              {module.result_count !== undefined && module.result_count > 0 && (
                <span className="result-badge">{module.result_count}</span>
              )}
            </div>

            {module.status === "running" && (
              <div className="module-progress">
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{ width: `${module.progress || 0}%` }}
                  ></div>
                </div>
                <div className="progress-info">
                  {module.current_item && (
                    <div className="current-item">{module.current_item}</div>
                  )}
                  {module.items_processed !== undefined && module.total_items !== undefined && (
                    <div className="progress-count">
                      {module.items_processed} / {module.total_items}
                    </div>
                  )}
                  {module.progress !== undefined && (
                    <div className="progress-percent">{module.progress}%</div>
                  )}
                </div>
              </div>
            )}

            {module.status === "error" && module.error && (
              <div className="module-error">{module.error}</div>
            )}

            {module.status === "complete" && (
              <div className="module-complete-time">
                Completed{" "}
                {module.completed_at && new Date(module.completed_at).toLocaleTimeString()}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
