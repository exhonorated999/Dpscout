import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

/**
 * Yellow strip that sits fixed at the top of the app in diag builds.
 * Tells the user exactly where the log file lives and gives them
 * two one-click ways to ship it to Teams:
 *
 *   • OPEN LOG → fires Notepad on the file
 *   • COPY TO CLIPBOARD → reads the file via Tauri, writes it to
 *     navigator.clipboard, ready to paste into Teams
 *
 * Gated by both:
 *   • VITE_DIAG=true (frontend env, so non-diag builds don't render it)
 *   • Tauri command `diag_is_active` (so it doesn't render if the
 *     command surface lies about being a diag build)
 */
const IS_DIAG_FRONTEND = import.meta.env.VITE_DIAG === "true";

export default function DiagBanner() {
  const [active, setActive] = useState(false);
  const [path, setPath] = useState<string>("");
  const [flash, setFlash] = useState<string>("");

  useEffect(() => {
    if (!IS_DIAG_FRONTEND) return;
    (async () => {
      try {
        const isActive = await invoke<boolean>("diag_is_active");
        if (!isActive) return;
        const p = await invoke<string>("diag_log_path");
        setPath(p);
        setActive(true);
      } catch {
        // No diag commands — bail silently
      }
    })();
  }, []);

  if (!active) return null;

  const openLog = async () => {
    try {
      await invoke("diag_open_log");
      setFlash("Opened in Notepad");
    } catch (e: any) {
      setFlash(String(e));
    }
    setTimeout(() => setFlash(""), 3500);
  };

  const copyLog = async () => {
    try {
      const text = await invoke<string>("diag_read_log");
      await navigator.clipboard.writeText(text);
      const kb = Math.round(text.length / 1024);
      setFlash(`Copied ${kb} KB to clipboard — paste it into Teams`);
    } catch (e: any) {
      setFlash(`Couldn't copy: ${e}`);
    }
    setTimeout(() => setFlash(""), 4000);
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 99999,
        background: "linear-gradient(90deg, #FFD24A 0%, #FFC42E 100%)",
        color: "#111",
        fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif",
        fontSize: 13,
        fontWeight: 600,
        padding: "8px 14px",
        display: "flex",
        alignItems: "center",
        gap: 14,
        boxShadow: "0 2px 10px rgba(0,0,0,0.4)",
        borderBottom: "2px solid #B8860B",
        userSelect: "none",
      }}
    >
      <span style={{ fontSize: 16 }}>🔬</span>
      <span>
        DIAGNOSTIC BUILD — log is written to <code style={{ background: "rgba(0,0,0,0.12)", padding: "2px 6px", borderRadius: 4 }}>{path}</code>
      </span>
      <button
        onClick={openLog}
        style={diagButton}
        title="Open the log file in Notepad"
      >
        Open Log
      </button>
      <button
        onClick={copyLog}
        style={diagButton}
        title="Copy the whole log to your clipboard so you can paste it into Teams"
      >
        Copy to Clipboard
      </button>
      {flash && (
        <span style={{ marginLeft: "auto", fontWeight: 700, color: "#0a4d00" }}>
          ✓ {flash}
        </span>
      )}
    </div>
  );
}

const diagButton: React.CSSProperties = {
  background: "#111",
  color: "#FFD24A",
  border: "none",
  padding: "5px 12px",
  borderRadius: 4,
  fontWeight: 700,
  fontSize: 12,
  cursor: "pointer",
  letterSpacing: 0.4,
};
