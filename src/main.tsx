import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import DiagBanner from "./components/DiagBanner";
import UpdateNotification from "./components/UpdateNotification";
import GlobalAlertHost from "./components/GlobalAlertHost";
import FilePickerHost from "./components/FilePickerHost";
import { MAC_PREVIEW } from "./lib/hostPlatform";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <DiagBanner />
    <App />
    <UpdateNotification />
    {/* G10: in-app file picker (macOS); below GlobalAlertHost in z-order. */}
    <FilePickerHost />
    {/*
      Renders the global `appDialog` queue, which `window.alert` is patched to
      feed.  Mounted last so it paints over everything, and outside <App/> so
      an error raised while App is unmounting still has somewhere to land.
    */}
    <GlobalAlertHost />
    {import.meta.env.DEV && MAC_PREVIEW && (
      <div
        title="Dev-only: VITE_MAC_PREVIEW. Mocked Mac host, drives and results. Not present in any build."
        style={{
          position: "fixed", bottom: 8, left: 8, zIndex: 10040, pointerEvents: "none",
          padding: "4px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700, letterSpacing: 1,
          background: "rgba(255, 159, 10, 0.9)", color: "#000",
        }}
      >
        🍎 MAC UI PREVIEW — mocked data, dev only
      </div>
    )}
  </React.StrictMode>,
);
