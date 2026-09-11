import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import DiagBanner from "./components/DiagBanner";
import UpdateNotification from "./components/UpdateNotification";
import GlobalAlertHost from "./components/GlobalAlertHost";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <DiagBanner />
    <App />
    <UpdateNotification />
    {/*
      Renders the global `appDialog` queue, which `window.alert` is patched to
      feed.  Mounted last so it paints over everything, and outside <App/> so
      an error raised while App is unmounting still has somewhere to land.
    */}
    <GlobalAlertHost />
  </React.StrictMode>,
);
