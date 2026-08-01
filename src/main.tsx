import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import DiagBanner from "./components/DiagBanner";
import UpdateNotification from "./components/UpdateNotification";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <DiagBanner />
    <App />
    <UpdateNotification />
  </React.StrictMode>,
);
