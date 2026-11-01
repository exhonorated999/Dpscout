@echo off
setlocal

REM ---------------------------------------------------------------------------
REM  Datapilot Scout - macOS UI PREVIEW (dev only, Windows host)
REM
REM  Runs the PORTABLE build in dev mode with VITE_MAC_PREVIEW=true, so the
REM  frontend presents itself as a Mac host: only the "Mac Computer" card, the
REM  macOS drive picker (/ and /Volumes/EVIDENCE, mocked), the Full Disk Access
REM  warning, and canned macOS results instead of a real scan.
REM
REM  The preview switch is gated on import.meta.env.DEV, so it cannot exist in
REM  anything produced by `vite build` / `tauri build`.
REM ---------------------------------------------------------------------------

title Datapilot Scout - MAC UI PREVIEW (dev)
cd /d "%~dp0"

set VITE_PORTABLE=true
set VITE_MAC_PREVIEW=true

echo ============================================
echo   Datapilot Scout - macOS UI PREVIEW (dev)
echo ============================================
echo Mocked Mac host. No real scanning happens.
echo The app window appears after the Rust build finishes.
echo ============================================
echo.

call npx tauri dev --features demo,portable --config src-tauri/tauri.conf.portable.json

echo.
echo Preview stopped. Press any key to close.
pause >nul
