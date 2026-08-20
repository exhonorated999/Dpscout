@echo off
setlocal

REM --- Self-elevate to Administrator (needed for Deleted Media / unallocated-space scanning) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title Datapilot Scout - DEV BUILD
cd /d "C:\Users\JUSTI\Workspace\Datapilot_scout"

echo ============================================
echo   Datapilot Scout - DEV BUILD (Administrator)
echo ============================================
echo Starting Tauri dev server. Leave this window open.
echo The app window will appear after the build finishes.
echo ============================================
echo.

npx tauri dev

echo.
echo Dev server stopped. Press any key to close.
pause >nul
