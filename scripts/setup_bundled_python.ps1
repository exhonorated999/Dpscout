<#
    setup_bundled_python.ps1

    Builds a fully self-contained Python runtime for Datapilot Scout's iOS
    features and drops it at  external\python\  so it can be bundled into the
    installer (tauri.conf.json resources "../external/**/*").

    The result requires NO system Python and NO internet/admin on the target
    machine — the embeddable interpreter plus pymobiledevice3 (and deps) are
    copied verbatim into the app.

    Idempotent: if external\python\python.exe already imports pymobiledevice3,
    the script exits early. Pass -Force to rebuild from scratch.

    Run standalone:   .\scripts\setup_bundled_python.ps1
    Called by     :   build-desktop.ps1 (before `tauri build`)
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Config -----------------------------------------------------------------
# Match the host toolchain (Python 3.12 -> cp312 wheels). Embeddable build.
$PyVersion    = "3.12.8"
$EmbedUrl     = "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-embed-amd64.zip"

# Pinned to the versions verified working on the dev machine.
# pywin32 is required by pymobiledevice3 on Windows (win32security etc.) but is
# NOT auto-resolved as a dependency here, so it is listed explicitly.
$Packages = @(
    "pymobiledevice3==9.4.5",
    "cryptography==46.0.5",
    "construct==2.10.70",
    "construct-typing==0.7.0",
    "packaging==26.0",
    "requests==2.32.5",
    "pywin32==311"
)

# --- Paths ------------------------------------------------------------------
$RepoRoot   = Split-Path -Parent $PSScriptRoot          # ..\ from scripts\
$PythonDir  = Join-Path $RepoRoot "external\python"
$PythonExe  = Join-Path $PythonDir "python.exe"
$SitePkgs   = Join-Path $PythonDir "Lib\site-packages"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "   Datapilot Scout - Bundled Python Runtime Setup"     -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Target Python : $PyVersion (embeddable, amd64)"      -ForegroundColor Gray
Write-Host "  Destination   : $PythonDir"                          -ForegroundColor Gray
Write-Host ""

# --- Idempotency check ------------------------------------------------------
function Test-BundledPython {
    if (-not (Test-Path $PythonExe)) { return $false }
    try {
        # user-site disabled so a leaked dev environment can't mask a broken bundle
        $env:PYTHONNOUSERSITE = "1"
        & $PythonExe -c "import pymobiledevice3, cryptography, construct, requests" 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

if (-not $Force -and (Test-BundledPython)) {
    Write-Host "[SKIP] Bundled Python already present and imports pymobiledevice3." -ForegroundColor Green
    Write-Host "       Use -Force to rebuild." -ForegroundColor DarkGray
    exit 0
}

if (Test-Path $PythonDir) {
    Write-Host "[CLEAN] Removing existing $PythonDir ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $PythonDir
}
New-Item -ItemType Directory -Force -Path $PythonDir | Out-Null

# --- 1. Download + extract embeddable interpreter ---------------------------
$tmpZip = Join-Path $env:TEMP "python-$PyVersion-embed-amd64.zip"
Write-Host "[1/5] Downloading embeddable Python..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $EmbedUrl -OutFile $tmpZip
Write-Host "      Extracting..." -ForegroundColor DarkGray
Expand-Archive -Path $tmpZip -DestinationPath $PythonDir -Force
Remove-Item $tmpZip -Force

# --- 2. Enable site + site-packages in the ._pth file -----------------------
# The embeddable ships with `import site` commented out and no site-packages
# on the path. We add Lib\site-packages (a plain path line is enough to import
# from it) and enable site so any .pth files in installed packages are honored.
# User-site leakage is prevented at RUNTIME via PYTHONNOUSERSITE=1 (set by the
# Rust sidecar) plus at build time via the install flags below.
Write-Host "[2/4] Enabling site-packages in ._pth ..." -ForegroundColor Yellow
$pthFile = Get-ChildItem -Path $PythonDir -Filter "python*._pth" | Select-Object -First 1
if (-not $pthFile) { throw "Could not find python*._pth in $PythonDir" }
$pthContent = @(
    "python312.zip",
    ".",
    "Lib\site-packages",
    "import site"
)
Set-Content -Path $pthFile.FullName -Value $pthContent -Encoding ASCII
New-Item -ItemType Directory -Force -Path $SitePkgs | Out-Null

# --- 3. Install pinned iOS deps INTO the embeddable's site-packages ---------
# We use the host's Python 3.12 pip with --target so wheels (cp312) match the
# embeddable, and --ignore-installed so pip does NOT skip packages that happen
# to already exist in the developer's user-site (the bug that made earlier
# bundles non-self-contained). Everything — pymobiledevice3 AND its full
# transitive dependency tree — is copied into external\python\Lib\site-packages.
Write-Host "[3/4] Installing iOS dependencies into the bundle (a few minutes)..." -ForegroundColor Yellow

# Locate a host Python 3.12 to drive pip.
$hostPy = $null
foreach ($c in @("py -3.12", "python", "py")) {
    $parts = $c.Split(" ")
    try {
        $v = & $parts[0] $parts[1..($parts.Length-1)] -c "import sys;print(sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v -match "3, 12") { $hostPy = $parts; break }
    } catch { continue }
}
if (-not $hostPy) { throw "No host Python 3.12 found to build the bundle (needed for cp312 wheels)." }
Write-Host "      Using host Python: $($hostPy -join ' ')" -ForegroundColor DarkGray

$env:PYTHONNOUSERSITE = "1"
& $hostPy[0] $hostPy[1..($hostPy.Length-1)] -m pip install `
    --target "$SitePkgs" `
    --ignore-installed `
    --no-warn-script-location `
    --no-cache-dir `
    @Packages
if ($LASTEXITCODE -ne 0) { throw "pip install --target of iOS dependencies failed" }

# --- 3b. pywin32 fixup for embeddable ---------------------------------------
# pywin32 installed via --target does NOT run its post-install step. Its
# compiled modules live in Lib\site-packages\win32(,\lib), \win32comext and
# \Pythonwin, and its DLLs (pywintypes312.dll, pythoncom312.dll) live in
# Lib\site-packages\pywin32_system32 and must be loadable. We (a) add those
# dirs to the ._pth and (b) copy the DLLs next to python.exe so they resolve.
Write-Host "      Wiring pywin32 for the embeddable runtime..." -ForegroundColor DarkGray
$pywinDllDir = Join-Path $SitePkgs "pywin32_system32"
if (Test-Path $pywinDllDir) {
    Copy-Item (Join-Path $pywinDllDir "*.dll") -Destination $PythonDir -Force
    # Append pywin32 module dirs to the ._pth (relative to the python root).
    Add-Content -Path $pthFile.FullName -Encoding ASCII -Value @(
        "Lib\site-packages\win32",
        "Lib\site-packages\win32\lib",
        "Lib\site-packages\win32comext",
        "Lib\site-packages\Pythonwin"
    )
} else {
    Write-Host "      WARNING: pywin32_system32 not found; win32 modules may fail." -ForegroundColor Yellow
}

# --- 4. Verify the bundle is TRULY self-contained ---------------------------
# Run the EMBEDDABLE interpreter with user-site disabled and exercise the exact
# imports the daemon/pairing/device scripts use, asserting they resolve from
# INSIDE external\python (not the dev AppData).
Write-Host "[4/4] Verifying self-contained deep imports (user-site disabled)..." -ForegroundColor Yellow
$verify = @"
import os, sys
os.environ['PYTHONNOUSERSITE'] = '1'
from pymobiledevice3.lockdown import create_using_usbmux, LockdownClient
from pymobiledevice3.services.afc import AfcService, AfcOpcode
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3 import exceptions
import win32security  # pywin32 -> required by pymobiledevice3 on Windows
import cryptography, construct, requests
import pymobiledevice3
f = os.path.abspath(pymobiledevice3.__file__)
root = os.path.abspath(r'$PythonDir')
assert f.lower().startswith(root.lower()), 'LEAK: pymobiledevice3 loaded from ' + f
print('SELF-CONTAINED OK ->', os.path.dirname(f))
"@
$env:PYTHONNOUSERSITE = "1"
& $PythonExe -c $verify
if ($LASTEXITCODE -ne 0) { throw "Verification failed: bundled Python is NOT self-contained (see above)" }

$sizeMB = [math]::Round((Get-ChildItem $PythonDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "   BUNDLED PYTHON READY" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "  Location : $PythonDir"      -ForegroundColor White
Write-Host "  Size     : $sizeMB MB"      -ForegroundColor White
Write-Host "  Runtime  : python.exe (no system Python required)" -ForegroundColor White
Write-Host ""
