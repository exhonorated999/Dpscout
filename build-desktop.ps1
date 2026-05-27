# Build Datapilot Scout - Desktop Edition
# Builds NSIS installer + .sig for auto-updater

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "   Datapilot Scout - Desktop Build" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

$keyPath = "$env:USERPROFILE\.tauri\datapilot-scout.key"
if (-Not (Test-Path $keyPath)) {
    Write-Host "ERROR: Signing key not found at $keyPath" -ForegroundColor Red
    exit 1
}

# Read version from package.json so we always target the right artifact
$pkg = Get-Content "package.json" -Raw | ConvertFrom-Json
$version = $pkg.version
if (-Not $version) {
    Write-Host "ERROR: Could not read version from package.json" -ForegroundColor Red
    exit 1
}
Write-Host "Target version: $version" -ForegroundColor Cyan

# Set signing env vars
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content $keyPath -Raw
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "scout"

Write-Host "[1/4] Building Tauri desktop (demo feature)..." -ForegroundColor Yellow
npx tauri build --features demo
if ($LASTEXITCODE -ne 0) {
    # Tauri's post-build auto-sign sometimes fails with "failed to decode pubkey";
    # that's recoverable because we sign manually below. Check whether the NSIS
    # bundle was actually produced before bailing out.
    $expected = "src-tauri\target\release\bundle\nsis\Datapilot Scout_${version}_x64-setup.exe"
    if (-Not (Test-Path $expected)) {
        Write-Host "Build failed before NSIS bundle was produced." -ForegroundColor Red
        exit 1
    }
    Write-Host "Tauri post-build step reported a non-zero exit, but the NSIS bundle exists. Continuing." -ForegroundColor Yellow
}

# Find the NSIS installer for THIS version (exclude portable variant)
$installer = Get-ChildItem "src-tauri\target\release\bundle\nsis\Datapilot Scout_${version}_x64-setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-Not $installer) {
    Write-Host "ERROR: Desktop NSIS installer not found for version $version" -ForegroundColor Red
    Write-Host "  Expected: src-tauri\target\release\bundle\nsis\Datapilot Scout_${version}_x64-setup.exe" -ForegroundColor Red
    exit 1
}

Write-Host "[2/4] Installer: $($installer.Name)" -ForegroundColor Green

# Always sign manually — Tauri's built-in auto-sign is unreliable in this setup
# and historically leaves stale .sig files from earlier versions matching first.
Write-Host "[3/4] Signing installer (manual)..." -ForegroundColor Yellow
$sigFile = "$($installer.FullName).sig"
if (Test-Path $sigFile) {
    Remove-Item $sigFile -Force
}
npx tauri signer sign -k $env:TAURI_SIGNING_PRIVATE_KEY -p $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD $installer.FullName
if ($LASTEXITCODE -ne 0 -or -Not (Test-Path $sigFile)) {
    Write-Host "Signing failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Signed -> $sigFile" -ForegroundColor Green

$sig = Get-Content $sigFile -Raw
$sizeMB = [math]::Round($installer.Length / 1MB, 1)

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "   DESKTOP BUILD COMPLETE" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "  Version   : $version" -ForegroundColor White
Write-Host "  Installer : $($installer.FullName)" -ForegroundColor White
Write-Host "  Size      : $sizeMB MB" -ForegroundColor White
Write-Host "  Signature : $sigFile" -ForegroundColor White
Write-Host ""
Write-Host "[4/4] Upload to admin dashboard:" -ForegroundColor Yellow
Write-Host "  Product: Desktop" -ForegroundColor White
Write-Host "  Paste sig content into NSIS SIGNATURE field" -ForegroundColor White
Write-Host ""
