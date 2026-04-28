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

# Set signing env vars
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content $keyPath -Raw
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "scout"

Write-Host "[1/4] Building Tauri desktop (demo feature)..." -ForegroundColor Yellow
npx tauri build --features demo
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

# Find the NSIS installer
$installer = Get-ChildItem "src-tauri\target\release\bundle\nsis\*-setup.exe" | Select-Object -First 1
if (-Not $installer) {
    Write-Host "ERROR: NSIS installer not found" -ForegroundColor Red
    exit 1
}

Write-Host "[2/4] Installer: $($installer.Name)" -ForegroundColor Green

# Check if .sig was auto-generated
$sigFile = "$($installer.FullName).sig"
if (Test-Path $sigFile) {
    Write-Host "[3/4] Signature auto-generated" -ForegroundColor Green
} else {
    Write-Host "[3/4] Signing installer manually..." -ForegroundColor Yellow
    npx tauri signer sign -k $env:TAURI_SIGNING_PRIVATE_KEY -p $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD $installer.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Signing failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Signed" -ForegroundColor Green
}

$sig = Get-Content $sigFile -Raw
$sizeMB = [math]::Round($installer.Length / 1MB, 1)

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "   DESKTOP BUILD COMPLETE" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "  Installer : $($installer.FullName)" -ForegroundColor White
Write-Host "  Size      : $sizeMB MB" -ForegroundColor White
Write-Host "  Signature : $sigFile" -ForegroundColor White
Write-Host ""
Write-Host "[4/4] Upload to admin dashboard:" -ForegroundColor Yellow
Write-Host "  Product: Desktop" -ForegroundColor White
Write-Host "  Paste sig content into NSIS SIGNATURE field" -ForegroundColor White
Write-Host ""
