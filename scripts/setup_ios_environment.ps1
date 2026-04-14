# iOS Python Environment Setup Script
# This script installs Python and required dependencies for iOS backup functionality

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "iOS Environment Setup for Scout" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
$pythonInstalled = $false
$pythonCmd = $null

# Try different Python commands
$pythonCommands = @("python", "python3", "py")
foreach ($cmd in $pythonCommands) {
    try {
        $version = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Found Python: $version" -ForegroundColor Green
            $pythonCmd = $cmd
            $pythonInstalled = $true
            break
        }
    } catch {
        continue
    }
}

# Install Python if not found
if (-not $pythonInstalled) {
    Write-Host "Python not found. Installing Python 3.12..." -ForegroundColor Yellow
    Write-Host ""
    
    # Download Python installer
    $installerUrl = "https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe"
    $installerPath = "$env:TEMP\python-installer.exe"
    
    Write-Host "Downloading Python installer..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
    
    Write-Host "Installing Python (this may take a few minutes)..." -ForegroundColor Cyan
    Start-Process -Wait -FilePath $installerPath -ArgumentList "/quiet","InstallAllUsers=1","PrependPath=1","Include_test=0"
    
    # Refresh environment
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    # Verify installation
    try {
        $version = & python --version 2>&1
        Write-Host "[OK] Python installed successfully: $version" -ForegroundColor Green
        $pythonCmd = "python"
    } catch {
        Write-Host "[ERROR] Python installation failed. Please install manually from https://www.python.org/downloads/" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Installing iOS dependencies..." -ForegroundColor Cyan

# Install pip if needed
& $pythonCmd -m ensurepip --upgrade 2>&1 | Out-Null

# Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Cyan
& $pythonCmd -m pip install --upgrade pip

# Install requirements
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$requirementsFile = Join-Path $scriptDir "requirements-ios.txt"

if (Test-Path $requirementsFile) {
    Write-Host "Installing packages from requirements-ios.txt..." -ForegroundColor Cyan
    & $pythonCmd -m pip install -r $requirementsFile
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "[OK] iOS environment setup complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Installed packages:" -ForegroundColor Cyan
        & $pythonCmd -m pip list | Select-String "pymobiledevice3|cryptography|construct"
    } else {
        Write-Host "[ERROR] Failed to install dependencies" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[ERROR] requirements-ios.txt not found at $requirementsFile" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "To test iOS device detection, connect an iOS device and run:" -ForegroundColor Yellow
Write-Host "  python scripts\ios_device_info.py" -ForegroundColor White
