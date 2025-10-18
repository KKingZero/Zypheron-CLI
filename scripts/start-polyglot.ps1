# COBRA AI Polyglot Services Startup Script
# This script starts all services in the polyglot architecture

Write-Host "🐍 COBRA AI Polyglot Architecture Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if Python is installed
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Python is not installed. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green

# Check if Rust is installed
$rustVersion = rustc --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Rust is not installed. Installing via rustup..." -ForegroundColor Yellow
    # Optionally install Rust
    # Invoke-WebRequest -Uri https://win.rustup.rs -OutFile rustup-init.exe
    # ./rustup-init.exe -y
    Write-Host "Please install Rust from https://rustup.rs/" -ForegroundColor Yellow
    exit 1
}
Write-Host "✅ Rust found: $rustVersion" -ForegroundColor Green

# Check if Node.js is installed
$nodeVersion = node --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Node.js is not installed." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Node.js found: $nodeVersion" -ForegroundColor Green

# Function to start a service in a new window
function Start-ServiceWindow {
    param(
        [string]$ServiceName,
        [string]$WorkingDirectory,
        [string]$Command
    )
    
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "powershell.exe"
    $startInfo.Arguments = "-NoExit -Command `"cd '$WorkingDirectory'; Write-Host '🚀 Starting $ServiceName...' -ForegroundColor Cyan; $Command`""
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $true
    
    [System.Diagnostics.Process]::Start($startInfo) | Out-Null
    Write-Host "✅ Started $ServiceName" -ForegroundColor Green
}

# Start Python OSINT Service
Write-Host "`n📊 Setting up Python OSINT Service..." -ForegroundColor Yellow
$osintPath = Join-Path $PSScriptRoot "..\backend\services\osint"
if (Test-Path $osintPath) {
    # Install Python dependencies if needed
    if (!(Test-Path (Join-Path $osintPath ".venv"))) {
        Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
        Push-Location $osintPath
        python -m venv .venv
        & .\.venv\Scripts\Activate.ps1
        pip install -r requirements.txt
        Pop-Location
    }
    
    Start-ServiceWindow -ServiceName "Python OSINT Service" `
        -WorkingDirectory $osintPath `
        -Command "if (Test-Path .venv) { .\.venv\Scripts\Activate.ps1 }; python osint_service.py"
} else {
    Write-Host "⚠️  OSINT service directory not found" -ForegroundColor Yellow
}

# Start Rust Scanner Service
Write-Host "`n🔍 Setting up Rust Scanner Service..." -ForegroundColor Yellow
$scannerPath = Join-Path $PSScriptRoot "..\backend\services\scanner"
if (Test-Path $scannerPath) {
    # Build Rust service if needed
    if (!(Test-Path (Join-Path $scannerPath "target\release\cobra-scanner.exe"))) {
        Write-Host "Building Rust scanner..." -ForegroundColor Yellow
        Push-Location $scannerPath
        cargo build --release
        Pop-Location
    }
    
    Start-ServiceWindow -ServiceName "Rust Scanner Service" `
        -WorkingDirectory $scannerPath `
        -Command "cargo run --release"
} else {
    Write-Host "⚠️  Scanner service directory not found" -ForegroundColor Yellow
}

# Start Node.js Backend
Write-Host "`n🖥️  Setting up Node.js Backend..." -ForegroundColor Yellow
$backendPath = Join-Path $PSScriptRoot "..\backend"
if (Test-Path $backendPath) {
    # Install Node dependencies if needed
    if (!(Test-Path (Join-Path $backendPath "node_modules"))) {
        Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
        Push-Location $backendPath
        npm install
        Pop-Location
    }
    
    Start-ServiceWindow -ServiceName "Node.js Backend" `
        -WorkingDirectory $backendPath `
        -Command "npm run dev"
} else {
    Write-Host "⚠️  Backend directory not found" -ForegroundColor Yellow
}

# Start Frontend
Write-Host "`n🎨 Setting up Frontend..." -ForegroundColor Yellow
$frontendPath = Join-Path $PSScriptRoot "..\frontend"
if (Test-Path $frontendPath) {
    # Install frontend dependencies if needed
    if (!(Test-Path (Join-Path $frontendPath "node_modules"))) {
        Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
        Push-Location $frontendPath
        npm install
        Pop-Location
    }
    
    Start-ServiceWindow -ServiceName "React Frontend" `
        -WorkingDirectory $frontendPath `
        -Command "npm run dev"
} else {
    Write-Host "⚠️  Frontend directory not found" -ForegroundColor Yellow
}

Write-Host "`n✨ All services are starting up!" -ForegroundColor Green
Write-Host "Services will be available at:" -ForegroundColor Cyan
Write-Host "  - Frontend:      http://localhost:5173" -ForegroundColor White
Write-Host "  - Backend API:   http://localhost:3001" -ForegroundColor White
Write-Host "  - OSINT Service: http://localhost:8001" -ForegroundColor White
Write-Host "  - Scanner:       http://localhost:8002" -ForegroundColor White
Write-Host "`nPress Ctrl+C in each window to stop services" -ForegroundColor Yellow 