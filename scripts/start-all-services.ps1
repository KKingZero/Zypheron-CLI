# Start all COBRA AI services
Write-Host "🐍 Starting COBRA AI Services..." -ForegroundColor Green

# Function to check if a port is in use
function Test-Port {
    param($Port)
    $connection = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue
    return $connection.TcpTestSucceeded
}

# Kill any existing processes on our ports
Write-Host "Cleaning up existing processes..." -ForegroundColor Yellow
$ports = @(3001, 5000, 50051, 5173, 5174)
foreach ($port in $ports) {
    $process = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
    if ($process) {
        Stop-Process -Id $process -Force -ErrorAction SilentlyContinue
        Write-Host "Killed process on port $port" -ForegroundColor Yellow
    }
}

Start-Sleep -Seconds 2

# Start Python OSINT Service
Write-Host "`n📊 Starting Python OSINT Service..." -ForegroundColor Cyan
$osintPath = Join-Path $PSScriptRoot "..\backend\services\osint"
if (Test-Path $osintPath) {
    $pythonCmd = @"
cd '$osintPath'
Write-Host 'Installing Python dependencies...' -ForegroundColor Yellow
pip install -r requirements.txt --quiet
Write-Host 'Starting OSINT Service on port 5000...' -ForegroundColor Green
python osint_service_simple.py
"@
    Start-Process powershell -ArgumentList @("-NoExit", "-Command", $pythonCmd) -WindowStyle Normal
} else {
    Write-Host "OSINT service directory not found!" -ForegroundColor Red
}

# Note about Rust
Write-Host "`n🦀 Rust Scanner Service..." -ForegroundColor Cyan
Write-Host "Note: Rust is not installed. The scanner will use fallback mode." -ForegroundColor Yellow
Write-Host "To install Rust, visit: https://rustup.rs/" -ForegroundColor Gray

# Wait a bit for services to start
Write-Host "`nWaiting for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Start Backend with ts-node-dev
Write-Host "`n🚀 Starting Backend Server..." -ForegroundColor Cyan
$backendPath = Join-Path $PSScriptRoot "..\backend"
$backendCmd = @"
cd '$backendPath'
Write-Host 'Starting Backend on port 3001...' -ForegroundColor Green
npm run dev
"@
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $backendCmd) -WindowStyle Normal

# Start Frontend
Write-Host "🎨 Starting Frontend..." -ForegroundColor Cyan
$frontendPath = Join-Path $PSScriptRoot "..\frontend"
$frontendCmd = @"
cd '$frontendPath'
Write-Host 'Starting Frontend on port 5173...' -ForegroundColor Green
npm run dev
"@
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $frontendCmd) -WindowStyle Normal

# Wait and check services
Start-Sleep -Seconds 10

Write-Host "`n✅ Service Status:" -ForegroundColor Green
Write-Host "-------------------" -ForegroundColor Gray

# Check each service
$services = @(
    @{Name="Backend API"; Port=3001; URL="http://localhost:3001/health"},
    @{Name="Frontend"; Port=5173; URL="http://localhost:5173"},
    @{Name="Python OSINT"; Port=5000; URL="http://localhost:5000/health"}
)

foreach ($service in $services) {
    if (Test-Port -Port $service.Port) {
        Write-Host "✅ $($service.Name) is running on port $($service.Port)" -ForegroundColor Green
        if ($service.URL) {
            Write-Host "   URL: $($service.URL)" -ForegroundColor Gray
        }
    } else {
        Write-Host "❌ $($service.Name) is NOT running on port $($service.Port)" -ForegroundColor Red
    }
}

Write-Host "`n📝 Instructions:" -ForegroundColor Yellow
Write-Host "1. Open http://localhost:5173 in your browser" -ForegroundColor White
Write-Host "2. Click 'New Penetration Test'" -ForegroundColor White
Write-Host "3. Enable OSINT option" -ForegroundColor White
Write-Host "4. Run a test - OSINT data will now be REAL!" -ForegroundColor White
Write-Host "`nPress Ctrl+C in each window to stop services" -ForegroundColor Gray 