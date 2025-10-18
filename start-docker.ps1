#!/usr/bin/env pwsh

Write-Host "=====================================================" -ForegroundColor Green
Write-Host "     🐍 COBRA AI - Docker Setup                    " -ForegroundColor Green  
Write-Host "=====================================================" -ForegroundColor Green
Write-Host

# Check if Docker is running
Write-Host "Checking if Docker is running..." -ForegroundColor Yellow
try {
    $null = docker info 2>$null
    Write-Host "✅ Docker is running!" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running or not installed!" -ForegroundColor Red
    Write-Host
    Write-Host "Please:" -ForegroundColor Yellow
    Write-Host "1. Install Docker Desktop from: https://docker.com/products/docker-desktop" -ForegroundColor White
    Write-Host "2. Start Docker Desktop" -ForegroundColor White
    Write-Host "3. Wait for it to fully load (check system tray)" -ForegroundColor White
    Write-Host "4. Run this script again" -ForegroundColor White
    Write-Host
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host

# Stop existing containers
Write-Host "🔧 Stopping any existing containers..." -ForegroundColor Yellow
docker-compose down --remove-orphans

Write-Host
Write-Host "🚀 Starting COBRA AI services..." -ForegroundColor Cyan
Write-Host "This may take several minutes on first run (downloading/building images)" -ForegroundColor Gray
Write-Host

# Start services
docker-compose up --build -d

if ($LASTEXITCODE -ne 0) {
    Write-Host
    Write-Host "❌ Failed to start services!" -ForegroundColor Red
    Write-Host "Check the error messages above." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host
Write-Host "⏳ Waiting for services to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

Write-Host
Write-Host "✅ COBRA AI is starting up!" -ForegroundColor Green
Write-Host

Write-Host "📍 Access Points:" -ForegroundColor Cyan
Write-Host "  🌐 Frontend: http://localhost" -ForegroundColor White
Write-Host "  🔧 Backend API: http://localhost:3001" -ForegroundColor White
Write-Host "  📊 OSINT Service: http://localhost:8001" -ForegroundColor White
Write-Host "  🔍 Scanner Service: http://localhost:8002" -ForegroundColor White
Write-Host "  📦 Packet Service: http://localhost:8003" -ForegroundColor White
Write-Host "  🕷️ Crawler Service: http://localhost:8004" -ForegroundColor White
Write-Host "  🛡️ Vulnerability Scanner: http://localhost:8005" -ForegroundColor White
Write-Host "  🗄️ Database: localhost:5432" -ForegroundColor White
Write-Host

Write-Host "🎯 To stop all services, run: " -NoNewline -ForegroundColor Yellow
Write-Host "docker-compose down" -ForegroundColor White
Write-Host

# Check service status
Write-Host "🔍 Checking service status..." -ForegroundColor Yellow
$services = @(
    @{Name="Frontend"; Port=80},
    @{Name="Backend"; Port=3001},
    @{Name="OSINT"; Port=8001},
    @{Name="Scanner"; Port=8002},
    @{Name="Packet"; Port=8003},
    @{Name="Crawler"; Port=8004},
    @{Name="VulnScanner"; Port=8005}
)

foreach ($service in $services) {
    $test = Test-NetConnection -ComputerName localhost -Port $service.Port -WarningAction SilentlyContinue
    if ($test.TcpTestSucceeded) {
        Write-Host "  ✅ $($service.Name) service is running" -ForegroundColor Green
    } else {
        Write-Host "  ⏳ $($service.Name) service is starting..." -ForegroundColor Yellow
    }
}

Write-Host
Write-Host "Opening COBRA AI in your browser..." -ForegroundColor Cyan
Start-Process "http://localhost"

Write-Host
Write-Host "Services are running in the background." -ForegroundColor Green
Write-Host "Check Docker Desktop for logs and status." -ForegroundColor Gray
Read-Host "Press Enter to continue" 