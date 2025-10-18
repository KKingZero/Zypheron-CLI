# COBRA AI Development Startup Script for Windows
Write-Host "🐍 Starting COBRA AI development environment..." -ForegroundColor Green

# Check if environment files exist
if (!(Test-Path "backend\.env")) {
    Write-Host "❌ backend\.env not found. Run setup.ps1 first." -ForegroundColor Red
    exit 1
}

if (!(Test-Path "frontend\.env")) {
    Write-Host "❌ frontend\.env not found. Run setup.ps1 first." -ForegroundColor Red
    exit 1
}

# Check if dependencies are installed
if (!(Test-Path "node_modules") -or !(Test-Path "frontend\node_modules") -or !(Test-Path "backend\node_modules")) {
    Write-Host "❌ Dependencies not installed. Run setup.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Environment files and dependencies found" -ForegroundColor Green
Write-Host "🚀 Starting development servers..." -ForegroundColor Yellow
Write-Host ""
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Cyan
Write-Host "Backend API: http://localhost:3001" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop all servers" -ForegroundColor Yellow

# Start both frontend and backend
npm run dev 