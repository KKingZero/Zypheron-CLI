# Simple startup script for COBRA AI services

Write-Host "Starting COBRA AI Services..." -ForegroundColor Green

# Kill existing processes
Write-Host "Cleaning up existing processes..." -ForegroundColor Yellow
Get-Process | Where-Object {$_.ProcessName -eq "node" -or $_.ProcessName -eq "python"} | Stop-Process -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2

# Start Python OSINT Service
Write-Host "Starting Python OSINT Service..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-c", "cd backend\services\osint; pip install -r requirements.txt; python osint_service_simple.py"

# Start Backend
Write-Host "Starting Backend Server..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-c", "cd backend; npm run dev"

# Start Frontend
Write-Host "Starting Frontend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-c", "cd frontend; npm run dev"

Write-Host "Waiting for services to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host "`nServices should be running:" -ForegroundColor Green
Write-Host "- Backend: http://localhost:3001" -ForegroundColor White
Write-Host "- Frontend: http://localhost:5173" -ForegroundColor White
Write-Host "- OSINT API: http://localhost:5000" -ForegroundColor White

Write-Host "`nTo test OSINT:" -ForegroundColor Yellow
Write-Host "1. Open http://localhost:5173" -ForegroundColor White
Write-Host "2. Click 'New Penetration Test'" -ForegroundColor White
Write-Host "3. Enable OSINT and select sources" -ForegroundColor White
Write-Host "4. Run the test!" -ForegroundColor White 