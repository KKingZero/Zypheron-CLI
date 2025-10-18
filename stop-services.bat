@echo off
echo =====================================================
echo     🐍 COBRA AI - Stop Services
echo =====================================================
echo.

echo 🔧 Stopping Docker services...
docker-compose down --remove-orphans

echo.
echo 🔧 Stopping development processes...
taskkill /f /im node.exe 2>nul
taskkill /f /im python.exe 2>nul
taskkill /f /im cargo.exe 2>nul
taskkill /f /im go.exe 2>nul

echo.
echo ✅ All services stopped!
pause 