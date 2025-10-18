@echo off
echo =====================================================
echo     🐍 COBRA AI - Simple Docker Setup 
echo =====================================================
echo.

echo Checking if Docker is running...
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running or not installed!
    echo.
    echo Please:
    echo 1. Start Docker Desktop from Windows Start menu
    echo 2. Wait for it to fully load
    echo 3. Run this script again
    echo.
    pause
    exit /b 1
)

echo ✅ Docker is running!
echo.

echo 🔧 Stopping any existing containers...
docker-compose -f docker-compose.simple.yml down --remove-orphans

echo.
echo 🚀 Starting COBRA AI core services...
echo This will start: Frontend, Backend, Database
echo.

docker-compose -f docker-compose.simple.yml up --build -d

if errorlevel 1 (
    echo.
    echo ❌ Failed to start services!
    echo Check the error messages above.
    pause
    exit /b 1
)

echo.
echo ⏳ Waiting for services to start...
timeout /t 20 /nobreak >nul

echo.
echo ✅ COBRA AI Core is running!
echo.
echo 📍 Access Points:
echo   🌐 COBRA AI: http://localhost
echo   🔧 Backend API: http://localhost:3001
echo   🗄️ Database: localhost:5432
echo.
echo 💡 Note: Advanced services (OSINT, Scanner, etc.) are not included
echo    in this simple setup. Use start-docker.bat for full features.
echo.
echo 🎯 To stop services: docker-compose -f docker-compose.simple.yml down
echo.

echo Opening COBRA AI in your browser...
start http://localhost

echo.
echo Services are running in the background.
pause 