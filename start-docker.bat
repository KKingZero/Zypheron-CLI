@echo off
echo =====================================================
echo     🐍 COBRA AI - Docker Setup 
echo =====================================================
echo.

echo Checking if Docker is running...
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running or not installed!
    echo.
    echo Please:
    echo 1. Install Docker Desktop from: https://docker.com/products/docker-desktop
    echo 2. Start Docker Desktop
    echo 3. Wait for it to fully load
    echo 4. Run this script again
    echo.
    pause
    exit /b 1
)

echo ✅ Docker is running!
echo.

echo 🔧 Stopping any existing containers...
docker-compose down --remove-orphans

echo.
echo 🚀 Starting COBRA AI services...
echo This may take several minutes on first run (downloading/building images)
echo.

docker-compose up --build -d

if errorlevel 1 (
    echo.
    echo ❌ Failed to start services!
    echo Check the error messages above.
    pause
    exit /b 1
)

echo.
echo ⏳ Waiting for services to start...
timeout /t 30 /nobreak >nul

echo.
echo ✅ COBRA AI is starting up!
echo.
echo 📍 Access Points:
echo   🌐 Frontend: http://localhost
echo   🔧 Backend API: http://localhost:3001
echo   📊 OSINT Service: http://localhost:8001
echo   🔍 Scanner Service: http://localhost:8002
echo   📦 Packet Service: http://localhost:8003
echo   🕷️  Crawler Service: http://localhost:8004
echo   🛡️  Vulnerability Scanner: http://localhost:8005
echo   🗄️  Database: http://localhost:5432
echo.
echo 🎯 To stop all services, run: docker-compose down
echo.

echo Opening COBRA AI in your browser...
start http://localhost

echo.
echo Services are running in the background.
echo Check Docker Desktop for logs and status.
pause 