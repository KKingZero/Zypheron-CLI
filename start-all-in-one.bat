@echo off
echo =====================================================
echo     🐍 COBRA AI - All-in-One Docker Setup
echo =====================================================
echo.

echo Checking if Docker is running...
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running or not installed!
    echo.
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

echo ✅ Docker is running!
echo.

echo 🔧 Stopping any existing containers...
docker-compose -f docker-compose.all-in-one.yml down --remove-orphans

echo.
echo 🚀 Building and starting COBRA AI (All-in-One)...
echo This may take 10-15 minutes on first run (building everything)
echo.

docker-compose -f docker-compose.all-in-one.yml up --build -d

if errorlevel 1 (
    echo.
    echo ❌ Failed to start services!
    pause
    exit /b 1
)

echo.
echo ⏳ Waiting for services to start...
timeout /t 60 /nobreak >nul

echo.
echo ✅ COBRA AI All-in-One is running!
echo.
echo 📍 Access Points:
echo   🌐 COBRA AI: http://localhost
echo   🔧 Backend API: http://localhost:3001
echo   📊 OSINT Service: http://localhost:8001
echo   🔍 Scanner Service: http://localhost:8002
echo   📦 Packet Service: http://localhost:8003
echo   🕷️ Crawler Service: http://localhost:8004
echo   🛡️ Vulnerability Scanner: http://localhost:8005
echo   🗄️ Database: localhost:5432
echo.
echo 🎯 To stop: docker-compose -f docker-compose.all-in-one.yml down
echo.

echo Opening COBRA AI in your browser...
start http://localhost

pause 