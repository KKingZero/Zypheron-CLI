@echo off
echo =====================================================
echo     🐍 COBRA AI - Core Services Setup
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
docker-compose -f docker-compose.core.yml down --remove-orphans

echo.
echo 🚀 Building and starting COBRA AI Core Services...
echo This includes: Frontend, Backend, OSINT Service, Database
echo.

docker-compose -f docker-compose.core.yml up --build -d

if errorlevel 1 (
    echo.
    echo ❌ Failed to start services!
    pause
    exit /b 1
)

echo.
echo ⏳ Waiting for services to start...
timeout /t 30 /nobreak >nul

echo.
echo ✅ COBRA AI Core is running!
echo.
echo 📍 Access Points:
echo   🌐 COBRA AI: http://localhost
echo   🔧 Backend API: http://localhost:3001
echo   📊 OSINT Service: http://localhost:8001
echo   🗄️ Database: localhost:5432
echo.
echo 💡 Tips:
echo   - This includes Frontend, Backend, OSINT, and Database
echo   - For AI features, start DeepSeek separately with start-deepseek.bat
echo   - Or use external APIs (OpenAI, XAI) via environment variables
echo.
echo 🎯 To stop: docker-compose -f docker-compose.core.yml down
echo.

echo Opening COBRA AI in your browser...
start http://localhost

pause 