@echo off
echo =====================================================
echo     🐍 COBRA AI + 🧠 DeepSeek Docker Setup
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
docker-compose -f docker-compose.with-deepseek.yml down --remove-orphans

echo.
echo 🚀 Building and starting COBRA AI + DeepSeek...
echo ⚠️  IMPORTANT: This will download the DeepSeek model (~4GB)
echo ⏱️  First run may take 20-30 minutes!
echo.

set /p continue="Continue? (y/N): "
if /i not "%continue%"=="y" (
    echo Cancelled.
    pause
    exit /b 0
)

docker-compose -f docker-compose.with-deepseek.yml up --build -d

if errorlevel 1 (
    echo.
    echo ❌ Failed to start services!
    pause
    exit /b 1
)

echo.
echo ⏳ Waiting for COBRA AI to start...
timeout /t 60 /nobreak >nul

echo.
echo 📥 DeepSeek model is downloading in the background...
echo    You can check progress with: docker-compose -f docker-compose.with-deepseek.yml logs deepseek-setup
echo.

echo ✅ COBRA AI + DeepSeek is starting!
echo.
echo 📍 Access Points:
echo   🌐 COBRA AI: http://localhost
echo   🧠 DeepSeek API: http://localhost:11434
echo   🎛️ DeepSeek Web UI: http://localhost:8080
echo   🔧 Backend API: http://localhost:3001
echo   📊 All COBRA AI Services: ports 8001-8005
echo   🗄️ Database: localhost:5432
echo.
echo 💡 Tips:
echo   - DeepSeek model download may take 15-30 minutes
echo   - Check logs: docker-compose -f docker-compose.with-deepseek.yml logs
echo   - Web UI will be available once model download completes
echo.
echo 🎯 To stop: docker-compose -f docker-compose.with-deepseek.yml down
echo.

echo Opening COBRA AI in your browser...
start http://localhost

echo Opening DeepSeek Web UI...
timeout /t 5 /nobreak >nul
start http://localhost:8080

pause 