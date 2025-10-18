@echo off
echo =====================================================
echo     🧠 DeepSeek-R1 Open Source AI Setup
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

echo 🔧 Stopping any existing DeepSeek containers...
docker-compose -f docker-compose.deepseek-only.yml down --remove-orphans

echo.
echo 🚀 Starting DeepSeek-R1 Open Source AI...
echo 📋 What you'll get:
echo   - DeepSeek-R1 8B (Latest reasoning model - 5.2GB)
echo   - DeepSeek-R1 7B (Alternative model - 4.7GB)
echo   - Open-WebUI interface for direct chat
echo   - MIT License - fully open source and commercial use allowed
echo.
echo ⚠️  IMPORTANT: First run will download ~10GB of models
echo ⏱️  Download time: 10-20 minutes depending on internet speed
echo 💾  RAM Required: 8GB+ recommended for 8B model, 6GB+ for 7B model
echo.

set /p continue="Continue with DeepSeek-R1 setup? (y/N): "
if /i not "%continue%"=="y" (
    echo Cancelled.
    pause
    exit /b 0
)

docker-compose -f docker-compose.deepseek-only.yml up -d

if errorlevel 1 (
    echo.
    echo ❌ Failed to start DeepSeek!
    echo Check Docker logs: docker-compose -f docker-compose.deepseek-only.yml logs
    pause
    exit /b 1
)

echo.
echo ⏳ Starting DeepSeek services...
timeout /t 15 /nobreak >nul

echo.
echo 📥 DeepSeek-R1 models are downloading in the background...
echo    You can monitor progress with: docker-compose -f docker-compose.deepseek-only.yml logs deepseek-setup
echo.

echo ✅ DeepSeek-R1 is starting!
echo.
echo 📍 Access Points:
echo   🧠 DeepSeek API: http://localhost:11434
echo   🎛️ DeepSeek Web UI: http://localhost:8080
echo   📚 API Documentation: http://localhost:11434/api/tags
echo.
echo 🤖 Available Models:
echo   - deepseek-r1:8b (Recommended - Latest reasoning model)
echo   - deepseek-r1:7b (Alternative - Smaller footprint)
echo.
echo 💡 Usage in COBRA AI:
echo   - The backend will automatically detect and use localhost:11434
echo   - Select "DeepSeek" or "Local" model in the chat interface
echo   - All processing stays completely local and private
echo.
echo 📜 License: MIT License (Open Source, Commercial Use Allowed)
echo 🏢 From: DeepSeek AI (https://github.com/deepseek-ai/DeepSeek-R1)
echo.
echo 🎯 To stop: docker-compose -f docker-compose.deepseek-only.yml down
echo.

echo Opening DeepSeek Web UI...
timeout /t 5 /nobreak >nul
start http://localhost:8080

echo.
echo 🔄 Checking model download progress...
timeout /t 10 /nobreak >nul
docker-compose -f docker-compose.deepseek-only.yml logs --tail=10 deepseek-setup

pause 