@echo off
REM Blue Team Defense System - Quick Setup Script
REM This script sets up all requirements for the Blue Team Defense System

echo.
echo 🛡️  BLUE TEAM DEFENSE SYSTEM - SETUP SCRIPT
echo ============================================
echo.

REM Check if Redis is running
echo 📦 Checking Redis...
redis-cli ping >nul 2>&1
if %errorlevel% == 0 (
    echo ✅ Redis is running
) else (
    echo ❌ Redis not running
    echo.
    echo Please start Redis:
    echo   Option 1: docker run -d --name redis-blueteam -p 6379:6379 redis:alpine
    echo   Option 2: Install Redis for Windows and run redis-server
    echo.
    pause
)

echo.
echo 📦 Installing backend dependencies...
cd backend

if not exist package.json (
    echo ❌ Error: backend/package.json not found
    pause
    exit /b 1
)

echo    Installing bullmq...
call npm install

if %errorlevel% == 0 (
    echo ✅ Backend dependencies installed
) else (
    echo ❌ Failed to install backend dependencies
    pause
    exit /b 1
)

cd ..

echo.
echo 📦 Installing frontend dependencies...
cd frontend

if not exist package.json (
    echo ❌ Error: frontend/package.json not found
    pause
    exit /b 1
)

echo    Installing visualization libraries...
call npm install recharts leaflet react-leaflet

if %errorlevel% == 0 (
    echo ✅ Frontend dependencies installed
) else (
    echo ❌ Failed to install frontend dependencies
    pause
    exit /b 1
)

cd ..

echo.
echo ✅ SETUP COMPLETE!
echo.
echo 📋 Next Steps:
echo.
echo 1. Configure Environment Variables:
echo    Add to backend/.env:
echo    REDIS_HOST=localhost
echo    REDIS_PORT=6379
echo    THREAT_DETECTION_ENABLED=true
echo    ML_ANOMALY_DETECTION=true
echo    BEHAVIORAL_ANALYSIS=true
echo    USE_ASYNC_QUEUE=true
echo.
echo 2. Run Database Migration:
echo    Execute the SQL in database/schema-defense.sql
echo    Plus the activity_log table from BLUE_TEAM_INTEGRATION_GUIDE.md
echo.
echo 3. Start the servers:
echo    Terminal 1: cd backend ^&^& npm run dev
echo    Terminal 2: cd frontend ^&^& npm run dev
echo.
echo 4. Access Blue Team Scanner:
echo    http://localhost:5173/blue-team-scanner
echo.
echo 🛡️  Your Blue Team Defense System is ready!
echo.
pause

