@echo off
echo =====================================================
echo     🐍 COBRA AI - Development Mode 
echo =====================================================
echo.

echo 🔧 This will start services in development mode
echo ⚠️  Note: Some services may not be available without Docker
echo.

cd /d "%~dp0"

echo 📊 Starting Python OSINT Service...
start "OSINT Service" cmd /k "cd backend\services\osint && pip install -r requirements.txt && python osint_service_grpc.py"

echo.
timeout /t 3 /nobreak >nul

echo 🚀 Starting Backend Server...
start "Backend Server" cmd /k "cd backend && npm install && npm run dev"

echo.
timeout /t 3 /nobreak >nul

echo 🎨 Starting Frontend...
start "Frontend" cmd /k "cd frontend && npm install && npm run dev"

echo.
echo ⏳ Waiting for services to start...
timeout /t 10 /nobreak >nul

echo.
echo ✅ Services are starting!
echo.
echo 📍 Access Points:
echo   🌐 Frontend: http://localhost:5173
echo   🔧 Backend API: http://localhost:3001
echo   📊 OSINT Service: http://localhost:8001 (if Python/grpc available)
echo.
echo ⚠️  Note: Scanner, Crawler, and Packet services require:
echo   - Rust (https://rustup.rs/)
echo   - Go (https://golang.org/dl/)
echo   - C++ Build Tools
echo.
echo 🎯 To stop services: Close the opened command windows
echo.

echo Opening COBRA AI in your browser...
timeout /t 5 /nobreak >nul
start http://localhost:5173

echo.
echo Development servers are running in separate windows.
pause 