@echo off
REM 🚀 Cobra AI - Windows Localhost Installation Script
REM This script automates the installation process for the advanced cybersecurity tools

setlocal enabledelayedexpansion

echo 🐍 COBRA AI - Advanced Cybersecurity Tools Installation
echo ========================================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if errorlevel 1 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js detected: 
node --version

REM Check if npm is installed
where npm >nul 2>nul
if errorlevel 1 (
    echo ❌ npm is not installed
    pause
    exit /b 1
)

echo ✅ npm detected:
npm --version

echo.
echo 📋 Step 1: Installing Dependencies
echo.

echo Installing backend dependencies...
cd backend
call npm install
if errorlevel 1 (
    echo ❌ Failed to install backend dependencies
    pause
    exit /b 1
)
echo ✅ Backend dependencies installed

echo Installing frontend dependencies...
cd ..\frontend
call npm install
if errorlevel 1 (
    echo ❌ Failed to install frontend dependencies
    pause
    exit /b 1
)
echo ✅ Frontend dependencies installed

cd ..

echo.
echo 📋 Step 2: Setting up Environment Files
echo.

REM Backend environment
if not exist "backend\.env" (
    if exist "backend\env.example" (
        copy "backend\env.example" "backend\.env" >nul
        echo ✅ Backend .env file created from example
        echo ⚠️  Please edit backend\.env with your API keys and configuration
    ) else (
        echo Creating basic backend .env file...
        (
            echo # Database Configuration
            echo DATABASE_URL="postgresql://localhost:5432/cobra_ai"
            echo.
            echo # AI Service API Keys ^(Add your keys here^)
            echo GEMINI_API_KEY=""
            echo OPENAI_API_KEY=""
            echo MOONSHOT_API_KEY=""
            echo.
            echo # External Tool APIs ^(Optional^)
            echo SHODAN_API_KEY=""
            echo VIRUSTOTAL_API_KEY=""
            echo.
            echo # Security Settings
            echo JWT_SECRET="your_jwt_secret_change_this_in_production"
            echo ENCRYPTION_KEY="your_encryption_key_change_this_in_production"
            echo.
            echo # Server Configuration
            echo PORT=3001
            echo NODE_ENV=development
            echo.
            echo # Supabase Configuration ^(Optional^)
            echo SUPABASE_URL=""
            echo SUPABASE_ANON_KEY=""
            echo SUPABASE_SERVICE_ROLE_KEY=""
        ) > "backend\.env"
        echo ✅ Basic backend .env file created
    )
) else (
    echo ✅ Backend .env file already exists
)

REM Frontend environment
if not exist "frontend\.env" (
    if exist "frontend\env.example" (
        copy "frontend\env.example" "frontend\.env" >nul
        echo ✅ Frontend .env file created from example
    ) else (
        echo Creating basic frontend .env file...
        (
            echo # API Configuration
            echo VITE_API_URL=http://localhost:3001
            echo VITE_WEBSOCKET_URL=ws://localhost:3001
            echo.
            echo # External Services
            echo VITE_SUPABASE_URL=""
            echo VITE_SUPABASE_ANON_KEY=""
            echo.
            echo # Development Settings
            echo VITE_DEV_MODE=true
            echo VITE_LOG_LEVEL=debug
        ) > "frontend\.env"
        echo ✅ Basic frontend .env file created
    )
) else (
    echo ✅ Frontend .env file already exists
)

echo.
echo 📋 Step 3: Checking Security Tools
echo.

where nmap >nul 2>nul
if errorlevel 1 (
    echo ⚠️  nmap is not installed. Download from https://nmap.org/download.html
) else (
    echo ✅ nmap is installed
)

where python >nul 2>nul
if errorlevel 1 (
    where python3 >nul 2>nul
    if errorlevel 1 (
        echo ⚠️  Python is not installed. Download from https://python.org/downloads/
    ) else (
        echo ✅ Python3 is installed
    )
) else (
    echo ✅ Python is installed
)

echo.
echo 📋 Step 4: Creating Start Scripts
echo.

if not exist "start-dev.bat" (
    (
        echo @echo off
        echo echo 🚀 Starting Cobra AI Development Environment...
        echo.
        echo echo Starting backend server...
        echo cd backend
        echo start cmd /k "npm run dev"
        echo.
        echo timeout /t 3 /nobreak ^>nul
        echo.
        echo echo Starting frontend development server...
        echo cd ..\frontend
        echo start cmd /k "npm run dev"
        echo.
        echo echo.
        echo echo 🎉 Cobra AI is starting up!
        echo echo 📊 Backend API: http://localhost:3001
        echo echo 🌐 Frontend App: http://localhost:5173
        echo echo 🛠️ Advanced Tools: Navigate to Red Team Ops → Advanced Tools
        echo echo.
        echo echo Press any key to continue...
        echo pause ^>nul
    ) > "start-dev.bat"
    echo ✅ start-dev.bat created
)

echo.
echo 📋 Step 5: Final Setup
echo.

REM Create logs directory
if not exist "logs" mkdir logs
echo ✅ Logs directory created

echo.
echo 🎉 Installation Complete!
echo ========================================================
echo.
echo Next steps:
echo 1. Edit backend\.env with your API keys ^(Gemini, OpenAI, Shodan, etc.^)
echo 2. Edit frontend\.env if needed
echo 3. Start the development environment: double-click start-dev.bat
echo 4. Open http://localhost:5173 in your browser
echo 5. Navigate to Red Team Operations → Advanced Tools
echo.
echo 🔒 Security Note:
echo These tools are for authorized testing only. Always ensure you have
echo explicit permission before testing any systems.
echo.
echo 📚 For detailed configuration, see LOCALHOST_INSTALLATION_GUIDE.md
echo.
echo ✅ Ready to launch Cobra AI! 🐍
echo.
pause