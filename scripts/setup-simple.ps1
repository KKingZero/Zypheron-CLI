# COBRA AI Setup Script for Windows
Write-Host "Setting up COBRA AI..." -ForegroundColor Green

# Check if Node.js is installed
try {
    $nodeVersion = node -v
    Write-Host "Node.js $nodeVersion detected" -ForegroundColor Green
    
    # Check if version is 18+
    $versionNumber = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
    if ($versionNumber -lt 18) {
        Write-Host "Node.js version 18+ is required. Current version: $nodeVersion" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Node.js is not installed. Please install Node.js 18+ first." -ForegroundColor Red
    exit 1
}

# Install root dependencies
Write-Host "Installing root dependencies..." -ForegroundColor Yellow
npm install

# Install frontend dependencies
Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
Set-Location frontend
npm install
Set-Location ..

# Install backend dependencies
Write-Host "Installing backend dependencies..." -ForegroundColor Yellow
Set-Location backend
npm install
Set-Location ..

# Create environment files from examples
Write-Host "Setting up environment files..." -ForegroundColor Yellow

# Create backend .env.example if it doesn't exist
if (!(Test-Path "backend\.env.example")) {
    @"
# Server Configuration
PORT=3001
NODE_ENV=development

# Supabase Configuration
SUPABASE_URL=your_supabase_project_url
SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# AI Model API Keys
OPENAI_API_KEY=your_openai_api_key

# Threat Intelligence API Keys (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# Security Configuration
JWT_SECRET=your_jwt_secret_key_here
CORS_ORIGIN=http://localhost:5173

# Logging Configuration
LOG_LEVEL=info
"@ | Out-File -FilePath "backend\.env.example" -Encoding UTF8
}

# Create frontend .env.example if it doesn't exist
if (!(Test-Path "frontend\.env.example")) {
    @"
# API Configuration
VITE_API_URL=http://localhost:3001

# Supabase Configuration
VITE_SUPABASE_URL=your_supabase_project_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key

# Application Configuration
VITE_APP_NAME=COBRA AI
VITE_APP_VERSION=1.0.0

# Feature Flags
VITE_ENABLE_MOCK_DATA=true
VITE_ENABLE_ANALYTICS=false
"@ | Out-File -FilePath "frontend\.env.example" -Encoding UTF8
}

if (!(Test-Path "backend\.env")) {
    Copy-Item "backend\.env.example" "backend\.env"
    Write-Host "Created backend\.env - Please update with your API keys" -ForegroundColor Cyan
}

if (!(Test-Path "frontend\.env")) {
    Copy-Item "frontend\.env.example" "frontend\.env"
    Write-Host "Created frontend\.env - Please update with your configuration" -ForegroundColor Cyan
}

# Create logs directory for backend
if (!(Test-Path "backend\logs")) {
    New-Item -ItemType Directory -Path "backend\logs" -Force | Out-Null
}

Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Update backend\.env with your API keys"
Write-Host "2. Update frontend\.env with your Supabase configuration"
Write-Host "3. Run 'npm run dev' to start the development servers" 