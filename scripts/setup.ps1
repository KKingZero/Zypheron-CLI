# COBRA AI Setup Script for Windows
Write-Host "🐍 Setting up COBRA AI..." -ForegroundColor Green

# Check if Node.js is installed
try {
    $nodeVersion = node -v
    Write-Host "✅ Node.js $nodeVersion detected" -ForegroundColor Green
    
    # Check if version is 18+
    $versionNumber = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
    if ($versionNumber -lt 18) {
        Write-Host "❌ Node.js version 18+ is required. Current version: $nodeVersion" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Node.js is not installed. Please install Node.js 18+ first." -ForegroundColor Red
    exit 1
}

# Install root dependencies
Write-Host "📦 Installing root dependencies..." -ForegroundColor Yellow
npm install

# Install frontend dependencies
Write-Host "📦 Installing frontend dependencies..." -ForegroundColor Yellow
Set-Location frontend
npm install
Set-Location ..

# Install backend dependencies
Write-Host "📦 Installing backend dependencies..." -ForegroundColor Yellow
Set-Location backend
npm install
Set-Location ..

# Create environment files from examples
Write-Host "🔧 Setting up environment files..." -ForegroundColor Yellow

if (!(Test-Path "backend\.env")) {
    Copy-Item "backend\.env.example" "backend\.env"
    Write-Host "📝 Created backend\.env - Please update with your API keys" -ForegroundColor Cyan
}

if (!(Test-Path "frontend\.env")) {
    Copy-Item "frontend\.env.example" "frontend\.env"
    Write-Host "📝 Created frontend\.env - Please update with your configuration" -ForegroundColor Cyan
}

# Create logs directory for backend
if (!(Test-Path "backend\logs")) {
    New-Item -ItemType Directory -Path "backend\logs" -Force
}

Write-Host "🎉 Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Update backend\.env with your API keys (OpenAI, Supabase, etc.)"
Write-Host "2. Update frontend\.env with your Supabase configuration"
Write-Host "3. Run 'npm run dev' to start the development servers"
Write-Host ""
Write-Host "📖 See SETUP.md for detailed configuration instructions" -ForegroundColor Cyan 