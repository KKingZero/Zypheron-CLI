# COBRA AI Secure Deployment Script
# This script ensures secure deployment with encrypted API keys and environment variables

param(
    [string]$Environment = "production",
    [switch]$SkipValidation = $false,
    [switch]$GenerateKeys = $false
)

Write-Host "🛡️  COBRA AI Secure Deployment" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "==============================`n" -ForegroundColor Green

# Function to check if required tools are installed
function Test-Prerequisites {
    Write-Host "🔍 Checking prerequisites..." -ForegroundColor Yellow
    
    # Check Node.js
    try {
        $nodeVersion = node -v
        Write-Host "✅ Node.js: $nodeVersion" -ForegroundColor Green
    } catch {
        Write-Host "❌ Node.js not found. Please install Node.js 18+" -ForegroundColor Red
        exit 1
    }
    
    # Check Docker (optional)
    try {
        $dockerVersion = docker --version
        Write-Host "✅ Docker: $dockerVersion" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Docker not found (optional for local deployment)" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Function to validate environment files
function Test-EnvironmentFiles {
    Write-Host "🔍 Validating environment configuration..." -ForegroundColor Yellow
    
    $backendEnvPath = "backend\.env"
    $frontendEnvPath = "frontend\.env"
    
    if (!(Test-Path $backendEnvPath)) {
        Write-Host "❌ Backend .env file not found" -ForegroundColor Red
        Write-Host "   Copy backend\env.example to backend\.env and configure your API keys" -ForegroundColor Yellow
        return $false
    }
    
    if (!(Test-Path $frontendEnvPath)) {
        Write-Host "❌ Frontend .env file not found" -ForegroundColor Red
        Write-Host "   Copy frontend\env.example to frontend\.env and configure your settings" -ForegroundColor Yellow
        return $false
    }
    
    # Check for required backend environment variables
    $backendEnv = Get-Content $backendEnvPath
    $requiredBackendVars = @(
        "SUPABASE_URL",
        "SUPABASE_ANON_KEY", 
        "SUPABASE_SERVICE_ROLE_KEY",
        "JWT_SECRET"
    )
    
    $missingVars = @()
    foreach ($var in $requiredBackendVars) {
        $found = $backendEnv | Where-Object { $_ -like "$var=*" -and $_ -notlike "*your_*" -and $_ -notlike "*=`$*" }
        if (!$found) {
            $missingVars += $var
        }
    }
    
    if ($missingVars.Count -gt 0) {
        Write-Host "❌ Missing required backend environment variables:" -ForegroundColor Red
        $missingVars | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        return $false
    }
    
    # Check for AI API keys
    $aiKeys = @("OPENAI_API_KEY", "GEMINI_API_KEY", "XAI_API_KEY")
    $foundAiKey = $false
    foreach ($key in $aiKeys) {
        $found = $backendEnv | Where-Object { $_ -like "$key=*" -and $_ -notlike "*your_*" -and $_ -notlike "*=`$*" }
        if ($found) {
            $foundAiKey = $true
            Write-Host "✅ Found AI API key: $key" -ForegroundColor Green
        }
    }
    
    if (!$foundAiKey) {
        Write-Host "⚠️  No AI API keys found. At least one is required for full functionality." -ForegroundColor Yellow
    }
    
    Write-Host "✅ Environment validation completed" -ForegroundColor Green
    Write-Host ""
    return $true
}

# Function to generate encryption keys
function New-EncryptionKeys {
    Write-Host "🔑 Generating encryption keys..." -ForegroundColor Yellow
    
    # Generate master encryption key
    $masterKey = -join ((1..64) | ForEach-Object { '{0:X}' -f (Get-Random -Maximum 16) })
    
    Write-Host "Generated master encryption key (add to backend .env):" -ForegroundColor Cyan
    Write-Host "ENCRYPTION_MASTER_KEY=$masterKey" -ForegroundColor Gray
    Write-Host ""
    
    # Generate JWT secret
    $jwtSecret = -join ((1..32) | ForEach-Object { [char](Get-Random -Minimum 65 -Maximum 91) })
    
    Write-Host "Generated JWT secret (add to backend .env):" -ForegroundColor Cyan
    Write-Host "JWT_SECRET=$jwtSecret" -ForegroundColor Gray
    Write-Host ""
}

# Function to install dependencies
function Install-Dependencies {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    
    # Install root dependencies
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install root dependencies" -ForegroundColor Red
        exit 1
    }
    
    # Install backend dependencies
    Set-Location backend
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install backend dependencies" -ForegroundColor Red
        exit 1
    }
    Set-Location ..
    
    # Install frontend dependencies  
    Set-Location frontend
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install frontend dependencies" -ForegroundColor Red
        exit 1
    }
    Set-Location ..
    
    Write-Host "✅ Dependencies installed successfully" -ForegroundColor Green
    Write-Host ""
}

# Function to build the application
function Build-Application {
    param([string]$Env)
    
    Write-Host "🔨 Building application for $Env..." -ForegroundColor Yellow
    
    # Build frontend
    Set-Location frontend
    if ($Env -eq "production") {
        $env:NODE_ENV = "production"
        npm run build
    } else {
        npm run build
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Frontend build failed" -ForegroundColor Red
        exit 1
    }
    Set-Location ..
    
    # Build backend (TypeScript compilation)
    Set-Location backend
    npm run build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Backend build failed" -ForegroundColor Red
        exit 1
    }
    Set-Location ..
    
    Write-Host "✅ Application built successfully" -ForegroundColor Green
    Write-Host ""
}

# Function to start services
function Start-Services {
    param([string]$Env)
    
    Write-Host "🚀 Starting COBRA AI services..." -ForegroundColor Yellow
    
    if ($Env -eq "production") {
        # Production deployment using Docker
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            Write-Host "Starting production services with Docker..." -ForegroundColor Cyan
            docker-compose -f docker-compose.core.yml up -d
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Production services started successfully" -ForegroundColor Green
                Write-Host "🌐 Frontend: http://localhost" -ForegroundColor Cyan
                Write-Host "🔧 Backend API: http://localhost:3001" -ForegroundColor Cyan
            } else {
                Write-Host "❌ Failed to start production services" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "❌ Docker not available for production deployment" -ForegroundColor Red
            exit 1
        }
    } else {
        # Development mode
        Write-Host "Starting development services..." -ForegroundColor Cyan
        Write-Host "🌐 Frontend: http://localhost:5173" -ForegroundColor Cyan
        Write-Host "🔧 Backend API: http://localhost:3001" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Run 'npm run dev' to start development servers" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Function to display security checklist
function Show-SecurityChecklist {
    Write-Host "🔒 SECURITY CHECKLIST" -ForegroundColor Green
    Write-Host "=====================" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Verify these security measures:" -ForegroundColor Yellow
    Write-Host "   □ API keys are stored in environment variables" -ForegroundColor Gray
    Write-Host "   □ .env files are excluded from version control" -ForegroundColor Gray
    Write-Host "   □ Encryption keys are backed up securely" -ForegroundColor Gray
    Write-Host "   □ Production uses different keys than development" -ForegroundColor Gray
    Write-Host "   □ API key usage is monitored in provider dashboards" -ForegroundColor Gray
    Write-Host "   □ JWT secret is strong and unique" -ForegroundColor Gray
    Write-Host "   □ Database access is properly configured" -ForegroundColor Gray
    Write-Host ""
    Write-Host "🔍 Additional recommendations:" -ForegroundColor Yellow
    Write-Host "   • Regularly rotate API keys" -ForegroundColor Gray
    Write-Host "   • Monitor API usage and costs" -ForegroundColor Gray
    Write-Host "   • Use separate environments for dev/staging/prod" -ForegroundColor Gray
    Write-Host "   • Enable API rate limiting where possible" -ForegroundColor Gray
    Write-Host "   • Review security logs regularly" -ForegroundColor Gray
    Write-Host ""
}

# Main execution
try {
    Test-Prerequisites
    
    if ($GenerateKeys) {
        New-EncryptionKeys
        Write-Host "🔐 Keys generated. Add them to your .env file and re-run deployment." -ForegroundColor Cyan
        exit 0
    }
    
    if (!$SkipValidation) {
        $envValid = Test-EnvironmentFiles
        if (!$envValid) {
            Write-Host "❌ Environment validation failed. Please fix the issues above." -ForegroundColor Red
            exit 1
        }
    }
    
    Install-Dependencies
    Build-Application -Env $Environment
    Start-Services -Env $Environment
    Show-SecurityChecklist
    
    Write-Host "🎉 COBRA AI deployment completed successfully!" -ForegroundColor Green
    Write-Host "📚 Check the security checklist above to ensure proper configuration." -ForegroundColor Cyan
    
} catch {
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} 