# COBRA AI Security Tools Setup Script
# This script sets up THC Hydra and Hashcat for brute force functionality

param(
    [switch]$SkipDownloads,
    [string]$InstallPath = "C:\SecurityTools"
)

Write-Host "🔧 COBRA AI Security Tools Setup" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Create installation directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "📁 Created installation directory: $InstallPath" -ForegroundColor Green
}

# THC Hydra Setup
$HydraPath = "$InstallPath\thc-hydra-master"
$HydraZip = "$InstallPath\thc-hydra-master.zip"
$HydraUrl = "https://github.com/vanhauser-thc/thc-hydra/archive/refs/heads/master.zip"

Write-Host "🌊 Setting up THC Hydra..." -ForegroundColor Yellow

if (!(Test-Path "$HydraPath\hydra.exe") -and !$SkipDownloads) {
    Write-Host "📥 Downloading THC Hydra..." -ForegroundColor Blue
    try {
        # Download using PowerShell's Invoke-WebRequest with progress
        $ProgressPreference = 'Continue'
        Invoke-WebRequest -Uri $HydraUrl -OutFile $HydraZip -UseBasicParsing
        
        # Extract the zip file
        Write-Host "📦 Extracting THC Hydra..." -ForegroundColor Blue
        Expand-Archive -Path $HydraZip -DestinationPath $InstallPath -Force
        
        # Clean up zip file
        Remove-Item $HydraZip -Force
        
        Write-Host "✅ THC Hydra downloaded and extracted" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download THC Hydra: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 You can manually download from: $HydraUrl" -ForegroundColor Yellow
    }
}

# Check if Hydra binary exists (might be pre-compiled)
if (Test-Path "$HydraPath\hydra.exe") {
    Write-Host "✅ THC Hydra binary found" -ForegroundColor Green
} elseif (Test-Path "$HydraPath") {
    Write-Host "⚠️  THC Hydra source downloaded but binary not found" -ForegroundColor Yellow
    Write-Host "💡 You may need to compile Hydra for Windows or download pre-compiled binaries" -ForegroundColor Yellow
    Write-Host "💡 Alternative: Download Windows binaries from: https://github.com/maaaaz/thc-hydra-windows" -ForegroundColor Yellow
}

# Hashcat Setup
$HashcatPath = "$InstallPath\hashcat-master"
$HashcatZip = "$InstallPath\hashcat.7z"
$HashcatUrl = "https://hashcat.net/files/hashcat-6.2.6.7z"

Write-Host "🔑 Setting up Hashcat..." -ForegroundColor Yellow

if (!(Test-Path "$HashcatPath\hashcat.exe") -and !$SkipDownloads) {
    Write-Host "📥 Downloading Hashcat..." -ForegroundColor Blue
    try {
        # Download Hashcat
        Invoke-WebRequest -Uri $HashcatUrl -OutFile $HashcatZip -UseBasicParsing
        
        # Check if 7-Zip is available for extraction
        $SevenZipPath = "${env:ProgramFiles}\7-Zip\7z.exe"
        if (Test-Path $SevenZipPath) {
            Write-Host "📦 Extracting Hashcat with 7-Zip..." -ForegroundColor Blue
            & $SevenZipPath x $HashcatZip "-o$InstallPath" -y
            
            # Rename extracted folder to hashcat-master for consistency
            $ExtractedFolder = Get-ChildItem -Path $InstallPath -Directory | Where-Object { $_.Name -like "hashcat-*" } | Select-Object -First 1
            if ($ExtractedFolder -and $ExtractedFolder.Name -ne "hashcat-master") {
                Rename-Item -Path $ExtractedFolder.FullName -NewName "hashcat-master"
            }
        } else {
            Write-Host "❌ 7-Zip not found. Please install 7-Zip to extract Hashcat" -ForegroundColor Red
            Write-Host "💡 Download 7-Zip from: https://www.7-zip.org/" -ForegroundColor Yellow
        }
        
        # Clean up archive
        Remove-Item $HashcatZip -Force -ErrorAction SilentlyContinue
        
        Write-Host "✅ Hashcat downloaded and extracted" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download Hashcat: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 You can manually download from: $HashcatUrl" -ForegroundColor Yellow
    }
}

# Verify Hashcat installation
if (Test-Path "$HashcatPath\hashcat.exe") {
    Write-Host "✅ Hashcat binary found" -ForegroundColor Green
} else {
    Write-Host "⚠️  Hashcat not found at expected location" -ForegroundColor Yellow
}

# Create wordlists directory
$WordlistsPath = "$HashcatPath\wordlists"
if (!(Test-Path $WordlistsPath)) {
    New-Item -ItemType Directory -Path $WordlistsPath -Force | Out-Null
    Write-Host "📁 Created wordlists directory" -ForegroundColor Green
}

# Download common wordlists
$RockyouUrl = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
$RockyouPath = "$WordlistsPath\rockyou.txt"

if (!(Test-Path $RockyouPath) -and !$SkipDownloads) {
    Write-Host "📥 Downloading RockYou wordlist..." -ForegroundColor Blue
    try {
        Invoke-WebRequest -Uri $RockyouUrl -OutFile $RockyouPath -UseBasicParsing
        Write-Host "✅ RockYou wordlist downloaded" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Failed to download RockYou wordlist: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "💡 You can manually download from: $RockyouUrl" -ForegroundColor Yellow
    }
}

# Create environment configuration
$EnvPath = "backend\.env"
if (Test-Path $EnvPath) {
    $EnvContent = Get-Content $EnvPath -Raw
    
    # Update or add Hydra path
    if ($EnvContent -match "HYDRA_PATH=") {
        $EnvContent = $EnvContent -replace "HYDRA_PATH=.*", "HYDRA_PATH=$HydraPath\hydra.exe"
    } else {
        $EnvContent += "`nHYDRA_PATH=$HydraPath\hydra.exe"
    }
    
    # Update or add Hashcat path  
    if ($EnvContent -match "HASHCAT_PATH=") {
        $EnvContent = $EnvContent -replace "HASHCAT_PATH=.*", "HASHCAT_PATH=$HashcatPath\hashcat.exe"
    } else {
        $EnvContent += "`nHASHCAT_PATH=$HashcatPath\hashcat.exe"
    }
    
    Set-Content -Path $EnvPath -Value $EnvContent
    Write-Host "✅ Updated backend .env with tool paths" -ForegroundColor Green
} else {
    Write-Host "⚠️  Backend .env file not found. Please run main setup script first." -ForegroundColor Yellow
}

# Test installations
Write-Host "`n🧪 Testing installations..." -ForegroundColor Cyan

# Test Hydra
if (Test-Path "$HydraPath\hydra.exe") {
    try {
        $HydraVersion = & "$HydraPath\hydra.exe" -h 2>&1 | Select-String "Hydra" | Select-Object -First 1
        Write-Host "✅ Hydra test: $($HydraVersion.Line)" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Hydra test failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Hydra binary not found" -ForegroundColor Red
}

# Test Hashcat
if (Test-Path "$HashcatPath\hashcat.exe") {
    try {
        $HashcatVersion = & "$HashcatPath\hashcat.exe" --version 2>&1
        Write-Host "✅ Hashcat test: v$HashcatVersion" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Hashcat test failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Hashcat binary not found" -ForegroundColor Red
}

# Final instructions
Write-Host "`n🎉 Security Tools Setup Complete!" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host "Installation paths:" -ForegroundColor Yellow
Write-Host "  Hydra: $HydraPath\hydra.exe" -ForegroundColor White
Write-Host "  Hashcat: $HashcatPath\hashcat.exe" -ForegroundColor White
Write-Host "  Wordlists: $WordlistsPath" -ForegroundColor White

Write-Host "`n📝 Next steps:" -ForegroundColor Yellow
Write-Host "1. Restart your COBRA AI backend server" -ForegroundColor White
Write-Host "2. Test the brute force functionality in the web interface" -ForegroundColor White
Write-Host "3. If tools don't work, check the paths in backend\.env" -ForegroundColor White

if (!(Test-Path "$HydraPath\hydra.exe")) {
    Write-Host "`n⚠️  HYDRA NOTICE:" -ForegroundColor Yellow
    Write-Host "THC Hydra may need manual compilation for Windows." -ForegroundColor White
    Write-Host "Alternative: Download pre-compiled Windows binaries from:" -ForegroundColor White
    Write-Host "https://github.com/maaaaz/thc-hydra-windows" -ForegroundColor Cyan
}

Write-Host "`n🔒 LEGAL NOTICE:" -ForegroundColor Red
Write-Host "These tools are for authorized security testing only." -ForegroundColor White
Write-Host "Unauthorized use may violate laws and terms of service." -ForegroundColor White 