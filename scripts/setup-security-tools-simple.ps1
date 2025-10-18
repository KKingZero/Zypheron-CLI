# COBRA AI Security Tools Setup Script (Simplified)
# This script downloads pre-compiled Windows binaries for THC Hydra and Hashcat

param(
    [string]$InstallPath = "C:\SecurityTools"
)

Write-Host "🔧 COBRA AI Security Tools Setup (Windows Binaries)" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

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

# THC Hydra Windows Setup (Pre-compiled)
$HydraPath = "$InstallPath\thc-hydra-master"
$HydraZip = "$InstallPath\thc-hydra-windows.zip"
$HydraUrl = "https://github.com/maaaaz/thc-hydra-windows/releases/latest/download/thc-hydra-windows.zip"

Write-Host "🌊 Setting up THC Hydra (Windows Binary)..." -ForegroundColor Yellow

if (!(Test-Path "$HydraPath\hydra.exe")) {
    Write-Host "📥 Downloading pre-compiled THC Hydra for Windows..." -ForegroundColor Blue
    try {
        # Download pre-compiled Windows binary
        $ProgressPreference = 'Continue'
        Invoke-WebRequest -Uri $HydraUrl -OutFile $HydraZip -UseBasicParsing
        
        # Extract the zip file
        Write-Host "📦 Extracting THC Hydra..." -ForegroundColor Blue
        Expand-Archive -Path $HydraZip -DestinationPath $InstallPath -Force
        
        # Find and rename the extracted folder to match expected path
        $ExtractedFolder = Get-ChildItem -Path $InstallPath -Directory | Where-Object { $_.Name -like "*hydra*" } | Select-Object -First 1
        if ($ExtractedFolder -and $ExtractedFolder.Name -ne "thc-hydra-master") {
            Rename-Item -Path $ExtractedFolder.FullName -NewName "thc-hydra-master" -Force
        }
        
        # Clean up zip file
        Remove-Item $HydraZip -Force
        
        Write-Host "✅ THC Hydra downloaded and extracted" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download THC Hydra: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 You can manually download from: $HydraUrl" -ForegroundColor Yellow
        
        # Create directory structure manually
        if (!(Test-Path $HydraPath)) {
            New-Item -ItemType Directory -Path $HydraPath -Force | Out-Null
        }
    }
}

# Hashcat Setup (Official Windows Binary)
$HashcatPath = "$InstallPath\hashcat-master"
$HashcatZip = "$InstallPath\hashcat.7z"
$HashcatUrl = "https://hashcat.net/files/hashcat-6.2.6.7z"

Write-Host "🔑 Setting up Hashcat..." -ForegroundColor Yellow

if (!(Test-Path "$HashcatPath\hashcat.exe")) {
    Write-Host "📥 Downloading Hashcat..." -ForegroundColor Blue
    try {
        # Download Hashcat
        Invoke-WebRequest -Uri $HashcatUrl -OutFile $HashcatZip -UseBasicParsing
        
        # Try to extract with built-in Windows capabilities first
        try {
            # For Windows 10+ with built-in 7z support
            Write-Host "📦 Extracting Hashcat..." -ForegroundColor Blue
            
            # Check if 7-Zip is available
            $SevenZipPath = "${env:ProgramFiles}\7-Zip\7z.exe"
            if (Test-Path $SevenZipPath) {
                & $SevenZipPath x $HashcatZip "-o$InstallPath" -y
            } else {
                # Try alternative extraction methods
                $Shell = New-Object -ComObject Shell.Application
                $ZipFile = $Shell.NameSpace($HashcatZip)
                $Destination = $Shell.NameSpace($InstallPath)
                $Destination.CopyHere($ZipFile.Items(), 4)
            }
            
            # Rename extracted folder to hashcat-master for consistency
            $ExtractedFolder = Get-ChildItem -Path $InstallPath -Directory | Where-Object { $_.Name -like "hashcat-*" } | Select-Object -First 1
            if ($ExtractedFolder -and $ExtractedFolder.Name -ne "hashcat-master") {
                Rename-Item -Path $ExtractedFolder.FullName -NewName "hashcat-master" -Force
            }
            
        } catch {
            Write-Host "⚠️  Could not extract automatically. Manual extraction required." -ForegroundColor Yellow
            Write-Host "💡 Extract $HashcatZip to $InstallPath manually" -ForegroundColor Yellow
        }
        
        # Clean up archive
        Remove-Item $HashcatZip -Force -ErrorAction SilentlyContinue
        
        Write-Host "✅ Hashcat downloaded" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download Hashcat: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 You can manually download from: $HashcatUrl" -ForegroundColor Yellow
    }
}

# Create sample files if tools are installed
if (Test-Path "$HydraPath") {
    # Create sample wordlists for Hydra
    $HydraWordsPath = "$HydraPath\wordlists"
    if (!(Test-Path $HydraWordsPath)) {
        New-Item -ItemType Directory -Path $HydraWordsPath -Force | Out-Null
        
        # Create basic username list
        $BasicUsers = @("admin", "root", "user", "test", "guest", "administrator", "login", "demo")
        $BasicUsers | Out-File -FilePath "$HydraWordsPath\users.txt" -Encoding utf8
        
        # Create basic password list
        $BasicPasswords = @("password", "123456", "admin", "root", "test", "password123", "admin123", "letmein", "welcome", "qwerty")
        $BasicPasswords | Out-File -FilePath "$HydraWordsPath\passwords.txt" -Encoding utf8
        
        Write-Host "📝 Created basic wordlists for Hydra" -ForegroundColor Green
    }
}

if (Test-Path "$HashcatPath") {
    # Create wordlists directory for Hashcat
    $WordlistsPath = "$HashcatPath\wordlists"
    if (!(Test-Path $WordlistsPath)) {
        New-Item -ItemType Directory -Path $WordlistsPath -Force | Out-Null
        Write-Host "📁 Created wordlists directory for Hashcat" -ForegroundColor Green
    }
    
    # Download RockYou wordlist if not exists
    $RockyouPath = "$WordlistsPath\rockyou.txt"
    if (!(Test-Path $RockyouPath)) {
        Write-Host "📥 Downloading RockYou wordlist..." -ForegroundColor Blue
        try {
            $RockyouUrl = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
            Invoke-WebRequest -Uri $RockyouUrl -OutFile $RockyouPath -UseBasicParsing
            Write-Host "✅ RockYou wordlist downloaded" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Failed to download RockYou wordlist" -ForegroundColor Yellow
            
            # Create a small sample wordlist
            $SamplePasswords = @("password", "123456", "password123", "admin", "letmein", "welcome", "monkey", "dragon", "qwerty", "abc123")
            $SamplePasswords | Out-File -FilePath "$WordlistsPath\sample.txt" -Encoding utf8
            Write-Host "📝 Created sample wordlist instead" -ForegroundColor Green
        }
    }
}

# Update environment configuration
$EnvPath = "backend\.env"
$HydraExePath = "$HydraPath\hydra.exe"
$HashcatExePath = "$HashcatPath\hashcat.exe"

# Create .env file if it doesn't exist
if (!(Test-Path $EnvPath)) {
    Write-Host "📝 Creating backend .env file..." -ForegroundColor Yellow
    $EnvTemplate = @"
# COBRA AI Environment Configuration
# Security Tools Configuration
HYDRA_PATH=$HydraExePath
HASHCAT_PATH=$HashcatExePath

# Add your other API keys below
# OPENAI_API_KEY=your_openai_key_here
# GOOGLE_API_KEY=your_google_key_here
# SUPABASE_URL=your_supabase_url_here
# SUPABASE_SERVICE_ROLE_KEY=your_supabase_key_here
"@
    Set-Content -Path $EnvPath -Value $EnvTemplate
} else {
    # Update existing .env file
    $EnvContent = Get-Content $EnvPath -Raw
    
    # Update or add Hydra path
    if ($EnvContent -match "HYDRA_PATH=") {
        $EnvContent = $EnvContent -replace "HYDRA_PATH=.*", "HYDRA_PATH=$HydraExePath"
    } else {
        $EnvContent += "`nHYDRA_PATH=$HydraExePath"
    }
    
    # Update or add Hashcat path  
    if ($EnvContent -match "HASHCAT_PATH=") {
        $EnvContent = $EnvContent -replace "HASHCAT_PATH=.*", "HASHCAT_PATH=$HashcatExePath"
    } else {
        $EnvContent += "`nHASHCAT_PATH=$HashcatExePath"
    }
    
    Set-Content -Path $EnvPath -Value $EnvContent
}

Write-Host "✅ Updated backend .env with tool paths" -ForegroundColor Green

# Test installations
Write-Host "`n🧪 Testing installations..." -ForegroundColor Cyan

# Test Hydra
if (Test-Path $HydraExePath) {
    try {
        $HydraTest = & $HydraExePath -h 2>&1 | Select-Object -First 5
        Write-Host "✅ Hydra installed and working" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Hydra found but may have issues: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Hydra binary not found at $HydraExePath" -ForegroundColor Red
}

# Test Hashcat
if (Test-Path $HashcatExePath) {
    try {
        $HashcatTest = & $HashcatExePath --version 2>&1
        Write-Host "✅ Hashcat installed: $HashcatTest" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Hashcat found but may have issues: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Hashcat binary not found at $HashcatExePath" -ForegroundColor Red
}

# Final instructions
Write-Host "`n🎉 Security Tools Setup Complete!" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host "Installation paths:" -ForegroundColor Yellow
Write-Host "  Hydra: $HydraExePath" -ForegroundColor White
Write-Host "  Hashcat: $HashcatExePath" -ForegroundColor White
Write-Host "  Environment: $EnvPath" -ForegroundColor White

Write-Host "`n📝 Next steps:" -ForegroundColor Yellow
Write-Host "1. Restart your COBRA AI backend server to load new paths" -ForegroundColor White
Write-Host "2. Test the brute force functionality in the web interface" -ForegroundColor White
Write-Host "3. Configure your API keys in backend\.env if needed" -ForegroundColor White

Write-Host "`n🔧 Troubleshooting:" -ForegroundColor Yellow
Write-Host "• If tools don't work, check Windows Defender/Antivirus settings" -ForegroundColor White
Write-Host "• Some antivirus software may block these security tools" -ForegroundColor White
Write-Host "• Add exceptions for: $InstallPath" -ForegroundColor White

Write-Host "`n🔒 LEGAL NOTICE:" -ForegroundColor Red
Write-Host "These tools are for authorized security testing only." -ForegroundColor White
Write-Host "Unauthorized use may violate laws and terms of service." -ForegroundColor White 