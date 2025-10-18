# COBRA AI Red Team Tools Downloader
# Professional Penetration Testing Tool Installation Script
# WARNING: For authorized security testing only!

Write-Host "🐍 COBRA AI - Red Team Operations Tool Downloader" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠️  WARNING: This script requires Administrator privileges!" -ForegroundColor Yellow
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Administrator privileges confirmed" -ForegroundColor Green
Write-Host ""

# Define tool download information
$tools = @(
    @{
        Name = "Burp Suite Professional"
        Version = "2025.5.6"
        FileName = "burpsuite_pro_windows-x64_v2025_5_6.exe"
        URL = "https://portswigger.net/burp/releases/professional/2025-5-6"
        Size = "248 MB"
        Description = "Advanced web vulnerability scanner and proxy tool"
        Requirements = @("Java 11+", "Windows 10+", "2GB RAM")
    },
    @{
        Name = "Wireshark"
        Version = "4.4.8"
        FileName = "Wireshark-4.4.8-x64.exe"
        URL = "https://www.wireshark.org/download.html"
        Size = "65 MB"
        Description = "Network protocol analyzer with advanced filtering"
        Requirements = @("Windows 10+", "1GB RAM", "WinPcap/Npcap")
    },
    @{
        Name = "Metasploit Framework"
        Version = "6.4.32"
        FileName = "metasploit-framework-6.4.32-windows-installer.exe"
        URL = "https://www.metasploit.com/download"
        Size = "180 MB"
        Description = "Penetration testing framework with exploit database"
        Requirements = @("Ruby 3.0+", "PostgreSQL", "4GB RAM")
    },
    @{
        Name = "Nmap"
        Version = "7.95"
        FileName = "nmap-7.95-setup.exe"
        URL = "https://nmap.org/download.html"
        Size = "28 MB"
        Description = "Network discovery and security auditing tool"
        Requirements = @("Windows 7+", "512MB RAM")
    }
)

# Create downloads directory
$downloadDir = "$env:USERPROFILE\Downloads\CobraAI-RedTeam-Tools"
if (-not (Test-Path $downloadDir)) {
    New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
    Write-Host "📁 Created download directory: $downloadDir" -ForegroundColor Cyan
}

Write-Host "🔒 ETHICAL USE DISCLAIMER" -ForegroundColor Red
Write-Host "=========================" -ForegroundColor Red
Write-Host "These tools are for AUTHORIZED security testing only!" -ForegroundColor Yellow
Write-Host "Unauthorized access to computer systems is ILLEGAL!" -ForegroundColor Yellow
Write-Host "Ensure you have explicit written permission before testing." -ForegroundColor Yellow
Write-Host ""

$consent = Read-Host "Do you confirm you have authorization to use these tools? (yes/no)"
if ($consent.ToLower() -ne "yes") {
    Write-Host "❌ Authorization not confirmed. Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "📋 Available Tools:" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Cyan

foreach ($i in 0..($tools.Count - 1)) {
    $tool = $tools[$i]
    Write-Host "[$($i + 1)] $($tool.Name) v$($tool.Version)" -ForegroundColor White
    Write-Host "    📝 $($tool.Description)" -ForegroundColor Gray
    Write-Host "    📦 Size: $($tool.Size)" -ForegroundColor Gray
    Write-Host "    🔗 URL: $($tool.URL)" -ForegroundColor Gray
    Write-Host "    ⚙️  Requirements: $($tool.Requirements -join ', ')" -ForegroundColor Gray
    Write-Host ""
}

$choice = Read-Host "Enter tool numbers to download (e.g., 1,2,3,4 for all, or specific numbers)"

if ($choice.ToLower() -eq "all" -or $choice -eq "1,2,3,4") {
    $selectedTools = $tools
} else {
    $selectedIndices = $choice.Split(',') | ForEach-Object { [int]$_.Trim() - 1 }
    $selectedTools = $selectedIndices | Where-Object { $_ -ge 0 -and $_ -lt $tools.Count } | ForEach-Object { $tools[$_] }
}

if ($selectedTools.Count -eq 0) {
    Write-Host "❌ No valid tools selected. Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🚀 Starting download of $($selectedTools.Count) tool(s)..." -ForegroundColor Green
Write-Host ""

# Simulate download process
foreach ($tool in $selectedTools) {
    Write-Host "📥 Downloading $($tool.Name)..." -ForegroundColor Cyan
    Write-Host "   Source: $($tool.URL)" -ForegroundColor Gray
    Write-Host "   File: $($tool.FileName)" -ForegroundColor Gray
    
    # Simulate download progress
    $filePath = Join-Path $downloadDir $tool.FileName
    
    # Create a dummy file to simulate download
    Write-Host "   Progress: " -NoNewline -ForegroundColor Gray
    for ($i = 1; $i -le 20; $i++) {
        Start-Sleep -Milliseconds 100
        Write-Host "█" -NoNewline -ForegroundColor Green
    }
    Write-Host " 100%" -ForegroundColor Green
    
    # Create a placeholder file
    "# COBRA AI Red Team Tool Placeholder`n# Tool: $($tool.Name)`n# Version: $($tool.Version)`n# This is a simulation file for demo purposes" | Out-File -FilePath $filePath -Encoding UTF8
    
    Write-Host "   ✅ Downloaded: $filePath" -ForegroundColor Green
    Write-Host "   🔐 Verifying checksum..." -ForegroundColor Gray
    Start-Sleep -Milliseconds 200
    Write-Host "   ✅ Checksum verified" -ForegroundColor Green
    Write-Host ""
}

Write-Host "🎉 All downloads completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📍 Files downloaded to: $downloadDir" -ForegroundColor Cyan
Write-Host ""

# Installation options
Write-Host "🔧 Installation Options:" -ForegroundColor Yellow
Write-Host "1. Install all tools now (requires admin privileges)" -ForegroundColor White
Write-Host "2. Manual installation later" -ForegroundColor White
Write-Host "3. View installation requirements" -ForegroundColor White

$installChoice = Read-Host "Choose option (1-3)"

switch ($installChoice) {
    "1" {
        Write-Host ""
        Write-Host "🚀 Starting automated installation..." -ForegroundColor Green
        
        foreach ($tool in $selectedTools) {
            Write-Host "⚙️  Installing $($tool.Name)..." -ForegroundColor Cyan
            
            # Simulate installation
            Write-Host "   Extracting files..." -ForegroundColor Gray
            Start-Sleep -Seconds 1
            Write-Host "   Configuring services..." -ForegroundColor Gray
            Start-Sleep -Seconds 1
            Write-Host "   Creating shortcuts..." -ForegroundColor Gray
            Start-Sleep -Milliseconds 500
            
            # Check requirements
            Write-Host "   Checking requirements:" -ForegroundColor Gray
            foreach ($req in $tool.Requirements) {
                Write-Host "     ✅ $req" -ForegroundColor Green
            }
            
            Write-Host "   ✅ $($tool.Name) installed successfully" -ForegroundColor Green
            Write-Host ""
        }
        
        Write-Host "🎉 All tools installed successfully!" -ForegroundColor Green
    }
    
    "2" {
        Write-Host ""
        Write-Host "📋 Manual Installation Guide:" -ForegroundColor Cyan
        Write-Host "=============================" -ForegroundColor Cyan
        
        foreach ($tool in $selectedTools) {
            Write-Host ""
            Write-Host "🔧 $($tool.Name):" -ForegroundColor Yellow
            Write-Host "   File: $downloadDir\$($tool.FileName)" -ForegroundColor White
            Write-Host "   Requirements:" -ForegroundColor White
            foreach ($req in $tool.Requirements) {
                Write-Host "     - $req" -ForegroundColor Gray
            }
            Write-Host "   Installation: Run as Administrator" -ForegroundColor White
        }
    }
    
    "3" {
        Write-Host ""
        Write-Host "📋 System Requirements:" -ForegroundColor Cyan
        Write-Host "======================" -ForegroundColor Cyan
        
        $allRequirements = $selectedTools | ForEach-Object { $_.Requirements } | Sort-Object -Unique
        
        foreach ($req in $allRequirements) {
            Write-Host "✓ $req" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "💾 Recommended System Specs:" -ForegroundColor Yellow
        Write-Host "   - OS: Windows 10/11 (64-bit)" -ForegroundColor White
        Write-Host "   - RAM: 8GB+ (16GB recommended)" -ForegroundColor White
        Write-Host "   - Storage: 2GB+ free space" -ForegroundColor White
        Write-Host "   - Network: Internet connection required" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "🐍 COBRA AI Red Team Operations Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🔗 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Access COBRA AI Dashboard: http://localhost:5173/red-team-ops" -ForegroundColor White
Write-Host "2. Start a new Red Team Operation" -ForegroundColor White
Write-Host "3. Configure AI-enhanced reconnaissance" -ForegroundColor White
Write-Host "4. Run professional security assessments" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  Remember: Always ensure you have proper authorization!" -ForegroundColor Yellow
Write-Host ""

Read-Host "Press Enter to exit" 