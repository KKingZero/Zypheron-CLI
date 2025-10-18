# Cobra AI - WSL Kali Tools Setup
# Installs common Kali tools into a WSL Kali instance and prepares them for backend use

param(
  [string]$Distro = "kali-linux",
  [switch]$SkipInstall
)

Write-Host "🐍 Cobra AI - WSL Kali Tools Setup" -ForegroundColor Cyan

function Test-WSLInstalled {
  try {
    $v = wsl.exe -l -q 2>$null
    return $LASTEXITCODE -eq 0
  } catch { return $false }
}

function Test-DistroExists($name) {
  try {
    $list = wsl.exe -l -q | ForEach-Object { $_.Trim() }
    return $list -contains $name
  } catch { return $false }
}

if (-not (Test-WSLInstalled)) {
  Write-Host "❌ WSL is not installed. Enable WSL and Virtual Machine Platform features, then reboot." -ForegroundColor Red
  Write-Host "Run in admin PowerShell:" -ForegroundColor Yellow
  Write-Host "  dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart" -ForegroundColor Gray
  Write-Host "  dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart" -ForegroundColor Gray
  Write-Host "Then install Kali with: wsl --install -d kali-linux" -ForegroundColor Gray
  exit 1
}

if (-not (Test-DistroExists $Distro)) {
  if ($SkipInstall) {
    Write-Host "⚠️  Distro '$Distro' not found and SkipInstall set. Exiting." -ForegroundColor Yellow
    exit 1
  }
  Write-Host "📥 Installing WSL distro: $Distro (this may require a reboot)" -ForegroundColor Yellow
  wsl.exe --install -d $Distro
  Write-Host "After installation completes and you created a user, re-run this script." -ForegroundColor Yellow
  exit 0
}

Write-Host "✅ WSL distro '$Distro' is available" -ForegroundColor Green

# List of packages to install (curated from Kali defaults)
$packages = @(
  # Core scanners
  'nmap','masscan','nikto','sqlmap','whatweb','ffuf','gobuster','dirb','dirbuster',
  # Network
  'netcat-traditional','ncat','tcpdump','socat','wireshark','tshark',
  # Wireless
  'aircrack-ng','reaver','cowpatty','wifite','airgraph-ng',
  # Brute-force / cracking
  'hydra','john','hashcat',
  # Exploitation
  'metasploit-framework',
  # OSINT
  'theharvester','amass','sublist3r','subfinder',
  # Misc
  'yara','steghide','foremost','testdisk','scapy','mitmproxy'
)

Write-Host "📦 Updating apt and installing ${($packages.Count)} tools inside $Distro..." -ForegroundColor Cyan

# Update and install
wsl.exe -d $Distro -- bash -lc "sudo apt-get update -y && sudo apt-get install -y $($packages -join ' ')"

if ($LASTEXITCODE -ne 0) {
  Write-Host "❌ Failed to install one or more packages. You can re-run the script." -ForegroundColor Red
  exit 1
}

Write-Host "✅ Kali tools installed. Verifying a few commands..." -ForegroundColor Green
wsl.exe -d $Distro -- bash -lc "which nmap && which hydra && which sqlmap && which john && which hashcat" | Write-Host

Write-Host "\nNext steps:" -ForegroundColor Yellow
Write-Host "- Start Cobra AI backend and call: GET http://localhost:3001/api/tools/detect" -ForegroundColor White
Write-Host "- Run a tool via: POST http://localhost:3001/api/tools/run/hydra with args" -ForegroundColor White


