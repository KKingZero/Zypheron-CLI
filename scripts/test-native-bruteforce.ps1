# Test script for native brute force functionality
Write-Host "Testing Native Brute Force Implementation..." -ForegroundColor Green

# Test 1: Hash cracking with MD5
Write-Host "`nTest 1: MD5 Hash Cracking" -ForegroundColor Yellow
$testHash = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"
Write-Host "Testing hash: $testHash (should crack to 'hello')"

$hashCrackBody = @{
    hashes = @($testHash)
    hashType = "md5"
    attackMode = "dictionary"
    useAI = $false
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:3001/api/bruteforce/native/hashcrack" -Method POST -Body $hashCrackBody -ContentType "application/json"
    Write-Host "Hash crack test started successfully" -ForegroundColor Green
} catch {
    Write-Host "Hash crack test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Native services endpoint
Write-Host "`nTest 2: Native Services List" -ForegroundColor Yellow
try {
    $services = Invoke-RestMethod -Uri "http://localhost:3001/api/bruteforce/native/services" -Method GET
    Write-Host "Available services:" -ForegroundColor Green
    $services.services | ForEach-Object {
        Write-Host "  - $($_.label) ($($_.value)) on port $($_.port)"
    }
} catch {
    Write-Host "Services test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Native hash types endpoint
Write-Host "`nTest 3: Native Hash Types List" -ForegroundColor Yellow
try {
    $hashTypes = Invoke-RestMethod -Uri "http://localhost:3001/api/bruteforce/native/hashtypes" -Method GET
    Write-Host "Available hash types:" -ForegroundColor Green
    $hashTypes.hashTypes | ForEach-Object {
        Write-Host "  - $($_.label) ($($_.value))"
    }
} catch {
    Write-Host "Hash types test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Simple HTTP brute force (to localhost)
Write-Host "`nTest 4: Native HTTP Brute Force (localhost)" -ForegroundColor Yellow
$bruteForceBody = @{
    target = "localhost"
    service = "http"
    port = 3001
    userList = @("admin", "test", "user")
    passwordList = @("password", "123456", "admin")
    threads = 2
    timeout = 5000
    useAI = $false
    verbose = $true
} | ConvertTo-Json

try {
    Write-Host "Starting brute force attack on localhost:3001..."
    # Note: This will likely fail since localhost:3001 isn't a login page, but it tests the endpoint
    $response = Invoke-RestMethod -Uri "http://localhost:3001/api/bruteforce/native/attack" -Method POST -Body $bruteForceBody -ContentType "application/json"
    Write-Host "Brute force test started successfully" -ForegroundColor Green
} catch {
    Write-Host "Brute force test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nNative implementation tests completed!" -ForegroundColor Green
Write-Host "The native tools are now built into the backend and don't require external tool installation." -ForegroundColor Cyan

# Show comparison
Write-Host "`n=== Implementation Comparison ===" -ForegroundColor Magenta
Write-Host "External Tools (THC Hydra / Hashcat):" -ForegroundColor Yellow
Write-Host "  + More features and attack modes"
Write-Host "  + Higher performance for complex attacks"
Write-Host "  + Industry standard tools"
Write-Host "  - Requires manual installation and setup"
Write-Host "  - Windows compatibility issues"
Write-Host "  - Complex dependency management"

Write-Host "`nNative Implementation:" -ForegroundColor Green
Write-Host "  + No setup required - works out of the box"
Write-Host "  + Cross-platform compatibility"
Write-Host "  + Integrated with Node.js backend"
Write-Host "  + Real-time progress updates"
Write-Host "  + AI-enhanced wordlist suggestions"
Write-Host "  - Limited to basic attack modes"
Write-Host "  - Lower performance for very large wordlists"

Write-Host "`nRecommendation: Use Native by default, External for advanced users." -ForegroundColor Cyan 