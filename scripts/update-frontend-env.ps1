# Update Frontend Environment File
Write-Host "Updating frontend .env file..." -ForegroundColor Green

$frontendEnvContent = @"
# API Configuration
VITE_API_URL=http://localhost:3001

# Supabase Configuration
VITE_SUPABASE_URL=https://wamuunamwtvutozcohfc.supabase.co
VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndhbXV1bmFtd3R2dXRvemNvaGZjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTA1MjUzODEsImV4cCI6MjA2NjEwMTM4MX0.VKlMW_8dxT7yAWigziBaLy3gk2fBrm2_CyydcGS1ZFs

# Application Configuration
VITE_APP_NAME=COBRA AI
VITE_APP_VERSION=1.0.0

# Feature Flags
VITE_ENABLE_MOCK_DATA=true
VITE_ENABLE_ANALYTICS=false
"@

$frontendEnvContent | Out-File -FilePath "frontend\.env" -Encoding UTF8 -Force

Write-Host "Frontend .env file updated successfully!" -ForegroundColor Green 