@echo off
REM Stripe Webhook Local Testing Script for Windows
REM This script helps test webhooks locally using Stripe CLI

echo.
echo ============================================
echo   Stripe Webhook Local Testing Setup
echo ============================================
echo.

REM Check if Stripe CLI is installed
where stripe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Stripe CLI is not installed!
    echo.
    echo Install Stripe CLI:
    echo.
    echo   Using Scoop:
    echo     scoop bucket add stripe https://github.com/stripe/scoop-stripe-cli.git
    echo     scoop install stripe
    echo.
    echo   Or download from: https://github.com/stripe/stripe-cli/releases
    echo.
    pause
    exit /b 1
)

echo [OK] Stripe CLI found!
echo.

REM Check if logged in
stripe config --list >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Not logged in to Stripe CLI
    echo Running: stripe login
    echo.
    stripe login
) else (
    echo [OK] Already logged in to Stripe CLI
)

echo.
echo Starting webhook listener...
echo.
echo Forwarding webhooks to: http://localhost:3001/api/billing/webhook
echo.
echo IMPORTANT:
echo   1. Make sure your backend is running on port 3001
echo   2. Copy the webhook signing secret (whsec_...) that appears below
echo   3. Add it to backend\.env as STRIPE_WEBHOOK_SECRET
echo.
echo Press Ctrl+C to stop
echo.
echo ==========================================
echo.

REM Start listening
stripe listen --forward-to localhost:3001/api/billing/webhook

echo.
echo Webhook listener stopped
pause

