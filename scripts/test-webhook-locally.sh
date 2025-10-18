#!/bin/bash

# Stripe Webhook Local Testing Script
# This script helps test webhooks locally using Stripe CLI

echo "🔧 Stripe Webhook Local Testing Setup"
echo "======================================"
echo ""

# Check if Stripe CLI is installed
if ! command -v stripe &> /dev/null; then
    echo "❌ Stripe CLI is not installed!"
    echo ""
    echo "📥 Install Stripe CLI:"
    echo ""
    echo "  macOS (Homebrew):"
    echo "    brew install stripe/stripe-cli/stripe"
    echo ""
    echo "  Linux:"
    echo "    wget https://github.com/stripe/stripe-cli/releases/download/v1.19.4/stripe_1.19.4_linux_x86_64.tar.gz"
    echo "    tar -xvf stripe_1.19.4_linux_x86_64.tar.gz"
    echo "    sudo mv stripe /usr/local/bin/"
    echo ""
    echo "  Windows (Scoop):"
    echo "    scoop bucket add stripe https://github.com/stripe/scoop-stripe-cli.git"
    echo "    scoop install stripe"
    echo ""
    exit 1
fi

echo "✅ Stripe CLI found!"
echo ""

# Check if logged in
if ! stripe config --list &> /dev/null; then
    echo "🔐 Not logged in to Stripe CLI"
    echo "Running: stripe login"
    echo ""
    stripe login
else
    echo "✅ Already logged in to Stripe CLI"
fi

echo ""
echo "🎧 Starting webhook listener..."
echo ""
echo "📍 Forwarding webhooks to: http://localhost:3001/api/billing/webhook"
echo ""
echo "⚠️  IMPORTANT:"
echo "   1. Make sure your backend is running on port 3001"
echo "   2. Copy the webhook signing secret (whsec_...) that appears below"
echo "   3. Add it to backend/.env as STRIPE_WEBHOOK_SECRET"
echo ""
echo "Press Ctrl+C to stop"
echo ""
echo "=" | tr '=' '='
echo ""

# Start listening
stripe listen --forward-to localhost:3001/api/billing/webhook

echo ""
echo "👋 Webhook listener stopped"

