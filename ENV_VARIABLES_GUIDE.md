# Environment Variables Guide

## Frontend Environment Variables

Create a `.env` file in the `frontend/` directory with these variables:

```bash
# ========================================
# COBRA AI Frontend Environment Variables
# ========================================

# ========================================
# BACKEND API CONFIGURATION
# ========================================
# Primary backend API URL
# Development: http://localhost:3001
# Production: https://your-backend-domain.com
VITE_API_URL=http://localhost:3001

# WebSocket URL for real-time features
# Development: ws://localhost:3001
# Production: wss://your-backend-domain.com
VITE_WS_URL=ws://localhost:3001

# ========================================
# SUPABASE CONFIGURATION
# ========================================
# Get these from https://app.supabase.com
# Project Settings > API
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key_here

# ========================================
# LOCAL AI PROVIDERS (Optional)
# ========================================
# LM Studio API endpoint
VITE_LM_STUDIO_URL=http://localhost:1234/v1

# Ollama API endpoint
VITE_OLLAMA_URL=http://localhost:11434

# Docker-based Ollama endpoint
VITE_DOCKER_OLLAMA_URL=http://localhost:11434/api

# ========================================
# APPLICATION SETTINGS
# ========================================
# Application name (displayed in UI)
VITE_APP_NAME=COBRA AI

# Application subdomain
VITE_APP_SUBDOMAIN=app

# ========================================
# DEVELOPMENT SETTINGS
# ========================================
# Enable development mode features (true/false)
VITE_ENABLE_DEV_MODE=false

# Allow localhost authentication bypass (true/false)
# WARNING: Only enable in local development!
VITE_ALLOW_LOCALHOST_DEV=false

# Enable localhost LAN access (true/false)
VITE_ALLOW_LOCALHOST_DEV_LAN=false
```

## Security Notes

1. **Never commit `.env` files** - Add to `.gitignore`
2. All `VITE_*` variables are **exposed to the browser**
3. Only put **public keys** in frontend environment variables
4. Backend secrets go in backend `.env` file
5. Restart dev server after changing environment variables

## Deployment Configurations

### Netlify
Set environment variables in: Site Settings → Build & Deploy → Environment

### Railway
Set environment variables in: Project Settings → Variables

### Vercel
Set environment variables in: Project Settings → Environment Variables

## Quick Setup

```bash
# 1. Copy this template to .env
cd frontend
cat > .env << 'EOF'
VITE_API_URL=http://localhost:3001
VITE_WS_URL=ws://localhost:3001
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_key_here
VITE_ALLOW_LOCALHOST_DEV=true
EOF

# 2. Edit .env with your actual values
nano .env

# 3. Restart dev server
npm run dev
```

