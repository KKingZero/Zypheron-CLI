#!/bin/bash

# COBRA AI Development Startup Script
echo "🐍 Starting COBRA AI development environment..."

# Check if environment files exist
if [ ! -f "backend/.env" ]; then
    echo "❌ backend/.env not found. Run setup.sh first."
    exit 1
fi

if [ ! -f "frontend/.env" ]; then
    echo "❌ frontend/.env not found. Run setup.sh first."
    exit 1
fi

# Check if dependencies are installed
if [ ! -d "node_modules" ] || [ ! -d "frontend/node_modules" ] || [ ! -d "backend/node_modules" ]; then
    echo "❌ Dependencies not installed. Run setup.sh first."
    exit 1
fi

echo "✅ Environment files and dependencies found"
echo "🚀 Starting development servers..."
echo ""
echo "Frontend: http://localhost:5173"
echo "Backend API: http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop all servers"

# Start both frontend and backend
npm run dev 