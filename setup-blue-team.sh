#!/bin/bash

# Blue Team Defense System - Quick Setup Script
# This script sets up all requirements for the Blue Team Defense System

echo "🛡️  BLUE TEAM DEFENSE SYSTEM - SETUP SCRIPT"
echo "============================================"
echo ""

# Check if Redis is installed
echo "📦 Checking Redis..."
if command -v redis-cli &> /dev/null; then
    echo "✅ Redis CLI found"
    
    # Check if Redis is running
    if redis-cli ping &> /dev/null; then
        echo "✅ Redis is running"
    else
        echo "⚠️  Redis is installed but not running"
        echo "   Starting Redis..."
        
        # Try to start Redis
        if command -v redis-server &> /dev/null; then
            redis-server --daemonize yes &
            sleep 2
            
            if redis-cli ping &> /dev/null; then
                echo "✅ Redis started successfully"
            else
                echo "❌ Failed to start Redis"
                echo "   Please start Redis manually: redis-server"
            fi
        fi
    fi
else
    echo "❌ Redis not found"
    echo ""
    echo "Please install Redis:"
    echo "  macOS:   brew install redis && redis-server"
    echo "  Linux:   sudo apt-get install redis-server && redis-server"
    echo "  Docker:  docker run -d --name redis-blueteam -p 6379:6379 redis:alpine"
    echo ""
    read -p "Press Enter once Redis is running..."
fi

echo ""
echo "📦 Installing backend dependencies..."
cd backend

if [ ! -f "package.json" ]; then
    echo "❌ Error: backend/package.json not found"
    exit 1
fi

echo "   Installing bullmq..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Backend dependencies installed"
else
    echo "❌ Failed to install backend dependencies"
    exit 1
fi

cd ..

echo ""
echo "📦 Installing frontend dependencies..."
cd frontend

if [ ! -f "package.json" ]; then
    echo "❌ Error: frontend/package.json not found"
    exit 1
fi

echo "   Installing visualization libraries..."
npm install recharts leaflet react-leaflet

if [ $? -eq 0 ]; then
    echo "✅ Frontend dependencies installed"
else
    echo "❌ Failed to install frontend dependencies"
    exit 1
fi

cd ..

echo ""
echo "✅ SETUP COMPLETE!"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Configure Environment Variables:"
echo "   Add to backend/.env:"
echo "   REDIS_HOST=localhost"
echo "   REDIS_PORT=6379"
echo "   THREAT_DETECTION_ENABLED=true"
echo "   ML_ANOMALY_DETECTION=true"
echo "   BEHAVIORAL_ANALYSIS=true"
echo "   USE_ASYNC_QUEUE=true"
echo ""
echo "2. Run Database Migration:"
echo "   Execute the SQL in database/schema-defense.sql"
echo "   Plus the activity_log table from BLUE_TEAM_INTEGRATION_GUIDE.md"
echo ""
echo "3. Start the servers:"
echo "   Terminal 1: cd backend && npm run dev"
echo "   Terminal 2: cd frontend && npm run dev"
echo ""
echo "4. Access Blue Team Scanner:"
echo "   http://localhost:5173/blue-team-scanner"
echo ""
echo "🛡️  Your Blue Team Defense System is ready!"

