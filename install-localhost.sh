#!/bin/bash

# 🚀 Cobra AI - Localhost Installation Script
# This script automates the installation process for the advanced cybersecurity tools

set -e  # Exit on any error

echo "🐍 COBRA AI - Advanced Cybersecurity Tools Installation"
echo "========================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_step() {
    echo -e "${BLUE}📋 Step $1: $2${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
print_step 1 "Checking Prerequisites"

if ! command_exists node; then
    print_error "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    print_error "Node.js version 18 or higher is required. Current version: $(node --version)"
    exit 1
fi
print_success "Node.js $(node --version) detected"

if ! command_exists npm; then
    print_error "npm is not installed"
    exit 1
fi
print_success "npm $(npm --version) detected"

if ! command_exists git; then
    print_warning "Git is not installed. Some features may not work properly."
else
    print_success "Git $(git --version | cut -d' ' -f3) detected"
fi

# Install dependencies
print_step 2 "Installing Dependencies"

echo "Installing backend dependencies..."
cd backend
npm install
if [ $? -eq 0 ]; then
    print_success "Backend dependencies installed"
else
    print_error "Failed to install backend dependencies"
    exit 1
fi

echo "Installing frontend dependencies..."
cd ../frontend
npm install
if [ $? -eq 0 ]; then
    print_success "Frontend dependencies installed"
else
    print_error "Failed to install frontend dependencies"
    exit 1
fi

cd ..

# Setup environment files
print_step 3 "Setting up Environment Files"

# Backend environment
if [ ! -f "backend/.env" ]; then
    if [ -f "backend/env.example" ]; then
        cp backend/env.example backend/.env
        print_success "Backend .env file created from example"
        print_warning "Please edit backend/.env with your API keys and configuration"
    else
        echo "Creating basic backend .env file..."
        cat > backend/.env << EOF
# Database Configuration
DATABASE_URL="postgresql://localhost:5432/cobra_ai"

# AI Service API Keys (Add your keys here)
GEMINI_API_KEY=""
OPENAI_API_KEY=""
MOONSHOT_API_KEY=""

# External Tool APIs (Optional)
SHODAN_API_KEY=""
VIRUSTOTAL_API_KEY=""

# Security Settings
JWT_SECRET="your_jwt_secret_change_this_in_production"
ENCRYPTION_KEY="your_encryption_key_change_this_in_production"

# Server Configuration
PORT=3001
NODE_ENV=development

# Supabase Configuration (Optional)
SUPABASE_URL=""
SUPABASE_ANON_KEY=""
SUPABASE_SERVICE_ROLE_KEY=""
EOF
        print_success "Basic backend .env file created"
    fi
else
    print_success "Backend .env file already exists"
fi

# Frontend environment
if [ ! -f "frontend/.env" ]; then
    if [ -f "frontend/env.example" ]; then
        cp frontend/env.example frontend/.env
        print_success "Frontend .env file created from example"
    else
        echo "Creating basic frontend .env file..."
        cat > frontend/.env << EOF
# API Configuration
VITE_API_URL=http://localhost:3001
VITE_WEBSOCKET_URL=ws://localhost:3001

# External Services
VITE_SUPABASE_URL=""
VITE_SUPABASE_ANON_KEY=""

# Development Settings
VITE_DEV_MODE=true
VITE_LOG_LEVEL=debug
EOF
        print_success "Basic frontend .env file created"
    fi
else
    print_success "Frontend .env file already exists"
fi

# Check for security tools
print_step 4 "Checking Security Tools"

check_tool() {
    if command_exists "$1"; then
        print_success "$1 is installed"
        return 0
    else
        print_warning "$1 is not installed"
        return 1
    fi
}

TOOLS_MISSING=0

check_tool "nmap" || TOOLS_MISSING=$((TOOLS_MISSING + 1))
check_tool "python3" || TOOLS_MISSING=$((TOOLS_MISSING + 1))

if command_exists "aircrack-ng"; then
    print_success "aircrack-ng is installed"
elif [ "$OSTYPE" = "linux-gnu" ]; then
    print_warning "aircrack-ng not found. Install with: sudo apt install aircrack-ng"
    TOOLS_MISSING=$((TOOLS_MISSING + 1))
elif [[ "$OSTYPE" == "darwin"* ]]; then
    print_warning "aircrack-ng not found. Install with: brew install aircrack-ng"
    TOOLS_MISSING=$((TOOLS_MISSING + 1))
fi

if [ $TOOLS_MISSING -gt 0 ]; then
    print_warning "$TOOLS_MISSING security tools are missing. Some features may not work."
    echo "To install missing tools:"
    if [ "$OSTYPE" = "linux-gnu" ]; then
        echo "  Ubuntu/Debian: sudo apt install nmap aircrack-ng python3-pip"
        echo "  CentOS/RHEL: sudo yum install nmap aircrack-ng python3-pip"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  macOS: brew install nmap aircrack-ng python"
    fi
fi

# Install Python dependencies
if command_exists python3; then
    echo "Installing Python dependencies..."
    python3 -m pip install --user requests beautifulsoup4 dnspython python-whois scapy 2>/dev/null || print_warning "Some Python packages may not have installed"
fi

# Create start scripts if they don't exist
print_step 5 "Creating Start Scripts"

if [ ! -f "start-dev.sh" ]; then
    cat > start-dev.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting Cobra AI Development Environment..."

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "Port $1 is already in use"
        return 1
    fi
    return 0
}

# Check ports
if ! check_port 3001; then
    echo "Backend port 3001 is busy. Please stop the process or use a different port."
    exit 1
fi

if ! check_port 5173; then
    echo "Frontend port 5173 is busy. Please stop the process or use a different port."
    exit 1
fi

# Start backend
echo "Starting backend server..."
cd backend
npm run dev &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Start frontend
echo "Starting frontend development server..."
cd ../frontend
npm run dev &
FRONTEND_PID=$!

echo ""
echo "🎉 Cobra AI is starting up!"
echo "📊 Backend API: http://localhost:3001"
echo "🌐 Frontend App: http://localhost:5173"
echo "🛠️ Advanced Tools: Navigate to Red Team Ops → Advanced Tools"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for interrupt
wait $BACKEND_PID $FRONTEND_PID
EOF
    chmod +x start-dev.sh
    print_success "start-dev.sh created"
fi

# Create Windows batch file
if [ ! -f "start-dev.bat" ]; then
    cat > start-dev.bat << 'EOF'
@echo off
echo 🚀 Starting Cobra AI Development Environment...

echo Starting backend server...
cd backend
start cmd /k "npm run dev"

timeout /t 3 /nobreak >nul

echo Starting frontend development server...
cd ../frontend
start cmd /k "npm run dev"

echo.
echo 🎉 Cobra AI is starting up!
echo 📊 Backend API: http://localhost:3001
echo 🌐 Frontend App: http://localhost:5173
echo 🛠️ Advanced Tools: Navigate to Red Team Ops → Advanced Tools
echo.
echo Press any key to continue...
pause >nul
EOF
    print_success "start-dev.bat created"
fi

# Final setup
print_step 6 "Final Setup"

# Create logs directory
mkdir -p logs
print_success "Logs directory created"

# Set permissions
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x *.sh 2>/dev/null || true

echo ""
echo "🎉 Installation Complete!"
echo "========================================================"
echo ""
echo "Next steps:"
echo "1. Edit backend/.env with your API keys (Gemini, OpenAI, Shodan, etc.)"
echo "2. Edit frontend/.env if needed"
echo "3. Start the development environment:"
echo ""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "   Windows: double-click start-dev.bat"
else
    echo "   Linux/macOS: ./start-dev.sh"
fi
echo ""
echo "4. Open http://localhost:5173 in your browser"
echo "5. Navigate to Red Team Operations → Advanced Tools"
echo ""
echo "🔒 Security Note:"
echo "These tools are for authorized testing only. Always ensure you have"
echo "explicit permission before testing any systems."
echo ""
echo "📚 For detailed configuration, see LOCALHOST_INSTALLATION_GUIDE.md"
echo ""
print_success "Ready to launch Cobra AI! 🐍"