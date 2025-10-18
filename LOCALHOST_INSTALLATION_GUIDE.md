# 🚀 Cobra AI - Localhost Installation Guide

## Prerequisites

Before installing Cobra AI with the new advanced cybersecurity tools, ensure you have the following installed:

### Required Software
- **Node.js** (v18 or higher) - [Download here](https://nodejs.org/)
- **npm** or **yarn** package manager
- **Git** - [Download here](https://git-scm.com/)
- **Python** (v3.8+) for backend services
- **Docker** (optional, for containerized deployment)

### System Requirements
- **OS**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 20.04+)
- **RAM**: 8GB minimum (16GB recommended)
- **Storage**: 10GB free space
- **Network**: Internet connection for API services and tool downloads

## 📦 Installation Steps

### Step 1: Clone and Setup

```bash
# Clone the repository (if not already done)
git clone <your-cobra-ai-repository>
cd CobraAI

# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install

# Return to root directory
cd ..
```

### Step 2: Environment Configuration

Create environment files for both backend and frontend:

#### Backend Environment (.env)
```bash
# Create backend environment file
cd backend
cp env.example .env
```

Edit `backend/.env` with your configuration:
```env
# Database Configuration
DATABASE_URL="your_database_url"

# AI Service API Keys
GEMINI_API_KEY="your_gemini_api_key"
OPENAI_API_KEY="your_openai_api_key"
MOONSHOT_API_KEY="your_moonshot_api_key"

# External Tool APIs (Optional - for enhanced features)
SHODAN_API_KEY="your_shodan_api_key"
VIRUSTOTAL_API_KEY="your_virustotal_api_key"

# Security Settings
JWT_SECRET="your_jwt_secret_key"
ENCRYPTION_KEY="your_encryption_key"

# Server Configuration
PORT=3001
NODE_ENV=development

# Supabase Configuration (if using)
SUPABASE_URL="your_supabase_url"
SUPABASE_ANON_KEY="your_supabase_anon_key"
SUPABASE_SERVICE_ROLE_KEY="your_supabase_service_role_key"
```

#### Frontend Environment (.env)
```bash
# Create frontend environment file
cd ../frontend
cp env.example .env
```

Edit `frontend/.env` with your configuration:
```env
# API Configuration
VITE_API_URL=http://localhost:3001
VITE_WEBSOCKET_URL=ws://localhost:3001

# External Services
VITE_SUPABASE_URL="your_supabase_url"
VITE_SUPABASE_ANON_KEY="your_supabase_anon_key"

# Development Settings
VITE_DEV_MODE=true
VITE_LOG_LEVEL=debug
```

### Step 3: Database Setup

```bash
# Navigate to database directory
cd ../database

# Run database setup script (if using PostgreSQL/Supabase)
psql -d your_database -f schema.sql
psql -d your_database -f schema-billing.sql
psql -d your_database -f schema-users.sql

# Or use the setup script
node ../scripts/setup-database.sql
```

### Step 4: Install Security Tools (Optional)

For full functionality, install the required security tools:

#### Windows
```powershell
# Run the Windows setup script
.\scripts\setup-security-tools.ps1

# Or install manually:
# - Download Nmap from https://nmap.org/download.html
# - Download Wireshark from https://www.wireshark.org/download.html
# - Install Python tools: pip install -r requirements.txt
```

#### Linux/macOS
```bash
# Run the setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Or install manually:
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark aircrack-ng john hashcat

# macOS (with Homebrew)
brew install nmap wireshark aircrack-ng john hashcat
```

### Step 5: Start the Development Environment

#### Option A: Use the provided scripts

**Windows:**
```powershell
# Start all services
.\start-dev.bat

# Or start individual components
.\start-backend.bat
.\start-frontend.bat
```

**Linux/macOS:**
```bash
# Start all services
chmod +x start-dev.sh
./start-dev.sh

# Or start individual components
npm run dev:backend &
npm run dev:frontend &
```

#### Option B: Manual startup

**Terminal 1 - Backend:**
```bash
cd backend
npm run dev
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

**Terminal 3 - Database (if local):**
```bash
# Start your database service
# PostgreSQL example:
sudo service postgresql start
```

### Step 6: Verify Installation

1. **Backend API**: Open http://localhost:3001/api/health
2. **Frontend App**: Open http://localhost:5173 (or shown port)
3. **Advanced Tools**: Navigate to Red Team Ops → Advanced Tools

## 🛠️ Advanced Tools Configuration

### API Keys Setup

To enable full functionality of the advanced tools, configure these API keys:

#### Shodan API (for internet intelligence)
1. Sign up at https://www.shodan.io/
2. Get your API key from account settings
3. Add to `backend/.env`: `SHODAN_API_KEY=your_key`

#### VirusTotal API (for threat intelligence)
1. Sign up at https://www.virustotal.com/
2. Get API key from user settings
3. Add to `backend/.env`: `VIRUSTOTAL_API_KEY=your_key`

#### AI Services
1. **Gemini**: Get key from Google AI Studio
2. **OpenAI**: Get key from OpenAI platform
3. **Moonshot**: Get key from Moonshot AI platform

### Tool-Specific Setup

#### Enhanced Aircrack-ng
```bash
# Ensure wireless interface is available
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Install additional dependencies
pip install scapy numpy matplotlib
```

#### Maltego OSINT
```bash
# Install Python dependencies for OSINT
pip install requests beautifulsoup4 dnspython python-whois
```

#### Ghost Mode
```bash
# Ensure all prerequisite tools are installed
nmap --version
nuclei -version
nikto -Version
```

## 🐳 Docker Installation (Alternative)

If you prefer containerized deployment:

```bash
# Build and start all services
docker-compose up --build

# Or use the simple configuration
docker-compose -f docker-compose.simple.yml up --build

# For development with hot reload
docker-compose -f docker-compose.yml up --build
```

## 🔧 Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check what's using ports 3001 and 5173
lsof -i :3001
lsof -i :5173

# Kill processes if needed
sudo kill -9 <PID>
```

#### Permission Issues (Linux/macOS)
```bash
# Fix permissions for security tools
sudo chown -R $USER:$USER /usr/local/bin/
sudo chmod +x scripts/*.sh
```

#### Database Connection
```bash
# Check database status
sudo service postgresql status

# Restart if needed
sudo service postgresql restart
```

#### Missing Dependencies
```bash
# Reinstall node modules
rm -rf node_modules package-lock.json
npm install

# Clear npm cache
npm cache clean --force
```

### Tool-Specific Issues

#### Aircrack-ng Not Working
```bash
# Check wireless interface
iwconfig
sudo airmon-ng check

# Install wireless drivers
sudo apt install linux-headers-$(uname -r)
```

#### API Rate Limits
- **Shodan**: Free tier allows 100 queries/month
- **VirusTotal**: Free tier allows 4 requests/minute
- **Gemini**: Has daily quotas

### Performance Optimization

#### Frontend
```bash
# Build for production
cd frontend
npm run build
npm run preview
```

#### Backend
```bash
# Use production mode
cd backend
NODE_ENV=production npm start
```

## 📊 Verification Checklist

After installation, verify these components:

- [ ] Backend server running on http://localhost:3001
- [ ] Frontend app accessible at http://localhost:5173
- [ ] Database connected successfully
- [ ] AI services responding (check API keys)
- [ ] Advanced Tools Dashboard loads
- [ ] Ghost Mode interface accessible
- [ ] Security tools installed and detected
- [ ] WebSocket connections working
- [ ] File upload/download functionality

## 🚀 Quick Start Guide

1. **Start the application**:
   ```bash
   ./start-dev.sh  # or start-dev.bat on Windows
   ```

2. **Access the interface**:
   - Open http://localhost:5173
   - Navigate to "Red Team Operations"
   - Click "Advanced Tools" button

3. **Test Ghost Mode**:
   - Enter a target domain (use your own for testing)
   - Select mission type
   - Click "Initiate Ghost Mode"

4. **Try OSINT tools**:
   - Use Maltego OSINT for entity mapping
   - Test Shodan search with simple queries
   - Explore Aircrack-ng for wireless analysis

## 🔒 Security Notes

### Development Environment
- Use test targets only
- Never test unauthorized systems
- Keep API keys secure
- Monitor resource usage

### Production Deployment
- Use HTTPS certificates
- Configure proper firewall rules
- Set up monitoring and logging
- Regular security updates

## 📞 Support

If you encounter issues:

1. **Check logs**:
   ```bash
   # Backend logs
   cd backend && npm run logs
   
   # Frontend dev tools
   # Open browser console (F12)
   ```

2. **Reset installation**:
   ```bash
   # Clean everything and reinstall
   ./scripts/clean-install.sh
   ```

3. **Update dependencies**:
   ```bash
   npm update
   cd frontend && npm update
   cd ../backend && npm update
   ```

---

**🎉 Installation Complete!**

Your Cobra AI instance with advanced cybersecurity tools is now ready for use. Navigate to the Advanced Tools Dashboard to explore the new capabilities.

**⚠️ Remember**: Always use these tools responsibly and only on systems you own or have explicit permission to test.