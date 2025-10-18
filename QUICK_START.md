# 🐍 COBRA AI - Quick Start Guide

This guide will help you get COBRA AI running quickly with just a few clicks!

## 🚀 Easy Setup Options

### Option 1: Docker Setup (Recommended) ⭐
**Best for:** Complete functionality, all services working

**Requirements:** Docker Desktop installed

#### Windows:
```batch
# Double-click this file:
start-docker.bat

# OR run in PowerShell:
.\start-docker.ps1
```

#### Linux/Mac:
```bash
docker-compose up --build -d
```

---

### Option 2: Development Mode 🔧
**Best for:** Development, testing without Docker

**Requirements:** Node.js, Python (other languages optional)

#### Windows:
```batch
# Double-click this file:
start-dev.bat
```

---

## 📋 First Time Setup

### 1. Install Prerequisites

**For Docker (Recommended):**
- [Docker Desktop](https://docker.com/products/docker-desktop)
- Start Docker Desktop and wait for it to load

**For Development Mode:**
- [Node.js](https://nodejs.org/) (v18+)
- [Python](https://python.org/) (v3.11+)
- [Rust](https://rustup.rs/) (optional, for scanner)
- [Go](https://golang.org/dl/) (optional, for crawler)

### 2. Configure API Keys (Optional)

```bash
# Copy environment template
copy .env.example .env

# Edit .env file and add your API keys
notepad .env
```

### 3. Start Services

**Docker:**
```batch
start-docker.bat
```

**Development:**
```batch
start-dev.bat
```

---

## 🌐 Access Points

After starting, access COBRA AI at:

- **🌐 Main App:** http://localhost (Docker) or http://localhost:5173 (Dev)
- **🔧 Backend API:** http://localhost:3001  
- **📊 OSINT Service:** http://localhost:8001
- **🔍 Scanner Service:** http://localhost:8002
- **📦 Packet Service:** http://localhost:8003
- **🕷️ Crawler Service:** http://localhost:8004
- **🛡️ Vulnerability Scanner:** http://localhost:8005

---

## 🛑 Stopping Services

```batch
# Stop all services
stop-services.bat

# OR for Docker only:
docker-compose down
```

---

## 🔧 Troubleshooting

### Docker Issues
- **"Docker is not running"**: Start Docker Desktop from Windows Start menu
- **"Port already in use"**: Run `stop-services.bat` first
- **Build failures**: Check Docker Desktop has enough memory (4GB+)

### Development Mode Issues  
- **Services not starting**: Install missing dependencies (Node.js, Python)
- **Python errors**: Run `pip install -r backend/services/osint/requirements.txt`
- **Permission errors**: Run as Administrator

### General Issues
- **Port conflicts**: Close other applications using ports 3001, 5173, 8001-8005
- **Firewall**: Allow the applications through Windows Firewall
- **Browser**: Try incognito/private mode if pages don't load

---

## 📚 What's Running?

**Docker Mode (Full Stack):**
✅ Frontend (React)  
✅ Backend (Node.js/TypeScript)  
✅ OSINT Service (Python/gRPC)  
✅ Scanner Service (Rust/gRPC)  
✅ Packet Manipulator (C++/gRPC)  
✅ Web Crawler (Go/gRPC)  
✅ Vulnerability Scanner (Rust/gRPC)  
✅ PostgreSQL Database  

**Development Mode (Limited):**
✅ Frontend (React)  
✅ Backend (Node.js/TypeScript)  
⚠️ OSINT Service (if Python available)  
❌ Other services (need language runtimes)  

---

## 🎯 Next Steps

1. **Open COBRA AI** in your browser
2. **Start a penetration test** from the main interface
3. **Enable OSINT scanning** to gather intelligence
4. **Configure API keys** in `.env` for real data
5. **Check the logs** in Docker Desktop for debugging

---

## 📞 Support

If you need help:
1. Check the troubleshooting section above
2. Look at service logs in Docker Desktop
3. Make sure all prerequisites are installed
4. Try restarting Docker Desktop

Happy hacking! 🐍⚡ 