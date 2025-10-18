# 🐍 COBRA AI - Complete Setup with Open Source DeepSeek-R1

## ✅ **What We've Created**

You now have a **complete, functional COBRA AI setup** with the latest open source DeepSeek-R1 models integrated!

## 🎯 **Two Main Components**

### **1. 🐍 COBRA AI Core** (Frontend + Backend + OSINT + Database)
**File:** `start-cobra-core.bat`
```bash
# Starts: Frontend, Backend, OSINT service, PostgreSQL database
start-cobra-core.bat
```

### **2. 🧠 DeepSeek-R1 Open Source AI** (Local LLM)
**File:** `start-deepseek.bat`
```bash
# Starts: DeepSeek-R1 8B + 7B models, Ollama server, Web UI
start-deepseek.bat
```

---

## 🚀 **How to Use**

### **Quick Start (Recommended):**
1. **Start COBRA AI Core:**
   ```bash
   start-cobra-core.bat
   ```
   - Access at: http://localhost
   - Includes: Frontend, Backend, OSINT, Database

2. **Start DeepSeek AI (Optional):**
   ```bash
   start-deepseek.bat
   ```
   - Access at: http://localhost:8080 (Web UI)
   - API at: http://localhost:11434
   - Downloads ~10GB of latest open source models

### **Combined Use:**
- Run both scripts to get **full AI-powered COBRA AI**
- COBRA AI will automatically detect and use DeepSeek when available
- Select "DeepSeek" or "Local" in the chat interface

---

## 🤖 **DeepSeek-R1 Models** (Latest Open Source)

| Model | Size | RAM Required | Description |
|-------|------|--------------|-------------|
| **deepseek-r1:8b** | 5.2GB | 8GB+ | Latest reasoning model (recommended) |
| **deepseek-r1:7b** | 4.7GB | 6GB+ | Alternative smaller model |

**License:** MIT License (Open Source, Commercial Use Allowed)
**Source:** https://github.com/deepseek-ai/DeepSeek-R1

---

## 📍 **Access Points**

### **COBRA AI Core:**
- 🌐 **Main App:** http://localhost
- 🔧 **Backend API:** http://localhost:3001
- 📊 **OSINT Service:** http://localhost:8001
- 🗄️ **Database:** localhost:5432

### **DeepSeek-R1 AI:**
- 🧠 **DeepSeek API:** http://localhost:11434
- 🎛️ **Web UI:** http://localhost:8080
- 📚 **API Docs:** http://localhost:11434/api/tags

---

## 🔄 **Management Commands**

### **Start Services:**
```bash
# COBRA AI only
start-cobra-core.bat

# DeepSeek AI only  
start-deepseek.bat

# Or both for full functionality
```

### **Stop Services:**
```bash
# Stop COBRA AI
docker-compose -f docker-compose.core.yml down

# Stop DeepSeek
docker-compose -f docker-compose.deepseek-only.yml down

# Stop everything
docker-compose down --remove-orphans
```

### **Check Status:**
```bash
# COBRA AI status
docker-compose -f docker-compose.core.yml ps

# DeepSeek status
docker-compose -f docker-compose.deepseek-only.yml ps

# All containers
docker ps
```

---

## 💡 **AI Model Selection in COBRA AI**

When both are running, you can choose:

1. **External APIs:** OpenAI, XAI (requires API keys)
2. **Local DeepSeek:** Completely private, no external calls
3. **Gemini:** Built-in API key (limited quota)

**How to select:**
- In chat interface, choose "DeepSeek" or "Local" for open source AI
- Or use "Flash"/"Pro" for Gemini models
- Configure API keys in environment variables for external services

---

## 🛠️ **Configuration**

### **Environment Variables (Optional):**
Create `.env` file:
```env
# AI API Keys (optional)
OPENAI_API_KEY=your_openai_key
XAI_API_KEY=your_xai_key

# DeepSeek Configuration
DEEPSEEK_API_URL=http://localhost:11434

# OSINT API Keys (optional)
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

---

## 📊 **System Requirements**

### **Minimum:**
- **RAM:** 8GB (4GB for COBRA AI + 4GB for DeepSeek-R1 7B)
- **Storage:** 15GB (5GB for COBRA AI + 10GB for DeepSeek models)
- **Docker Desktop** installed and running

### **Recommended:**
- **RAM:** 16GB+ (for DeepSeek-R1 8B + room for other processes)
- **Storage:** 25GB+ (for additional models and data)
- **SSD** for better performance

---

## 🎯 **Features Available**

### **COBRA AI Core:**
- ✅ **Web Interface** - Modern React frontend
- ✅ **Backend API** - Node.js with gRPC services
- ✅ **OSINT Service** - Python-based intelligence gathering
- ✅ **Database** - PostgreSQL for data persistence
- ✅ **Chat Interface** - AI-powered security consultation

### **DeepSeek-R1 Integration:**
- ✅ **Latest Open Source Model** - DeepSeek-R1 reasoning models
- ✅ **Local Processing** - No data sent to external services
- ✅ **Web UI** - Beautiful chat interface via Open-WebUI
- ✅ **API Access** - REST API for programmatic access
- ✅ **Multi-Model Support** - Choose between 7B and 8B variants

---

## 🚨 **Troubleshooting**

### **Port Conflicts:**
```bash
# Stop all Docker containers
docker stop $(docker ps -aq)

# Remove orphan containers
docker-compose down --remove-orphans

# Restart services
start-cobra-core.bat
```

### **DeepSeek Not Responding:**
```bash
# Check if DeepSeek is running
docker-compose -f docker-compose.deepseek-only.yml ps

# Restart DeepSeek
docker-compose -f docker-compose.deepseek-only.yml restart deepseek

# Check model download progress
docker-compose -f docker-compose.deepseek-only.yml logs deepseek-setup
```

### **Memory Issues:**
- Ensure you have 8GB+ available RAM
- Close other memory-intensive applications
- Use DeepSeek-R1 7B instead of 8B for lower memory usage

---

## 🎉 **Success! You now have:**

1. ✅ **Complete COBRA AI** running in a single container
2. ✅ **Latest DeepSeek-R1 models** (open source, MIT license)
3. ✅ **Easy startup scripts** for both components
4. ✅ **Local AI processing** (no external dependencies)
5. ✅ **Web interfaces** for both COBRA AI and DeepSeek
6. ✅ **API access** for programmatic integration

**Start using it now:**
```bash
start-cobra-core.bat    # Start COBRA AI
start-deepseek.bat      # Start DeepSeek AI (optional)
```

**Then open:** http://localhost (COBRA AI) and http://localhost:8080 (DeepSeek UI) 