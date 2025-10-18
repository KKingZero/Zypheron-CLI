# 🐍 COBRA AI - Complete Docker Setup Guide

This guide provides **three different ways** to run COBRA AI with Docker, from simple to full-featured setups.

## 🚀 **Quick Start Options**

### **Option 1: All-in-One Container (Recommended) ⭐**
```batch
# Everything in one container
start-all-in-one.bat
```

### **Option 2: All-in-One + DeepSeek LLM 🧠**
```batch
# COBRA AI + Local DeepSeek model
start-with-deepseek.bat
```

### **Option 3: Microservices (Advanced) 🔧**
```batch
# Separate containers for each service
start-docker.bat
```

---

## 📋 **Prerequisites**

1. **Docker Desktop** installed and running
2. **8GB+ RAM** (16GB recommended for DeepSeek)
3. **10GB+ free disk space** (20GB+ for DeepSeek)

---

## 🎯 **Option 1: All-in-One Setup**

**Best for:** Production deployment, single-server setup

**What you get:**
- ✅ All COBRA AI services in one container
- ✅ Frontend, Backend, OSINT, Scanner, Crawler, Packet tools
- ✅ Easy deployment and management
- ✅ Smaller resource footprint

### **Start:**
```batch
start-all-in-one.bat
```

### **Access:**
- **COBRA AI:** http://localhost
- **API:** http://localhost:3001
- **Individual Services:** ports 8001-8005

### **Stop:**
```batch
docker-compose -f docker-compose.all-in-one.yml down
```

---

## 🧠 **Option 2: All-in-One + DeepSeek**

**Best for:** Complete AI-powered penetration testing with local LLM

**What you get:**
- ✅ Everything from Option 1
- ✅ **DeepSeek-Coder 6.7B** model locally
- ✅ **No external API calls** for LLM features
- ✅ **Open-WebUI** for chat interface
- ✅ **Privacy-focused** (all local)

### **Start:**
```batch
start-with-deepseek.bat
```

### **Access:**
- **COBRA AI:** http://localhost
- **DeepSeek Web UI:** http://localhost:8080
- **DeepSeek API:** http://localhost:11434

### **⚠️ Important Notes:**
- **First run:** Downloads ~4GB DeepSeek model (takes 15-30 minutes)
- **RAM:** Requires 8GB+ available RAM
- **GPU:** Optional NVIDIA GPU support available

### **Monitor Download:**
```batch
docker-compose -f docker-compose.with-deepseek.yml logs deepseek-setup
```

### **Stop:**
```batch
docker-compose -f docker-compose.with-deepseek.yml down
```

---

## 🔧 **Option 3: Microservices Setup**

**Best for:** Development, debugging, custom configurations

**What you get:**
- ✅ Each service in separate containers
- ✅ Independent scaling and updates
- ✅ Easy debugging and logs per service
- ✅ Full control over each component

### **Start:**
```batch
start-docker.bat
```

### **Services Running:**
- **Frontend:** Port 80
- **Backend:** Port 3001
- **Database:** Port 5432
- **OSINT:** Port 8001
- **Scanner:** Port 8002
- **Packet:** Port 8003
- **Crawler:** Port 8004
- **Vulnerability:** Port 8005

---

## ⚙️ **Configuration**

### **1. Environment Setup:**
```bash
# Copy environment template
copy .env.example .env

# Edit with your API keys
notepad .env
```

### **2. API Keys (Optional but Recommended):**
```env
# AI Services
OPENAI_API_KEY=your_openai_key
XAI_API_KEY=your_xai_key

# OSINT Services
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

### **3. DeepSeek Configuration:**
```env
# Local LLM
DEEPSEEK_API_URL=http://localhost:11434
DEEPSEEK_MODEL=deepseek-coder:6.7b
ENABLE_LOCAL_LLM=true
```

---

## 🔧 **Advanced Configuration**

### **GPU Support for DeepSeek:**
Edit `docker-compose.with-deepseek.yml`:
```yaml
deepseek:
  runtime: nvidia
  environment:
    - NVIDIA_VISIBLE_DEVICES=all
```

### **Custom DeepSeek Models:**
```bash
# Connect to running container
docker exec -it cobraai-deepseek-1 bash

# Install different models
ollama pull codellama:13b
ollama pull mistral:7b
ollama pull llama2:7b
```

### **Memory Limits:**
```yaml
services:
  cobra-ai:
    mem_limit: 4g
  deepseek:
    mem_limit: 8g
```

---

## 📊 **Resource Requirements**

| Setup | RAM | Disk | Build Time |
|-------|-----|------|------------|
| All-in-One | 4GB | 5GB | 10-15 min |
| + DeepSeek | 8GB | 15GB | 20-30 min |
| Microservices | 6GB | 8GB | 15-20 min |

---

## 🐛 **Troubleshooting**

### **Docker Issues:**
```bash
# Check Docker status
docker info

# View container logs
docker-compose logs cobra-ai

# Restart services
docker-compose restart
```

### **DeepSeek Issues:**
```bash
# Check model download
docker-compose -f docker-compose.with-deepseek.yml logs deepseek-setup

# Test DeepSeek API
curl http://localhost:11434/api/tags

# Restart DeepSeek
docker-compose restart deepseek
```

### **Port Conflicts:**
```bash
# Check what's using ports
netstat -an | findstr "80 3001 11434"

# Stop conflicting services
stop-services.bat
```

### **Build Failures:**
```bash
# Clean rebuild
docker-compose down --rmi all
docker system prune -f
start-all-in-one.bat
```

---

## 🔄 **Updates & Maintenance**

### **Update COBRA AI:**
```bash
# Pull latest code
git pull

# Rebuild containers
docker-compose build --no-cache
```

### **Update DeepSeek Models:**
```bash
docker exec -it cobraai-deepseek-1 ollama pull deepseek-coder:latest
```

### **Backup Data:**
```bash
# Backup volumes
docker run --rm -v cobraai_postgres_data:/data -v $(pwd):/backup ubuntu tar czf /backup/postgres-backup.tar.gz /data
```

---

## 🎯 **Production Deployment**

### **Recommended: All-in-One + DeepSeek**
```bash
# Production environment
copy .env.example .env.production

# Start with production config
docker-compose -f docker-compose.with-deepseek.yml --env-file .env.production up -d
```

### **Security Hardening:**
- Change default passwords
- Set up SSL certificates
- Configure firewall rules
- Enable container resource limits

---

## 📞 **Support**

**Common Issues:**
1. **Port conflicts:** Use `stop-services.bat` first
2. **Memory issues:** Ensure 8GB+ RAM for DeepSeek
3. **Model download fails:** Check internet connection
4. **Build timeouts:** Increase Docker memory limits

**Getting Help:**
- Check logs: `docker-compose logs`
- Test individually: `docker-compose up service-name`
- Clean restart: `docker system prune -f`

---

**🎉 You now have multiple deployment options for COBRA AI, from simple all-in-one to full AI-powered setup with local LLM!** 