# 🚀 Agent Mode - Quick Start Guide

## ⚡ Get Agent Mode Running in 5 Minutes

### **Step 1: Start Redis** (Required for Job Queue)
```bash
docker run -d -p 6379:6379 --name zypheron-redis redis:alpine
```

### **Step 2: Start Backend**
```bash
cd backend
npm install  # If you haven't already
npm run dev
```

**You should see:**
```
🔐 Initializing security services...
🚀 Pentest Job Queue initialized with concurrency: 3
🤖 AI Pentest Orchestrator initialized
✅ Security services initialized
Server running on port 3001
```

### **Step 3: Start Frontend**
```bash
cd frontend
npm run dev
```

### **Step 4: Test Agent Mode**

1. Open browser to `http://localhost:5173`
2. Navigate to **Red Team Ops** page
3. Click the **"Agent Mode"** button (should turn green with pulse)
4. Click **"Professional Suite"** button
5. Select any tool and enter a target
6. Watch the AI work! 🤖

---

## 🧪 Test API Endpoints

### **Test 1: Health Check**
```bash
curl http://localhost:3001/api/agent/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "services": {
    "jobQueue": "operational",
    "aiOrchestrator": "operational",
    "vulnCorrelator": "operational",
    "auditLogger": "operational"
  },
  "queueStats": {
    "waiting": 0,
    "active": 0,
    "completed": 0
  }
}
```

### **Test 2: AI Tool Recommendations**
```bash
curl -X POST http://localhost:3001/api/agent/recommend-tools \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "operationType": "reconnaissance",
    "agentMode": true
  }'
```

**Expected Response:**
```json
{
  "tools": [
    "recon_ng",
    "shodan_search",
    "nmap_scan",
    "maltego_osint",
    "web_port_scan"
  ],
  "reasoning": "AI selected 5 optimal tools for reconnaissance of example.com",
  "estimatedDuration": 600000,
  "confidence": 0.85
}
```

### **Test 3: Execute Tool with AI**
```bash
curl -X POST http://localhost:3001/api/agent/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer localhost-dev-token" \
  -H "x-dev-bypass: true" \
  -d '{
    "toolName": "web_port_scan",
    "parameters": {
      "target": "example.com",
      "portRange": "1-1000",
      "timing": 3
    },
    "agentMode": true
  }'
```

**Expected Response:**
```json
{
  "success": true,
  "toolName": "web_port_scan",
  "result": {
    "ports": [...],
    "aiAnalysis": {
      "recommendations": [...],
      "relatedTools": [...],
      "techniques": [...]
    }
  },
  "agentMode": true
}
```

---

## 🔍 Verify It's Working

### **Check Backend Logs:**
```bash
tail -f backend/logs/audit/combined.log
```

**You should see:**
- Tool execution logs
- AI analysis entries
- Job queue activity

### **Check Redis:**
```bash
redis-cli ping
# Should return: PONG

redis-cli KEYS "bull:*"
# Should show job queue keys
```

### **Check WebSocket Connection:**

Open browser console and run:
```javascript
const ws = new WebSocket('ws://localhost:3001/?type=agent')
ws.onopen = () => console.log('✅ Agent WebSocket connected')
ws.onmessage = (msg) => console.log('📨', JSON.parse(msg.data))
```

---

## 🎯 Use Agent Mode in UI

### **1. Enable Agent Mode:**
- Click the green **"Agent Mode"** button in the top right
- Chat will show: "🤖 Agent Mode Enabled"

### **2. Activate Professional Suite:**
- Click the red **"Professional Suite"** button
- "⚡ WEB TOOLS ACTIVE" badge appears

### **3. Run Automated Assessment:**
When both are enabled:
- AI automatically analyzes the target
- Selects optimal security tools
- Executes comprehensive assessment
- Displays results in real-time chat
- Generates professional reports

### **4. Watch the Magic:**
- Tool execution notifications appear in chat
- Progress bars show real-time status
- AI insights display inline
- Risk scores update automatically
- Recommendations provided after each tool

---

## 📊 What Agent Mode Does

### **Without Agent Mode:**
- ❌ Manual tool selection
- ❌ Manual parameter entry
- ❌ Sequential execution only
- ❌ Basic results display
- ❌ No correlation

### **With Agent Mode:**
- ✅ **AI selects optimal tools** based on target analysis
- ✅ **Auto-generates parameters** contextually
- ✅ **Parallel execution** via job queue (3x faster)
- ✅ **Intelligent analysis** with vulnerability correlation
- ✅ **Attack chain identification** across findings
- ✅ **Business risk scoring** for prioritization
- ✅ **Automated reporting** with remediation steps

---

## 🎨 UI Indicators

### **Agent Mode Active:**
- 🟢 Green button with pulse animation
- "🤖 AGENT MODE" badge visible
- Chat shows AI thinking process
- Tools execute with "AI Analysis" sections

### **Professional Suite Active:**
- 🔴 Red button with pulse animation
- "⚡ WEB TOOLS ACTIVE" label
- All 12+ tools available
- Real-time progress indicators

### **Both Active (Full Automation):**
- 🤖 AI + ⚡ Professional Suite badges
- Automated tool selection starts
- Sequential execution with AI analysis
- Comprehensive assessment runs end-to-end

---

## 🛠️ Troubleshooting

### **"Connection Refused" Error?**
```bash
# Check if Redis is running:
docker ps | grep redis

# If not, start it:
docker run -d -p 6379:6379 --name zypheron-redis redis:alpine
```

### **"Service Unavailable" Error?**
```bash
# Restart backend:
cd backend
npm run dev
```

### **Agent Mode Button Not Working?**
1. Check browser console for errors
2. Verify backend is running on port 3001
3. Test API health: `curl http://localhost:3001/api/agent/health`

### **No AI Analysis in Results?**
1. Ensure `agentMode: true` in request
2. Check if Ollama is running (optional, uses fallback if not)
3. Verify audit logs: `tail -f backend/logs/audit/combined.log`

---

## 📝 Environment Variables (Optional)

Create `backend/.env`:
```bash
# Redis (Required)
REDIS_URL=redis://localhost:6379

# Docker (Required for tool sandboxing)
DOCKER_HOST=unix:///var/run/docker.sock

# AI LLM (Optional - uses fallback if not set)
OLLAMA_URL=http://localhost:11434

# Metasploit (Optional - for exploit features)
METASPLOIT_HOST=localhost
METASPLOIT_PORT=55553
METASPLOIT_USER=msf
METASPLOIT_PASS=msf
```

---

## 🎉 Success!

If you can:
- ✅ Click Agent Mode button and see green pulse
- ✅ Get AI tool recommendations
- ✅ Execute tools with AI analysis
- ✅ See results in real-time chat
- ✅ View WebSocket updates in console

**🎊 Agent Mode is working perfectly!**

---

## 📚 Next Steps

1. **Read Full Documentation:** `AI_PENTEST_IMPROVEMENTS_GUIDE.md`
2. **Explore API Endpoints:** `AGENT_MODE_INTEGRATION_COMPLETE.md`
3. **Review Security Features:** `IMPLEMENTATION_SUMMARY.md`
4. **Test Individual Tools:** Use Professional Suite manually
5. **Run Full Automation:** Enable both Agent Mode + Professional Suite

---

## 💡 Pro Tips

### **Tip 1: Target Format**
```
✅ example.com
✅ https://example.com
✅ 192.168.1.100
❌ example (no TLD)
❌ 192.168.1 (incomplete IP)
```

### **Tip 2: Operation Types**
- `reconnaissance` → recon_ng, shodan, nmap
- `analysis` → nessus, nikto, nuclei
- `exploitation` → metasploit, sqlmap
- `comprehensive` → all tools

### **Tip 3: Watch Logs**
```bash
# Real-time monitoring:
tail -f backend/logs/audit/combined.log | grep "Agent"

# Job queue activity:
redis-cli MONITOR | grep "bull"

# WebSocket traffic:
# Check browser console Network tab → WS
```

---

## 🆘 Need Help?

- **API not responding?** → Check `curl http://localhost:3001/health`
- **Redis connection failed?** → Run `redis-cli ping`
- **Docker permission denied?** → Add user to docker group
- **WebSocket not connecting?** → Check firewall/ports

---

**Status:** ✅ Agent Mode Ready  
**Time to Start:** < 5 minutes  
**Difficulty:** Easy  
**Requirements:** Docker, Redis, Node.js  

🚀 **Let's hack (ethically)!**


